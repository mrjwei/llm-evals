"""
WP3 — triage every alert of one session (or the live indexer) with Claude and
write one row per alert. Moved from run_wp3.py in Plan P2.1; run it as
`cjp triage`. Output goes to data/outputs/wp3/<session>/<variant>_v<N>/.

Each row is written and flushed as soon as its call returns, so a crash loses
at most the call in flight, and --resume skips alert IDs already answered.
A call that fails even after the client's retries (Plan P2.10) is written as
an `api_error` row: it records the failure but is not an answer, so --resume
tries that alert again and scoring leaves it out (an outage is not the
model's mistake). A fatal error (bad key, unknown model, rejected request)
stops the batch at once; three other failures in a row stop it too, with the
command that resumes it. Calls go through the response cache (cjp.cache, Plan P2.5): before the first
call the runner counts how many alerts the cache already answers and how many
need a paid call, and prints both.
"""

import json
import os
from datetime import datetime, timezone

from rich.console import Console
from rich.progress import track

from cjp import cache
from cjp.config import OUTPUTS_DIR, model_profile
from cjp.errors import explain
from cjp.indexer import get_alerts
from cjp.runs import append_invocation, git_sha, resolve_run_dir
from cjp.triage.client import FATAL_ERRORS, analyse_alert, cache_key_for
from cjp.triage.prompt import DEFAULT_FORMAT, PROMPT_ID, extract_cid, prompt_version

console = Console()

OUTPUT_DIR = str(OUTPUTS_DIR / "wp3")


def load_alerts_from_session(session_path: str, alerts_file: str = "wazuh_alerts.jsonl") -> list[dict]:
    """Read alerts from a WP2 session's alert file (offline replay). alerts_file
    is relative to session_path — pass enriched_wazuh_alerts.jsonl or
    body_field_wazuh_alerts.jsonl to analyse one of the other two collection
    arms instead, mirroring `cjp map --alerts-file`."""
    alerts_path = os.path.join(session_path, alerts_file)
    alerts = []
    with open(alerts_path) as f:
        for line in f:
            line = line.strip()
            if line:
                alerts.append(json.loads(line))
    return alerts


def load_ingest_log(session_path: str) -> dict[str, dict]:
    """Index a WP2 session's ingest_log.jsonl (request/response bodies logged
    by the ingest proxy, ARCHITECTURE §5) by cid, for per-alert
    lookup in run(). Empty dict if the session predates the sidecar or ran
    with it off (application_logging: false in manifest.json) — either way
    ingest_log.jsonl won't exist or will be empty, and callers treat a miss
    as "no body evidence for this alert" exactly like today."""
    ingest_file = os.path.join(session_path, "ingest_log.jsonl")
    if not os.path.exists(ingest_file):
        return {}
    by_cid = {}
    with open(ingest_file) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            entry = json.loads(line)
            by_cid[entry["cid"]] = entry
    return by_cid


def is_api_error(rec: dict) -> bool:
    """A row written because the call failed, not because the model answered.
    Rows from before P2.10 carry no flag but an "exception: …" error."""
    if rec.get("api_error"):
        return True
    error = (rec.get("llm_output") or {}).get("error")
    return isinstance(error, str) and error.startswith("exception: ")


def load_completed_ids(path: str) -> set:
    """wazuh_alert_ids already answered in an (possibly partial) output file.
    api_error rows don't count, so --resume retries those alerts; the retry's
    row is appended after them, and readers keep the last row per alert."""
    completed = set()
    if not os.path.exists(path):
        return completed
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                console.print(
                    f"[yellow]⚠ Skipping unparseable line while loading resume "
                    f"state: {line[:80]!r}[/yellow]"
                )
                continue
            alert_id = rec.get("wazuh_alert_id")
            if alert_id is None:
                continue
            if is_api_error(rec):
                completed.discard(alert_id)
            else:
                completed.add(alert_id)
    return completed


def api_error_row(alert: dict, exc: BaseException, *, fmt: str, repeat: int) -> dict:
    """The row written for a call that failed (see the module docstring)."""
    return {
        "wazuh_alert_id": alert.get("id"),
        "wazuh_timestamp": alert.get("timestamp"),
        "wazuh_rule_id": alert.get("rule", {}).get("id"),
        "wazuh_rule_description": alert.get("rule", {}).get("description"),
        "ground_truth_location": alert.get("location"),
        "format": fmt,
        "ingest_matched": False,
        "repeat": repeat,
        "cache_hit": False,
        "api_error": True,
        "llm_output": {"error": f"exception: {type(exc).__name__}: {exc}"},
        "parse_ok": False,
        "schema_ok": False,
        "stop_reason": None,
        "token_usage": {"input_tokens": 0, "output_tokens": 0, "total_tokens": 0},
    }


MAX_CONSECUTIVE_FAILURES = 3

def make_jobs(alerts: list[dict], ingest_by_cid: dict[str, dict] | None) -> list[tuple[dict, dict | None]]:
    """Pair each alert with its ingest_log entry, looked up by CID before the
    CID is redacted. ingest_by_cid None or empty: no body evidence (L0)."""
    jobs = []
    for alert in alerts:
        cid = extract_cid(alert.get("full_log", "")) if ingest_by_cid else None
        jobs.append((alert, ingest_by_cid.get(cid) if cid else None))
    return jobs


def triage_jobs(jobs: list[tuple[dict, dict | None]], output_file: str, *, append: bool = False,
                repeat: int = 1, cache_mode: str = "use", fmt: str = DEFAULT_FORMAT,
                model: str | None = None, verbose: bool = True) -> dict:
    """Triage each (alert, ingest entry) and write one row per alert to
    output_file, flushed as soon as its call returns, so a crash loses only
    the call in flight. Shared by `cjp triage` and `cjp experiment run`.
    Stops early on a fatal error or MAX_CONSECUTIVE_FAILURES failures in a
    row (see the module docstring). Returns the counts."""
    stats = {"processed": 0, "cache_hits": 0, "api_calls": 0, "api_errors": 0,
             "tokens_billed": 0, "total_tokens": 0, "aborted": False}
    consecutive_failures = 0
    with open(output_file, "a" if append else "w") as f:
        for alert, ingest_entry in track(jobs, description="Analysing alerts...",
                                         disable=not jobs, console=console):
            fatal = False
            try:
                result = analyse_alert(alert, ingest_entry=ingest_entry, repeat=repeat,
                                       cache_mode=cache_mode, fmt=fmt, model=model)
                consecutive_failures = 0
            except Exception as e:
                consecutive_failures += 1
                stats["api_errors"] += 1
                fatal = isinstance(e, FATAL_ERRORS)
                console.print(f"[red]✗ Alert {alert.get('id')} failed: {explain(e) or e}[/red]")
                result = api_error_row(alert, e, fmt=fmt, repeat=repeat)

            f.write(json.dumps(result) + "\n")
            f.flush()
            stats["processed"] += 1
            stats["total_tokens"] += result["token_usage"]["total_tokens"]
            if result["cache_hit"]:
                stats["cache_hits"] += 1
            else:
                stats["api_calls"] += 1
                stats["tokens_billed"] += result["token_usage"]["total_tokens"]

            llm = result.get("llm_output", {})
            if verbose and "error" not in llm:
                console.print(
                    f"  [{_disposition_colour(llm.get('disposition', ''))}]"
                    f"{llm.get('disposition', '?')}[/] "
                    f"[white]{llm.get('technique_label', '?')}[/] "
                    f"[dim]({llm.get('confidence', '?')} confidence, "
                    f"{result['token_usage']['total_tokens']} tokens)[/dim]"
                )

            if fatal or consecutive_failures >= MAX_CONSECUTIVE_FAILURES:
                why = ("it would fail the same way for every alert" if fatal else
                       f"{consecutive_failures} consecutive failures")
                console.print(f"\n[red]✗ Stopping: {why}.[/red]")
                stats["aborted"] = True
                break
    return stats


def run(session: str | None = None, variant: str | None = None,
        out: str | None = None, limit: int = 50, resume: str | None = None,
        alerts_file: str = "wazuh_alerts.jsonl", repeat: int = 1, cache_mode: str = "use",
        fmt: str = DEFAULT_FORMAT, model: str | None = None):
    fmt = fmt.upper()
    profile = model_profile(model)
    console.print("\n[bold cyan]WP3 — LLM-Based Log Analysis[/bold cyan]\n")
    console.print(f"[dim]→ Prompt {PROMPT_ID}, format {fmt} (prompt version {prompt_version(fmt)}), "
                  f"model {profile['id']}[/dim]")

    if session:
        console.print(f"[dim]→ Reading alerts from session {session!r} ({alerts_file})...[/dim]")
        alerts = load_alerts_from_session(session, alerts_file)
        session_tag = os.path.basename(os.path.normpath(session))
        ingest_by_cid = load_ingest_log(session)
        if ingest_by_cid:
            console.print(
                f"[dim]→ {len(ingest_by_cid)} ingest_log.jsonl entries loaded — "
                f"alerts with a matching cid will include request/response body[/dim]"
            )
    else:
        console.print(
            "[yellow]⚠ No --session given — querying the live indexer. "
            "Results are not bound to a frozen alert corpus and will not "
            "be reproducible.[/yellow]"
        )
        console.print(f"[dim]→ Fetching up to {limit} Juice Shop alerts...[/dim]")
        alerts = get_alerts(limit=limit)
        session_tag = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        ingest_by_cid = {}

    console.print(f"[green]✓ {len(alerts)} alerts retrieved[/green]\n")

    if not alerts:
        console.print("[yellow]No Juice Shop alerts found.[/yellow]")
        console.print("Run your attack scripts in the VM first:")
        console.print("  [dim]bash run_sessions.sh[/dim]")
        return

    # resolve output path and resume state
    if resume:
        if not session:
            console.print(
                "[red]✗ --resume requires --session — live-mode results aren't "
                "reproducible, so resuming against a fresh live query is unsound.[/red]"
            )
            return
        output_file = resume
        completed_ids = load_completed_ids(output_file)
        console.print(f"[dim]→ Resuming {output_file!r}: {len(completed_ids)} alert(s) already completed[/dim]")
    else:
        completed_ids = set()

    pending = [a for a in alerts if a.get("id") not in completed_ids]
    skipped = len(alerts) - len(pending)
    if skipped:
        console.print(f"[dim]→ Skipping {skipped} already-completed alert(s)[/dim]")

    if not pending:
        console.print("[green]✓ Nothing to do — every alert is already in this output file.[/green]\n")
        return

    # pair each alert with its ingest_log entry (looked up by CID before the
    # CID is redacted), then count what the cache already answers
    jobs = make_jobs(pending, ingest_by_cid)
    if cache_mode == "refresh":
        cached = 0
    else:
        cached = sum(cache.has(cache_key_for(a, e, repeat, fmt, model)) for a, e in jobs)
    console.print(f"[dim]→ Repeat {repeat}: {cached} alert(s) answered by the cache, "
                  f"{len(jobs) - cached} API call(s) needed (cache: {cache_mode})[/dim]")
    if cache_mode == "only" and cached < len(jobs):
        console.print(f"[red]✗ --cache-only: {len(jobs) - cached} alert(s) have no cached "
                      f"response. Nothing written.[/red]")
        return

    # a new run's directory is created only once there is work to do
    if not resume:
        if out:
            output_file = out
        else:
            run_dir = resolve_run_dir(OUTPUT_DIR, session_tag, variant or "default")
            output_file = os.path.join(run_dir, "output.jsonl")

    stats = triage_jobs(jobs, output_file, append=bool(resume), repeat=repeat,
                        cache_mode=cache_mode, fmt=fmt, model=model)
    aborted, processed, cache_hits = stats["aborted"], stats["processed"], stats["cache_hits"]
    api_errors, tokens_billed, total_tokens = (stats["api_errors"], stats["tokens_billed"],
                                               stats["total_tokens"])
    if aborted:
        console.print(f"[dim]  Fix the underlying issue, then resume with:\n"
                      f"  {resume_command(session, output_file, alerts_file, repeat, fmt, model)}"
                      f"[/dim]")

    # summary
    if aborted:
        console.print(f"\n[bold yellow]⚠ Analysis aborted early[/bold yellow]")
    else:
        console.print(f"\n[bold green]✓ Analysis complete[/bold green]")
    console.print(f"  Alerts analysed this run : {processed}")
    if skipped:
        console.print(f"  Alerts skipped (resumed) : {skipped}")
    console.print(f"  From the cache           : {cache_hits}")
    console.print(f"  API calls (this run)     : {processed - cache_hits}")
    if api_errors:
        console.print(f"  [red]Failed calls           : {api_errors} (retried by --resume)[/red]")
    console.print(f"  Tokens billed (this run) : {tokens_billed}")
    console.print(f"  Total tokens (all rows)  : {total_tokens}")
    console.print(f"  Avg per alert (all rows) : {total_tokens // processed if processed else 0}")
    console.print(f"  Output saved to          : {output_file}\n")

    meta_file = append_invocation(output_file, {
        "script": "cjp triage",
        "cli_args": {"session": session, "variant": variant, "out": out,
                     "limit": limit, "resume": resume, "alerts_file": alerts_file,
                     "repeat": repeat, "cache_mode": cache_mode, "format": fmt,
                     "model": model},
        "git_sha": git_sha(),
        "prompt_id": PROMPT_ID,
        "prompt_version": prompt_version(fmt),
        "format": fmt,
        "model": profile["id"],
        "session_dir": session,
        "alerts_processed": processed,
        "alerts_skipped_resumed": skipped,
        "cache_hits": cache_hits,
        "api_calls": processed - cache_hits,
        "api_errors": api_errors,
        "total_tokens": total_tokens,
        "tokens_billed": tokens_billed,
        "aborted": aborted,
    })
    console.print(f"  Run metadata saved to    : {meta_file}\n")


def resume_command(session, output_file, alerts_file, repeat, fmt, model) -> str:
    """The exact `cjp triage` call that continues this batch: same arm,
    repeat, format and model, or the resumed alerts would be asked a
    different question than the ones already in the file."""
    cmd = f"cjp triage --session {session} --resume {output_file}"
    if alerts_file != "wazuh_alerts.jsonl":
        cmd += f" --alerts-file {alerts_file}"
    if repeat != 1:
        cmd += f" --repeat {repeat}"
    if fmt != DEFAULT_FORMAT:
        cmd += f" --format {fmt}"
    if model:
        cmd += f" --model {model}"
    return cmd


def _disposition_colour(disposition: str) -> str:
    return {
        "escalate": "bold red",
        "needs_more_info": "yellow",
        "dismiss_false_positive": "green",
    }.get(disposition, "white")
