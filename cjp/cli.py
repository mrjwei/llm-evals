"""
`cjp`: the single command-line entry point (Plan P2.1).

Each subcommand is a thin wrapper: it parses flags and calls one function in
the package, so the web app (Plan P6) can call the same functions. Modules
are imported inside each handler, so `cjp --help` loads neither the Anthropic
SDK nor matplotlib.

The four pipeline commands keep the legacy scripts' flags one for one:

  cjp collect   ← wp2_collector.py      cjp map      ← wp4_mapper.py
  cjp triage    ← run_wp3.py            cjp metrics  ← wp4_metrics.py

except `cjp metrics`, which Plan P2.7 rewrote: repeatable --input, and no
--wp3, --synonym or --category (grounding and the legacy event-type score
are gone; legacy rows are scored with the legacy synonym table always).

`cjp doctor` (Plan P2.10) checks every piece the pipeline needs and prints
the fix for each one that fails; `--selftest` adds the test suite (P2.8).
`cjp prompt show` (Plan P2.6) prints the triage prompt and output schema
exactly as sent. `cjp session new` (Plan P2.3) runs a session's traffic on the VM and
collects it. `cjp corpus freeze` copies sessions into a checksummed corpus
(Plan P3.5). `cjp experiment run <ID>` runs one experiment YAML over its
corpus: triage through the cache, map, score, report, all at one address in
the run registry (data/runs/), which `cjp runs` (Plan P2.4) manages along
with the pins in results/canonical.yaml; `cjp results build` regenerates
results/ from those pins (Plan P5). triage, map and metrics stay for
one-off work on a single session. `cjp vm deploy | smoke` (Plan P2.2)
deploy the repo's vm/ to the VM.

`cjp ui` (Plan P6) serves the local web app on 127.0.0.1, whose API calls
the same functions (web/api/). `cjp rating` (Plan P6.6) reports rating
progress and moves a remote rater's scores through the offline pack;
`cjp rating make-batch` (Plan P7.1) draws the blind X5 batch from the
pinned X1 and X2 runs.

Every command except doctor and ui first validates config/settings.yaml and the
environment (Plan P2.10; doctor and the ui's health tiles report problems
as checks instead), and a failure with a known cause (tunnel down, key
rejected, …) prints one line with the fix instead of a traceback
(cjp/errors.py; CJP_DEBUG=1 shows the traceback too).
"""

import argparse
import sys

from cjp import __version__


def _doctor(args: argparse.Namespace) -> int:
    from cjp import doctor
    return doctor.main(offline=args.offline, run_selftest=args.selftest)


# Errors the user can fix (a bad YAML field, an unknown corpus or run, a
# corpus that already exists) print as one line, like `cjp runs`; the
# messages already say what to do.
USER_ERRORS = (ValueError, LookupError, FileNotFoundError, FileExistsError)


def _reraise_if_debug() -> None:
    from cjp.errors import debug
    if debug():
        raise


def _corpus_freeze(args: argparse.Namespace) -> int:
    from cjp import corpus
    try:
        c = corpus.freeze(args.corpus_id, args.sessions, note=args.note)
    except USER_ERRORS as e:
        _reraise_if_debug()
        print(f"[corpus] {e}")
        return 1
    print(f"[corpus] froze {c.id}: {len(c.sessions)} session(s) in {c.path}")
    print(f"[corpus] corpus.json sha256 {c.sha256}")
    for w in c.meta["warnings"]:
        print(f"[corpus] [!] {w}")
    return 0


def _corpus_verify(args: argparse.Namespace) -> int:
    from cjp import corpus
    try:
        c = corpus.load(args.corpus_id)
    except USER_ERRORS as e:
        _reraise_if_debug()
        print(f"[corpus] {e}")
        return 1
    problems = corpus.verify(c)
    for p in problems:
        print(f"[corpus] ✗ {p}")
    print(f"[corpus] {c.id}: " + ("intact" if not problems else f"{len(problems)} problem(s)")
          + f"; corpus.json sha256 {c.sha256}")
    return 1 if problems else 0


def _corpus_list(args: argparse.Namespace) -> int:
    from cjp import corpus
    found = corpus.list_corpora()
    if not found:
        print("[corpus] none frozen yet (cjp corpus freeze C1 --sessions …)")
    for c in found:
        print(f"  {c.id:<8} {len(c.sessions)} session(s), frozen {c.meta['created_at']}, "
              f"sha256 {c.sha256[:12]}" + (f": {c.meta['note']}" if c.meta.get("note") else ""))
    return 0


def _experiment_list(args: argparse.Namespace) -> int:
    from cjp import experiment
    return experiment.list_experiments()


def _experiment_run(args: argparse.Namespace) -> int:
    from cjp import experiment
    cache_mode = "refresh" if args.no_cache else "only" if args.cache_only else "use"
    try:
        return experiment.run(args.experiment, dry_run=args.dry_run, resume=args.resume,
                              cache_mode=cache_mode, yes=args.yes, count=not args.no_count)
    except USER_ERRORS as e:
        _reraise_if_debug()
        print(f"[experiment] {e}")
        return 1


def _experiment_status(args: argparse.Namespace) -> int:
    from cjp import experiment
    try:
        return experiment.status(args.run)
    except USER_ERRORS as e:
        _reraise_if_debug()
        print(f"[experiment] {e}")
        return 1


def _collect(args: argparse.Namespace) -> None:
    from cjp import collect
    if args.offline:
        collect.collect_offline(session_id=args.session_id)
    else:
        collect.collect_online(benign_traffic=args.benign_traffic,
                               application_logging=args.application_logging)


def _session_new(args: argparse.Namespace) -> int:
    from cjp import collect
    return collect.new_session(seed=args.seed, settle=args.settle)


def _triage(args: argparse.Namespace) -> None:
    from cjp.triage import batch
    cache_mode = "refresh" if args.no_cache else "only" if args.cache_only else "use"
    batch.run(session=args.session, variant=args.variant, out=args.out,
              limit=args.limit, resume=args.resume, alerts_file=args.alerts_file,
              repeat=args.repeat, cache_mode=cache_mode, fmt=args.format, model=args.model)


def _prompt_show(args: argparse.Namespace) -> None:
    import json
    from cjp.triage import prompt, schema
    fmt = args.format
    print(f"# prompt {prompt.PROMPT_ID} · format {fmt} · prompt_version "
          f"{prompt.prompt_version(fmt)} · schema_version {schema.schema_version(fmt)}\n")
    print(json.dumps(schema.render_schema(fmt), indent=2) if args.schema
          else prompt.system_prompt(fmt))


def _map(args: argparse.Namespace) -> None:
    from cjp.evaluate import mapper
    mapper.map_session(args.session, wp3=args.wp3, alerts_file=args.alerts_file,
                       out=args.out, tolerance=args.tolerance)


def _metrics(args: argparse.Namespace) -> int:
    from cjp.evaluate import report
    try:
        report.write_report(args.input, args.session, report=args.report)
    except ValueError as e:
        print(f"[metrics] {e}")
        return 1
    return 0


def _results_build(args: argparse.Namespace) -> int:
    from cjp import results
    try:
        return results.build()
    except USER_ERRORS as e:
        _reraise_if_debug()
        print(f"[results] {e}")
        return 1


def _rating_status(args: argparse.Namespace) -> int:
    from cjp import rating
    batches = [b for b in rating.list_batches() if not args.batch or b["id"] == args.batch]
    if args.batch and not batches:
        print(f"[rating] no rating batch {args.batch!r} in {rating.ratings_root()}")
        return 1
    if not batches:
        print(f"[rating] no batches in {rating.ratings_root()}")
    for b in batches:
        cells = []
        for r, p in b["raters"].items():
            cells.append(f"rater {r}: " + ("not started" if p is None else
                                           f"{p['complete']}/{p['total']} complete (via {p['via']})"))
        print(f"[rating] {b['id']}: {b['items']} items, {b['calibration']} calibration · " + " · ".join(cells))
    return 0


def _rating_make_batch(args: argparse.Namespace) -> int:
    from cjp import rating_batch
    try:
        s = rating_batch.make_batch([e.strip() for e in args.sources.split(",") if e.strip()], args.n,
                                    args.seed, args.batch, dry_run=args.dry_run)
    except USER_ERRORS as e:
        _reraise_if_debug()
        print(f"[rating] {e}")
        return 1
    print(f"[rating] {s['batch']}: {s['items']} items ({s['analysed']} analysed + {s['calibration']} "
          f"calibration), seed {s['seed']}, from " + ", ".join(s["runs"].values()))
    for cell_stratum, count in s["counts"].items():
        have = s["available"].get(cell_stratum)
        print(f"[rating]   {cell_stratum:<30} {count:>2}" + (f"   of {have} distinct requests" if have else ""))
    if s["path"] is None:
        print("[rating] dry run: nothing written")
    else:
        print(f"[rating] wrote {s['path']}. key.json maps items to conditions and outcomes: "
              "raters never open it (Plan P7.1)")
    return 0


def _rating_export_pack(args: argparse.Namespace) -> int:
    from cjp import rating
    try:
        path = rating.export_pack(args.batch, args.out)
    except (*USER_ERRORS, rating.RatingConflict) as e:
        _reraise_if_debug()
        print(f"[rating] {e}")
        return 1
    print(f"[rating] wrote {path}: send it to the rater; it opens in any browser, offline. "
          "Their download comes back through `cjp rating import <file>`")
    return 0


def _rating_import(args: argparse.Namespace) -> int:
    from cjp import rating
    try:
        result = rating.import_ratings(args.file)
    except (*USER_ERRORS, rating.RatingConflict) as e:
        _reraise_if_debug()
        print(f"[rating] {e}")
        return 1
    p = result["progress"]
    verb = "already imported, unchanged:" if result["unchanged"] else "saved"
    print(f"[rating] {verb} {result['path']} (rater {result['rater']}, {p['complete']}/{p['total']} complete)")
    return 0


def _ui(args: argparse.Namespace) -> int:
    from web.api.app import serve
    return serve(port=args.port, open_browser=not args.no_browser)


def _vm_deploy(args: argparse.Namespace) -> int:
    from cjp import vm
    return vm.deploy(allow_dirty=args.allow_dirty, smoke=not args.no_smoke, dry_run=args.dry_run)


def _vm_smoke(args: argparse.Namespace) -> int:
    from cjp import vm
    ok, fix = vm.check_agent_localfiles()
    if ok is False:
        print(f"[vm] run this first, then retry:\n\n    {fix}\n")
        return 2
    return 0 if vm.smoke_test(timeout=args.timeout) else 3


def _runs_index(args: argparse.Namespace) -> int:
    from collections import Counter

    from cjp import runs
    path = runs.write_index()
    counts = Counter(r.status for r in runs.list_runs())
    summary = ", ".join(f"{n} {s}" for s, n in sorted(counts.items())) or "no runs"
    print(f"[runs] wrote {path} ({summary})")
    return 0


def _runs_mark_canonical(args: argparse.Namespace) -> int:
    from cjp import runs
    try:
        pin, old = runs.mark_canonical(args.run, args.key, note=args.note)
    except (LookupError, ValueError) as e:
        print(f"[runs] {e}")
        return 1
    was = f" (was {old.get('run')})" if old and old.get("run") != pin["run"] else ""
    print(f"[runs] {args.key} -> {pin['run']}{was}; review and commit results/canonical.yaml")
    return 0


def _runs_supersede(args: argparse.Namespace) -> int:
    from cjp import runs
    try:
        old = runs.supersede(args.run, args.by)
    except (LookupError, ValueError) as e:
        print(f"[runs] {e}")
        return 1
    print(f"[runs] {old.address} superseded by {old.meta['superseded_by']}; "
          "its files stay until `cjp runs prune`")
    return 0


def _runs_prune(args: argparse.Namespace) -> int:
    from cjp import runs
    runs.prune(yes=args.yes)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cjp", description="LLM triage of Wazuh alerts from OWASP Juice Shop traffic.")
    parser.add_argument("--version", action="version", version=f"cjp {__version__}")
    sub = parser.add_subparsers(dest="command", required=True, metavar="<command>")

    # ── doctor (Plan P2.10, P2.8) ────────────────────────────────────────────
    p = sub.add_parser(
        "doctor", help="Check config, API key, models, VM, SSH, Wazuh, Juice Shop and proxy",
        description="Each check prints ok / warn / fail / skip, and the fix for anything not ok. "
                    "Uses no API tokens (the key and models are checked through the Models API) "
                    "and changes nothing. Exit code 0 when nothing failed, else 1.")
    p.add_argument("--offline", action="store_true",
                   help="Skip everything that needs the network (Claude API, VM, Wazuh)")
    p.add_argument("--selftest", action="store_true",
                   help="Also run the offline test suite (pytest; skipped tests are a warning)")
    p.set_defaults(func=_doctor)

    # ── collect (WP2) ────────────────────────────────────────────────────────
    p = sub.add_parser(
        "collect", help="Collect a session's Wazuh alerts into data/sessions/ (WP2)",
        description="Collect a session's alerts (one file per SIEM evidence arm) and "
                    "manifest.json into data/sessions/session_<id>/.")
    p.add_argument(
        "--offline", action="store_true",
        help="Collect session(s) after the traffic scripts have already finished on the "
             "VM. With no --session-id, pulls every VM session not yet in data/sessions/ "
             "(needs VM_HOST in .env). Start/end times, benign_traffic and "
             "application_logging are read from the pulled session, not from flags.")
    p.add_argument(
        "--session-id",
        help="Offline mode only: pull just this VM session id (data/sessions/<id> on the VM).")
    p.add_argument(
        "--benign-traffic", action="store_true",
        help="Online mode only: record in manifest.json that benign_traffic.sh also ran "
             "(it does not run it). --offline detects this from benign_log.jsonl.")
    p.add_argument(
        "--application-logging", action="store_true",
        help="Online mode only: record in manifest.json that the traffic went through the "
             "ingest proxy (JUICE_URL set). --offline reads the value attacks.sh recorded.")
    p.set_defaults(func=_collect)

    # ── session (Plan P2.3) ──────────────────────────────────────────────────
    session_parser = sub.add_parser("session", help="Run a session's traffic on the VM and collect it",
                                    description="Sessions go to data/sessions/session_<id>/.")
    session_sub = session_parser.add_subparsers(dest="session_command", required=True,
                                                metavar="<session command>")
    p = session_sub.add_parser(
        "new", help="Warm-up, traffic, settle, collect: one proxied session (WP1 + WP2)",
        description="Runs run_sessions.sh in the deployed VM_ROOT (attacks, then benign traffic, "
                    "through the ingest proxy), waits for Wazuh, then collects it like "
                    "`cjp collect --offline --session-id <id>`. manifest.json records the VM's "
                    "deployed SHA, the seed, the benign-set version and, per arm, log lines and "
                    "alerts. Takes about 5 minutes. Exit codes: 0 all three arms have alerts, "
                    "1 failed, 3 collected but an arm has no alerts.")
    p.add_argument("--seed", type=int, required=True,
                   help="Traffic seed, recorded in the manifest (benign pacing now; payload "
                        "variants from Plan P3.3)")
    p.add_argument("--settle", type=float, default=60.0,
                   help="Seconds to wait for Wazuh after the traffic (default 60)")
    p.set_defaults(func=_session_new)

    # ── corpus (Plan P3.5) ───────────────────────────────────────────────────
    corpus_parser = sub.add_parser(
        "corpus", help="Freeze sessions into a checksummed corpus that experiments run on",
        description="A corpus is data/corpus/<ID>/: read-only copies of its sessions and "
                    "corpus.json (per-file sha256, provenance). It is never overwritten.")
    corpus_sub = corpus_parser.add_subparsers(dest="corpus_command", required=True,
                                              metavar="<corpus command>")
    p = corpus_sub.add_parser("freeze", help="Copy sessions into data/corpus/<ID>/ and checksum them")
    p.add_argument("corpus_id", help="Corpus ID, e.g. C1 or C1-inj")
    p.add_argument("--sessions", nargs="+", required=True,
                   help="Session names under data/sessions/ (session_<id> or <id>) or paths")
    p.add_argument("--note", help="One line on what the corpus is, stored in corpus.json")
    p.set_defaults(func=_corpus_freeze)
    p = corpus_sub.add_parser("verify", help="Check every file against corpus.json's checksums")
    p.add_argument("corpus_id")
    p.set_defaults(func=_corpus_verify)
    p = corpus_sub.add_parser("list", help="List frozen corpora")
    p.set_defaults(func=_corpus_list)

    # ── experiment (Plan §2.3, P5) ───────────────────────────────────────────
    experiment_parser = sub.add_parser(
        "experiment", help="Run one experiment YAML end to end: triage, map, score, report",
        description="experiments/<ID>.yaml names the question, RQ, corpus, conditions and repeats. "
                    "A run goes to data/runs/<ID>-<slug>/<run>/ (run.json, report.md, "
                    "conditions/<c>/…) and INDEX.md is regenerated.")
    experiment_sub = experiment_parser.add_subparsers(dest="experiment_command", required=True,
                                                      metavar="<experiment command>")
    p = experiment_sub.add_parser("list", help="List experiments/*.yaml and whether each corpus is frozen")
    p.set_defaults(func=_experiment_list)
    p = experiment_sub.add_parser(
        "run", help="Run an experiment (paid API calls on cache misses; asks first)",
        description="Verifies the corpus, then prints per condition the alerts, what the cache "
                    "answers and the paid calls needed, with input tokens (count_tokens, free) and "
                    "the most it can cost. Asks before any paid call unless --yes. Exit codes: 0 "
                    "complete, 1 not run, failed or incomplete (the resume command is printed).")
    p.add_argument("experiment", help="Experiment ID (experiments/<ID>.yaml), e.g. X1")
    p.add_argument("--dry-run", action="store_true",
                   help="Print the plan and the estimate, then stop: nothing written, nothing spent")
    p.add_argument("--resume", metavar="RUN",
                   help="Continue a failed or interrupted run (address or run ID) in place; "
                        "only with the same inputs (config_hash)")
    p.add_argument("--yes", action="store_true",
                   help="Don't ask before paid calls (the estimate still prints)")
    p.add_argument("--no-count", action="store_true",
                   help="Estimate input tokens from characters instead of count_tokens (offline)")
    cache_flags = p.add_mutually_exclusive_group()
    cache_flags.add_argument("--no-cache", action="store_true",
                             help="Call the API for every alert (old cache entries kept as superseded)")
    cache_flags.add_argument("--cache-only", action="store_true",
                             help="Never call the API; refuse to start if any alert is uncached")
    p.set_defaults(func=_experiment_run)
    p = experiment_sub.add_parser("status", help="Progress of a run, or the latest run per experiment")
    p.add_argument("run", nargs="?", help="Run address or run ID (default: latest of each experiment)")
    p.set_defaults(func=_experiment_status)

    # ── triage (WP3) ─────────────────────────────────────────────────────────
    p = sub.add_parser(
        "triage", help="Triage every alert of a session with Claude (WP3; paid API calls)",
        description="One Claude call per alert, unless the response cache "
                    "(data/cache/responses/) already holds the same request and repeat. Output: "
                    "data/outputs/wp3/<session>/<variant>_v<N>/output.jsonl. "
                    "Cache misses call the Claude API and cost money; the count is printed first.")
    p.add_argument("--session", help="Session directory to replay offline. Always pass it: "
                                     "without it the live indexer is read, which is not reproducible")
    p.add_argument("--variant", help="Run-directory tag (default: 'default'), e.g. primary / "
                                     "enriched / body_field")
    p.add_argument("--out", help="Explicit output file (overrides the auto-versioned run directory)")
    p.add_argument("--limit", type=int, default=50,
                   help="Alert limit for live-indexer mode (ignored with --session)")
    p.add_argument("--resume", help="Existing (possibly partial) output file to continue; alert IDs "
                                    "already in it are skipped. Requires --session")
    p.add_argument("--alerts-file", default="wazuh_alerts.jsonl",
                   help="Alert file, relative to --session: wazuh_alerts.jsonl (default, S1), "
                        "enriched_wazuh_alerts.jsonl (S2) or body_field_wazuh_alerts.jsonl (S3)")
    p.add_argument("--repeat", type=int, default=1,
                   help="Repeat number (default 1). Each repeat of the same request is a separate "
                        "sample with its own cache entry")
    p.add_argument("--format", type=str.upper, choices=["A", "B"], default="A",
                   help="Output format: A = full schema (default), B = minimal schema "
                        "(technique_label, disposition, confidence, recommended_action)")
    p.add_argument("--model", help="Model alias or ID from config/settings.yaml `models` "
                                   "(default: triage.model, or CJP_TRIAGE_MODEL)")
    cache_flags = p.add_mutually_exclusive_group()
    cache_flags.add_argument("--no-cache", action="store_true",
                             help="Call the API for every alert; the old cache entry is kept as "
                                  "superseded, the new response replaces it")
    cache_flags.add_argument("--cache-only", action="store_true",
                             help="Never call the API: stop before writing anything if an alert has "
                                  "no cached response")
    p.set_defaults(func=_triage)

    # ── prompt (P2.6) ────────────────────────────────────────────────────────
    prompt_parser = sub.add_parser(
        "prompt", help="Show the triage prompt and output schema as sent (no API call)")
    prompt_sub = prompt_parser.add_subparsers(dest="prompt_command", required=True,
                                              metavar="<prompt command>")
    p = prompt_sub.add_parser(
        "show", help="Print the rendered system prompt (or --schema) with its version hashes",
        description="Rendered from prompts/triage_v2.md, taxonomy/labels.yaml and "
                    "prompts/format_<a|b>.json, exactly as cjp triage sends it.")
    p.add_argument("--format", type=str.upper, choices=["A", "B"], default="A",
                   help="Output format (default A)")
    p.add_argument("--schema", action="store_true",
                   help="Print the JSON Schema sent as output_config.format instead of the prompt")
    p.set_defaults(func=_prompt_show)

    # ── map (WP4) ────────────────────────────────────────────────────────────
    p = sub.add_parser(
        "map", help="Map each alert to the attack technique that caused it (WP4)",
        description="Join alerts to ground truth by correlation ID (interval fallback for old "
                    "sessions; URL-signature cross-check). Output: "
                    "data/outputs/wp4/<session>/<arm>_v<N>/output.jsonl.")
    p.add_argument("--session", required=True, help="Session directory")
    p.add_argument("--wp3", help="Optional triage output file to join the LLM's answers in")
    p.add_argument("--alerts-file", default="wazuh_alerts.jsonl",
                   help="Alert file to map, relative to --session (default: wazuh_alerts.jsonl)")
    p.add_argument("--out", help="Explicit output file (overrides the auto-versioned run directory)")
    p.add_argument("--tolerance", type=float, default=1.5,
                   help="Interval-fallback tolerance in seconds (default 1.5)")
    p.set_defaults(func=_map)

    # ── metrics (WP4) ────────────────────────────────────────────────────────
    p = sub.add_parser(
        "metrics", help="Metrics, report.md and charts for mapped alerts (WP4; no API calls)",
        description="SIEM detection metrics, then the triage answer scored three ways (correct / "
                    "wrong / abstained), coverage, selective and strict accuracy (fine and coarse), "
                    "disposition, calibration and cost, with bootstrap CIs over distinct requests. "
                    "Writes report.md, metrics.json, scores.jsonl, report_meta.json and charts/ next "
                    "to the first --input (or in metrics/report_v<N>/ there if a report exists).")
    p.add_argument("--input", required=True, action="append",
                   help="Mapper output file (cjp map --wp3 …). Repeat the flag once per triage "
                        "repeat of the same session; the repeats are pooled and their spread shown")
    p.add_argument("--session", required=True,
                   help="Session directory --input was mapped from (supplies the techniques with "
                        "zero alerts, the benign population and the request clusters)")
    p.add_argument("--report", help="Explicit report path")
    p.set_defaults(func=_metrics)

    # ── runs (Plan P2.4) ─────────────────────────────────────────────────────
    runs_parser = sub.add_parser(
        "runs", help="Run registry: INDEX.md, canonical pins, superseded runs",
        description="Runs live at data/runs/<experiment>/<run>/ (run.json, conditions/<c>/rep<N>/). "
                    "A run is named by its address, e.g. X1-evidence/2026-10-09T1030_ab12cd, "
                    "or by its bare run ID when that is unique.")
    runs_sub = runs_parser.add_subparsers(dest="runs_command", required=True, metavar="<runs command>")
    p = runs_sub.add_parser("index", help="Regenerate data/runs/INDEX.md (also done after every run)")
    p.set_defaults(func=_runs_index)
    p = runs_sub.add_parser(
        "mark-canonical", help="Pin a complete run as its experiment's canonical run",
        description="Writes results/canonical.yaml (tracked; commit it) and regenerates INDEX.md. "
                    "Every figure that reads the experiment then comes from this run "
                    "(decision 012). Re-pinning moves the key to the new run.")
    p.add_argument("run", help="Run address or run ID")
    p.add_argument("--as", dest="key", metavar="KEY",
                   help="Pin key (default: the run's experiment ID, e.g. X1, which is what "
                        "`cjp results build` reads)")
    p.add_argument("--note", help="Optional one-line reason, stored with the pin")
    p.set_defaults(func=_runs_mark_canonical)
    p = runs_sub.add_parser(
        "supersede", help="Mark a run superseded by a newer complete run of the same experiment",
        description="Nothing is deleted: the old run stays, marked, until `cjp runs prune`.")
    p.add_argument("run", help="The run being replaced (address or run ID)")
    p.add_argument("--by", required=True, help="The complete run that replaces it")
    p.set_defaults(func=_runs_supersede)
    p = runs_sub.add_parser(
        "prune", help="Delete superseded runs after listing them and asking once",
        description="Prints a manifest (path · action · reason) and asks before deleting. "
                    "Runs pinned in results/canonical.yaml are never deleted.")
    p.add_argument("--yes", action="store_true", help="Skip the question (the manifest still prints)")
    p.set_defaults(func=_runs_prune)

    # ── results (Plan §2.3 rule 4, P5) ───────────────────────────────────────
    results_parser = sub.add_parser(
        "results", help="Regenerate results/ (tables, figures) from the canonical runs",
        description="results/canonical.yaml lists the figures and pins one run per experiment "
                    "(decision 012).")
    results_sub = results_parser.add_subparsers(dest="results_command", required=True,
                                                metavar="<results command>")
    p = results_sub.add_parser(
        "build", help="Write results/tables/*.csv, results/figures/*.png and results/manifest.json",
        description="Reads only the pinned runs' stored outputs (no API call, no re-scoring). "
                    "Every figure's footer names its runs. Checks each pin: a complete run of its "
                    "experiment, made from a clean prereg-C1 descendant. Never deletes; files it "
                    "did not write are listed as stale. Exit code 0 when every figure was built "
                    "and every check passed, else 1.")
    p.set_defaults(func=_results_build)

    # ── rating (Plan P6.6, WP5′) ──────────────────────────────────────────────
    rating_parser = sub.add_parser(
        "rating", help="Blind expert rating: the batch, progress, the offline pack, importing its scores",
        description="Batches live at data/ratings/<batch>/ (batch.json, items.jsonl, key.json, "
                    "ratings/rater-<A|B>.json). Raters work in `cjp ui` (Rate) or in the offline "
                    "pack; neither ever reads key.json.")
    rating_sub = rating_parser.add_subparsers(dest="rating_command", required=True,
                                              metavar="<rating command>")
    p = rating_sub.add_parser("status", help="Each batch's items and each rater's progress")
    p.add_argument("batch", nargs="?", help="One batch ID (default: all)")
    p.set_defaults(func=_rating_status)
    p = rating_sub.add_parser(
        "make-batch", help="Draw the blind X5 batch from the pinned X1 and X2 runs (Plan P7.1)",
        description="Stratified per METHODS §7 and decision 021: per cell (S1xL0 FA, S1xL1 FA, "
                    "S1xL1 FB) the same number of attack-correct, attack-wrong, attack-abstained "
                    "and benign items, plus 6 calibration items; each request at most once. Every "
                    "item is rebuilt from the corpus and checked against the answer's cache key. "
                    "Prints counts only, never which item is which. Never replaces a batch.")
    p.add_argument("--from", dest="sources", default="X1,X2",
                   help="The pinned experiments to draw from (default and only choice: X1,X2)")
    p.add_argument("--n", type=int, default=48, help="Items analysed, a multiple of 12 (default 48)")
    p.add_argument("--seed", type=int, default=7, help="Random seed (default 7)")
    p.add_argument("--batch", default="X5", help="Batch ID, the folder in data/ratings/ (default X5)")
    p.add_argument("--dry-run", action="store_true", help="Draw and check, but write nothing")
    p.set_defaults(func=_rating_make_batch)
    p = rating_sub.add_parser(
        "export-pack", help="Write a self-contained HTML file for a rater without the app",
        description="One file, no network: the rater picks A or B, rates one item per screen, "
                    "scores autosave in their browser, and \"Download ratings\" saves a JSON for "
                    "`cjp rating import`. Default: data/ratings/<batch>/<batch>_rating-pack.html.")
    p.add_argument("batch", help="Batch ID (a folder in data/ratings/)")
    p.add_argument("--out", help="Where to write the pack")
    p.set_defaults(func=_rating_export_pack)
    p = rating_sub.add_parser(
        "import", help="Save a pack's downloaded ratings as that rater's file",
        description="Checks the batch, the rater, every item and score, and the rubric version. "
                    "Never replaces scores a rater already has: move that file away first.")
    p.add_argument("file", help="The JSON the pack downloaded (<batch>_rater-<A|B>.json)")
    p.set_defaults(func=_rating_import)

    # ── ui (Plan P6) ─────────────────────────────────────────────────────────
    p = sub.add_parser(
        "ui", help="Open the local web app: health, triage, rating and results",
        description="Serves the API and the built UI (web/ui/dist/) from one process on "
                    "http://127.0.0.1:<port>/, reachable from this Mac only, and opens the "
                    "browser. The API key stays in this process. Ctrl-C stops it.")
    p.add_argument("--port", type=int, default=8738, help="Local port (default 8738)")
    p.add_argument("--no-browser", action="store_true", help="Don't open the browser")
    p.set_defaults(func=_ui)

    # ── vm (Plan P2.2) ───────────────────────────────────────────────────────
    vm_parser = sub.add_parser("vm", help="Deploy vm/ to the VM and smoke-test it",
                               description="The VM runs whatever `cjp vm deploy` puts in VM_ROOT "
                                           "(~/cjp-vm), so one git SHA pins the Mac and the VM.")
    vm_sub = vm_parser.add_subparsers(dest="vm_command", required=True, metavar="<vm command>")
    p = vm_sub.add_parser(
        "deploy", help="rsync vm/ to the VM, run vm/deploy.sh, check the agent, smoke-test",
        description="Idempotent. rsync vm/ to VM_ROOT; on the VM: data dirs, proxy venv, custom "
                    "rules (wazuh-logtest cases before any manager restart), Juice Shop container, "
                    "ingest proxy, DEPLOYED_SHA. Then check the agent's <localfile> paths through "
                    "the manager API (prints the one sudo command if they differ) and smoke-test "
                    "all three arms. Exit codes: 0 ok, 1 failed, 2 sudo step needed, 3 smoke failed.")
    p.add_argument("--allow-dirty", action="store_true",
                   help="Deploy even if vm/ has uncommitted changes (recorded as <sha>-dirty)")
    p.add_argument("--no-smoke", action="store_true", help="Skip the end-to-end smoke test")
    p.add_argument("--dry-run", action="store_true", help="Only show what rsync would change")
    p.set_defaults(func=_vm_deploy)
    p = vm_sub.add_parser("smoke", help="Check the agent paths, then send one request and wait for "
                                        "its alert in every arm")
    p.add_argument("--timeout", type=float, default=180.0, help="Seconds to wait (default 180)")
    p.set_defaults(func=_vm_smoke)

    return parser


def main(argv: list[str] | None = None) -> int | None:
    from cjp import config, errors
    args = build_parser().parse_args(argv)
    try:
        if args.command not in ("doctor", "ui"):    # both report config problems as a check
            config.check()
        return args.func(args)
    except KeyboardInterrupt:
        print("\n[cjp] interrupted; finished work is kept (triage: rerun with --resume)")
        return 130
    except Exception as e:
        message = errors.explain(e)
        if message is None or errors.debug():
            raise
        print(f"[cjp] {message}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
