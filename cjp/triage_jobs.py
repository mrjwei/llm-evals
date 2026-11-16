"""
Triage jobs (Plan P6.2): the web app's Triage page runs Claude over alerts a
person picks. Each job lives in data/triage_jobs/<job-id>/, never mixed with
research runs (Plan §2.3):

    data/triage_jobs/<job-id>/
        job.json            source, options, estimate, progress, actual tokens and cost, status
        alerts.jsonl        the job's alerts, captured once, every correlation ID redacted
        bodies.jsonl        request/response bodies by alert ID (only with bodies on)
        verdicts_A.jsonl    one triage row per alert, as `cjp triage` writes it (format A)
        verdicts_B.jsonl    the same for format B, when the job asked for it

Three sources:
- **demo**: one session of a frozen corpus (C1). Ground truth stays behind:
  no attack or benign log is copied, and the correlation IDs, which name the
  session and mark benign traffic, are redacted.
- **upload**: a Wazuh alerts `.jsonl`, plus an optional ingest_log.jsonl for bodies.
- **live**: the indexer's alerts in a time window, optionally for one agent,
  with bodies read from the VM's ingest log by correlation ID over SSH.

The alerts are captured when the job is created, so resuming a live job
continues on the same alerts instead of a new query.

Every call goes through the response cache at repeat 1, with the same
request `cjp triage` and the experiments send: build_alert_summary()
redacts the IDs anyway, so redacting them first changes nothing. A demo job
on C1 therefore replays X1's and X2's cached answers and costs nothing.

Spending is never silent. create() captures, plans and estimates (paid
calls, input tokens, the most they can cost), then stops. start() takes the
number of paid calls the person approved and refuses a job that needs more.
One job runs at a time, in a background thread, one alert at a time: each
row is flushed as soon as its call returns, and progress goes to job.json.
stop() ends it after the call in flight. Starting a stopped, failed or
interrupted job again resumes it: answered alerts are skipped, and api_error
rows are retried, as in `cjp triage --resume`.

cjp/triage/ is frozen at prereg-C1, so this module reuses it unchanged. The
loop is batch.triage_jobs()'s rules (fatal errors and three failures in a row
stop it), rewritten here to add progress and a stop flag.
"""

import fcntl
import hashlib
import inspect
import json
import os
import re
import secrets
import shlex
import threading
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cjp import cache, config
from cjp.config import ARM_LOCATION_PATTERNS, model_profile, settings

SCHEMA_VERSION = 1
FORMATS = ("A", "B")
ARM_FILES = {"S1-plain": "wazuh_alerts.jsonl",
             "S2-body-in-url": "enriched_wazuh_alerts.jsonl",
             "S3-body-field": "body_field_wazuh_alerts.jsonl"}
REPEAT = 1                      # every job asks the cache for the first sample
MAX_ALERTS = 1000
MAX_UPLOAD_BYTES = 25 * 2**20
LIVE_DEFAULT_LIMIT = 200
LIVE_MAX_MINUTES = 7 * 24 * 60
RESTARTABLE = ("planned", "stopped", "failed", "interrupted")
_JOB_ID = re.compile(r"\d{4}-\d{2}-\d{2}T\d{4}_[0-9a-f]{6}")
_AGENT = re.compile(r"[\w.-]{1,64}")

_lock = threading.Lock()                     # job.json read-modify-write, and _active
_active: dict[str, threading.Event] = {}     # job ID → stop flag, for jobs running in this process


class JobNotFound(LookupError):
    """No job with that ID."""


class JobConflict(RuntimeError):
    """The job can't start now: it is running, another job is, or it needs
    more paid calls than were approved."""


def jobs_root() -> Path:
    return config.TRIAGE_JOBS_DIR


def job_dir(job_id: str, jobs_dir: Path | None = None) -> Path:
    """The job's directory. The ID must have the job-ID shape, so a URL can
    never name a path outside data/triage_jobs/."""
    if not _JOB_ID.fullmatch(job_id or ""):
        raise JobNotFound(f"no triage job {job_id!r}")
    path = Path(jobs_dir or jobs_root()) / job_id
    if not (path / "job.json").is_file():
        raise JobNotFound(f"no triage job {job_id!r}")
    return path


# ── files ────────────────────────────────────────────────────────────────────
def _read_jsonl(path: Path) -> list[dict]:
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def _write_jsonl(path: Path, rows: list[dict]) -> None:
    with open(path, "w") as f:
        for row in rows:
            f.write(json.dumps(row) + "\n")


def _write_meta(path: Path, meta: dict) -> None:
    """job.json, atomically: a reader never sees half a file."""
    tmp = path / ".job.json.tmp"
    tmp.write_text(json.dumps(meta, indent=2, default=str) + "\n")
    os.replace(tmp, path / "job.json")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def verdicts_path(path: Path, fmt: str) -> Path:
    return path / f"verdicts_{fmt}.jsonl"


# ── sources ──────────────────────────────────────────────────────────────────
def _check_arm(arm: str) -> str:
    if arm not in ARM_FILES:
        raise ValueError(f"arm {arm!r} is not one of {', '.join(ARM_FILES)}")
    return arm


def demo_alerts(corpus: str = "C1", session: str | None = None, arm: str = "S1-plain",
                bodies: bool = True, corpus_dir: Path | None = None):
    """One session of a frozen corpus. Reads only its alerts file for the arm
    and, with bodies, its ingest log: never the attack or benign log."""
    from cjp import corpus as corpus_mod
    from cjp.triage.batch import load_alerts_from_session, load_ingest_log
    corp = corpus_mod.load(corpus, corpus_dir or config.CORPUS_DIR)
    names = [s.name for s in corp.sessions]
    session = session or names[0]
    if session not in names:
        raise ValueError(f"corpus {corpus} has no session {session!r} (it has {', '.join(names)})")
    path = corp.path / "sessions" / session
    alerts = load_alerts_from_session(str(path), ARM_FILES[_check_arm(arm)])
    ingest = load_ingest_log(str(path)) if bodies else None
    return alerts, ingest, {"kind": "demo", "corpus": corpus, "session": session, "arm": arm}, []


def _parse_jsonl(content: str, name: str, valid) -> list[dict]:
    rows, bad = [], []
    for n, line in enumerate(content.splitlines(), 1):
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            bad.append(n)
            continue
        if isinstance(row, dict) and valid(row):
            rows.append(row)
        else:
            bad.append(n)
    if bad:
        more = f" and {len(bad) - 5} more" if len(bad) > 5 else ""
        raise ValueError(f"{name}: line(s) {', '.join(map(str, bad[:5]))}{more} are not valid "
                         "(expected one JSON object per line)")
    return rows


def upload_alerts(content: str, filename: str = "alerts.jsonl", ingest_log: str | None = None,
                  bodies: bool = True):
    """A Wazuh alerts .jsonl (one alert with a `rule` per line), plus optionally
    an ingest_log.jsonl whose `cid`s match the alerts' correlation IDs. The
    file name is only shown, never used as a path."""
    name = Path(filename or "alerts.jsonl").name[:200]
    for text in (content, ingest_log or ""):
        if len(text.encode()) > MAX_UPLOAD_BYTES:
            raise ValueError(f"upload larger than {MAX_UPLOAD_BYTES // 2**20} MB; split the file")
    alerts = _parse_jsonl(content, name, lambda a: isinstance(a.get("rule"), dict))
    ingest = None
    if bodies and ingest_log:
        ingest = {e["cid"]: e for e in _parse_jsonl(ingest_log, "ingest log",
                                                    lambda e: isinstance(e.get("cid"), str))}
    source = {"kind": "upload", "filename": name,
              "sha256": hashlib.sha256(content.encode()).hexdigest(),
              "ingest_log": bool(ingest_log)}
    return alerts, ingest, source, []


def _parse_time(value: str, what: str) -> datetime:
    try:
        t = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (AttributeError, ValueError):
        raise ValueError(f"{what} {value!r} is not an ISO time like 2026-10-04T09:00:00Z") from None
    if t.tzinfo is None:
        raise ValueError(f"{what} {value!r} has no time zone; add Z for UTC or an offset")
    return t.astimezone(timezone.utc)


def live_window(minutes: int | None = None, start: str | None = None, end: str | None = None,
                now: datetime | None = None) -> tuple[datetime, datetime]:
    """The last N minutes, or start to end (end defaults to now)."""
    now = now or datetime.now(timezone.utc)
    if minutes is not None:
        if start or end:
            raise ValueError("give either minutes or start/end, not both")
        if not 1 <= minutes <= LIVE_MAX_MINUTES:
            raise ValueError(f"minutes must be from 1 to {LIVE_MAX_MINUTES} (a week)")
        return now - timedelta(minutes=minutes), now
    if not start:
        raise ValueError("a live source needs minutes, or a start time")
    t0, t1 = _parse_time(start, "start"), _parse_time(end, "end") if end else now
    if t1 <= t0:
        raise ValueError("end must be after start")
    return t0, t1


def vm_bodies(alerts: list[dict]) -> tuple[dict[str, dict], list[str]]:
    """The VM's ingest-log entries for these alerts' correlation IDs, read
    over SSH with one fixed-string grep. Returns (entries by CID, warnings)."""
    from cjp import vm
    from cjp.triage.prompt import extract_cid
    cids = sorted({c for a in alerts if (c := extract_cid(a.get("full_log", "")))})
    if not cids:
        return {}, ["no alert carries a correlation ID, so no bodies could be matched"]
    log = f"{config.VM_DATA_DIR}/logs/ingest_log.jsonl"
    patterns = " ".join(f"-e {shlex.quote(json.dumps(c))}" for c in cids)   # the quoted "cid" value
    out = vm.ssh_run(f"test -f {shlex.quote(log)} && {{ grep -hF {patterns} {shlex.quote(log)} || true; }}",
                     timeout=30)
    if out is None:
        return {}, [f"could not read {log} on the VM (VM_HOST set? SSH up?); triaged without bodies"]
    found = {}
    for line in out.splitlines():
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            continue
        if entry.get("cid") in cids:
            found[entry["cid"]] = entry
    return found, []


def live_alerts(minutes: int | None = None, start: str | None = None, end: str | None = None,
                arm: str = "S1-plain", agent: str | None = None, limit: int = LIVE_DEFAULT_LIMIT,
                bodies: bool = True):
    """The indexer's alerts for one arm in a time window, oldest first."""
    from cjp import indexer
    t0, t1 = live_window(minutes, start, end)
    if agent is not None and not _AGENT.fullmatch(agent):
        raise ValueError(f"agent {agent!r}: give an agent ID like 001 or its name")
    if not 1 <= limit <= MAX_ALERTS:
        raise ValueError(f"limit must be from 1 to {MAX_ALERTS}")
    alerts = indexer.get_alerts_since(t0.isoformat(), t1.isoformat(), limit=limit,
                                      location_pattern=ARM_LOCATION_PATTERNS[_check_arm(arm)],
                                      agent=agent)
    if not alerts:
        raise LookupError(f"the indexer has no {arm} alerts between {t0:%Y-%m-%d %H:%M} and "
                          f"{t1:%Y-%m-%d %H:%M} UTC" + (f" for agent {agent}" if agent else ""))
    warnings = []
    if len(alerts) >= limit:
        warnings.append(f"the window holds at least {limit} alerts; this job has the first {limit}. "
                        "Narrow the window or raise the limit for the rest")
    ingest = None
    if bodies:
        ingest, w = vm_bodies(alerts)
        warnings += w
    source = {"kind": "live", "start": t0.isoformat(), "end": t1.isoformat(), "arm": arm,
              "agent": agent, "limit": limit}
    return alerts, ingest, source, warnings


LOADERS = {"demo": demo_alerts, "upload": upload_alerts, "live": live_alerts}


def _unique_ids(alerts: list[dict]) -> tuple[list[dict], list[str]]:
    """Resume and the verdict files key rows by the alert's `id`. An alert
    without one (a hand-made upload) gets `line-<n>`; a repeated ID is the
    same alert twice and is dropped."""
    seen, out, dropped = set(), [], 0
    for n, alert in enumerate(alerts, 1):
        if not alert.get("id"):
            alert = {**alert, "id": f"line-{n}"}
        if alert["id"] in seen:
            dropped += 1
            continue
        seen.add(alert["id"])
        out.append(alert)
    return out, [f"dropped {dropped} alert(s) whose ID repeats an earlier one"] if dropped else []


def _capture(alerts: list[dict], ingest_by_cid: dict | None) -> tuple[list[dict], dict[str, dict]]:
    """What the job stores: each alert with every correlation ID redacted,
    and its bodies by alert ID. Bodies are paired by CID before the CID is
    redacted (batch.make_jobs). The prompt redacts the same strings the same
    way, so the request, and its cache key, is unchanged. (A body over the
    2,000-character cut with a CID before the cut would be cut at another
    place, a cache miss but no leak; no C1 body has one.)"""
    from cjp.triage.batch import make_jobs
    from cjp.triage.prompt import _redact      # the prompt's own redaction, so requests match
    stored, bodies = [], {}
    for alert, entry in make_jobs(alerts, ingest_by_cid):
        stored.append(_redact(alert))
        if entry and (entry.get("request_body") or entry.get("response_body")):
            bodies[alert["id"]] = {"alert_id": alert["id"],
                                   "request_body": _redact(entry.get("request_body") or ""),
                                   "response_body": _redact(entry.get("response_body") or "")}
    return stored, bodies


# ── planning and estimate ────────────────────────────────────────────────────
@dataclass
class Item:
    alert: dict
    body: dict | None
    fmt: str
    key: str
    cached: bool


def _plan(alerts: list[dict], bodies: dict[str, dict], formats: list[str], model: str,
          done: dict[str, set] | None = None) -> list[Item]:
    """Every (alert, format) still to triage, alert by alert so both formats
    of a verdict arrive together. A request planned earlier in the job counts
    as cached: its first call fills the cache for the rest."""
    from cjp.triage.client import cache_key_for
    items, planned = [], set()
    for alert in alerts:
        for fmt in formats:
            if alert["id"] in (done or {}).get(fmt, ()):
                continue
            body = bodies.get(alert["id"])
            key = cache_key_for(alert, body, REPEAT, fmt, model)
            items.append(Item(alert, body, fmt, key, key in planned or cache.has(key)))
            planned.add(key)
    return items


def estimate(items: list[Item], model: str, count: bool = True) -> dict:
    """Paid calls, input tokens and the most they can cost, by
    experiment.estimate() (count_tokens on a sample; no model call). If
    count_tokens can't be reached, characters / 3.5, and the method says so."""
    from cjp.experiment import Condition, Unit
    from cjp.experiment import estimate as estimate_units
    units = []
    for fmt in sorted({i.fmt for i in items}):
        mine = [i for i in items if i.fmt == fmt]
        units.append(Unit(Condition(f"F{fmt}", "", "", fmt=fmt, model=model), Path("."), REPEAT,
                          [(i.alert, i.body) for i in mine], [i.key for i in mine],
                          [i.cached for i in mine]))
    try:
        per = estimate_units(units, count=count)
    except Exception:       # count_tokens unreachable: estimating offline still beats nothing
        per = estimate_units(units, count=False)
    priced = all(e["cost_max_usd"] is not None for e in per.values() if e["calls"])
    paid = [e for e in per.values() if e["calls"]]
    return {
        "calls": sum(e["calls"] for e in per.values()),
        "cached": sum(i.cached for i in items),
        "input_tokens": sum(e["input_tokens"] for e in per.values()),
        "output_tokens_max": sum(e["output_tokens_max"] for e in per.values()),
        "cost_max_usd": sum(e["cost_max_usd"] or 0 for e in per.values()) if priced else None,
        "method": "; ".join(sorted({e["method"] for e in paid})) or None,
        "by_format": {cid[1:]: {k: e[k] for k in ("calls", "input_tokens", "output_tokens_max",
                                                  "cost_max_usd", "cached_mean_output_tokens")}
                      for cid, e in per.items()},
        "max_tokens": settings()["triage"]["max_tokens"],
        "price_retrieved": str(settings()["prices"]["retrieved"]),
        "estimated_at": _now(),
    }


# ── actual tokens and cost ───────────────────────────────────────────────────
def _row_cost(row: dict) -> float | None:
    from cjp.evaluate.score import price_of
    price, usage = price_of(row.get("model")), row["token_usage"]
    if price is None:
        return None
    return (usage["input_tokens"] * price["input"] + usage["output_tokens"] * price["output"]) / 1e6


def _empty_actual() -> dict:
    return {"calls": 0, "cache_hits": 0, "failed_calls": 0, "input_tokens": 0, "output_tokens": 0,
            "cost_usd": 0.0, "answers_cost_usd": 0.0, "unpriced": []}


def _add_row(actual: dict, row: dict) -> None:
    """Count one verdict row. `cost_usd` is what this job's own calls cost at
    list price; `answers_cost_usd` is what every answer cost to obtain,
    cached or not (the research cost metric, decision 006)."""
    from cjp.triage.batch import is_api_error
    if is_api_error(row):
        actual["failed_calls"] += 1
        return
    cost = _row_cost(row)
    if cost is None and row.get("model") not in actual["unpriced"]:
        actual["unpriced"].append(row.get("model"))
    actual["answers_cost_usd"] += cost or 0.0
    if row.get("cache_hit"):
        actual["cache_hits"] += 1
        return
    actual["calls"] += 1
    actual["input_tokens"] += row["token_usage"]["input_tokens"]
    actual["output_tokens"] += row["token_usage"]["output_tokens"]
    actual["cost_usd"] += cost or 0.0


def actuals(path: Path, formats: list[str]) -> dict:
    """The actual tokens and cost, from the verdict files."""
    actual = _empty_actual()
    for fmt in formats:
        for row in _read_jsonl(verdicts_path(path, fmt)):
            _add_row(actual, row)
    return actual


def _answered(path: Path, formats: list[str]) -> dict[str, set]:
    from cjp.triage.batch import load_completed_ids
    return {fmt: load_completed_ids(str(verdicts_path(path, fmt))) for fmt in formats}


# ── jobs ─────────────────────────────────────────────────────────────────────
def _new_dir(root: Path) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    while True:     # a new name every time; never reuse a directory
        job_id = f"{datetime.now(timezone.utc):%Y-%m-%dT%H%M}_{secrets.token_hex(3)}"
        try:
            (root / job_id).mkdir()
            return root / job_id
        except FileExistsError:
            continue


def create(source: dict, *, bodies: bool = True, formats: list[str] | tuple = FORMATS,
           model: str | None = None, count: bool = True, jobs_dir: Path | None = None) -> dict:
    """Capture a source's alerts, plan and estimate the job, and write it as
    `planned`. Calls no model: start() does, once the person has seen the
    estimate. Both formats by default, so the verdict's A/B toggle shows two
    real answers (decision 014). Raises ValueError or LookupError for a
    source that can't be used."""
    from cjp.runs import git_describe
    from cjp.triage import schema
    from cjp.triage.prompt import PROMPT_ID, prompt_version
    formats = list(dict.fromkeys(f.upper() for f in formats))
    if not formats or any(f not in FORMATS for f in formats):
        raise ValueError(f"formats must be one or both of {', '.join(FORMATS)}")
    profile = model_profile(model)
    params = dict(source)
    kind = params.pop("kind", None)
    loader = LOADERS.get(kind)
    if loader is None:
        raise ValueError(f"source kind must be one of {', '.join(LOADERS)}, not {kind!r}")
    allowed = set(inspect.signature(loader).parameters) - {"bodies", "corpus_dir"}
    if unknown := set(params) - allowed:
        raise ValueError(f"a {kind} source takes {', '.join(sorted(allowed))}, not {', '.join(sorted(unknown))}")
    alerts, ingest, source_meta, warnings = loader(**params, bodies=bodies)
    alerts, w = _unique_ids(alerts)
    warnings += w
    if not alerts:
        raise LookupError("the source has no alerts")
    if len(alerts) > MAX_ALERTS:
        raise ValueError(f"{len(alerts)} alerts; a job takes at most {MAX_ALERTS}, so split the source")
    stored, body_rows = _capture(alerts, ingest)
    if bodies and not body_rows:
        warnings.append("bodies on, but no alert has a matching request or response body")
    est = estimate(_plan(stored, body_rows, formats, profile["alias"]), profile["alias"], count)

    path = _new_dir(Path(jobs_dir or jobs_root()))
    _write_jsonl(path / "alerts.jsonl", stored)
    if bodies:
        _write_jsonl(path / "bodies.jsonl", list(body_rows.values()))
    meta = {
        "schema_version": SCHEMA_VERSION,
        "id": path.name,
        "created_at": _now(),
        "status": "planned",
        "source": source_meta,
        "options": {"bodies": bodies, "formats": formats, "model": profile["alias"]},
        "model_id": profile["id"],
        "prompts": {f: {"prompt_id": PROMPT_ID, "prompt_version": prompt_version(f),
                        "schema_version": schema.schema_version(f)} for f in formats},
        "git_describe": git_describe(),
        "alerts": len(stored),
        "bodies_matched": len(body_rows),
        "warnings": warnings,
        "estimate": est,
        "progress": {"total": len(stored) * len(formats), "answered": 0},
        "actual": _empty_actual(),
        "error": None,
    }
    _write_meta(path, meta)
    return meta


def _lock_file(path: Path):
    """Hold the job's `.lock` while a worker runs it. The OS drops the lock
    when the process dies, however it dies, so a crash can never leave a job
    that reads as running."""
    f = open(path / ".lock", "w")
    try:
        fcntl.flock(f, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        f.close()
        return None
    return f


def _status(path: Path, meta: dict) -> str:
    """`running` only while a worker still runs it, in this process or
    another `cjp ui`. A job whose process died mid-run is `interrupted`."""
    if meta["status"] != "running":
        return meta["status"]
    if meta["id"] in _active:
        return "running"
    probe = _lock_file(path)
    if probe is None:
        return "running"
    probe.close()
    return "interrupted"


def load(job_id: str, jobs_dir: Path | None = None) -> dict:
    path = job_dir(job_id, jobs_dir)
    meta = json.loads((path / "job.json").read_text())
    return {**meta, "status": _status(path, meta)}


def list_jobs(jobs_dir: Path | None = None) -> list[dict]:
    """Every job, newest first (IDs start with their UTC creation time)."""
    root = Path(jobs_dir or jobs_root())
    out = []
    for path in sorted(root.glob("*/job.json"), reverse=True):
        if _JOB_ID.fullmatch(path.parent.name):
            out.append(load(path.parent.name, root))
    return out


def _inputs(path: Path) -> tuple[list[dict], dict[str, dict]]:
    alerts = _read_jsonl(path / "alerts.jsonl")
    return alerts, {b["alert_id"]: b for b in _read_jsonl(path / "bodies.jsonl")}


def reestimate(job_id: str, count: bool = True, jobs_dir: Path | None = None) -> dict:
    """The estimate for what is left (after a stop or a failure), stored in job.json."""
    path = job_dir(job_id, jobs_dir)
    meta = load(job_id, jobs_dir)
    alerts, bodies = _inputs(path)
    opts = meta["options"]
    items = _plan(alerts, bodies, opts["formats"], opts["model"], _answered(path, opts["formats"]))
    est = estimate(items, opts["model"], count)
    with _lock:
        meta = json.loads((path / "job.json").read_text())
        meta["estimate"] = est
        _write_meta(path, meta)
    return load(job_id, jobs_dir)


@dataclass
class Batch:
    """The work start() approved for one job."""
    path: Path
    items: list[Item]
    stop: threading.Event
    lock: object            # the open .lock file, held until execute() ends


def start(job_id: str, max_calls: int, jobs_dir: Path | None = None) -> Batch:
    """Approve and mark a job running. Refuses (JobConflict) when it or another
    job is running, or when it needs more paid calls than max_calls, the
    number the person saw and approved. execute() then does the work."""
    from cjp.runs import git_describe
    path = job_dir(job_id, jobs_dir)
    meta = load(job_id, jobs_dir)
    opts = meta["options"]
    alerts, bodies = _inputs(path)
    items = _plan(alerts, bodies, opts["formats"], opts["model"], _answered(path, opts["formats"]))
    calls = sum(not i.cached for i in items)
    with _lock:
        meta = json.loads((path / "job.json").read_text())
        status = _status(path, meta)
        if status not in RESTARTABLE:
            raise JobConflict(f"job {job_id} is {status}; only a planned, stopped, failed or "
                              "interrupted job can start")
        if _active:
            raise JobConflict(f"job {next(iter(_active))} is running; wait for it or stop it first")
        if calls > max_calls:
            raise JobConflict(f"job {job_id} needs {calls} paid call(s), more than the {max_calls} "
                              "approved; estimate it again and approve the new number")
        lock = _lock_file(path)
        if lock is None:
            raise JobConflict(f"job {job_id} is running in another cjp ui")
        stop = threading.Event()
        _active[job_id] = stop
        meta.update(status="running", pid=os.getpid(), finished_at=None, error=None)
        meta.setdefault("starts", []).append({"at": _now(), "approved_calls": max_calls,
                                              "paid_calls_planned": calls,
                                              "git_describe": git_describe()})
        _write_meta(path, meta)
    return Batch(path, items, stop, lock)


def stop(job_id: str, jobs_dir: Path | None = None) -> dict:
    """Ask a running job to stop after the call in flight."""
    job_dir(job_id, jobs_dir)
    with _lock:
        flag = _active.get(job_id)
    if flag is None:
        raise JobConflict(f"job {job_id} is not running in this app")
    flag.set()
    return load(job_id, jobs_dir)


def _update(path: Path, **fields) -> None:
    with _lock:
        meta = json.loads((path / "job.json").read_text())
        meta.update(fields)
        _write_meta(path, meta)


def execute(batch: Batch) -> dict:
    """Triage the approved work, one call at a time, writing each row and the
    progress as it goes. Ends `complete`, `stopped` or `failed` (with the
    reason). Returns the final job.json."""
    from cjp.errors import explain
    from cjp.triage.batch import MAX_CONSECUTIVE_FAILURES, api_error_row, is_api_error
    from cjp.triage.client import FATAL_ERRORS, analyse_alert
    path = batch.path
    meta = json.loads((path / "job.json").read_text())
    formats, model = meta["options"]["formats"], meta["options"]["model"]
    actual = actuals(path, formats)
    answered = sum(len(ids) for ids in _answered(path, formats).values())
    status, error, failures = "complete", None, 0
    files = {f: open(verdicts_path(path, f), "a") for f in formats}
    try:
        for item in batch.items:
            if batch.stop.is_set():
                status = "stopped"
                break
            fatal = False
            try:
                row = analyse_alert(item.alert, ingest_entry=item.body, repeat=REPEAT,
                                    cache_mode="use", fmt=item.fmt, model=model)
                failures = 0
            except Exception as e:
                failures += 1
                fatal = isinstance(e, FATAL_ERRORS)
                error = explain(e) or f"{type(e).__name__}: {e}"
                row = api_error_row(item.alert, e, fmt=item.fmt, repeat=REPEAT)
            files[item.fmt].write(json.dumps(row) + "\n")
            files[item.fmt].flush()
            _add_row(actual, row)
            answered += not is_api_error(row)
            _update(path, actual=actual, progress={"total": meta["progress"]["total"],
                                                   "answered": answered})
            if fatal or failures >= MAX_CONSECUTIVE_FAILURES:
                why = "it would fail the same way for every alert" if fatal else \
                    f"{failures} failures in a row"
                status, error = "failed", f"stopped: {why}. {error}"
                break
        if status == "complete" and answered < meta["progress"]["total"]:
            missing = meta["progress"]["total"] - answered
            status, error = "failed", (f"{missing} alert(s) have no answer ({error}); "
                                       "start the job again to retry them")
    except BaseException as e:      # a bug or a full disk: record it, then let it surface
        status, error = "failed", f"{type(e).__name__}: {e}"
        raise
    finally:
        for f in files.values():
            f.close()
        _update(path, status=status, error=error if status == "failed" else None,
                finished_at=_now(), actual=actual,
                progress={"total": meta["progress"]["total"], "answered": answered})
        with _lock:
            _active.pop(path.name, None)
        batch.lock.close()
    return json.loads((path / "job.json").read_text())


def run(job_id: str, max_calls: int, jobs_dir: Path | None = None) -> dict:
    """start() and execute() in this thread."""
    return execute(start(job_id, max_calls, jobs_dir))


def run_in_background(job_id: str, max_calls: int, jobs_dir: Path | None = None) -> threading.Thread:
    """start() here, so a refusal reaches the caller, then execute() in a
    daemon thread. If the app stops mid-call, the job reads as `interrupted`
    and starting it again resumes it."""
    batch = start(job_id, max_calls, jobs_dir)
    thread = threading.Thread(target=execute, args=(batch,), name=f"triage-job-{job_id}", daemon=True)
    thread.start()
    return thread


def sources(corpus_dir: Path | None = None) -> dict:
    """What the source picker can offer: the frozen corpora and their sessions
    (demo), the arms, formats and models, and the limits."""
    from cjp import corpus as corpus_mod
    corpora = []
    for c in corpus_mod.list_corpora(corpus_dir or config.CORPUS_DIR):
        corpora.append({"id": c.id, "note": c.meta.get("note"),
                        "sessions": [{"name": s["name"], "alerts": s.get("alerts")}
                                     for s in c.meta["sessions"]]})
    models = settings()["models"]
    return {
        "demo": {"corpora": corpora, "default_corpus": "C1"},
        "arms": list(ARM_FILES),
        "formats": list(FORMATS),
        "models": {alias: spec["id"] for alias, spec in models.items()},
        "default_model": model_profile()["alias"],
        "live": {"bodies_from_vm": bool(config.VM_HOST), "default_limit": LIVE_DEFAULT_LIMIT,
                 "max_minutes": LIVE_MAX_MINUTES},
        "max_alerts": MAX_ALERTS,
        "max_upload_bytes": MAX_UPLOAD_BYTES,
    }
