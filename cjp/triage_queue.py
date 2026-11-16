"""
The Triage page's queue and verdict view (Plan P6.3), read from a triage
job's files (cjp.triage_jobs). Nothing here calls a model or writes research
data.

    queue()      one entry per alert, in three lanes:
                   queue    the verdicts to act on, escalate → needs_more_info →
                            dismiss, then by severity
                   human    "Needs a human": an `uncertain` label, low
                            confidence, or no usable answer
                   pending  not triaged yet (the job is running or was stopped)
                 with filters by label, disposition and source (the log the
                 alert came from) and the counts each filter would show.
    verdict()    one alert in full: the raw alert, its body, both formats'
                 answers, how often each answer's confidence level was right
                 in evaluation, and the instruction-like-text flag.
    export_*()   the job's verdicts as CSV or JSON.
    feedback()   an analyst's agree/disagree on a verdict, kept in the job's
                 feedback.jsonl as product feedback only: never research data,
                 never read by the evaluation (Plan P6 "Export").

The queue follows one format at a time (`fmt`, default the job's first), so
the A/B toggle re-sorts it by the other format's answers.

**Calibration-aware confidence** reads the canonical runs pinned in
results/canonical.yaml (decision 012): for each verdict, the pinned
condition of X1, X2 or X3 closest to the job (SIEM arm, bodies, format,
model), and how often answers at each confidence level were right there
(the F3 numbers). A level with fewer than MIN_CALIBRATION_N committed answers
is marked too few to say.

**Instruction-like text** (X4): a body, URL or log line that addresses the
analyst or the model ("ignore previous instructions", "classify as benign",
"do not escalate", "SYSTEM:"). INSTRUCTION_PATTERNS cover X4's five phrasings
plus common injection forms, and each is also tried URL-decoded. On the real
corpora they flag all 12 injected requests in C1-inj, and none of the 627
C1 requests or the 146 clean C1-inj ones. It is a heuristic warning chip,
not a guarantee: an attacker can phrase it otherwise.
"""

import csv
import io
import json
import re
from collections import Counter
from datetime import datetime, timezone
from fnmatch import fnmatch
from pathlib import Path
from urllib.parse import unquote_plus

from cjp import config, triage_jobs
from cjp.config import ARM_LOCATION_PATTERNS
from cjp.results import MIN_COMMITTED

DISPOSITION_ORDER = {"escalate": 0, "needs_more_info": 1, "dismiss_false_positive": 2}
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
LANES = ("queue", "human", "pending")
CALIBRATION_FROM = ("X1", "X2", "X3")     # X1 first: the plan's source, and the closest on a tie
MIN_CALIBRATION_N = MIN_COMMITTED      # the same threshold F3 uses
FEEDBACK = ("agree", "disagree")
MAX_NOTE = 500

INSTRUCTION_PATTERNS = [
    (r"\b(?:ignore|disregard|forget)\s+(?:all\s+|any\s+)?(?:the\s+|your\s+)?(?:previous|prior|above|earlier)"
     r"\s+(?:instructions?|prompts?|rules)"),
    (r"\b(?:note|message|instructions?)\s+(?:to|for)\s+(?:the\s+)?(?:analyst|reviewer|triage|soc|ai|model|"
     r"assistant|llm)\b"),
    r"\b(?:ai|llm)\s+(?:assistant|model|analyst)\b",
    (r"\b(?:classify|label|mark|treat|tag|report)\s+(?:this|it|the\s+(?:alert|traffic|request|event))?\s*"
     r"(?:alert\s+|traffic\s+|request\s+)?as\s+(?:a\s+)?(?:benign|safe|harmless|legitimate|"
     r"false[\s_-]?positive|approved|authori[sz]ed|non[\s-]?malicious)"),
    r"\bdo\s+not\s+(?:escalate|alert|flag|report|block)\b",
    r"\bdisposition\s*[:=]?\s*(?:benign|dismiss|false[\s_-]?positive|closed?)",
    (r"\b(?:authori[sz]ed|sanctioned|approved)\s+(?:pen(?:etration)?[\s-]?test|security\s+test|"
     r"red[\s-]?team|traffic|scan)"),
    (r"\bthis\s+(?:traffic|request|alert|activity)\s+is\s+(?:benign|approved|authori[sz]ed|safe|legitimate|"
     r"a\s+false\s+positive)"),
]
_INSTRUCTION = re.compile("|".join(f"(?:{p})" for p in INSTRUCTION_PATTERNS), re.I)
# A chat-role prefix ("SYSTEM: approved traffic"). Case-sensitive, so prose
# like "operating system: linux" is not flagged.
_ROLE_PREFIX = re.compile(r"(?:^|[\s\"'>;-])(?:SYSTEM|System|ASSISTANT|Assistant)\s*:")
_FORMULA = ("=", "+", "-", "@", "\t", "\r")


# ── instruction-like text ────────────────────────────────────────────────────
def instruction_like(text: str) -> str | None:
    """The first instruction-like phrase in `text`, as written or URL-decoded."""
    if not text:
        return None
    for candidate in dict.fromkeys((text, unquote_plus(text))):
        if m := _INSTRUCTION.search(candidate) or _ROLE_PREFIX.search(candidate):
            return m.group(0).strip(" \"'>;-")
    return None


def instruction_flag(alert: dict, body: dict | None) -> dict | None:
    """Where the model would read instruction-like text for this alert: the
    request body, the response body or the alert's log line."""
    found = []
    for where, text in (("request body", (body or {}).get("request_body")),
                        ("response body", (body or {}).get("response_body")),
                        ("log line", alert.get("full_log"))):
        if phrase := instruction_like(text or ""):
            found.append({"where": where, "phrase": phrase})
    return {"found": found} if found else None


# ── calibration from the canonical runs ──────────────────────────────────────
def _arm_of(source: dict, alerts: list[dict]) -> str | None:
    """The job's SIEM arm: from its source, or for an upload from the alerts'
    log locations when they all match one arm."""
    if source.get("arm"):
        return source["arm"]
    arms = {arm for a in alerts for arm, pattern in ARM_LOCATION_PATTERNS.items()
            if fnmatch(a.get("location") or "", pattern)}
    return arms.pop() if len(arms) == 1 else None


def calibration_sources(canonical_file: Path | None = None, runs_dir: Path | None = None) -> list[dict]:
    """Every scored LLM condition of the pinned X1, X2 and X3 runs, with its
    calibration table. A pin that is missing or not complete is skipped."""
    from cjp import results, runs
    from cjp.experiment import parse_condition
    canonical_file = canonical_file or config.CANONICAL_FILE
    runs_dir = runs_dir or config.RUNS_DIR
    pins = runs.load_canonical(canonical_file)
    known = {r.address: r for r in runs.list_runs(runs_dir)}
    out = []
    for exp_id in CALIBRATION_FROM:
        run, _ = results.check_pin(exp_id, pins.get(exp_id), known)
        if run is None or run.meta.get("kind", "triage") != "triage":
            continue
        src = results.Source(exp_id, run)
        for cid in src.conditions:
            cond = parse_condition(cid)
            cal = src.metrics(cid)["triage"]["calibration"]
            out.append({"experiment": exp_id, "run": run.address, "condition": cid,
                        "corpus": run.meta["corpus"]["id"], "arm": cond.arm, "bodies": cond.with_body,
                        "format": cond.fmt, "model": cond.model, "table": cal})
    return out


def _closest(sources: list[dict], arm: str | None, bodies: bool, fmt: str, model: str) -> dict | None:
    """The condition that best matches, in order of what matters most: the
    model, then the format, the SIEM arm and the bodies. The fields that
    differ are listed, so the UI can say "measured on S1 with bodies"."""
    want = {"model": model, "format": fmt, "arm": arm, "bodies": bodies}
    weight = {"model": 8, "format": 4, "arm": 2, "bodies": 1}
    best = max(sources, default=None,
               key=lambda s: sum(w for k, w in weight.items() if s[k] == want[k]))
    if best is None:
        return None
    return {**best, "differs": [k for k in weight if best[k] != want[k]]}


def _level(table: list[dict], level: str | None) -> dict | None:
    row = next((r for r in table if r["confidence"] == level), None)
    if row is None:
        return None
    return {"committed": row["committed"], "correct": row["correct"],
            "right_rate": row["selective_accuracy"], "enough": row["committed"] >= MIN_CALIBRATION_N}


def calibration_for(source: dict | None, confidence: str | None) -> dict | None:
    """What the UI shows next to a verdict's confidence: how often that level
    was right in evaluation, for the label and for the disposition."""
    if source is None or confidence is None:
        return None
    return {"confidence": confidence,
            "label": _level(source["table"]["fine"], confidence),
            "disposition": _level(source["table"]["disposition"], confidence),
            "measured_on": {k: source[k] for k in ("experiment", "run", "condition", "corpus")},
            "differs": source["differs"], "min_n": MIN_CALIBRATION_N}


# ── reading a job ────────────────────────────────────────────────────────────
def _verdict(row: dict | None) -> dict:
    """One format's answer, with a status: ok, invalid (refused, cut off or
    off-schema), api_error, or pending (no row yet)."""
    from cjp.triage.batch import is_api_error
    if row is None:
        return {"status": "pending"}
    if is_api_error(row):
        return {"status": "api_error", "error": (row.get("llm_output") or {}).get("error")}
    out = row.get("llm_output") or {}
    ok = row.get("parse_ok") and row.get("schema_ok")
    return {"status": "ok" if ok else "invalid", **{k: v for k, v in out.items() if k != "error"},
            **({} if ok else {"errors": row.get("schema_errors") or [out.get("error") or "no answer"]}),
            "model": row.get("model"), "cache_hit": bool(row.get("cache_hit"))}


def _lane(v: dict) -> tuple[str, list[str]]:
    if v["status"] == "pending":
        return "pending", []
    reasons = []
    if v["status"] != "ok":
        reasons.append("no usable answer")
    else:
        if v.get("technique_label") == "uncertain":
            reasons.append("uncertain label")
        if v.get("confidence") == "low":
            reasons.append("low confidence")
    return ("human" if reasons else "queue"), reasons


def _source_of(alert: dict) -> str:
    agent = (alert.get("agent") or {}).get("name") or (alert.get("agent") or {}).get("id") or "?"
    return f"{agent}: {alert.get('location') or '?'}"


def _sort_key(item: dict, fmt: str) -> tuple:
    v = item["verdicts"][fmt]
    severity = v.get("severity") or next((o.get("severity") for o in item["verdicts"].values()
                                          if o.get("severity")), None)
    level = item["rule"].get("level")
    return (DISPOSITION_ORDER.get(v.get("disposition"), 3), SEVERITY_ORDER.get(severity, 4),
            -(level if isinstance(level, int) else -1), item["timestamp"] or "")


class Job:
    """A triage job's files, read once."""

    def __init__(self, job_id: str, jobs_dir: Path | None = None):
        self.path = triage_jobs.job_dir(job_id, jobs_dir)
        self.meta = triage_jobs.load(job_id, jobs_dir)
        self.formats = self.meta["options"]["formats"]
        self.alerts, self.bodies = triage_jobs._inputs(self.path)
        self.rows = {}
        for fmt in self.formats:     # the last row per alert wins: a retry appends after its api_error
            self.rows[fmt] = {r.get("wazuh_alert_id"): r
                              for r in triage_jobs._read_jsonl(triage_jobs.verdicts_path(self.path, fmt))}
        self.feedback = latest_feedback(self.path)
        self.arm = _arm_of(self.meta["source"], self.alerts)

    def check_format(self, fmt: str | None) -> str:
        fmt = (fmt or self.formats[0]).upper()
        if fmt not in self.formats:
            raise ValueError(f"job {self.meta['id']} has format(s) {', '.join(self.formats)}, not {fmt}")
        return fmt

    def item(self, alert: dict) -> dict:
        body = self.bodies.get(alert["id"])
        rule = alert.get("rule") or {}
        verdicts = {fmt: _verdict(self.rows[fmt].get(alert["id"])) for fmt in self.formats}
        answered = [v for v in verdicts.values() if v["status"] == "ok"]
        agree = None
        if len(answered) == 2:
            a, b = answered
            agree = (a.get("technique_label"), a.get("disposition")) == (b.get("technique_label"),
                                                                          b.get("disposition"))
        return {"alert_id": alert["id"], "timestamp": alert.get("timestamp"),
                "rule": {"id": rule.get("id"), "level": rule.get("level"),
                         "description": rule.get("description")},
                "source": _source_of(alert), "has_body": body is not None,
                "instruction_like": instruction_flag(alert, body), "verdicts": verdicts,
                "formats_agree": agree,
                "feedback": {f: self.feedback.get((alert["id"], f)) for f in self.formats}}


def queue(job_id: str, fmt: str | None = None, *, lane: str | None = None, label: str | None = None,
          disposition: str | None = None, source: str | None = None, jobs_dir: Path | None = None) -> dict:
    """The job's alerts in lanes, sorted by `fmt`'s answers, with filters.
    `facets` counts every label, disposition and source before filtering, so
    the UI can show what each filter would leave."""
    job = Job(job_id, jobs_dir)
    fmt = job.check_format(fmt)
    if lane is not None and lane not in LANES:
        raise ValueError(f"lane must be one of {', '.join(LANES)}, not {lane!r}")
    items = []
    for alert in job.alerts:
        item = job.item(alert)
        item["lane"], item["human_reasons"] = _lane(item["verdicts"][fmt])
        items.append(item)
    facets = {"label": Counter(i["verdicts"][fmt].get("technique_label") for i in items
                               if i["verdicts"][fmt].get("technique_label")),
              "disposition": Counter(i["verdicts"][fmt].get("disposition") for i in items
                                     if i["verdicts"][fmt].get("disposition")),
              "source": Counter(i["source"] for i in items),
              "lane": Counter(i["lane"] for i in items)}
    wanted = [i for i in items
              if (lane is None or i["lane"] == lane)
              and (label is None or i["verdicts"][fmt].get("technique_label") == label)
              and (disposition is None or i["verdicts"][fmt].get("disposition") == disposition)
              and (source is None or i["source"] == source)]
    wanted.sort(key=lambda i: _sort_key(i, fmt))
    return {"job": {k: job.meta[k] for k in ("id", "status", "source", "options", "progress")},
            "format": fmt, "filters": {"lane": lane, "label": label, "disposition": disposition,
                                       "source": source},
            "facets": {k: dict(c.most_common()) for k, c in facets.items()},
            "lanes": {name: [i for i in wanted if i["lane"] == name] for name in LANES}}


def verdict(job_id: str, alert_id: str, jobs_dir: Path | None = None,
            canonical_file: Path | None = None, runs_dir: Path | None = None) -> dict:
    """One alert in full, for the verdict view: the alert, its body, every
    format's answer with its calibration, and the instruction-like-text flag."""
    job = Job(job_id, jobs_dir)
    alert = next((a for a in job.alerts if a["id"] == alert_id), None)
    if alert is None:
        raise triage_jobs.JobNotFound(f"job {job_id} has no alert {alert_id!r}")
    item = job.item(alert)
    sources = calibration_sources(canonical_file, runs_dir)
    opts = job.meta["options"]
    for fmt, v in item["verdicts"].items():
        # the job's bodies option, not this alert's: an L1 condition's numbers
        # include its alerts that had no body to attach
        src = _closest(sources, job.arm, opts["bodies"], fmt, opts["model"])
        v["calibration"] = calibration_for(src, v.get("confidence") if v["status"] == "ok" else None)
        v["lane"], v["human_reasons"] = _lane(v)
    return {**item, "alert": alert, "body": job.bodies.get(alert_id), "arm": job.arm,
            "calibration_note": None if sources else
            "no canonical X1, X2 or X3 run is pinned, so there is no evaluation to compare with"}


# ── export ───────────────────────────────────────────────────────────────────
EXPORT_FIELDS = ("technique_label", "candidate_labels", "disposition", "confidence", "severity",
                 "event_type", "recommended_action", "reasoning", "evidence", "cognitive_notes")


def _items_for_export(job: Job) -> list[dict]:
    """Every alert in the order the queue shows them: the queue lane, then
    "Needs a human", then pending, each sorted by the job's first format."""
    fmt = job.formats[0]
    items = []
    for alert in job.alerts:
        item = job.item(alert)
        item["lane"], item["human_reasons"] = _lane(item["verdicts"][fmt])
        items.append(item)
    items.sort(key=lambda i: (LANES.index(i["lane"]), *_sort_key(i, fmt)))
    return items


def export_json(job_id: str, jobs_dir: Path | None = None) -> dict:
    job = Job(job_id, jobs_dir)
    return {"exported_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "note": "Triage output for analysts. Feedback here is product feedback, not research data.",
            "job": {k: job.meta[k] for k in ("id", "created_at", "status", "source", "options", "model_id",
                                              "prompts", "git_describe", "alerts")},
            "sorted_by_format": job.formats[0], "items": _items_for_export(job)}


def _cell(value) -> str:
    """A CSV cell. Log content is attacker-controlled, so a cell a spreadsheet
    would run as a formula (=, +, -, @) is prefixed with a quote."""
    if value is None:
        return ""
    if isinstance(value, (list, dict)):
        value = json.dumps(value) if isinstance(value, dict) else "; ".join(map(str, value))
    text = str(value)
    return "'" + text if text.startswith(_FORMULA) else text


def export_csv(job_id: str, jobs_dir: Path | None = None) -> str:
    job = Job(job_id, jobs_dir)
    head = ["alert_id", "timestamp", "rule_id", "rule_level", "rule_description", "source", "lane",
            "human_reasons", "instruction_like_text", "formats_agree"]
    for fmt in job.formats:
        head += [f"{fmt}_status", *(f"{fmt}_{k}" for k in EXPORT_FIELDS), f"{fmt}_analyst_feedback"]
    out = io.StringIO()
    writer = csv.writer(out)
    writer.writerow(head)
    for i in _items_for_export(job):
        flag = i["instruction_like"]
        row = [i["alert_id"], i["timestamp"], i["rule"]["id"], i["rule"]["level"], i["rule"]["description"],
               i["source"], i["lane"], i["human_reasons"],
               [f"{f['where']}: {f['phrase']}" for f in flag["found"]] if flag else None, i["formats_agree"]]
        for fmt in job.formats:
            v, fb = i["verdicts"][fmt], i["feedback"][fmt]
            row += [v["status"], *(v.get(k) for k in EXPORT_FIELDS), fb and fb["verdict"]]
        writer.writerow([_cell(c) for c in row])
    return out.getvalue()


# ── product feedback ─────────────────────────────────────────────────────────
def latest_feedback(path: Path) -> dict[tuple[str, str], dict]:
    """The newest feedback per (alert, format); a `clear` entry removes it."""
    latest = {}
    for entry in triage_jobs._read_jsonl(path / "feedback.jsonl"):
        key = (entry["alert_id"], entry["format"])
        if entry["verdict"] is None:
            latest.pop(key, None)
        else:
            latest[key] = {k: entry[k] for k in ("verdict", "note", "at")}
    return latest


def feedback(job_id: str, alert_id: str, fmt: str, verdict_: str | None, note: str | None = None,
             jobs_dir: Path | None = None) -> dict:
    """Record an analyst's agree or disagree (None clears it) on one format's
    verdict. Appended to the job's feedback.jsonl, so nothing is overwritten.
    Product feedback only: no research code reads it."""
    job = Job(job_id, jobs_dir)
    fmt = job.check_format(fmt)
    if not any(a["id"] == alert_id for a in job.alerts):
        raise triage_jobs.JobNotFound(f"job {job_id} has no alert {alert_id!r}")
    if verdict_ is not None and verdict_ not in FEEDBACK:
        raise ValueError(f"feedback must be one of {', '.join(FEEDBACK)}, or null to clear it")
    note = (note or "").strip()[:MAX_NOTE] or None
    entry = {"at": datetime.now(timezone.utc).isoformat(timespec="seconds"), "alert_id": alert_id,
             "format": fmt, "verdict": verdict_, "note": note, "purpose": "product feedback"}
    with triage_jobs._lock, open(job.path / "feedback.jsonl", "a") as f:
        f.write(json.dumps(entry) + "\n")
    return latest_feedback(job.path).get((alert_id, fmt)) or {"verdict": None}
