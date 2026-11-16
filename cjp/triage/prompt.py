"""
The triage prompt and everything that shapes what the model sees: the system
prompt, its version hash, the correlation-ID sanitiser, body truncation and
the per-alert payload.

Prompt v2 (Plan P2.6, M2–M4) is rendered from three tracked files:
prompts/triage_v2.md (the instructions, with no testbed specifics),
taxonomy/labels.yaml (the technique labels and their descriptions) and the
output format, prompts/format_a.json or format_b.json (the field list). The
rendered text differs per format, so every row records its own
`prompt_version`: the first 8 hex digits of the sha256 of the exact system
prompt sent. `cjp prompt show` prints it.

The legacy prompt (v1, `1cce404d`) that the legacy no_body/with_body runs
used is kept byte for byte in prompts/legacy/triage_v1.txt, so every
prompt_version in any output row resolves to a file. It named Juice Shop
endpoints and their candidate labels (the leak Plan M4 removes) and is no
longer sent.
"""

import json
import re
from pathlib import Path

from cjp.config import PROMPTS_DIR
from cjp.triage import schema

PROMPT_ID = "triage_v2"
PROMPT_TEMPLATE = PROMPTS_DIR / f"{PROMPT_ID}.md"
LEGACY_PROMPT_FILE = PROMPTS_DIR / "legacy" / "triage_v1.txt"
DEFAULT_FORMAT = "A"


def _technique_label_lines() -> str:
    taxonomy = schema.load_taxonomy()
    lines = [f"- `{label}`: {spec['description']}" for label, spec in taxonomy["labels"].items()]
    lines += [f"- `{label}`: {text}" for label, text in taxonomy["special"].items()]
    return "\n".join(lines)


def _output_field_lines(fmt: str) -> str:
    lines = []
    for name, spec in schema.fields(fmt):
        line = f"- `{name}`: {spec['description']}"
        if "enum" in spec and name != "technique_label":
            line += " One of: " + ", ".join(f"`{v}`" for v in spec["enum"]) + "."
        lines.append(line)
    return "\n".join(lines)


def system_prompt(fmt: str = DEFAULT_FORMAT, template: Path = PROMPT_TEMPLATE) -> str:
    """The exact system prompt sent for an output format."""
    text = template.read_text()
    for marker, value in (("{{technique_labels}}", _technique_label_lines()),
                          ("{{output_fields}}", _output_field_lines(fmt))):
        if marker not in text:
            raise ValueError(f"{template} has no {marker} marker")
        text = text.replace(marker, value)
    return text.strip()


def prompt_version(fmt: str = DEFAULT_FORMAT) -> str:
    """Content hash of system_prompt(fmt), stamped onto every triage row."""
    return schema.short_hash(system_prompt(fmt))


# WP1's attacks.sh (Tier-1 fix) tags every request with a correlation ID,
# carried in the Referer header, of the form wp1-<session>-<attack_seq>-<req_seq>.
# benign_traffic.sh (WP1 benign-traffic generator) uses the same scheme with a
# "benign-" infix: wp1-benign-<session>-<attack_seq>-<req_seq>. Both survive
# verbatim into Wazuh's full_log and must never reach the model — the CID is
# ground truth (the exact attack technique, or the fact that this was benign
# traffic, that produced this alert).
CID_RE = re.compile(r'wp1-(?:benign-)?\d{8}_\d{6}-\d+-\d+')


def sanitise_full_log(full_log: str) -> str:
    """Strip the WP1 correlation ID from a raw log line before it is sent to the LLM."""
    return CID_RE.sub("[REDACTED]", full_log)


def _redact(value):
    """sanitise_full_log() applied to every string in a nested dict/list."""
    if isinstance(value, str):
        return sanitise_full_log(value)
    if isinstance(value, dict):
        return {k: _redact(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_redact(v) for v in value]
    return value


def extract_cid(full_log: str) -> str | None:
    """Return the WP1 correlation ID embedded in a raw log line, or None if
    absent — used by callers (triage/batch.py) to look up this alert's matching
    ingest_log.jsonl entry before ground truth gets redacted out of full_log."""
    match = CID_RE.search(full_log)
    return match.group(0) if match else None


# Cap on how much of an ingest_log.jsonl request_body/response_body gets sent
# to the model — bodies can be large (e.g. a full HTML error page), and this
# is a per-alert SOC prompt, not a bulk log dump. 2000 chars covers every
# WP1 attack payload seen so far with headroom; truncation is marked rather
# than silent so a cut-off body isn't mistaken for a short one.
INGEST_BODY_MAX_CHARS = 2000


def _truncate(text: str, limit: int = INGEST_BODY_MAX_CHARS) -> str:
    if len(text) <= limit:
        return text
    return text[:limit] + f"...[truncated, {len(text) - limit} more chars]"


# Rule fields dropped from the payload (prompt v2, decision 005). firedtimes
# counts how often the rule has fired since the manager started: it describes
# the manager's uptime, not this alert, and it made the same alert a new
# request (a cache miss) in every session.
VOLATILE_RULE_FIELDS = ("firedtimes",)

# The date suffix Wazuh's log rotation adds, e.g. access.log.2026-09-30.
_ROTATION_SUFFIX_RE = re.compile(r"\.\d{4}-\d{2}-\d{2}$")


def log_file_name(location: str) -> str:
    """The alert's `location` reduced to the log file's name without its
    rotation date: /home/<user>/cjp-vm/juice-shop/data/logs/access.log.2026-09-30
    becomes access.log. The directory named the application under test
    (Plan M4); the file name still tells the model which log produced the
    alert."""
    return _ROTATION_SUFFIX_RE.sub("", location.rsplit("/", 1)[-1])


def build_alert_summary(alert: dict, ingest_entry: dict | None = None) -> tuple[dict, bool]:
    """The fields of one Wazuh alert that the model sees, with every CID
    redacted wherever it appears. ingest_entry, if given, is this alert's matching row from a
    session's ingest_log.jsonl (looked up by the caller via extract_cid()
    before the CID gets redacted) — the request/response body the access log
    itself never carries. Returns (summary, ingest_matched)."""
    alert_summary = {
        "timestamp": alert.get("timestamp"),
        "rule": {k: v for k, v in alert.get("rule", {}).items() if k not in VOLATILE_RULE_FIELDS},
        "data": alert.get("data", {}),
        "full_log": sanitise_full_log(alert.get("full_log", "")),
        "location": log_file_name(alert.get("location", "")),
        "agent": alert.get("agent", {})
    }
    ingest_matched = False
    if ingest_entry is not None:
        request_body = ingest_entry.get("request_body") or ""
        response_body = ingest_entry.get("response_body") or ""
        if request_body:
            alert_summary["request_body"] = sanitise_full_log(_truncate(request_body))
            ingest_matched = True
        if response_body:
            alert_summary["response_body"] = sanitise_full_log(_truncate(response_body))
            ingest_matched = True
    # Redact the whole payload, not just full_log and the bodies: the S3
    # decoder (vm/wazuh/decoders/body_field_decoders.xml) also extracts the
    # CID into its own field, data.cid, which the legacy code sent unredacted
    # — including the "benign-" infix. No legacy triage run used S3.
    return _redact(alert_summary), ingest_matched


def user_message(alert_summary: dict) -> str:
    return f"Analyse this Wazuh alert:\n\n{json.dumps(alert_summary, indent=2)}"
