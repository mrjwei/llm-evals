"""
Per-alert scoring of triage answers (Plan P2.7: M1, M3, M5; decision 006).

Input: the mapper's rows (cjp map --wp3), which carry the ground truth and
the model's answer side by side. Output: one scored row per alert with an
outcome for each question the answer is judged on:

  fine         technique_label against the ground-truth label, exact match
               after taxonomy/labels.yaml's `ground_truth` map (M2)
  coarse       the same after mapping both to their coarse group, so
               brute force / weak credentials / enumeration are one class (M5)
  disposition  escalate on an attack alert, dismiss_false_positive on a
               benign one (M3)
  severity     Format A only, attack alerts only: inside the label's
               `acceptable_severity` band in rubric/expected_decisions.yaml
               (a secondary metric, pre-registered in P4, decision 011)

Every outcome is one of OUTCOMES (M1): `correct`, `wrong`, `abstained` (the
model said `uncertain`, or `needs_more_info` for disposition) or `no_answer`
(refusal, truncation, unparseable or schema-invalid answer: nothing to
score). An abstention is never counted as correct. `uncertain` is abstained
at the coarse level too, even when every candidate is in one coarse group:
Format B has no candidates, and crediting them would favour Format A in X2.

Legacy rows (prompt v1, `1cce404d`: free-text event_type, no label and no
disposition) are scored so the audit's re-computation can be reproduced
(Plan P2 acceptance): an event_type starting "Ambiguous" is the hedge the v1
prompt prescribed and counts as abstained; any other answer is correct when
it contains a synonym of the true label from taxonomy/legacy_synonyms.json,
the table the legacy reports used. Their disposition is None (never asked).

Each row also gets `cluster`, the distinct HTTP request that raised the
alert (method, URL and request body as sent), for the clustered bootstrap in
cjp.evaluate.metrics, and its token cost at the list price in
config/settings.yaml.
"""

import functools
import hashlib
import json
import os

import yaml

from cjp.config import EXPECTED_DECISIONS_FILE, LEGACY_SYNONYM_TABLE, settings
from cjp.evaluate.mapper import load_jsonl
from cjp.triage.schema import load_taxonomy

OUTCOMES = ("correct", "wrong", "abstained", "no_answer")
COMMITTED = ("correct", "wrong")
LEGACY_HEDGE_PREFIX = "ambiguous"
EXPECTED_DISPOSITION = {True: "escalate", False: "dismiss_false_positive"}


@functools.cache
def legacy_synonyms() -> dict[str, list[str]]:
    return json.loads(LEGACY_SYNONYM_TABLE.read_text())


@functools.cache
def expected_decisions() -> dict:
    """rubric/expected_decisions.yaml, checked against the taxonomy: one entry
    per label, a valid severity band, and the dispositions the scorer uses."""
    where = EXPECTED_DECISIONS_FILE
    spec = yaml.safe_load(where.read_text())
    levels = spec["severity_levels"]
    labels = load_taxonomy()["labels"]
    if missing := set(labels) ^ set(spec["labels"]):
        raise ValueError(f"{where}: labels differ from taxonomy/labels.yaml: {sorted(missing)}")
    for label, entry in spec["labels"].items():
        if entry["expected_disposition"] != EXPECTED_DISPOSITION[True]:
            raise ValueError(f"{where}: {label} expects {entry['expected_disposition']!r}; "
                             "decision 006 scores every attack against 'escalate'")
        band = entry["acceptable_severity"]
        if not band or any(b not in levels for b in band):
            raise ValueError(f"{where}: {label} acceptable_severity {band} must use {levels}")
    if spec["benign"]["expected_disposition"] != EXPECTED_DISPOSITION[False]:
        raise ValueError(f"{where}: benign must expect {EXPECTED_DISPOSITION[False]!r} (decision 006)")
    return spec


def severity_gap(answer: str, label: str) -> int:
    """Steps from the answer to the label's acceptable band: 0 inside it,
    negative below (under-rated), positive above (over-rated)."""
    spec = expected_decisions()
    order = spec["severity_levels"].index
    band = [order(b) for b in spec["labels"][label]["acceptable_severity"]]
    a = order(answer)
    return a - max(band) if a > max(band) else a - min(band) if a < min(band) else 0


def coarse_of(label: str) -> str:
    """A label's coarse group; `none`, `other` and `uncertain` are their own."""
    return load_taxonomy()["labels"].get(label, {}).get("coarse", label)


def truth_of(row: dict) -> tuple[str, str] | None:
    """(fine, coarse) ground truth of a mapped alert, or None when it has none
    to score against: aggregate or unattributed alerts, or an attack label the
    taxonomy doesn't map."""
    if row.get("is_attack") is False:
        return "none", "none"
    if row.get("is_attack") is True:
        label = load_taxonomy()["ground_truth"].get(row.get("matched_label"))
        if label is not None:
            return label, coarse_of(label)
    return None


# ── Request clusters (Plan M7) ───────────────────────────────────────────────

def request_index(session_dir: str) -> dict[str, str]:
    """cid -> cluster key for every scripted request of a session.

    The key hashes the method, URL and request body as sent, so two sessions
    of a seeded corpus that send the same request share a key. Bodies come
    from ingest_log.jsonl; a session without one clusters on method and URL
    only, which merges more requests and so widens the intervals."""
    bodies = {}
    ingest = os.path.join(session_dir, "ingest_log.jsonl")
    if os.path.exists(ingest):
        bodies = {e["cid"]: e.get("request_body") or "" for e in load_jsonl(ingest) if "cid" in e}
    index = {}
    for name in ("attack_log.jsonl", "benign_log.jsonl"):
        path = os.path.join(session_dir, name)
        if not os.path.exists(path):
            continue
        for r in load_jsonl(path):
            if r.get("kind") == "request" and r.get("cid"):
                request = json.dumps([r.get("method"), r.get("url"), bodies.get(r["cid"], "")])
                index[r["cid"]] = "req:" + hashlib.sha256(request.encode()).hexdigest()[:12]
    return index


def cluster_of(row: dict, index: dict[str, str]) -> str:
    """The row's request cluster. Alerts matched without a CID (interval or
    signature tier, pre-CID sessions only) are their own cluster."""
    return index.get(row.get("matched_cid")) or f"alert:{row.get('wazuh_alert_id')}"


# ── Outcomes ─────────────────────────────────────────────────────────────────

def is_legacy(row: dict) -> bool:
    """A prompt-v1 row: triaged (llm_parse_ok set) but with no output format."""
    return row.get("llm_parse_ok") is not None and row.get("llm_format") is None


def _label_outcome(answer: str | None, truth: str) -> str:
    if answer is None:
        return "no_answer"
    if answer == "uncertain":
        return "abstained"
    return "correct" if answer == truth else "wrong"


def _legacy_outcomes(row: dict, truth: tuple[str, str]) -> tuple[str | None, str | None]:
    """(fine, coarse) for a prompt-v1 answer. Benign alerts are not scored:
    v1 had no way to say an alert was legitimate."""
    if row.get("is_attack") is not True:
        return None, None
    event_type = (row.get("llm_event_type") or "").lower()
    if not row.get("llm_parse_ok") or not event_type:
        return "no_answer", "no_answer"
    if event_type.startswith(LEGACY_HEDGE_PREFIX):
        return "abstained", "abstained"
    table = legacy_synonyms()
    ground_truth = load_taxonomy()["ground_truth"]

    def says(raw_label: str) -> bool:
        return any(s.lower() in event_type for s in table.get(raw_label, [raw_label]))

    fine = "correct" if says(row["matched_label"]) else "wrong"
    same_group = [raw for raw, label in ground_truth.items() if coarse_of(label) == truth[1]]
    coarse = "correct" if any(says(raw) for raw in same_group) else "wrong"
    return fine, coarse


def _disposition_outcome(answer: str | None, is_attack: bool) -> str:
    if answer is None:
        return "no_answer"
    if answer == "needs_more_info":
        return "abstained"
    return "correct" if answer == EXPECTED_DISPOSITION[is_attack] else "wrong"


def _severity_outcome(row: dict, valid: bool, truth: tuple[str, str] | None) -> tuple[str | None, int | None]:
    """(outcome, gap) for Format A's severity on an attack alert; (None, None)
    when it isn't scored: Format B has no severity, and benign alerts have no
    expected severity."""
    if truth is None or row.get("is_attack") is not True or row.get("llm_format") != "A":
        return None, None
    answer = row.get("llm_severity") if valid else None
    if answer is None:
        return "no_answer", None
    gap = severity_gap(answer, truth[0])
    return ("correct" if gap == 0 else "wrong"), gap


def price_of(model: str | None) -> dict | None:
    return settings()["prices"]["usd_per_mtok"].get(model) if model else None


def score_row(row: dict, index: dict[str, str] | None = None, repeat: int = 1) -> dict | None:
    """Score one mapped row. None when the alert was never triaged, or its
    call failed (an api_error row, P2.10): no answer exists, and counting it
    as `no_answer` would charge an outage to the model."""
    if row.get("llm_parse_ok") is None or row.get("llm_api_error"):
        return None
    truth = truth_of(row)
    legacy = is_legacy(row)
    valid = bool(row.get("llm_parse_ok")) and (legacy or row.get("llm_schema_ok") is True)
    answer = row.get("llm_technique_label") if valid and not legacy else None
    disposition = row.get("llm_disposition") if valid and not legacy else None

    fine = coarse = disposition_outcome = None
    severity_outcome = gap = None
    if truth is not None:
        if legacy:
            fine, coarse = _legacy_outcomes(row, truth)
        else:
            fine = _label_outcome(answer, truth[0])
            coarse = _label_outcome(None if answer is None else coarse_of(answer), truth[1])
            disposition_outcome = _disposition_outcome(disposition, row["is_attack"])
            severity_outcome, gap = _severity_outcome(row, valid, truth)

    usage = row.get("llm_token_usage") or {}
    price = price_of(row.get("llm_model"))
    cost = None
    if price is not None and usage:
        cost = (usage.get("input_tokens", 0) * price["input"]
                + usage.get("output_tokens", 0) * price["output"]) / 1_000_000

    return {
        "wazuh_alert_id": row.get("wazuh_alert_id"),
        "repeat": row.get("llm_repeat") or repeat,
        "cluster": cluster_of(row, index or {}),
        "scheme": "legacy" if legacy else "v2",
        "is_attack": row.get("is_attack"),
        "truth_raw": row.get("matched_label") if truth else None,   # attacks.sh's label, e.g. *_inj (X4)
        "truth_label": truth[0] if truth else None,
        "truth_coarse": truth[1] if truth else None,
        "answer_label": answer,
        "event_type": row.get("llm_event_type"),
        "fine": fine,
        "coarse": coarse,
        "disposition": disposition,
        "disposition_outcome": disposition_outcome,
        "severity": row.get("llm_severity") if valid and not legacy else None,
        "severity_outcome": severity_outcome,
        "severity_gap": gap,
        "confidence": row.get("llm_confidence") if valid else None,
        "schema_ok": row.get("llm_schema_ok"),
        "parse_ok": row.get("llm_parse_ok"),
        "model": row.get("llm_model"),
        "input_tokens": usage.get("input_tokens"),
        "output_tokens": usage.get("output_tokens"),
        "cost_usd": cost,
    }


def score_rows(rows: list[dict], session_dir: str | None = None, repeat: int = 1) -> list[dict]:
    """Score every triaged row of one mapper output (one repeat)."""
    index = request_index(session_dir) if session_dir else {}
    scored = (score_row(r, index, repeat) for r in rows)
    return [s for s in scored if s is not None]
