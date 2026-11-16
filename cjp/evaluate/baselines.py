"""
The two lookup baselines of experiment X0 (Plan M9, P5; METHODS §5.6):
does the LLM beat a lookup table?

    B-url-regex  the mapper's SIGNATURES table on the alert's method and URL
    B-rule       what Wazuh's own rule says: its group, else its level

Both are defined in taxonomy/baselines.yaml, frozen with tag prereg-C1; this
module only applies that file. Each baseline answers the LLM's two scored
questions for every alert, a technique_label and a disposition, and writes
them as a verdict row in the same shape a triage call writes
(cjp/triage/batch.py). The unchanged mapper joins it and the unchanged
scorer scores it, so a baseline is held to exactly the LLM's rules
(decision 006). A baseline has no confidence, so it has no calibration, and
no tokens, so its cost is zero rather than unpriced.

`format` on the row is the baseline's name (B-url-regex, B-rule). That keeps
the scorer from reading it as a legacy prompt-v1 row (no format) and from
scoring severity (Format A only).
"""

import functools

import yaml

from cjp.config import BASELINES_FILE
from cjp.evaluate.mapper import AMBIGUOUS_GROUPS, SIGNATURES, signature_match
from cjp.triage.schema import load_taxonomy

BASELINES = ("B-url-regex", "B-rule")
ANSWERS = ("none", "uncertain")      # the special values a baseline may give besides a label
DISPOSITIONS = ("escalate", "dismiss_false_positive")


@functools.cache
def spec() -> dict:
    """taxonomy/baselines.yaml, checked against the taxonomy and the
    signature table: every signature has a label, every label exists."""
    where = BASELINES_FILE
    doc = yaml.safe_load(where.read_text())
    labels = set(load_taxonomy()["labels"]) | set(ANSWERS)
    url, rule = doc["url_regex"], doc["rule"]
    if missing := {s[0] for s in SIGNATURES} - set(url["label"]):
        raise ValueError(f"{where}: url_regex.label has no entry for signature(s) {sorted(missing)}")
    answers = [*url["label"].values(), url["no_match"], *rule["label_by_group"].values(),
               rule["at_or_above"]["label"], rule["below"]["label"]]
    if unknown := sorted({a for a in answers if a not in labels}):
        raise ValueError(f"{where}: {unknown} are not labels in taxonomy/labels.yaml")
    dispositions = [*url["disposition"].values(), rule["at_or_above"]["disposition"],
                    rule["below"]["disposition"]]
    if unknown := sorted({d for d in dispositions if d not in DISPOSITIONS}):
        raise ValueError(f"{where}: dispositions {unknown} must be one of {DISPOSITIONS}")
    return doc


def _candidates(signature: str) -> list[str]:
    """For an ambiguous signature, the labels it cannot tell apart (shown in
    the verdict for the reader; the scorer never credits candidates)."""
    ground_truth = load_taxonomy()["ground_truth"]
    return sorted({ground_truth[raw] for raw in AMBIGUOUS_GROUPS.get(signature, ())})


def url_regex(alert: dict) -> dict:
    """B-url-regex: first matching signature → label; a match escalates
    (`uncertain` included), no match is `none` and dismissed."""
    s = spec()["url_regex"]
    data = alert.get("data") or {}
    signature = signature_match(data.get("protocol"), data.get("url"))
    if signature is None:
        return {"technique_label": s["no_match"], "candidate_labels": [],
                "disposition": s["disposition"]["no_match"], "matched": None}
    label = s["label"][signature]
    return {"technique_label": label,
            "candidate_labels": _candidates(signature) if label == "uncertain" else [],
            "disposition": s["disposition"]["match"], "matched": f"signature {signature}"}


def rule(alert: dict) -> dict:
    """B-rule: a rule group naming a technique gives that label and escalates
    (baselines.yaml: "a group-named label also escalates"). Otherwise the
    rule level decides: at or above `attack_level` is an unnamed attack
    (`uncertain`, escalate), below it is `none` and dismissed."""
    s = spec()["rule"]
    r = alert.get("rule") or {}
    groups = r.get("groups") or []
    for group, label in s["label_by_group"].items():
        if group in groups:
            return {"technique_label": label, "candidate_labels": [], "disposition": "escalate",
                    "matched": f"rule {r.get('id')} group {group}"}
    side = "at_or_above" if int(r.get("level") or 0) >= s["attack_level"] else "below"
    return {"technique_label": s[side]["label"], "candidate_labels": [],
            "disposition": s[side]["disposition"], "matched": f"rule {r.get('id')} level {r.get('level')}"}


APPLY = {"B-url-regex": url_regex, "B-rule": rule}


def verdict(alert: dict, baseline: str) -> dict:
    """One verdict row, shaped like a triage row so the mapper joins it."""
    if baseline not in APPLY:
        raise ValueError(f"baseline {baseline!r} is not one of {', '.join(BASELINES)}")
    answer = APPLY[baseline](alert)
    matched = answer.pop("matched")
    return {
        "wazuh_alert_id": alert.get("id"),
        "wazuh_timestamp": alert.get("timestamp"),
        "wazuh_rule_id": (alert.get("rule") or {}).get("id"),
        "wazuh_rule_description": (alert.get("rule") or {}).get("description"),
        "llm_output": answer,
        "parse_ok": True,
        "schema_ok": True,
        "format": baseline,
        "baseline": baseline,
        "baseline_matched": matched,
        "baselines_version": spec()["version"],
        "model": None,
        "repeat": 1,
        "token_usage": None,
    }


def verdicts(alerts: list[dict], baseline: str) -> list[dict]:
    return [verdict(a, baseline) for a in alerts]
