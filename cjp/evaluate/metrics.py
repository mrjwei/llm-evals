"""
WP4 — aggregate evaluation metrics over the mapper's per-alert output; run
it as `cjp metrics`. Moved from wp4_metrics.py in Plan P2.1 and rewritten
around the Plan P2.7 metrics (decision 006). The report is in
cjp/evaluate/report.py.

Two families:

  SIEM (D1, kept from the legacy metrics): technique recall, request-level
      alert rate, alert volume per technique, alert-level precision and
      request-level FPR on benign traffic, and the URL-signature cross-check.
  Triage (from the scored rows of cjp.evaluate.score):
      technique, fine and coarse (M1, M5): coverage = committed / scored,
          selective accuracy = correct / committed, strict accuracy =
          correct / scored, on attack alerts; plus the share of benign
          alerts labelled `none`.
      disposition (M3): escalation recall = escalate / attack alerts,
          false-positive dismissal rate = dismiss_false_positive / benign
          alerts, and the needs_more_info rate on each.
      severity (secondary, Format A, attack alerts): agreement = answers
          inside the label's band in rubric/expected_decisions.yaml / scored,
          plus the share under-rated (below the band).
      calibration (M8): cjp.evaluate.calibration.
      cost: tokens and list-price USD per alert, per correct fine answer
          (primary) and per correct disposition (decision 011).
      schema: parse and schema-valid rates.

Every triage rate comes with a 95% percentile bootstrap interval that
resamples distinct requests, not alerts (M7): all alerts of one request, and
all its repeats, move together. With several repeats (one mapper output
each) the rate is pooled over them and the per-repeat values give the
min–max spread. Evidence grounding is gone (M10); the raters judge evidence.

The mapper's output file is one row per *alert* — a technique with zero
alerts produces zero rows there, so it alone can't be a recall denominator.
This module also reads the session directory that the mapper ran against
(attack_log.jsonl, benign_log.jsonl, access.log) to recover that denominator,
the true-negative population for FPR, and the request-level alert rate.
"""

import os
import random
from collections import Counter

from cjp.config import settings
from cjp.evaluate.calibration import calibration_table, high_confidence_wrong
from cjp.evaluate.mapper import build_ground_truth, load_benign_ground_truth, load_jsonl
from cjp.evaluate.score import COMMITTED, score_rows
from cjp.runs import git_sha
from cjp.triage.schema import load_taxonomy


def count_lines(path: str) -> int | None:
    if not path or not os.path.exists(path):
        return None
    with open(path) as f:
        return sum(1 for _ in f)


def cohens_kappa(labels_a: list[str], labels_b: list[str]) -> float | None:
    """Unweighted Cohen's kappa over paired categorical labels."""
    n = len(labels_a)
    if n == 0:
        return None
    po = sum(1 for a, b in zip(labels_a, labels_b) if a == b) / n
    count_a, count_b = Counter(labels_a), Counter(labels_b)
    categories = set(count_a) | set(count_b)
    pe = sum((count_a.get(c, 0) / n) * (count_b.get(c, 0) / n) for c in categories)
    if pe >= 1.0:
        return 1.0 if po >= 1.0 else 0.0
    return (po - pe) / (1 - pe)


def detection_metrics(rows: list[dict], attacks: dict[int, dict], access_log_lines: int | None) -> dict:
    real = {seq: a for seq, a in attacks.items() if not a["skipped"]}
    detected = {r["matched_attack_seq"] for r in rows if r["matched_attack_seq"] is not None}
    missed = sorted(
        (a for seq, a in real.items() if seq not in detected),
        key=lambda a: a["attack_seq"],
    )
    volume = Counter(r["matched_label"] for r in rows if r["is_attack"] is True)

    return {
        "techniques_total": len(real),
        "techniques_detected": len(detected),
        "technique_recall": (len(detected) / len(real)) if real else None,
        "missed_techniques": [f"{a['category']}/{a['label']}" for a in missed],
        "alerts_total": len(rows),
        "access_log_lines": access_log_lines,
        "request_level_alert_rate": (len(rows) / access_log_lines) if access_log_lines else None,
        "alert_volume_per_technique": volume.most_common(),
    }


def precision_fpr_metrics(rows: list[dict], total_benign_requests: int | None) -> dict:
    tp = sum(1 for r in rows if r["is_attack"] is True)
    fp = sum(1 for r in rows if r["is_attack"] is False)
    unclassified = sum(1 for r in rows if r["is_attack"] is None)
    precision = (tp / (tp + fp)) if (tp + fp) > 0 else None

    fpr = None
    if total_benign_requests:
        benign_cids_alerted = {r["matched_cid"] for r in rows
                                if r["is_attack"] is False and r["matched_cid"]}
        fpr = len(benign_cids_alerted) / total_benign_requests

    return {
        "true_positive_alerts": tp,
        "false_positive_alerts": fp,
        "unclassified_alerts": unclassified,
        "precision_alert_level": precision,
        "total_benign_requests": total_benign_requests,
        "false_positive_rate_request_level": fpr,
    }


def signature_crosscheck_metrics(rows: list[dict]) -> dict:
    paired = [r for r in rows if r["matched_label"] and r["signature_label"]]
    group_aware = [r for r in rows if r.get("signature_agrees") is not None]
    group_agree = sum(1 for r in group_aware if r["signature_agrees"])

    kappa = cohens_kappa([r["matched_label"] for r in paired],
                          [r["signature_label"] for r in paired])

    return {
        "signature_pairs": len(paired),
        "signature_group_aware_agreement_rate":
            (group_agree / len(group_aware)) if group_aware else None,
        "signature_raw_label_cohens_kappa": kappa,
        "_note": ("Raw κ compares the mapped label and the signature label as literal "
                  "strings, so it is undercounted: the two shared-endpoint signatures "
                  "(login, feedback) never equal a single technique label. The "
                  "group-aware agreement counts a match when the mapped label is in "
                  "the signature's group, and is the fairer of the two."),
    }




# ── Triage metrics (Plan P2.7) ───────────────────────────────────────────────

def _percentile(sorted_values: list[float], q: float) -> float:
    """Linear-interpolated percentile of an already sorted list, q in [0, 1]."""
    pos = q * (len(sorted_values) - 1)
    lo = int(pos)
    hi = min(lo + 1, len(sorted_values) - 1)
    return sorted_values[lo] + (sorted_values[hi] - sorted_values[lo]) * (pos - lo)


def cluster_bootstrap_ci(pairs: list[tuple[int, int]], resamples: int, seed: int,
                         level: float) -> list[float] | None:
    """Percentile CI of sum(num) / sum(den), resampling clusters with
    replacement. pairs holds one (num, den) per cluster. Resamples whose
    denominator is 0 are skipped. None with fewer than 2 clusters."""
    if len(pairs) < 2 or resamples < 1:
        return None
    rng = random.Random(seed)
    stats = []
    for _ in range(resamples):
        num = den = 0
        for n, d in rng.choices(pairs, k=len(pairs)):
            num += n
            den += d
        if den:
            stats.append(num / den)
    if not stats:
        return None
    stats.sort()
    tail = (1 - level) / 2
    return [_percentile(stats, tail), _percentile(stats, 1 - tail)]


def estimate(rows: list[dict], num, den, boot: dict) -> dict:
    """A rate over scored rows: num and den are predicates on a row. Returns
    the pooled value, its clustered bootstrap CI and, with more than one
    repeat, the per-repeat values and their min–max spread."""
    in_den = [r for r in rows if den(r)]
    hits = sum(1 for r in in_den if num(r))
    clusters: dict[str, list[int]] = {}
    for r in in_den:
        c = clusters.setdefault(r["cluster"], [0, 0])
        c[0] += bool(num(r))
        c[1] += 1
    per_repeat = {}
    for rep in sorted({r["repeat"] for r in rows}):
        rep_den = [r for r in in_den if r["repeat"] == rep]
        per_repeat[rep] = (sum(1 for r in rep_den if num(r)) / len(rep_den)) if rep_den else None
    values = [v for v in per_repeat.values() if v is not None]
    return {
        "value": hits / len(in_den) if in_den else None,
        "num": hits,
        "den": len(in_den),
        "clusters": len(clusters),
        "ci": cluster_bootstrap_ci([tuple(c) for c in clusters.values()], **boot),
        "per_repeat": per_repeat if len(per_repeat) > 1 else None,
        "spread": [min(values), max(values)] if len(values) > 1 else None,
    }


def _outcome_counts(rows: list[dict], key: str) -> dict:
    return {k: sum(1 for r in rows if r[key] == k) for k in ("correct", "wrong", "abstained", "no_answer")}


def technique_metrics(scored: list[dict], level: str, boot: dict) -> dict:
    """Coverage, selective and strict accuracy on attack alerts (M1), at the
    fine or coarse level (M5)."""
    attack = [s for s in scored if s["is_attack"] is True and s[level] is not None]
    committed = lambda s: s[level] in COMMITTED  # noqa: E731
    correct = lambda s: s[level] == "correct"    # noqa: E731
    return {
        "scored": len(attack),
        "counts": _outcome_counts(attack, level),
        "coverage": estimate(attack, committed, lambda s: True, boot),
        "selective_accuracy": estimate(attack, correct, committed, boot),
        "strict_accuracy": estimate(attack, correct, lambda s: True, boot),
    }


def per_label_table(scored: list[dict]) -> list[dict]:
    """Fine and coarse outcomes per ground-truth label, attack alerts only,
    sorted by OWASP 2025 category then label."""
    labels = load_taxonomy()["labels"]
    by_label: dict[str, list[dict]] = {}
    for s in scored:
        if s["is_attack"] is True and s["fine"] is not None:
            by_label.setdefault(s["truth_label"], []).append(s)
    table = []
    for label, rows in by_label.items():
        fine = _outcome_counts(rows, "fine")
        table.append({
            "label": label,
            "owasp_2025": labels[label]["owasp_2025"],
            "coarse": labels[label]["coarse"],
            "n": len(rows),
            **fine,
            "strict_accuracy": fine["correct"] / len(rows),
            "coarse_correct": sum(1 for r in rows if r["coarse"] == "correct"),
        })
    return sorted(table, key=lambda t: (t["owasp_2025"], t["label"]))


def disposition_metrics(scored: list[dict], boot: dict) -> dict:
    """M3: escalation recall on attack alerts, false-positive dismissal on
    benign ones, and how often the model asked for more information.
    Legacy rows are left out: prompt v1 had no disposition."""
    rows = [s for s in scored if s["disposition_outcome"] is not None]
    attack = [s for s in rows if s["is_attack"] is True]
    benign = [s for s in rows if s["is_attack"] is False]
    said = lambda value: (lambda s: s["disposition"] == value)  # noqa: E731
    always = lambda s: True  # noqa: E731
    return {
        "attack_alerts": len(attack),
        "benign_alerts": len(benign),
        "counts": {
            name: dict(Counter(s["disposition"] or "no_answer" for s in group))
            for name, group in (("attack", attack), ("benign", benign))},
        "escalation_recall": estimate(attack, said("escalate"), always, boot),
        "fp_dismissal_rate": estimate(benign, said("dismiss_false_positive"), always, boot),
        "needs_more_info_attack": estimate(attack, said("needs_more_info"), always, boot),
        "needs_more_info_benign": estimate(benign, said("needs_more_info"), always, boot),
        "benign_escalated": estimate(benign, said("escalate"), always, boot),
    }


def severity_metrics(scored: list[dict], boot: dict) -> dict | None:
    """Severity agreement on Format A attack alerts (decision 011): the share
    whose severity is inside the label's acceptable band, with the shares
    below and above it. None when no row has a scored severity (Format B,
    legacy)."""
    rows = [s for s in scored if s.get("severity_outcome") is not None]
    if not rows:
        return None
    always = lambda s: True  # noqa: E731
    return {
        "scored": len(rows),
        "counts": _outcome_counts(rows, "severity_outcome"),
        "agreement": estimate(rows, lambda s: s["severity_outcome"] == "correct", always, boot),
        "under_rated": estimate(rows, lambda s: (s["severity_gap"] or 0) < 0, always, boot),
        "over_rated": estimate(rows, lambda s: (s["severity_gap"] or 0) > 0, always, boot),
    }


def cost_metrics(scored: list[dict]) -> dict:
    """Tokens and list-price cost per triaged alert, per correct fine answer
    on an attack alert (primary) and per correct disposition on any alert
    (decision 011). Cost is only totalled when every row is priced; unpriced
    models are named, never guessed."""
    prices = settings()["prices"]
    with_usage = [s for s in scored if s["input_tokens"] is not None]
    unpriced = Counter(s["model"] or "unknown (legacy row)" for s in with_usage if s["cost_usd"] is None)
    n = len(with_usage)
    total = sum(s["cost_usd"] for s in with_usage) if with_usage and not unpriced else None
    correct = sum(1 for s in scored if s["is_attack"] is True and s["fine"] == "correct")
    correct_disposition = sum(1 for s in scored if s["disposition_outcome"] == "correct")
    return {
        "alerts": n,
        "input_tokens_per_alert": sum(s["input_tokens"] for s in with_usage) / n if n else None,
        "output_tokens_per_alert": sum(s["output_tokens"] for s in with_usage) / n if n else None,
        "cost_total_usd": total,
        "cost_per_alert_usd": total / n if total is not None else None,
        "correct_fine_answers": correct,
        "cost_per_correct_usd": total / correct if total is not None and correct else None,
        "correct_dispositions": correct_disposition,
        "cost_per_correct_disposition_usd":
            total / correct_disposition if total is not None and correct_disposition else None,
        "models": sorted({s["model"] for s in with_usage if s["model"]}),
        "unpriced": dict(unpriced),
        "price_source": prices["source"],
        "price_retrieved": str(prices["retrieved"]),
    }


def triage_metrics(scored: list[dict], boot: dict | None = None, api_errors: int = 0) -> dict:
    """Every triage metric over the scored rows of one condition (all its
    repeats pooled). None when no row was triaged. api_errors counts rows
    left out because their call failed (shown in the report, never scored)."""
    if not scored:
        return None
    if boot is None:
        s = settings()["scoring"]
        boot = {"resamples": s["bootstrap_resamples"], "seed": s["bootstrap_seed"],
                "level": s["ci_level"]}
    benign_v2 = [s for s in scored if s["is_attack"] is False and s["fine"] is not None]
    valid = [s for s in scored if s["confidence"] is not None]
    attack_scored = [s for s in scored if s["is_attack"] is True]
    return {
        "rows": len(scored),
        "repeats": sorted({s["repeat"] for s in scored}),
        "schemes": dict(Counter(s["scheme"] for s in scored)),
        "unscored_alerts": sum(1 for s in scored if s["truth_label"] is None),
        "api_errors": api_errors,
        "bootstrap": boot,
        "fine": technique_metrics(scored, "fine", boot),
        "coarse": technique_metrics(scored, "coarse", boot),
        "by_label": per_label_table(scored),
        "benign_labelled_none": estimate(benign_v2, lambda s: s["answer_label"] == "none",
                                         lambda s: True, boot) if benign_v2 else None,
        "disposition": disposition_metrics(scored, boot),
        "severity": severity_metrics(scored, boot),
        "calibration": {
            "fine": calibration_table(attack_scored, "fine"),
            "disposition": calibration_table(scored, "disposition_outcome"),
            "high_confidence_wrong": high_confidence_wrong(attack_scored, "fine"),
        },
        "cost": cost_metrics(scored),
        "schema": {
            "parse_ok_rate": sum(1 for s in scored if s["parse_ok"]) / len(scored),
            "schema_ok_rate": (sum(1 for s in scored if s["schema_ok"]) / len(scored))
            if any(s["scheme"] == "v2" for s in scored) else None,
            "valid_answers": len(valid),
        },
    }


def compute_metrics(input_paths: list[str], session_dir: str, boot: dict | None = None) -> dict:
    """SIEM metrics from the first mapper output and triage metrics pooled
    over all of them. Each input is one repeat of the same session's mapped
    alerts (cjp map --wp3), in repeat order."""
    rows = load_jsonl(input_paths[0])
    _, attacks, _ = build_ground_truth(os.path.join(session_dir, "attack_log.jsonl"))
    cid_to_benign = load_benign_ground_truth(session_dir)
    access_log_lines = count_lines(os.path.join(session_dir, "access.log"))

    scored, api_errors = [], 0
    for i, path in enumerate(input_paths, start=1):
        mapped = rows if i == 1 else load_jsonl(path)
        api_errors += sum(1 for r in mapped if r.get("llm_api_error"))
        rep = score_rows(mapped, session_dir, repeat=i)
        if clash := {s["repeat"] for s in rep} & {s["repeat"] for s in scored}:
            raise ValueError(f"{path}: repeat {sorted(clash)} is already in an earlier input; "
                             "each input must be a different repeat (cjp triage --repeat N)")
        scored += rep

    return {
        "git_sha": git_sha(),
        "inputs": list(input_paths),
        "detection": detection_metrics(rows, attacks, access_log_lines),
        "precision_fpr": precision_fpr_metrics(rows, len(cid_to_benign) or None),
        "signature": signature_crosscheck_metrics(rows),
        "triage": triage_metrics(scored, boot, api_errors=api_errors),
    }
