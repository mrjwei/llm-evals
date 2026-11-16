"""
Named contrasts with a paired cluster bootstrap (METHODS §6; Plan P5,
decision 011 rule 7).

A contrast compares two conditions, A (the reference) and B, on one rate and
reports B − A with a 95% interval. The bootstrap is *paired*: each resample
draws one set of request clusters (the distinct requests of decision 006
rule 4) and computes both conditions' rates on it, each over its own alerts
in those clusters. Both conditions ran on the same corpus, so the same
request is one cluster on both sides, and the request-to-request variation
they share cancels out of the difference. A difference is called a
difference only when its interval excludes 0 (`excludes_zero`); there are no
p-values and no multiple-comparison correction.

The contrasts are the ones METHODS §6 names, nothing else:

    X1  LLM evidence  S1×L0 → S1×L1
        SIEM evidence S1 → S2, S1 → S3, S2 → S3 (all at L0)
    X2  format        FA → FB
    X3  model         sonnet (X1) → haiku (X3), at S1×L0 and S1×L1
    X0  vs X1         per arm: each baseline → each X1 condition on that arm

Rates are the primary metrics of METHODS §5.2–§5.4, computed from scored rows
(cjp.evaluate.score) with the same populations as cjp.evaluate.metrics. The
cost rate is the primary cost metric, list-price USD per correct fine label,
and is left out when either side has unpriced or uncosted rows (baselines).
This module adds no metric and changes no rule; it only implements §6.
"""

import random
from dataclasses import dataclass

import numpy as np

from cjp.config import settings
from cjp.evaluate.metrics import _percentile
from cjp.evaluate.score import COMMITTED


def boot_settings() -> dict:
    """The pre-registered bootstrap parameters (config/settings.yaml)."""
    s = settings()["scoring"]
    return {"resamples": s["bootstrap_resamples"], "seed": s["bootstrap_seed"], "level": s["ci_level"]}


# ── rates: per scored row, its (numerator, denominator) contribution ────────
def _attack(level):
    return lambda s: s["is_attack"] is True and s[level] is not None


def _disp(is_attack):
    return lambda s: s["is_attack"] is is_attack and s["disposition_outcome"] is not None


def _rate(population, num, den=lambda s: True):
    return lambda s: (1.0 if population(s) and den(s) and num(s) else 0.0,
                      1.0 if population(s) and den(s) else 0.0)


def _cost_per_correct(s):
    correct = s["is_attack"] is True and s["fine"] == "correct"
    return (s["cost_usd"] or 0.0, 1.0 if correct else 0.0)


RATES = {
    "fine_coverage": _rate(_attack("fine"), lambda s: s["fine"] in COMMITTED),
    "fine_selective_accuracy": _rate(_attack("fine"), lambda s: s["fine"] == "correct",
                                     lambda s: s["fine"] in COMMITTED),
    "fine_strict_accuracy": _rate(_attack("fine"), lambda s: s["fine"] == "correct"),
    "coarse_coverage": _rate(_attack("coarse"), lambda s: s["coarse"] in COMMITTED),
    "coarse_selective_accuracy": _rate(_attack("coarse"), lambda s: s["coarse"] == "correct",
                                       lambda s: s["coarse"] in COMMITTED),
    "coarse_strict_accuracy": _rate(_attack("coarse"), lambda s: s["coarse"] == "correct"),
    "escalation_recall": _rate(_disp(True), lambda s: s["disposition"] == "escalate"),
    "fp_dismissal": _rate(_disp(False), lambda s: s["disposition"] == "dismiss_false_positive"),
    "high_confidence_wrong": _rate(
        lambda s: s["is_attack"] is True and s["confidence"] == "high" and s["fine"] in COMMITTED,
        lambda s: s["fine"] == "wrong"),
    "cost_per_correct_fine_usd": _cost_per_correct,
}


def _costed(rows: list[dict]) -> bool:
    """Every triaged row has a list-price cost (cost_metrics' own rule:
    no total while any row is unpriced)."""
    return bool(rows) and all(r["cost_usd"] is not None for r in rows)


def _cluster_sums(rows: list[dict], rate) -> dict[str, list[float]]:
    sums: dict[str, list[float]] = {}
    for r in rows:
        n, d = rate(r)
        if n or d:
            c = sums.setdefault(r["cluster"], [0.0, 0.0])
            c[0] += n
            c[1] += d
    return sums


def paired_difference(rows_a: list[dict], rows_b: list[dict], rate, boot: dict | None = None) -> dict | None:
    """B − A on one rate with a paired cluster-bootstrap percentile interval:
    {a, b (the two rates), diff, ci, excludes_zero, a_den, b_den, clusters}.
    None when either side has no rows in the rate's denominator."""
    boot = boot or boot_settings()
    sa, sb = _cluster_sums(rows_a, rate), _cluster_sums(rows_b, rate)
    da, db = sum(v[1] for v in sa.values()), sum(v[1] for v in sb.values())
    if not da or not db:
        return None
    a = sum(v[0] for v in sa.values()) / da
    b = sum(v[0] for v in sb.values()) / db
    keys = sorted(set(sa) | set(sb))
    table = np.array([[*sa.get(k, (0.0, 0.0)), *sb.get(k, (0.0, 0.0))] for k in keys])
    ci = None
    if len(keys) >= 2 and boot["resamples"] >= 1:
        rng = random.Random(boot["seed"])      # reseeded per estimate, like metrics.estimate
        draws = np.array(rng.choices(range(len(keys)), k=len(keys) * boot["resamples"]))
        totals = table[draws.reshape(boot["resamples"], len(keys))].sum(axis=1)
        ok = (totals[:, 1] > 0) & (totals[:, 3] > 0)
        diffs = sorted((totals[ok, 2] / totals[ok, 3] - totals[ok, 0] / totals[ok, 1]).tolist())
        if diffs:
            tail = (1 - boot["level"]) / 2
            ci = [_percentile(diffs, tail), _percentile(diffs, 1 - tail)]
    return {"a": a, "b": b, "diff": b - a, "ci": ci,
            "excludes_zero": bool(ci) and (ci[0] > 0 or ci[1] < 0),
            "a_den": da, "b_den": db, "clusters": len(keys)}


# ── the named contrasts (METHODS §6) ────────────────────────────────────────
@dataclass(frozen=True)
class Contrast:
    id: str
    question: str
    a: tuple[str, str]      # (experiment, condition): the reference
    b: tuple[str, str]


def _x1(arm: str, evidence: str = "L0-alert", model: str = "sonnet") -> str:
    return f"{arm}__{evidence}__FA__{model}"


ARMS = ("S1-plain", "S2-body-in-url", "S3-body-field")
X1_CONDITIONS = (_x1("S1-plain"), _x1("S1-plain", "L1-alert+body"), _x1("S2-body-in-url"),
                 _x1("S3-body-field"))


def named_contrasts() -> list[Contrast]:
    s1l0, s1l1 = _x1("S1-plain"), _x1("S1-plain", "L1-alert+body")
    out = [
        Contrast("X1-llm-evidence", "LLM evidence at S1: L1 − L0", ("X1", s1l0), ("X1", s1l1)),
        Contrast("X1-siem-S2-S1", "SIEM evidence at L0: S2 − S1", ("X1", s1l0), ("X1", _x1(ARMS[1]))),
        Contrast("X1-siem-S3-S1", "SIEM evidence at L0: S3 − S1", ("X1", s1l0), ("X1", _x1(ARMS[2]))),
        Contrast("X1-siem-S3-S2", "SIEM evidence at L0: S3 − S2", ("X1", _x1(ARMS[1])), ("X1", _x1(ARMS[2]))),
        Contrast("X2-format", "Format at S1×L1: FB − FA",
                 ("X2", s1l1), ("X2", s1l1.replace("__FA__", "__FB__"))),
        Contrast("X3-model-L0", "Model at S1×L0: haiku − sonnet", ("X1", s1l0), ("X3", _x1("S1-plain", model="haiku"))),
        Contrast("X3-model-L1", "Model at S1×L1: haiku − sonnet",
                 ("X1", s1l1), ("X3", _x1("S1-plain", "L1-alert+body", "haiku"))),
    ]
    for cond in X1_CONDITIONS:
        arm, evidence = cond.split("__")[:2]
        for baseline in ("B-url-regex", "B-rule"):
            out.append(Contrast(f"X0-X1-{arm.split('-')[0]}-{evidence.split('-')[0]}-{baseline[2:]}",
                                f"LLM ({arm}×{evidence.split('-')[0]}) − {baseline}",
                                ("X0", f"{arm}__{baseline}"), ("X1", cond)))
    return out


def compute(scored: dict[tuple[str, str], list[dict]], boot: dict | None = None,
            only: set[str] | None = None) -> list[dict]:
    """Every named contrast whose two conditions are both in `scored`
    ({(experiment, condition): scored rows}), on every rate both sides
    define. `only` restricts to the given experiments (a run's report shows
    only contrasts inside its own experiment). One row per contrast × rate."""
    boot = boot or boot_settings()
    out = []
    for c in named_contrasts():
        if c.a not in scored or c.b not in scored:
            continue
        if only is not None and not {c.a[0], c.b[0]} <= only:
            continue
        ra, rb = scored[c.a], scored[c.b]
        for name, rate in RATES.items():
            if name == "cost_per_correct_fine_usd" and not (_costed(ra) and _costed(rb)):
                continue
            d = paired_difference(ra, rb, rate, boot)
            if d is None:
                continue
            out.append({"contrast": c.id, "question": c.question, "a_condition": "/".join(c.a),
                        "b_condition": "/".join(c.b), "rate": name, **d})
    return out
