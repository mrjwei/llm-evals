"""
Calibration table (Plan P2.7, M8): how often answers are right at each
confidence level the model reported.

The model reports confidence as high / medium / low, not a probability, so
there is no expected-calibration-error to compute. The table shows, per
level, how many answers there were and what share of the committed ones
were wrong. The headline is the share of `high` answers that are wrong: a
confident wrong answer is the case a junior analyst is most likely to act on
(audit A4.4).
"""

from cjp.evaluate.score import COMMITTED

LEVELS = ("high", "medium", "low")


def calibration_table(scored: list[dict], outcome: str = "fine") -> list[dict]:
    """One row per confidence level for the given outcome field ("fine",
    "coarse" or "disposition_outcome"). Rows without that outcome, or
    without a confidence (no_answer), are left out."""
    table = []
    for level in LEVELS:
        rows = [s for s in scored if s["confidence"] == level and s.get(outcome) is not None]
        counts = {k: sum(1 for s in rows if s[outcome] == k) for k in ("correct", "wrong", "abstained")}
        committed = counts["correct"] + counts["wrong"]
        table.append({
            "confidence": level,
            "n": len(rows),
            **counts,
            "committed": committed,
            "selective_accuracy": counts["correct"] / committed if committed else None,
            "wrong_share": counts["wrong"] / committed if committed else None,
        })
    return table


def high_confidence_wrong(scored: list[dict], outcome: str = "fine") -> dict:
    """Of the committed answers given with high confidence, how many were wrong."""
    rows = [s for s in scored if s["confidence"] == "high" and s.get(outcome) in COMMITTED]
    wrong = sum(1 for s in rows if s[outcome] == "wrong")
    return {"wrong": wrong, "committed": len(rows),
            "rate": wrong / len(rows) if rows else None}
