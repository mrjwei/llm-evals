"""
Chart generation for WP4 metrics reports. Moved from wp4_charts.py in Plan
P2.1; Plan P2.7 replaced the event-type and grounding charts with the
three-way outcome per label and the calibration chart.

Renders selected sections of the metrics dict (cjp.evaluate.metrics) as
small PNGs saved into a `charts/` directory next to report.md, referenced
from the report via markdown image links. Kept in its own module so a caller
that only wants the numbers (a test, the Results page) doesn't pull in
matplotlib just to import compute_metrics().

All axes for percentage metrics are fixed to 0-100% so charts from different
runs/sessions line up visually when viewed side by side, which is the actual
point of plotting these.
"""

import os

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

BAR_COLOR = "#4C72B0"


def _save(fig, out_dir: str, filename: str) -> str:
    os.makedirs(out_dir, exist_ok=True)
    path = os.path.join(out_dir, filename)
    fig.savefig(path, bbox_inches="tight", dpi=150)
    plt.close(fig)
    return path


def plot_headline_summary(metrics: dict, out_dir: str, filename: str = "headline_summary.png") -> str | None:
    """One horizontal bar per top-line rate that has a value, all on a
    0-100% axis, with the bootstrap interval as an error bar when there is one."""
    d, p, t = metrics["detection"], metrics["precision_fpr"], metrics.get("triage") or {}
    fine = t.get("fine", {})
    disp = t.get("disposition", {})
    point = lambda v: {"value": v, "ci": None}  # noqa: E731
    candidates = [
        ("Technique recall (SIEM)", point(d.get("technique_recall"))),
        ("Precision (SIEM, alert-level)", point(p.get("precision_alert_level"))),
        ("Coverage", fine.get("coverage")),
        ("Selective accuracy", fine.get("selective_accuracy")),
        ("Strict accuracy", fine.get("strict_accuracy")),
        ("Escalation recall", disp.get("escalation_recall")),
        ("FP dismissal", disp.get("fp_dismissal_rate")),
    ]
    rows = [(label, est) for label, est in candidates if est and est.get("value") is not None]
    if not rows:
        return None

    labels = [label for label, _ in rows]
    values = [est["value"] * 100 for _, est in rows]
    fig, ax = plt.subplots(figsize=(6.5, 0.5 * len(rows) + 1))
    y = range(len(rows))
    ax.barh(y, values, color=BAR_COLOR)
    for i, (_, est) in enumerate(rows):
        if est.get("ci"):
            lo, hi = (v * 100 for v in est["ci"])
            ax.errorbar(values[i], i, xerr=[[values[i] - lo], [hi - values[i]]],
                        color="#333333", capsize=3)
    ax.set_yticks(list(y))
    ax.set_yticklabels(labels)
    ax.invert_yaxis()
    ax.set_xlim(0, 100)
    ax.set_xlabel("% (whiskers: 95% bootstrap CI over distinct requests)")
    ax.set_title("Headline metrics")
    for i, (v, (_, est)) in enumerate(zip(values, rows)):
        end = max(v, est["ci"][1] * 100) if est.get("ci") else v
        inside = end > 85
        ax.text(v - 1 if inside else end + 1, i, f"{v:.1f}%", fontsize=8, va="center",
                ha="right" if inside else "left", color="white" if inside else "black")
    return _save(fig, out_dir, filename)


def plot_alert_volume(metrics: dict, out_dir: str, filename: str = "alert_volume.png") -> str | None:
    volume = metrics["detection"].get("alert_volume_per_technique")
    if not volume:
        return None

    labels, counts = zip(*volume)
    fig, ax = plt.subplots(figsize=(6.5, 0.35 * len(labels) + 1))
    y = range(len(labels))
    ax.barh(y, counts, color=BAR_COLOR)
    ax.set_yticks(list(y))
    ax.set_yticklabels(labels)
    ax.invert_yaxis()
    ax.set_xlabel("Alerts")
    ax.set_title("Alert volume per technique")
    return _save(fig, out_dir, filename)


OUTCOME_COLORS = {"correct": "#4C9A6A", "wrong": "#C0504D", "abstained": "#C9A227",
                  "no_answer": "#9E9E9E"}


def plot_outcomes_by_label(metrics: dict, out_dir: str,
                           filename: str = "outcomes_by_label.png") -> str | None:
    """Stacked share of correct / wrong / abstained / no answer per
    ground-truth label (fine level, attack alerts)."""
    by_label = (metrics.get("triage") or {}).get("by_label")
    if not by_label:
        return None

    fig, ax = plt.subplots(figsize=(7.5, 0.35 * len(by_label) + 1.2))
    y = list(range(len(by_label)))
    left = [0.0] * len(by_label)
    for outcome, color in OUTCOME_COLORS.items():
        widths = [row[outcome] / row["n"] * 100 for row in by_label]
        ax.barh(y, widths, left=left, color=color, label=outcome.replace("_", " "))
        left = [a + b for a, b in zip(left, widths)]
    ax.set_yticks(y)
    ax.set_yticklabels([f"{row['owasp_2025']} {row['label']} (n={row['n']})" for row in by_label])
    ax.invert_yaxis()
    ax.set_xlim(0, 100)
    ax.set_xlabel("% of alerts")
    ax.set_title("Technique label outcome by ground-truth label")
    ax.legend(loc="upper left", bbox_to_anchor=(1.01, 1), fontsize=7)
    return _save(fig, out_dir, filename)


def plot_calibration(metrics: dict, out_dir: str, filename: str = "calibration.png") -> str | None:
    """Selective accuracy of the technique label at each reported
    confidence level, with the number of committed answers on each bar."""
    table = ((metrics.get("triage") or {}).get("calibration") or {}).get("fine")
    rows = [r for r in table or [] if r["selective_accuracy"] is not None]
    if not rows:
        return None

    fig, ax = plt.subplots(figsize=(5, 3))
    x = range(len(rows))
    ax.bar(x, [r["selective_accuracy"] * 100 for r in rows], color=BAR_COLOR)
    ax.set_xticks(list(x))
    ax.set_xticklabels([r["confidence"] for r in rows])
    ax.set_ylim(0, 100)
    ax.set_ylabel("Selective accuracy (%)")
    ax.set_xlabel("Reported confidence")
    ax.set_title("Calibration (technique label, attack alerts)")
    for i, r in enumerate(rows):
        ax.text(i, r["selective_accuracy"] * 100 + 2, f"{r['correct']}/{r['committed']}",
                ha="center", fontsize=8)
    return _save(fig, out_dir, filename)


def generate_charts(metrics: dict, out_dir: str) -> dict[str, str | None]:
    """Generate every chart for a metrics dict. Returns {name: path},
    with path None for a chart that had no data to plot."""
    return {
        "headline_summary": plot_headline_summary(metrics, out_dir),
        "alert_volume": plot_alert_volume(metrics, out_dir),
        "outcomes_by_label": plot_outcomes_by_label(metrics, out_dir),
        "calibration": plot_calibration(metrics, out_dir),
    }
