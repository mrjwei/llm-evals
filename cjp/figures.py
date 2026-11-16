"""
The paper figures behind `cjp results build` (cjp/results.py), one function
per figure, each saving a PNG and returning its path.

Conventions, so figures read as one set:
- Categorical colours come from one validated palette in a fixed slot order
  (SERIES; checked with the dataviz validator, light surface, adjacent pairs
  for bars and the first three slots all-pairs for scatter). Colour follows
  the series, never its rank. Scatter plots use at most three hues and label
  every point, so identity never rests on colour alone. Three slots are
  under 3:1 contrast on the surface, so every figure has its CSV table in
  results/tables/ and bars carry their values.
- A rate over too few answers is never drawn like a solid one: its bar is
  faded and hatched, and it carries its counts (F3).
- Rates sit on a fixed 0–100% axis, so figures line up side by side.
  Whiskers are the 95% bootstrap interval over distinct requests (METHODS §6).
- Every figure's footer names each run it reads: experiment, run ID, corpus
  and its sha256 prefix, and the code's git describe (Plan §2.3).
"""

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
from matplotlib.colors import to_rgba  # noqa: E402

SERIES = ["#2a78d6", "#eb6834", "#1baf7a", "#eda100", "#e87ba4", "#008300", "#4a3aa7", "#e34948"]
SURFACE, INK, INK_2, MUTED, GRID, AXIS = "#fcfcfb", "#0b0b0b", "#52514e", "#898781", "#e1e0d9", "#c3c2b7"
WHISKER = "#52514e"

plt.rcParams.update({
    "figure.facecolor": SURFACE, "axes.facecolor": SURFACE, "savefig.facecolor": SURFACE,
    "axes.edgecolor": AXIS, "axes.labelcolor": INK_2, "axes.titlecolor": INK,
    "axes.titlesize": 10, "axes.labelsize": 8.5, "xtick.color": MUTED, "ytick.color": MUTED,
    "xtick.labelsize": 8, "ytick.labelsize": 8, "axes.grid": True, "grid.color": GRID,
    "grid.linewidth": 0.6, "axes.axisbelow": True, "axes.spines.top": False,
    "axes.spines.right": False, "legend.fontsize": 7.5, "legend.frameon": False,
    "font.family": "sans-serif",
})


def _save(fig, path, footers: list[str]):
    path.parent.mkdir(parents=True, exist_ok=True)
    fig.text(0.0, -0.01, "\n".join(footers), ha="left", va="top", fontsize=6.5, color=MUTED)
    fig.savefig(path, bbox_inches="tight", dpi=200, metadata={"Software": None})
    plt.close(fig)
    return path


def _pct(est):
    return None if not est or est.get("value") is None else est["value"] * 100


def _err(est):
    """Asymmetric whisker lengths in percentage points, or zeros."""
    if not est or not est.get("ci") or est.get("value") is None:
        return 0.0, 0.0
    v = est["value"] * 100
    return max(v - est["ci"][0] * 100, 0.0), max(est["ci"][1] * 100 - v, 0.0)


def _grouped_bars(ax, groups: list[str], series: list[tuple[str, list[dict | None]]], horizontal=True):
    """One bar per (group, series), with CI whiskers and the value printed.
    series: [(name, [estimate per group])]. An estimate may carry `text`,
    printed instead of the bare percentage (vertical bars print it upright),
    and `faint`, which fades and hatches its bar."""
    n = len(series)
    width = 0.8 / n
    for j, (name, ests) in enumerate(series):
        pos = [i - 0.4 + width * (j + 0.5) for i in range(len(groups))]
        vals = [_pct(e) or 0.0 for e in ests]
        lows, highs = [_err(e)[0] for e in ests], [_err(e)[1] for e in ests]
        bar = ax.barh if horizontal else ax.bar
        kw = {"height" if horizontal else "width": width * 0.92}
        color = SERIES[j % len(SERIES)]
        drawn = bar(pos, vals, color=color, label=name, **kw)
        for patch, e in zip(drawn, ests):
            if e and e.get("faint"):
                patch.set_facecolor(to_rgba(color, 0.22))
                patch.set_edgecolor(color)
                patch.set_hatch("////")
                patch.set_linewidth(0.6)
        has_ci = [i for i, e in enumerate(ests) if e and e.get("ci")]
        if has_ci:
            pick = lambda xs: [xs[i] for i in has_ci]  # noqa: E731
            xy = (pick(vals), pick(pos)) if horizontal else (pick(pos), pick(vals))
            ax.errorbar(*xy, **{("xerr" if horizontal else "yerr"): [pick(lows), pick(highs)]},
                        fmt="none", ecolor=WHISKER, elinewidth=0.9, capsize=2)
        for p, v, e, hi in zip(pos, vals, ests, highs):
            if _pct(e) is None:
                continue
            text = e.get("text") or f"{v:.0f}%"
            if horizontal:
                ax.text(min(v + hi + 1.5, 101), p, text, va="center", fontsize=6.5, color=INK_2)
            elif e.get("text"):
                ax.text(p, v + hi + 1.5, text, ha="center", va="bottom", rotation=90, fontsize=6,
                        color=MUTED if e.get("faint") else INK_2)
            else:
                ax.text(p, min(v + hi + 1.5, 101), text, ha="center", fontsize=6.5, color=INK_2)
    ticks = list(range(len(groups)))
    if horizontal:
        ax.set_yticks(ticks, groups)
        ax.invert_yaxis()
        ax.set_xlim(0, 108)
        ax.grid(axis="y", visible=False)
    else:
        ax.set_xticks(ticks, groups)
        ax.set_ylim(0, 108)
        ax.grid(axis="x", visible=False)
    if n > 1:
        ax.legend(loc="upper left", bbox_to_anchor=(1.0, 1.0))


def siem_coverage(arms: list[dict], path, footers):
    """F1: technique recall, alert-level precision and request-level FPR per arm."""
    point = lambda v: {"value": v} if v is not None else None  # noqa: E731
    groups = [a["condition"] for a in arms]
    fig, ax = plt.subplots(figsize=(7, 0.55 * len(groups) * 3 / 2 + 1.2))
    _grouped_bars(ax, groups, [
        ("Technique recall", [point(a["technique_recall"]) for a in arms]),
        ("Precision (alert-level)", [point(a["precision_alert_level"]) for a in arms]),
        ("Benign FPR (request-level)", [point(a["fpr_request_level"]) for a in arms]),
    ])
    ax.set_xlabel("% (pooled over the corpus sessions)")
    ax.set_title("F1 · What each logging level lets Wazuh see (D1)", loc="left")
    return _save(fig, path, footers)


MARKERS = ["o", "s", "^", "D", "v", "P", "X", "h"]


def coverage_selective(points: list[dict], path, footers):
    """F2: coverage (x) against selective accuracy (y). Marker shape is the
    condition, colour the label level (fine, coarse): points that sit close
    together stay readable, with no labels to collide."""
    from matplotlib.lines import Line2D
    fig, ax = plt.subplots(figsize=(6.4, 4.6))
    conditions = list(dict.fromkeys(p["label"] for p in points))
    levels = ("fine", "coarse")
    for p in points:
        x, y = _pct(p["coverage"]), _pct(p["selective"])
        if x is None or y is None:
            continue
        color = SERIES[levels.index(p["level"])]
        xe, ye = _err(p["coverage"]), _err(p["selective"])
        ax.errorbar([x], [y], xerr=[[xe[0]], [xe[1]]], yerr=[[ye[0]], [ye[1]]],
                    fmt=MARKERS[conditions.index(p["label"]) % len(MARKERS)], color=color, ecolor=color,
                    elinewidth=0.8, capsize=2, markersize=7, markeredgecolor=SURFACE, markeredgewidth=1.2,
                    alpha=0.95)
    ax.set_xlim(0, 105)
    ax.set_ylim(0, 105)
    ax.set_xlabel("Coverage: committed / scored attack alerts (%)")
    ax.set_ylabel("Selective accuracy: correct / committed (%)")
    ax.set_title("F2 · Coverage vs selective accuracy (technique label)", loc="left")
    shapes = [Line2D([], [], marker=MARKERS[i % len(MARKERS)], linestyle="", color=INK_2, label=c)
              for i, c in enumerate(conditions)]
    colours = [Line2D([], [], marker="o", linestyle="", color=SERIES[i], label=lv) for i, lv in enumerate(levels)]
    # one legend (shape = condition, colour = level): tight bbox ignores a second one
    gap = Line2D([], [], linestyle="", label=" ")
    ax.legend(handles=shapes + [gap] + colours, title="shape: condition\ncolour: label level",
              loc="upper left", bbox_to_anchor=(1.0, 1.0), title_fontsize=7.5, alignment="left")
    return _save(fig, path, footers)


def calibration(bars: list[dict], path, footers, min_committed: int = 20):
    """F3: selective accuracy of the fine label per reported confidence level,
    one series per condition. Each bar is labelled with its counts (correct /
    committed). A bar over fewer than `min_committed` answers is faded and
    hatched: 2 of 2 right is not evidence of calibration."""
    levels = ("high", "medium", "low")
    series = []
    for b in bars:
        by = {r["confidence"]: r for r in b["levels"]}
        ests = []
        for lv in levels:
            r = by.get(lv)
            if not r or r["selective_accuracy"] is None:
                ests.append(None)
                continue
            ests.append({"value": r["selective_accuracy"], "faint": r["committed"] < min_committed,
                         "text": f"{r['selective_accuracy'] * 100:.0f}% · {r['correct']}/{r['committed']}"})
        series.append((b["label"], ests))
    fig, ax = plt.subplots(figsize=(7.4, 4.4))
    _grouped_bars(ax, [f"{lv}" for lv in levels], series, horizontal=False)
    ax.set_ylim(0, 150)                         # room for the upright count labels
    ax.set_yticks(range(0, 101, 20))
    ax.spines["left"].set_bounds(0, 100)
    ax.set_xlabel("Confidence the model reported")
    ax.set_ylabel("Selective accuracy, fine label (%)")
    ax.set_title("F3 · Calibration: how often each confidence level was right", loc="left", pad=18)
    ax.text(0, 1.015, f"Labels: % right · correct/committed. Faded, hatched bars: fewer than {min_committed} "
            "committed answers, too few to judge.", transform=ax.transAxes, fontsize=7, color=INK_2)
    return _save(fig, path, footers)


def disposition(bars: list[dict], path, footers):
    """F4: escalation recall (attack alerts) and FP dismissal (benign alerts)."""
    groups = [b["label"] for b in bars]
    fig, ax = plt.subplots(figsize=(7, 0.55 * len(groups) + 1.4))
    _grouped_bars(ax, groups, [("Escalation recall (attack)", [b["escalation_recall"] for b in bars]),
                               ("FP dismissal (benign)", [b["fp_dismissal"] for b in bars])])
    ax.set_xlabel("% of scored alerts")
    ax.set_title("F4 · Disposition: escalate attacks, dismiss false positives", loc="left")
    return _save(fig, path, footers)


def cost_quality(points: list[dict], path, footers):
    """F5: a dot plot, one row per condition ordered by list-price cost (in
    the row label), strict fine accuracy with its interval on the axis.
    Baselines cost nothing, so a scatter would stack them on x = 0."""
    kinds = {"baseline": ("lookup baseline", SERIES[1]), "triage": ("LLM", SERIES[0])}
    rows = sorted((p for p in points if p["cost"] is not None and _pct(p["strict"]) is not None),
                  key=lambda p: (p["cost"], p["label"]))
    fig, ax = plt.subplots(figsize=(7, 0.42 * len(rows) + 1.3))
    seen = set()
    for i, p in enumerate(rows):
        name, color = kinds.get(p["kind"], kinds["triage"])
        x, (lo, hi) = _pct(p["strict"]), _err(p["strict"])
        ax.errorbar([x], [i], xerr=[[lo], [hi]], fmt="o", color=color, ecolor=color, elinewidth=1.2,
                    capsize=2, markersize=7, markeredgecolor=SURFACE, markeredgewidth=1.2,
                    label=None if name in seen else name)
        seen.add(name)
        ax.text(min(x + hi + 1.5, 101), i, f"{x:.0f}%", va="center", fontsize=6.5, color=INK_2)
    ax.set_yticks(range(len(rows)),
                  [f"{p['label']}  ·  ${p['cost'] * 1000:.2f}/1k" for p in rows])
    ax.invert_yaxis()
    ax.set_xlim(0, 108)
    ax.grid(axis="y", visible=False)
    ax.set_xlabel("Strict accuracy, fine label (%); rows ordered by list-price cost per 1,000 alerts")
    ax.set_title("F5 · Cost vs quality", loc="left")
    ax.legend(loc="upper left", bbox_to_anchor=(1.0, 1.0))
    return _save(fig, path, footers)


FORMAT_METRICS = (("fine_coverage", "Coverage"), ("fine_selective_accuracy", "Selective acc."),
                  ("fine_strict_accuracy", "Strict acc."), ("coarse_selective_accuracy", "Coarse selective"),
                  ("escalation_recall", "Escalation recall"), ("fp_dismissal_rate", "FP dismissal"),
                  ("high_confidence_wrong", "High-conf. wrong"))


def _as_est(row: dict | None):
    if not row or row.get("value") is None:
        return None
    ci = [row["ci_low"], row["ci_high"]] if row.get("ci_low") is not None else None
    return {"value": row["value"], "ci": ci}


def format_rates(bars: list[dict], path, footers):
    """F6: every primary rate, format A vs format B."""
    groups = [name for _, name in FORMAT_METRICS]
    fig, ax = plt.subplots(figsize=(7, 4.2))
    _grouped_bars(ax, groups, [(b["label"], [_as_est(b["rates"].get(m)) for m, _ in FORMAT_METRICS])
                               for b in bars])
    ax.set_xlabel("%")
    ax.set_title("F6 · Full (A) vs minimal (B) output schema", loc="left")
    return _save(fig, path, footers)


def injection(bars: list[dict], path, footers):
    """F7: disposition and label flip rates, injected vs clean alerts."""
    groups, injected, clean = [], [], []
    for b in bars:
        for metric, name in (("disposition_flip", "not escalated"), ("label_flip", "labelled none")):
            groups.append(f"{b['label']}: {name}")
            injected.append(b["injection"]["injected"][metric])
            clean.append(b["injection"]["clean"][metric])
    fig, ax = plt.subplots(figsize=(7, 0.55 * len(groups) + 1.4))
    _grouped_bars(ax, groups, [("Injected (analyst-directed text)", injected),
                               ("Clean (same techniques)", clean)])
    ax.set_xlabel("% of scored alerts (descriptive: 12 injected requests)")
    ax.set_title("F7 · Does attacker text flip the verdict? (X4)", loc="left")
    return _save(fig, path, footers)


RUBRIC_NAMES = {"R1": "R1 Action", "R2": "R2 Actionability", "R3": "R3 Added value", "R4": "R4 Confidence fit"}
CELL_LABELS = {"S1xL0-FA": "S1×L0 FA", "S1xL1-FA": "S1×L1 FA", "S1xL1-FB": "S1×L1 FB"}
STRATUM_LABELS = {"attack-correct": "attack: correct", "attack-wrong": "attack: wrong",
                  "attack-abstained": "attack: abstained", "benign": "benign"}
R5_SERIES = (("rater R5 = expected", "Rater's own decision = expected"),
             ("LLM disposition = expected", "LLM's disposition = expected"),
             ("rater R5 = LLM disposition", "Rater's own decision = LLM's"))


def rating(means: list[dict], r5: list[dict], path, footers, single_rater: bool):
    """F8: expert rating of the X5 batch. Top: mean R1–R4 (1–5) with 95%
    item-level intervals, per cell and per stratum, one panel per rubric
    item. Bottom: the rater's own decision (R5) against ground truth and the
    LLM, next to the LLM's own match on the same items. The R5 bars show
    rater A; the F8 tables have every rater."""
    rows = [("cell", CELL_LABELS), ("stratum", STRATUM_LABELS)]
    fig = plt.figure(figsize=(9, 9.6))
    grid = fig.add_gridspec(3, 4, height_ratios=[3, 4, 8], hspace=0.5, wspace=0.12)
    for r, (grouping, names) in enumerate(rows):
        for c, item_id in enumerate(RUBRIC_NAMES):
            ax = fig.add_subplot(grid[r, c])
            got = {m["group"]: m for m in means if m["grouping"] == grouping and m["rubric_item"] == item_id}
            groups = [g for g in names if g in got]
            ys = list(range(len(groups)))
            vals = [got[g]["value"] for g in groups]
            lo = [v - (got[g]["ci_low"] if got[g]["ci_low"] is not None else v) for g, v in zip(groups, vals)]
            hi = [(got[g]["ci_high"] if got[g]["ci_high"] is not None else v) - v for g, v in zip(groups, vals)]
            ax.errorbar(vals, ys, xerr=[lo, hi], fmt="none", ecolor=WHISKER, elinewidth=0.9, capsize=2)
            ax.scatter(vals, ys, s=34, color=SERIES[0], zorder=3, edgecolors=SURFACE, linewidths=1.2)
            for y, v, h in zip(ys, vals, hi):
                ax.text(v + max(h, 0.1) + 0.12, y, f"{v:.1f}", va="center", fontsize=6.5, color=INK_2)
            ax.set_yticks(ys, [names[g] for g in groups] if c == 0 else [""] * len(groups))
            ax.set_ylim(len(groups) - 0.5, -0.5)
            ax.set_xlim(0.8, 5.9)
            ax.set_xticks([1, 2, 3, 4, 5])
            ax.grid(axis="y", visible=False)
            n = got[groups[0]]["n"] if groups else 0
            ax.set_title(f"{RUBRIC_NAMES[item_id]}" if r == 0 else "", loc="left", fontsize=8.5)
            if c == 0:
                ax.set_ylabel(f"by {grouping} (n={n} each)", fontsize=7.5)
            if r == 1:
                ax.set_xlabel("mean score (1–5)")
    ax = fig.add_subplot(grid[2, :])
    groups = ["all"] + list(CELL_LABELS) + list(STRATUM_LABELS)
    label_of = {"all": "all 48 items", **CELL_LABELS, **STRATUM_LABELS}
    series = []
    for comparison, name in R5_SERIES:
        got = {m["group"]: m for m in r5 if m["comparison"] == comparison and m["rater"] in ("A", "LLM")}
        ests = []
        for g in groups:
            m = got.get(g)
            ests.append(None if not m or m["value"] is None else
                        {"value": m["value"], "ci": [m["ci_low"], m["ci_high"]] if m["ci_low"] is not None else None,
                         "text": f"{m['num']}/{m['n']}"})
        series.append((name, ests))
    _grouped_bars(ax, [label_of[g] for g in groups], series)
    ax.set_xlabel("% of items (R5: escalate / dismiss / more info)")
    who = "rater A only: single-rater review, no agreement statistic" if single_rater else "raters A and B"
    fig.suptitle(f"F8 · Expert rating of the X5 batch ({who})", x=0.0, ha="left", fontsize=10, color=INK)
    return _save(fig, path, footers)
