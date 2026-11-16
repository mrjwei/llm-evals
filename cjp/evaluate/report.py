"""
WP4 report: render the metrics (cjp.evaluate.metrics) as report.md with
charts, next to the mapper output they were computed from; run it as
`cjp metrics`. Moved from wp4_metrics.py in Plan P2.1 and rewritten around
the Plan P2.7 metrics: SIEM detection first, then the triage answer
(technique, disposition, calibration, cost). Evidence grounding is no longer
reported (M10), and there is no category filter: every label is shown.

Beside report.md it writes metrics.json (every number in the report) and
scores.jsonl (one scored row per triaged alert and repeat, from
cjp.evaluate.score), so figures and rating samples can be rebuilt without
re-scoring.
"""

import json
import os

from cjp.evaluate.charts import generate_charts
from cjp.evaluate.metrics import compute_metrics
from cjp.evaluate.score import score_rows
from cjp.evaluate.mapper import load_jsonl
from cjp.runs import resolve_run_dir, write_meta


def _md_table(headers: list[str], rows: list[list[str]]) -> list[str]:
    lines = ["| " + " | ".join(headers) + " |",
             "| " + " | ".join("---" for _ in headers) + " |"]
    lines += ["| " + " | ".join(row) + " |" for row in rows]
    return lines


def _pct(value: float | None) -> str:
    return f"{value:.1%}" if value is not None else "n/a"




def _rate(est: dict | None) -> str:
    """"61.2% (30/49) [95% CI 48.0–73.5%] · repeats 58.3–64.0%"."""
    if not est or est["value"] is None:
        return "n/a"
    text = f"{est['value']:.1%} ({est['num']}/{est['den']})"
    if est["ci"]:
        text += f" [CI {est['ci'][0]:.1%}–{est['ci'][1]:.1%}]"
    if est["spread"]:
        text += f" · repeats {est['spread'][0]:.1%}–{est['spread'][1]:.1%}"
    return text


def _usd(value: float | None) -> str:
    return f"${value:.4f}" if value is not None else "n/a"


def _embed(chart_paths: dict, name: str, alt: str) -> list[str]:
    return [f"![{alt}]({chart_paths[name]})", ""] if chart_paths.get(name) else []


def _siem_sections(metrics: dict, chart_paths: dict) -> list[str]:
    d = metrics["detection"]
    lines = ["## Detection (SIEM, D1)"]
    lines += _md_table(
        ["Metric", "Value"],
        [
            ["Technique-level recall",
             f"{d['techniques_detected']}/{d['techniques_total']}"
             + (f" ({d['technique_recall']:.1%})" if d["technique_recall"] is not None else "")],
            ["Request-level alert rate",
             (f"{d['alerts_total']} / {d['access_log_lines']}"
              + (f" ({d['request_level_alert_rate']:.1%})" if d["request_level_alert_rate"] is not None else ""))
             if d["access_log_lines"] is not None
             else f"{d['alerts_total']} alerts (access-log line count unavailable)"],
        ],
    )
    lines.append("")
    if d["missed_techniques"]:
        lines += ["**Missed techniques:** " + ", ".join(d["missed_techniques"]), ""]
    if d["alert_volume_per_technique"]:
        lines += ["**Alert volume per technique:**", ""]
        lines += _embed(chart_paths, "alert_volume", "Alert volume per technique")
        lines += _md_table(["Label", "Alerts"],
                           [[label, str(count)] for label, count in d["alert_volume_per_technique"]])
        lines.append("")

    p = metrics["precision_fpr"]
    lines.append("## Precision and false positives (SIEM)")
    lines += _md_table(
        ["Metric", "Value"],
        [
            ["Precision (alert-level)",
             _pct(p["precision_alert_level"]) if p["precision_alert_level"] is not None
             else "n/a (no attributed or benign-matched alerts)"],
            ["True positive / false positive / unclassified alerts",
             f"{p['true_positive_alerts']} / {p['false_positive_alerts']} / {p['unclassified_alerts']}"
             " (unclassified and aggregate alerts are left out of precision)"],
            ["False positive rate (request-level, benign traffic only)",
             _pct(p["false_positive_rate_request_level"]) if p["total_benign_requests"] is not None
             else "n/a: no benign_log.jsonl in this session"],
        ],
    )
    lines.append("")

    s = metrics["signature"]
    lines.append("## Signature cross-check")
    lines += _md_table(
        ["Metric", "Value"],
        [
            ["Group-aware agreement with the CID/interval mapper",
             _pct(s["signature_group_aware_agreement_rate"])],
            ["Raw-label Cohen's κ",
             f"{s['signature_raw_label_cohens_kappa']:.3f}"
             if s["signature_raw_label_cohens_kappa"] is not None else "n/a"],
        ],
    )
    lines += ["", f"_{s['_note']}_", ""]
    return lines


def _technique_rows(level: dict) -> list[list[str]]:
    c = level["counts"]
    return [
        ["Scored attack alerts", str(level["scored"])],
        ["Correct / wrong / abstained / no answer",
         f"{c['correct']} / {c['wrong']} / {c['abstained']} / {c['no_answer']}"],
        ["Coverage (committed / scored)", _rate(level["coverage"])],
        ["Selective accuracy (correct / committed)", _rate(level["selective_accuracy"])],
        ["Strict accuracy (correct / scored)", _rate(level["strict_accuracy"])],
    ]


def _triage_sections(t: dict, chart_paths: dict) -> list[str]:
    boot = t["bootstrap"]
    lines = [
        "## Triage: technique label",
        "",
        f"{t['rows']} triaged alert rows over repeat(s) {', '.join(map(str, t['repeats']))}"
        f" (scoring: {', '.join(f'{n} {k}' for k, n in t['schemes'].items())}); "
        f"{t['unscored_alerts']} aggregate or unattributed rows have no ground truth. "
        f"Intervals are {boot['level']:.0%} percentile bootstraps over distinct requests "
        f"({boot['resamples']} resamples, seed {boot['seed']}). "
        "An abstention (`uncertain`, or the legacy \"Ambiguous …\" hedge) is never correct.",
        "",
    ]
    if t.get("api_errors"):
        lines += [f"**{t['api_errors']} alert row(s) have no answer because the API call failed;** "
                  "they are left out of every rate below. Resume the triage run "
                  "(`cjp triage --resume …`) and re-map to fill them in.", ""]
    lines += _embed(chart_paths, "headline_summary", "Headline metrics")
    lines += _md_table(["Fine (exact label)", "Value"], _technique_rows(t["fine"]))
    lines.append("")
    lines += _md_table(["Coarse (login labels merged)", "Value"], _technique_rows(t["coarse"]))
    lines.append("")
    if t["benign_labelled_none"]:
        lines += [f"Benign alerts labelled `none`: {_rate(t['benign_labelled_none'])}", ""]

    if t["by_label"]:
        lines += ["**Per ground-truth label (attack alerts):**", ""]
        lines += _embed(chart_paths, "outcomes_by_label", "Outcomes by label")
        lines += _md_table(
            ["OWASP 2025", "Label", "n", "Correct", "Wrong", "Abstained", "No answer",
             "Strict acc.", "Coarse correct"],
            [[r["owasp_2025"], r["label"], str(r["n"]), str(r["correct"]), str(r["wrong"]),
              str(r["abstained"]), str(r["no_answer"]), _pct(r["strict_accuracy"]),
              str(r["coarse_correct"])] for r in t["by_label"]],
        )
        lines.append("")

    d = t["disposition"]
    lines.append("## Triage: disposition")
    if d["attack_alerts"] or d["benign_alerts"]:
        lines += _md_table(
            ["Metric", "Value"],
            [
                ["Escalation recall (attack alerts escalated)", _rate(d["escalation_recall"])],
                ["False-positive dismissal (benign alerts dismissed)", _rate(d["fp_dismissal_rate"])],
                ["Benign alerts escalated", _rate(d["benign_escalated"])],
                ["needs_more_info, attack alerts", _rate(d["needs_more_info_attack"])],
                ["needs_more_info, benign alerts", _rate(d["needs_more_info_benign"])],
            ],
        )
    else:
        lines.append("n/a: no row has a disposition (the legacy prompt did not ask for one).")
    lines.append("")

    sev = t.get("severity")
    if sev:
        c = sev["counts"]
        lines += ["## Triage: severity (secondary)", "",
                  "Format A attack alerts; the acceptable band per label is in "
                  "`rubric/expected_decisions.yaml`.", ""]
        lines += _md_table(
            ["Metric", "Value"],
            [
                ["Scored attack alerts", str(sev["scored"])],
                ["In band / outside / no answer", f"{c['correct']} / {c['wrong']} / {c['no_answer']}"],
                ["Severity agreement (in band / scored)", _rate(sev["agreement"])],
                ["Under-rated (below the band)", _rate(sev["under_rated"])],
                ["Over-rated (above the band)", _rate(sev["over_rated"])],
            ],
        )
        lines.append("")

    c = t["calibration"]
    hw = c["high_confidence_wrong"]
    lines += ["## Calibration", "",
              f"**High-confidence answers that are wrong:** "
              + (f"{hw['rate']:.1%} ({hw['wrong']}/{hw['committed']})" if hw["rate"] is not None else "n/a"),
              ""]
    lines += _embed(chart_paths, "calibration", "Calibration")
    for key, title in (("fine", "Technique label (fine), attack alerts"),
                       ("disposition", "Disposition, all alerts")):
        if not any(row["n"] for row in c[key]):
            continue
        lines += [f"**{title}:**", ""]
        lines += _md_table(
            ["Confidence", "n", "Correct", "Wrong", "Abstained", "Selective acc.", "Wrong share"],
            [[r["confidence"], str(r["n"]), str(r["correct"]), str(r["wrong"]), str(r["abstained"]),
              _pct(r["selective_accuracy"]), _pct(r["wrong_share"])] for r in c[key]],
        )
        lines.append("")

    k = t["cost"]
    unpriced = ", ".join(f"{m} ({n})" for m, n in k["unpriced"].items())
    lines.append("## Cost")
    lines += _md_table(
        ["Metric", "Value"],
        [
            ["Input / output tokens per alert",
             f"{k['input_tokens_per_alert']:.0f} / {k['output_tokens_per_alert']:.0f}"
             if k["alerts"] else "n/a"],
            ["Cost per alert (list price)", _usd(k["cost_per_alert_usd"])],
            ["Cost per correct fine answer", _usd(k["cost_per_correct_usd"])],
            ["Cost per correct disposition", _usd(k["cost_per_correct_disposition_usd"])],
            ["Total", _usd(k["cost_total_usd"])],
            ["Model(s)", ", ".join(k["models"]) or "not recorded"],
        ],
    )
    lines += ["", f"_Prices: {k['price_source']}, retrieved {k['price_retrieved']}._"
              + (f" _Unpriced rows: {unpriced}._" if unpriced else ""), ""]

    sc = t["schema"]
    lines += [f"Parsed answers: {_pct(sc['parse_ok_rate'])}; schema-valid: {_pct(sc['schema_ok_rate'])}.", ""]
    return lines


def render_report(session_tag: str, metrics: dict, chart_paths: dict[str, str | None] | None = None) -> str:
    """chart_paths maps chart name (see charts.generate_charts) to a path
    relative to the report file, or None/missing if that chart wasn't
    generated; tables carry the same numbers either way."""
    chart_paths = chart_paths or {}
    lines = [f"# WP4 metrics — {session_tag}",
             f"_Pipeline git_sha: {metrics['git_sha'] or 'unknown'}_", ""]
    lines += _siem_sections(metrics, chart_paths)
    if metrics["triage"]:
        lines += _triage_sections(metrics["triage"], chart_paths)
    else:
        lines += ["## Triage", "", "n/a: no triage rows were joined (run `cjp map --wp3 …`).", ""]
    return "\n".join(lines).rstrip()


def write_report(inputs: list[str], session: str, report: str | None = None,
                 boot: dict | None = None) -> str:
    """Compute the metrics for one or more mapper outputs (one per repeat),
    write report.md, metrics.json, scores.jsonl, charts/ and
    report_meta.json, print the report, and return the report path.

    Default location: next to the first input. If a report.md is already
    there (e.g. a legacy report in data/legacy/), a new metrics/report_v<N>/
    is used instead, so no report is ever overwritten."""
    if isinstance(inputs, str):
        inputs = [inputs]
    metrics = compute_metrics(inputs, session, boot)

    session_tag = os.path.basename(os.path.normpath(session))
    input_dir = os.path.dirname(inputs[0]) or "."
    report_path = report or os.path.join(input_dir, "report.md")
    if not report and os.path.exists(report_path):
        report_path = os.path.join(resolve_run_dir(input_dir, "metrics", "report"), "report.md")
    report_dir = os.path.dirname(report_path) or "."
    os.makedirs(report_dir, exist_ok=True)
    chart_abs_paths = generate_charts(metrics, os.path.join(report_dir, "charts"))
    chart_rel_paths = {name: os.path.relpath(path, report_dir) if path else None
                       for name, path in chart_abs_paths.items()}

    text = render_report(session_tag, metrics, chart_rel_paths)
    with open(report_path, "w") as f:
        f.write(text + "\n")
    with open(os.path.join(report_dir, "metrics.json"), "w") as f:
        json.dump(metrics, f, indent=2, default=str)
        f.write("\n")
    with open(os.path.join(report_dir, "scores.jsonl"), "w") as f:
        for i, path in enumerate(inputs, start=1):
            for row in score_rows(load_jsonl(path), session, repeat=i):
                f.write(json.dumps(row) + "\n")

    meta_path = write_meta(report_path, {
        "script": "cjp metrics",
        "cli_args": {"input": inputs, "session": session, "report": report},
        "git_sha": metrics["git_sha"],
        "charts": chart_rel_paths,
    })

    print(text)
    print(f"\nWrote report to {report_path} (+ metrics.json, scores.jsonl)")
    print(f"Wrote run metadata to {meta_path}")
    return report_path
