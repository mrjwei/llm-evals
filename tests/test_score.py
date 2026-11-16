"""Triage scoring and metrics (Plan P2.7): three-way outcomes, coarse groups,
disposition, request clusters and the clustered bootstrap, calibration, cost,
repeats, and the audit's re-computation on legacy evidence."""

import json

import pytest
from conftest import LEGACY, read_jsonl

from cjp.config import settings
from cjp.evaluate import calibration, mapper, metrics, report, score
from cjp.triage.schema import load_taxonomy

LEGACY_HEDGE = "Ambiguous /rest/user/login attempt (SQLi/brute-force/weak-creds/enum)"


def v2_row(answer="sql_injection", disposition="escalate", *, matched="sql_injection",
           is_attack=True, confidence="high", schema_ok=True, parse_ok=True, cid="c1",
           model="claude-sonnet-5-5", repeat=1, tokens=(1000, 100), severity="high", fmt="A"):
    """A mapped row as `cjp map --wp3` writes it for a prompt-v2 answer."""
    return {"wazuh_alert_id": f"a-{cid}-{repeat}", "is_attack": is_attack, "matched_label": matched,
            "matched_cid": cid, "llm_technique_label": answer, "llm_disposition": disposition,
            "llm_confidence": confidence, "llm_format": fmt, "llm_schema_ok": schema_ok,
            "llm_severity": severity if fmt == "A" else None,
            "llm_parse_ok": parse_ok, "llm_model": model, "llm_repeat": repeat,
            "llm_token_usage": {"input_tokens": tokens[0], "output_tokens": tokens[1]}}


def legacy_row(event_type, matched="brute_force", confidence="low", parse_ok=True):
    return {"wazuh_alert_id": "x", "is_attack": True, "matched_label": matched, "matched_cid": None,
            "llm_event_type": event_type, "llm_confidence": confidence, "llm_parse_ok": parse_ok,
            "llm_prompt_version": "1cce404d",
            "llm_token_usage": {"input_tokens": 1500, "output_tokens": 300}}


# ── Per-row outcomes ─────────────────────────────────────────────────────────

def test_the_real_legacy_hedge_is_abstained_not_correct():
    # the v1 hedge contains "sqli" and "brute-force", which the legacy
    # substring scorer credited as correct (audit A4.1)
    for truth in ("sql_injection", "brute_force", "weak_credentials", "account_enumeration"):
        s = score.score_row(legacy_row(LEGACY_HEDGE, matched=truth))
        assert (s["scheme"], s["fine"], s["coarse"]) == ("legacy", "abstained", "abstained")
        assert s["disposition_outcome"] is None                    # v1 never asked


@pytest.mark.parametrize("event_type,matched,fine,coarse", [
    ("Login brute-force / weak credentials", "brute_force", "correct", "correct"),
    ("Weak credentials login attempt", "brute_force", "wrong", "correct"),     # same coarse group
    ("Reflected XSS attempt", "sql_injection", "wrong", "wrong"),
    ("SQL injection via UNION", "sql_injection_union", "correct", "correct"),
])
def test_legacy_answers_use_the_legacy_synonym_table(event_type, matched, fine, coarse):
    s = score.score_row(legacy_row(event_type, matched=matched))
    assert (s["fine"], s["coarse"]) == (fine, coarse)


def test_legacy_parse_failure_and_benign_rows():
    assert score.score_row(legacy_row(None, parse_ok=False))["fine"] == "no_answer"
    benign = {**legacy_row("Verbose error"), "is_attack": False, "matched_label": "browse_catalogue"}
    assert score.score_row(benign)["fine"] is None                 # v1 could not say "legitimate"


@pytest.mark.parametrize("answer,matched,fine,coarse", [
    ("sql_injection", "sql_injection", "correct", "correct"),
    ("sql_injection", "sql_injection_union", "correct", "correct"),   # ground_truth map
    ("user_impersonation", "forged_feedback", "correct", "correct"),
    ("brute_force", "weak_credentials", "wrong", "correct"),          # login_campaign (M5)
    ("xss", "brute_force", "wrong", "wrong"),
    ("uncertain", "brute_force", "abstained", "abstained"),           # never credited
    ("other", "idor", "wrong", "wrong"),
    ("none", "idor", "wrong", "wrong"),
])
def test_v2_label_outcomes(answer, matched, fine, coarse):
    s = score.score_row(v2_row(answer, matched=matched))
    assert (s["scheme"], s["fine"], s["coarse"]) == ("v2", fine, coarse)


def test_invalid_answers_score_as_no_answer():
    for row in (v2_row(schema_ok=False), v2_row(parse_ok=False, answer=None, disposition=None)):
        s = score.score_row(row)
        assert (s["fine"], s["coarse"], s["disposition_outcome"]) == ("no_answer",) * 3
        assert s["confidence"] is None


@pytest.mark.parametrize("is_attack,disposition,outcome", [
    (True, "escalate", "correct"), (True, "dismiss_false_positive", "wrong"),
    (True, "needs_more_info", "abstained"),
    (False, "dismiss_false_positive", "correct"), (False, "escalate", "wrong"),
    (False, "needs_more_info", "abstained"),
])
def test_disposition_outcomes(is_attack, disposition, outcome):
    row = v2_row("none", disposition, is_attack=is_attack,
                 matched="sql_injection" if is_attack else "browse_catalogue")
    assert score.score_row(row)["disposition_outcome"] == outcome


def test_injection_probe_labels_score_as_their_base_technique():
    """C1-inj's `_inj` labels (Plan P3.4) are the same attacks with text
    appended, so X4 scores them like the clean ones and keeps the raw label."""
    s = score.score_row(v2_row(matched="sql_injection_union_inj"))
    assert (s["truth_label"], s["truth_raw"], s["fine"]) == ("sql_injection", "sql_injection_union_inj", "correct")
    s = score.score_row(v2_row("none", "dismiss_false_positive", matched="forged_feedback_inj"))
    assert (s["truth_label"], s["fine"], s["disposition_outcome"]) == ("user_impersonation", "wrong", "wrong")


def test_expected_decisions_cover_every_label_and_match_decision_006():
    spec = score.expected_decisions()
    assert set(spec["labels"]) == set(load_taxonomy()["labels"])
    assert {e["expected_disposition"] for e in spec["labels"].values()} == {"escalate"}
    assert spec["benign"]["expected_disposition"] == "dismiss_false_positive"
    for entry in spec["labels"].values():
        idx = sorted(spec["severity_levels"].index(b) for b in entry["acceptable_severity"])
        assert idx == list(range(idx[0], idx[-1] + 1))          # a band, no holes


@pytest.mark.parametrize("matched,severity,fmt,is_attack,outcome,gap", [
    ("sql_injection", "high", "A", True, "correct", 0),
    ("sql_injection", "medium", "A", True, "wrong", -1),        # under-rated
    ("error_probing", "critical", "A", True, "wrong", 2),       # forced_browsing, over-rated
    ("sql_injection_inj", "critical", "A", True, "correct", 0),
    ("sql_injection", None, "B", True, None, None),             # Format B has no severity
    ("benign", "low", "A", False, None, None),                  # benign: no expected severity
])
def test_severity_outcomes(matched, severity, fmt, is_attack, outcome, gap):
    s = score.score_row(v2_row(matched=matched, severity=severity, fmt=fmt, is_attack=is_attack))
    assert (s["severity_outcome"], s["severity_gap"]) == (outcome, gap)


def test_severity_of_an_invalid_answer_is_no_answer():
    s = score.score_row(v2_row(schema_ok=False))
    assert (s["severity"], s["severity_outcome"]) == (None, "no_answer")


def test_severity_metrics():
    rows = [score.score_row(v2_row(cid=c, severity=sev)) for c, sev in
            (("c1", "high"), ("c2", "critical"), ("c3", "low"), ("c4", "medium"))]
    m = metrics.severity_metrics(rows, {"resamples": 100, "seed": 0, "level": 0.95})
    assert m["counts"] == {"correct": 2, "wrong": 2, "abstained": 0, "no_answer": 0}
    assert (m["agreement"]["value"], m["under_rated"]["value"], m["over_rated"]["value"]) == (0.5, 0.5, 0.0)
    assert metrics.severity_metrics([score.score_row(v2_row(fmt="B"))], {}) is None


def test_benign_truth_is_none_and_unattributed_rows_are_not_scored():
    s = score.score_row(v2_row("none", "dismiss_false_positive", is_attack=False, matched="search"))
    assert (s["truth_label"], s["fine"]) == ("none", "correct")
    s = score.score_row(v2_row(is_attack=None, matched=None))
    assert (s["truth_label"], s["fine"], s["disposition_outcome"]) == (None, None, None)
    assert score.score_row({"wazuh_alert_id": "never triaged"}) is None


# ── Clusters and the bootstrap ───────────────────────────────────────────────

def test_request_clusters_follow_the_request_not_the_alert(session_dir, tmp_path):
    index = score.request_index(str(session_dir))
    assert index["wp1-20990101_000000-1-1"] != index["wp1-20990101_000000-1-2"]   # other URL
    # the same request sent in another session gets the same key
    other = tmp_path / "session_20990102_000000"
    other.mkdir()
    for name in ("attack_log.jsonl", "ingest_log.jsonl"):
        text = (session_dir / name).read_text().replace("20990101_000000", "20990102_000000")
        (other / name).write_text(text)
    assert score.request_index(str(other))["wp1-20990102_000000-3-1"] == \
        index["wp1-20990101_000000-3-1"]
    # the body is part of the request
    (other / "ingest_log.jsonl").write_text((other / "ingest_log.jsonl").read_text()
                                            .replace("union select 1", "admin"))
    assert score.request_index(str(other))["wp1-20990102_000000-3-1"] != \
        index["wp1-20990101_000000-3-1"]
    assert score.cluster_of({"matched_cid": None, "wazuh_alert_id": "9"}, index) == "alert:9"


def test_bootstrap_resamples_clusters_not_alerts():
    boot = {"resamples": 500, "seed": 0, "level": 0.95}
    ci = metrics.cluster_bootstrap_ci([(1, 1), (0, 1)] * 5, **boot)
    assert ci == metrics.cluster_bootstrap_ci([(1, 1), (0, 1)] * 5, **boot)   # seeded
    assert ci[0] < 0.5 < ci[1]
    # ten copies of every alert inside the same cluster add no information
    assert metrics.cluster_bootstrap_ci([(10, 10), (0, 10)] * 5, **boot) == ci
    assert metrics.cluster_bootstrap_ci([(1, 1)], **boot) is None


def test_estimate_pools_repeats_and_reports_their_spread():
    rows = [{"cluster": f"c{i}", "repeat": rep, "ok": i < n}
            for rep, n in ((1, 2), (2, 3)) for i in range(4)]
    est = metrics.estimate(rows, lambda r: r["ok"], lambda r: True,
                           {"resamples": 200, "seed": 0, "level": 0.95})
    assert (est["value"], est["num"], est["den"], est["clusters"]) == (5 / 8, 5, 8, 4)
    assert est["per_repeat"] == {1: 0.5, 2: 0.75} and est["spread"] == [0.5, 0.75]


# ── Calibration and cost ─────────────────────────────────────────────────────

def test_calibration_table_and_high_confidence_wrong():
    rows = [score.score_row(r) for r in (
        v2_row(confidence="high"), v2_row("xss", confidence="high"), v2_row("xss", confidence="high"),
        v2_row("uncertain", confidence="low"), v2_row(schema_ok=False))]
    table = {t["confidence"]: t for t in calibration.calibration_table(rows)}
    assert (table["high"]["correct"], table["high"]["wrong"]) == (1, 2)
    assert table["high"]["wrong_share"] == pytest.approx(2 / 3)
    assert (table["low"]["abstained"], table["low"]["selective_accuracy"]) == (1, None)
    assert sum(t["n"] for t in table.values()) == 4                # no_answer has no confidence
    assert calibration.high_confidence_wrong(rows) == {"wrong": 2, "committed": 3, "rate": 2 / 3}


def test_prices_have_a_source_and_date():
    prices = settings()["prices"]
    assert prices["source"].startswith("https://") and prices["retrieved"]
    assert set(prices["usd_per_mtok"]["claude-sonnet-5-5"]) == {"input", "output"}


def test_cost_per_alert_and_per_correct_answer():
    rows = [score.score_row(r) for r in (v2_row(cid="c1"), v2_row("xss", cid="c2"))]
    p = settings()["prices"]["usd_per_mtok"]["claude-sonnet-5-5"]
    per_alert = (1000 * p["input"] + 100 * p["output"]) / 1e6
    c = metrics.cost_metrics(rows)
    assert c["cost_per_alert_usd"] == pytest.approx(per_alert)
    assert c["cost_per_correct_usd"] == pytest.approx(2 * per_alert)   # 1 of 2 correct
    assert c["cost_per_correct_disposition_usd"] == pytest.approx(per_alert)   # both escalated
    unpriced = metrics.cost_metrics([score.score_row(v2_row(model="claude-unknown"))])
    assert unpriced["cost_total_usd"] is None and unpriced["unpriced"] == {"claude-unknown": 1}


# ── End to end: triage → map → metrics ───────────────────────────────────────

def _triage_and_map(session_dir, tmp_path, fake_claude, repeat):
    from cjp.triage import batch
    wp3 = tmp_path / f"wp3_rep{repeat}.jsonl"
    batch.run(session=str(session_dir), out=str(wp3), repeat=repeat)
    mapped = tmp_path / f"mapped_rep{repeat}.jsonl"
    mapper.map_session(str(session_dir), wp3=str(wp3), out=str(mapped))
    return str(mapped)


def test_metrics_over_two_repeats(fake_claude, session_dir, tmp_path):
    inputs = [_triage_and_map(session_dir, tmp_path, fake_claude, rep) for rep in (1, 2)]
    rows = read_jsonl(inputs[1])
    assert {r["llm_repeat"] for r in rows} == {2} and {r["llm_model"] for r in rows} == {"claude-sonnet-5-5"}

    path = report.write_report(inputs, str(session_dir), report=str(tmp_path / "r" / "report.md"))
    m = json.loads((tmp_path / "r" / "metrics.json").read_text())
    t = m["triage"]
    # the fake always answers sql_injection / escalate / high: right on the
    # SQLi alert, wrong on the two IDOR alerts, escalates the benign one
    assert t["repeats"] == [1, 2] and t["fine"]["scored"] == 6
    assert t["fine"]["counts"] == {"correct": 2, "wrong": 4, "abstained": 0, "no_answer": 0}
    assert t["disposition"]["escalation_recall"]["value"] == 1.0
    assert t["disposition"]["fp_dismissal_rate"]["value"] == 0.0
    assert t["calibration"]["high_confidence_wrong"]["rate"] == pytest.approx(4 / 6)
    assert t["cost"]["cost_per_alert_usd"] > 0
    assert len(read_jsonl(tmp_path / "r" / "scores.jsonl")) == 2 * 6
    text = open(path).read()
    assert "Selective accuracy" in text and "Escalation recall" in text

    with pytest.raises(ValueError, match="repeat"):
        metrics.compute_metrics([inputs[0], inputs[0]], str(session_dir))


# ── The audit's re-computation (Plan P2 acceptance), skipped without data/ ───
AUDIT = LEGACY / "outputs" / "wp4" / "session_20260902_122150"


@pytest.mark.skipif(not AUDIT.exists(), reason="legacy evidence not present (data/ is gitignored)")
@pytest.mark.parametrize("run,abstained,correct,committed,high_wrong", [
    ("no_body", 27, 20, 21, (0, 5)),
    ("with_body", 0, 33, 48, (12, 32)),       # audit A4.4: 12 of 32 high-confidence answers wrong
])
def test_audit_recomputation_on_legacy_runs(run, abstained, correct, committed, high_wrong):
    m = metrics.compute_metrics([str(AUDIT / run / "output.jsonl")],
                                str(LEGACY / "sessions" / "session_20260902_122150"))
    fine = m["triage"]["fine"]
    assert fine["scored"] == 48
    assert fine["counts"]["abstained"] == abstained
    assert (fine["selective_accuracy"]["num"], fine["selective_accuracy"]["den"]) == (correct, committed)
    hw = m["triage"]["calibration"]["high_confidence_wrong"]
    assert (hw["wrong"], hw["committed"]) == high_wrong
