"""Evaluation: mapper tiers, signature table, SIEM metrics and the report.
Triage scoring is in test_score.py."""

import json
from datetime import datetime, timezone

import pytest
from conftest import FIXTURE_SESSION, LEGACY, read_jsonl

from cjp.evaluate import mapper, metrics, report

S = "20990101_000000"


@pytest.mark.parametrize("method,url,label", [
    ("GET", "/rest/basket/3", "idor"),
    ("GET", "/ftp/../etc/passwd", "path_traversal"),
    ("GET", "/ftp/%2e%2e/x", "path_traversal"),
    ("GET", "/ftp/acquisitions.md", "sensitive_data_exposure"),
    ("POST", "/rest/user/login", "login_endpoint_probe"),
    ("GET", "/rest/products/search?q=x')) UNION SELECT", "sql_injection_union"),
    ("GET", "/rest/products/search?q=<script>", "xss"),
    ("GET", "/api-docs", "security_misconfiguration"),
    ("POST", "/api/Feedbacks/", "feedback_endpoint_probe"),
    ("GET", "/.env", "error_probing"),
    ("POST", "/profile/image/url", "ssrf"),
    ("GET", "/rest/user/login", None),          # method must match
    ("GET", "/rest/products", None),
])
def test_signature_match(method, url, label):
    assert mapper.signature_match(method, url) == label


def test_labels_agree_uses_ambiguous_groups():
    assert mapper.labels_agree("brute_force", "login_endpoint_probe") is True
    assert mapper.labels_agree("idor", "login_endpoint_probe") is False
    assert mapper.labels_agree("idor", "idor") is True
    assert mapper.labels_agree(None, "idor") is None


def test_parse_log_time_applies_offset():
    t = mapper.parse_log_time('x [01/Jan/2099:10:00:00 +1000] "GET /"')
    assert t == datetime(2099, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
    assert mapper.parse_log_time("no time") is None


def test_map_alerts_covers_every_tier():
    rows, attacks = mapper.map_alerts(str(FIXTURE_SESSION), None, 1.5)
    by_id = {r["wazuh_alert_id"][-1]: r for r in rows}
    assert (by_id["1"]["match_method"], by_id["1"]["matched_label"], by_id["1"]["is_attack"]) == \
        ("cid", "idor", True)
    assert (by_id["3"]["match_method"], by_id["3"]["matched_label"], by_id["3"]["is_attack"]) == \
        ("cid", "browse_catalogue", False)                       # benign traffic: candidate FP
    assert (by_id["4"]["match_method"], by_id["4"]["is_attack"]) == ("aggregate", None)
    assert (by_id["5"]["match_method"], by_id["5"]["matched_label"]) == \
        ("interval_unique", "sql_injection")                     # no CID, inside attack 3's window
    assert by_id["5"]["signature_agrees"] is True                # login probe is in the SQLi group
    assert by_id["6"]["match_method"] == "unattributed"
    assert sorted(attacks) == [1, 2, 3]


def test_map_alerts_never_attributes_another_sessions_cid(tmp_path):
    """A back-to-back neighbour's first request caught at the window edge
    (C1 seed 2, 2 Oct) carries its own session's CID. It must not fall
    through to the time or signature tiers (it did: /rest/basket/1 -> idor),
    because the neighbour session scores it."""
    import shutil
    session = tmp_path / FIXTURE_SESSION.name
    shutil.copytree(FIXTURE_SESSION, session)
    first = json.loads((session / "wazuh_alerts.jsonl").read_text().splitlines()[0])
    first["id"] = "4070908800.9"
    first["full_log"] = first["full_log"].replace("wp1-20990101_000000-1-1", "wp1-20990101_000600-1-1")
    with open(session / "wazuh_alerts.jsonl", "a") as f:
        f.write(json.dumps(first) + "\n")
    rows, _ = mapper.map_alerts(str(session), None, 1.5)
    row = next(r for r in rows if r["wazuh_alert_id"] == "4070908800.9")
    assert (row["match_method"], row["is_attack"], row["matched_label"]) == ("other_session", None, None)
    assert row["matched_cid"] == "wp1-20990101_000600-1-1"
    assert mapper.cid_session("wp1-benign-20990101_000600-2-3") == "20990101_000600"


def test_map_session_writes_versioned_output(session_dir, data_dir, capsys):
    out = mapper.map_session(str(session_dir))
    assert out == str(data_dir / "outputs" / "wp4" / session_dir.name / "primary_v1" / "output.jsonl")
    assert "Techniques detected : 2/3" in capsys.readouterr().out
    meta = json.loads((data_dir / "outputs/wp4" / session_dir.name / "primary_v1/output_meta.json").read_text())
    assert meta["script"] == "cjp map" and meta["alert_rows"] == 6
    out2 = mapper.map_session(str(session_dir), alerts_file="body_field_wazuh_alerts.jsonl")
    assert "/body_field_v1/" in out2


def test_legacy_metrics_on_fixture(session_dir, tmp_path):
    rows, _ = mapper.map_alerts(str(session_dir), None, 1.5)
    mapped = tmp_path / "mapped.jsonl"
    mapped.write_text("".join(json.dumps(r) + "\n" for r in rows))
    m = metrics.compute_metrics([str(mapped)], str(session_dir))
    d, p = m["detection"], m["precision_fpr"]
    assert (d["techniques_detected"], d["techniques_total"]) == (2, 3)
    assert d["missed_techniques"] == ["A01/path_traversal"]
    assert (d["alerts_total"], d["access_log_lines"]) == (6, 6)
    assert (p["true_positive_alerts"], p["false_positive_alerts"], p["unclassified_alerts"]) == (3, 1, 2)
    assert p["false_positive_rate_request_level"] == 0.5          # 1 of 2 benign requests alerted
    assert m["triage"] is None                                     # mapped without --wp3
    assert "grounding" not in m and "event_type" not in m          # dropped in P2.7 (M10, M2)


def test_cohens_kappa():
    assert metrics.cohens_kappa(["a", "b"], ["a", "b"]) == 1.0
    assert metrics.cohens_kappa([], []) is None
    assert metrics.cohens_kappa(["a", "a"], ["a", "a"]) == 1.0      # pe == 1 edge case


def test_write_report_default_location_never_overwrites(session_dir):
    rows, _ = mapper.map_alerts(str(session_dir), None, 1.5)
    run = session_dir / "run"
    run.mkdir()
    mapped = run / "output.jsonl"
    mapped.write_text("".join(json.dumps(r) + "\n" for r in rows))

    path = report.write_report([str(mapped)], str(session_dir))
    assert path == str(run / "report.md")
    text = (run / "report.md").read_text()
    assert "Technique-level recall | 2/3 (66.7%)" in text
    assert "no triage rows were joined" in text
    assert "grounding" not in text.lower()
    assert (run / "charts" / "headline_summary.png").exists()
    assert json.loads((run / "metrics.json").read_text())["detection"]["techniques_detected"] == 2
    assert json.loads((run / "report_meta.json").read_text())["script"] == "cjp metrics"

    # a second report next to the same input goes into its own versioned directory
    path = report.write_report([str(mapped)], str(session_dir))
    assert path == str(run / "metrics" / "report_v1" / "report.md")


def test_legacy_synonym_table_is_the_canonical_one(session_dir):
    from cjp.config import LEGACY_SYNONYM_TABLE
    table = json.loads(LEGACY_SYNONYM_TABLE.read_text())
    assert "sql_injection" in table and "idor" in table


# ── Golden test on real legacy evidence (Plan P2.8), skipped without data/ ──
GOLDEN = LEGACY / "sessions" / "session_20260916_095620"


@pytest.mark.skipif(not GOLDEN.exists(), reason="legacy evidence not present (data/ is gitignored)")
@pytest.mark.parametrize("alerts_file,n_alerts,n_detected", [
    ("wazuh_alerts.jsonl", 57, 7),                # S1-plain
    ("enriched_wazuh_alerts.jsonl", 82, 9),       # S2-body-in-url
    ("body_field_wazuh_alerts.jsonl", 71, 8),     # S3-body-field
])
def test_golden_three_arm_session(alerts_file, n_alerts, n_detected):
    rows, attacks = mapper.map_alerts(str(GOLDEN), None, 1.5, alerts_file)
    detected = {r["matched_attack_seq"] for r in rows if r["matched_attack_seq"] is not None}
    real = [a for a in attacks.values() if not a["skipped"]]
    assert (len(rows), len(detected), len(real)) == (n_alerts, n_detected, 14)
    # and the rows equal the ones kept as evidence, apart from the code version
    kept = LEGACY / "outputs/wp4" / GOLDEN.name / (mapper.run_tag_for(alerts_file) + "_v1") / "output.jsonl"
    strip = lambda rs: [{k: v for k, v in r.items() if k != "git_sha"} for r in rs]
    assert strip(rows) == strip(read_jsonl(kept))
