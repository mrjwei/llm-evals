"""Triage: prompt identity and content, the output schemas, CID sanitising,
the payload, response parsing, the response cache and the batch runner."""

import json

from conftest import FIXTURE_SESSION, read_jsonl

import pytest

from cjp.triage import batch, client, prompt, schema

S = "20990101_000000"

# Every name, path or label that would tell the model it is looking at the
# testbed (Plan M4). None may appear in the rendered prompt.
TESTBED_TERMS = ["juice", "wp4_mapper", "attacks.sh", "/rest/", "/api/", "feedback",
                 "forged_feedback", "error_probing", "sql_injection_union", "ftp", "wp1-"]


def test_legacy_prompt_is_kept_byte_for_byte():
    # The legacy no_body/with_body runs carry prompt_version 1cce404d; the
    # file lets that version resolve to its text. A change here breaks that.
    text = prompt.LEGACY_PROMPT_FILE.read_text()
    assert schema.short_hash(text) == "1cce404d"


@pytest.mark.parametrize("fmt", ["A", "B"])
def test_prompt_v2_names_no_testbed_specifics(fmt):
    text = prompt.system_prompt(fmt).lower()
    assert [t for t in TESTBED_TERMS if t in text] == []
    assert "{{" not in text


@pytest.mark.parametrize("fmt", ["A", "B"])
def test_prompt_lists_every_label_and_field(fmt):
    text = prompt.system_prompt(fmt)
    for label in schema.technique_labels():
        assert f"- `{label}`:" in text
    names = [name for name, _ in schema.fields(fmt)]
    for name in names:
        assert f"- `{name}`:" in text
    # fields are listed in generation order
    assert [text.index(f"- `{n}`:") for n in names] == \
        sorted(text.index(f"- `{n}`:") for n in names)


def test_prompt_and_schema_versions_differ_by_format():
    assert prompt.prompt_version("A") != prompt.prompt_version("B")
    assert schema.schema_version("A") != schema.schema_version("B")
    assert prompt.prompt_version("a") == prompt.prompt_version("A")


def test_sanitise_redacts_attack_and_benign_cids():
    line = f'"GET / HTTP/1.1" 200 - "wp1-{S}-3-12" x wp1-benign-{S}-1-1'
    assert prompt.sanitise_full_log(line) == '"GET / HTTP/1.1" 200 - "[REDACTED]" x [REDACTED]'
    assert prompt.extract_cid(line) == f"wp1-{S}-3-12"
    assert prompt.extract_cid("no cid here") is None


def test_body_truncation_is_marked():
    body = "x" * (prompt.INGEST_BODY_MAX_CHARS + 5)
    out = prompt._truncate(body)
    assert out.startswith("x" * prompt.INGEST_BODY_MAX_CHARS)
    assert out.endswith("...[truncated, 5 more chars]")
    assert prompt._truncate("short") == "short"


def test_alert_summary_attaches_sanitised_bodies():
    alert = read_jsonl(FIXTURE_SESSION / "wazuh_alerts.jsonl")[4]
    entry = read_jsonl(FIXTURE_SESSION / "ingest_log.jsonl")[0]
    summary, matched = prompt.build_alert_summary(alert, entry)
    assert matched is True
    assert "union select" in summary["request_body"]
    assert "wp1-" not in summary["response_body"]  # the CID echoed in the body is redacted
    assert set(summary) == {"timestamp", "rule", "data", "full_log", "location", "agent",
                            "request_body", "response_body"}
    assert summary["location"] == "access.log"
    summary, matched = prompt.build_alert_summary(alert, None)
    assert matched is False and "request_body" not in summary


def test_extract_json_takes_first_balanced_object():
    assert client.extract_json('pre {"a": {"b": 1}} post {"c": 2}') == '{"a": {"b": 1}}'
    assert client.extract_json("no json") == "no json"


def test_analyse_alert_row(fake_claude):
    alert = read_jsonl(FIXTURE_SESSION / "wazuh_alerts.jsonl")[0]
    row = client.analyse_alert(alert)
    call = fake_claude.calls[0]
    assert call["model"] == "claude-sonnet-5-5"
    assert call["max_tokens"] == 1024
    # Sonnet 5.5: "disabled" is a 400; between_tools (thinking off) takes no
    # other field and needs effort high or below; sampling params must not be sent
    assert call["thinking"] == {"type": "between_tools"}
    # prompt v2: the schema is enforced by the API (structured outputs)
    assert call["output_config"] == {
        "effort": "high", "format": {"type": "json_schema", "schema": schema.render_schema("A")}}
    assert not {"temperature", "top_p", "top_k"} & set(call)
    assert call["system"] == prompt.system_prompt("A")
    assert "wp1-" not in call["messages"][0]["content"]
    assert row["parse_ok"] is True and row["schema_ok"] is True and row["schema_errors"] == []
    assert row["llm_output"]["technique_label"] == "sql_injection"
    assert row["prompt_id"] == "triage_v2" and row["format"] == "A"
    assert row["prompt_version"] == prompt.prompt_version("A")
    assert row["schema_version"] == schema.schema_version("A")
    assert row["model"] == "claude-sonnet-5-5"
    assert row["wazuh_alert_id"] == alert["id"]
    assert row["token_usage"] == {"input_tokens": 100, "output_tokens": 20, "total_tokens": 120}


def test_analyse_alert_parse_failures(fake_claude):
    alert = read_jsonl(FIXTURE_SESSION / "wazuh_alerts.jsonl")[0]
    fake_claude.reply = "not json at all"
    row = client.analyse_alert(alert)
    assert row["parse_ok"] is False and row["llm_output"]["raw"] == "not json at all"
    assert row["schema_ok"] is False and row["schema_errors"] is None
    fake_claude.reply, fake_claude.stop_reason = {"event_type": "x"}, "max_tokens"
    row = client.analyse_alert(alert, cache_mode="refresh")   # same alert: skip its cached reply
    assert row["parse_ok"] is False and row["llm_output"] == {"error": "truncated_at_max_tokens"}


def test_analyse_alert_records_a_refusal(fake_claude):
    alert = read_jsonl(FIXTURE_SESSION / "wazuh_alerts.jsonl")[0]
    fake_claude.stop_reason = "refusal"
    fake_claude.stop_details = {"type": "refusal", "category": "cyber", "explanation": "e"}
    row = client.analyse_alert(alert)
    assert row["parse_ok"] is False and row["stop_reason"] == "refusal"
    assert row["llm_output"] == {"error": "refusal", "category": "cyber", "explanation": "e"}
    assert len(fake_claude.calls) == 1        # no silent retry on another model


def test_batch_run_writes_one_row_per_alert_and_resumes(fake_claude, session_dir, data_dir):
    batch.run(session=str(session_dir), variant="t")
    out = data_dir / "outputs" / "wp3" / session_dir.name / "t_v1" / "output.jsonl"
    rows = read_jsonl(out)
    assert [r["wazuh_alert_id"] for r in rows] == \
        [a["id"] for a in read_jsonl(session_dir / "wazuh_alerts.jsonl")]
    # none of the S1 alerts' CIDs is in ingest_log.jsonl, so none gets bodies
    assert [r["ingest_matched"] for r in rows] == [False] * 6
    meta = json.loads((out.parent / "output_meta.json").read_text())
    assert meta["invocations"][0]["script"] == "cjp triage"

    # a second run gets a new version directory, never overwriting the first,
    # and is answered entirely from the cache
    batch.run(session=str(session_dir), variant="t")
    rerun = read_jsonl(out.parent.parent / "t_v2" / "output.jsonl")
    assert len(fake_claude.calls) == 6 and all(r["cache_hit"] for r in rerun)
    assert [r["llm_output"] for r in rerun] == [r["llm_output"] for r in rows]

    # resume: drop the last two rows, rerun with fresh calls, and only those two are called
    out.write_text("".join(json.dumps(r) + "\n" for r in rows[:4]))
    batch.run(session=str(session_dir), resume=str(out), cache_mode="refresh")
    assert len(fake_claude.calls) == 8
    assert [r["wazuh_alert_id"] for r in read_jsonl(out)] == [r["wazuh_alert_id"] for r in rows]


def test_batch_attaches_bodies_by_cid(fake_claude, session_dir, tmp_path):
    out = tmp_path / "s3.jsonl"
    batch.run(session=str(session_dir), out=str(out), alerts_file="body_field_wazuh_alerts.jsonl")
    # the first S3 alert's CID (…-3-1) has an ingest_log entry, the benign one has none
    assert [r["ingest_matched"] for r in read_jsonl(out)] == [True, False]
    assert "request_body" in fake_claude.calls[0]["messages"][0]["content"]


def test_batch_aborts_after_consecutive_failures(monkeypatch, session_dir, tmp_path):
    def boom(alert, **kwargs):
        raise RuntimeError("api down")
    monkeypatch.setattr(batch, "analyse_alert", boom)
    out = tmp_path / "o.jsonl"
    batch.run(session=str(session_dir), out=str(out))
    rows = read_jsonl(out)
    assert len(rows) == batch.MAX_CONSECUTIVE_FAILURES
    assert all(r["parse_ok"] is False and r["api_error"] for r in rows)


def test_no_cid_reaches_the_payload_from_any_field():
    # S3 alerts carry the CID in data.cid (custom decoder), not just full_log
    for alert in read_jsonl(FIXTURE_SESSION / "body_field_wazuh_alerts.jsonl"):
        assert alert["data"]["cid"].startswith("wp1-")
        entry = read_jsonl(FIXTURE_SESSION / "ingest_log.jsonl")[0]
        summary, _ = prompt.build_alert_summary(alert, entry)
        payload = prompt.user_message(summary)
        assert "wp1-" not in payload and "benign" not in payload
        assert summary["data"]["cid"] == "[REDACTED]"
