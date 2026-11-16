"""Prompt v2 output formats (Plan P2.6): the taxonomy, the rendered schemas,
local validation, Format B end to end, the payload changes and the CLI."""

import json
import re

import pytest
from conftest import FIXTURE_SESSION, REPO_ROOT, read_jsonl

from cjp import cli
from cjp.triage import batch, client, prompt, schema

VALID_A = {"technique_label": "uncertain",
           "candidate_labels": ["brute_force", "account_enumeration"],
           "disposition": "needs_more_info", "confidence": "low",
           "recommended_action": "Pull the request bodies for this source.",
           "event_type": "Login endpoint probing", "severity": "medium",
           "reasoning": "r", "evidence": "POST, 401", "cognitive_notes": "n"}
VALID_B = {"technique_label": "xss", "disposition": "escalate", "confidence": "high",
           "recommended_action": "Block the source."}


def _alert():
    return read_jsonl(FIXTURE_SESSION / "wazuh_alerts.jsonl")[0]


# ── taxonomy ─────────────────────────────────────────────────────────────────
def test_ground_truth_covers_every_attacks_sh_label():
    script = (REPO_ROOT / "vm" / "juice-shop" / "attacks.sh").read_text()
    # indented calls too: the injection probe's `_inj` labels sit inside its INJECTION=1 gate
    testbed = set(re.findall(r'^\s*log_attack "A\d\d" "(\w+)"', script, re.MULTILINE))
    taxonomy = schema.load_taxonomy()
    assert testbed and testbed == set(taxonomy["ground_truth"])
    # every testbed technique's label is marked testbed, and only those are
    assert {taxonomy["ground_truth"][t] for t in testbed} == \
        {label for label, spec in taxonomy["labels"].items() if spec["testbed"]}


def test_coarse_groups_merge_only_the_login_campaign():
    labels = schema.load_taxonomy()["labels"]
    merged = {label for label, spec in labels.items() if spec["coarse"] != label}
    assert merged == {"brute_force", "weak_credentials", "account_enumeration"}
    assert {labels[m]["coarse"] for m in merged} == {"login_campaign"}


def test_every_label_has_a_2025_category():
    for spec in schema.load_taxonomy()["labels"].values():
        assert re.fullmatch(r"A(0[1-9]|10)", spec["owasp_2025"])


def test_label_enums():
    labels = schema.technique_labels()
    assert labels[-3:] == ["none", "other", "uncertain"] and len(set(labels)) == len(labels)
    assert "uncertain" not in schema.candidate_labels() and "other" in schema.candidate_labels()


# ── rendered schemas ─────────────────────────────────────────────────────────
@pytest.mark.parametrize("fmt", ["A", "B"])
def test_rendered_schema_is_plain_json_schema(fmt):
    text = json.dumps(schema.render_schema(fmt))
    for key in ("x-cjp-enum", "$comment", "description", "minItems", "minLength", "maxLength"):
        assert key not in text
    s = schema.render_schema(fmt)
    assert s["additionalProperties"] is False and s["required"] == list(s["properties"])


def test_format_b_is_the_decision_prefix_of_format_a():
    a = [name for name, _ in schema.fields("A")]
    b = [name for name, _ in schema.fields("B")]
    assert b == ["technique_label", "disposition", "confidence", "recommended_action"]
    assert [n for n in a if n in b] == b and a[:5] == ["technique_label", "candidate_labels", *b[1:]]
    for (name, spec) in schema.fields("B"):
        assert spec == dict(schema.fields("A"))[name]


def test_unknown_format_is_refused():
    with pytest.raises(ValueError):
        schema.render_schema("C")


# ── local validation ─────────────────────────────────────────────────────────
def test_valid_answers_pass():
    assert schema.validate(VALID_A, "A") == []
    assert schema.validate(VALID_B, "B") == []
    assert schema.validate({**VALID_A, "technique_label": "none", "candidate_labels": []}, "A") == []


@pytest.mark.parametrize("change,error", [
    ({"technique_label": "sqli"}, "$.technique_label: 'sqli' is not an allowed value"),
    ({"confidence": 3}, "$.confidence: expected string, got int"),
    ({"extra": 1}, "$.extra: not in the schema"),
    ({"candidate_labels": ["xss", "nope"]}, "$.candidate_labels[1]: 'nope' is not an allowed value"),
])
def test_schema_violations_are_named(change, error):
    assert error in schema.validate({**VALID_A, **change}, "A")


def test_missing_field_and_wrong_format():
    no_action = {k: v for k, v in VALID_B.items() if k != "recommended_action"}
    assert schema.validate(no_action, "B") == ["$.recommended_action: missing"]
    assert "$.candidate_labels: not in the schema" in schema.validate(VALID_A, "B")


def test_candidate_rule():
    one = {**VALID_A, "candidate_labels": ["brute_force", "brute_force"]}
    assert schema.validate(one, "A") == ["$.candidate_labels: uncertain needs two or more candidates"]
    committed = {**VALID_A, "technique_label": "brute_force"}
    assert schema.validate(committed, "A") == \
        ["$.candidate_labels: must be empty unless technique_label is uncertain"]


# ── the client with Format B ─────────────────────────────────────────────────
def test_format_b_row(fake_claude):
    fake_claude.reply = VALID_B
    row = client.analyse_alert(_alert(), fmt="b")
    call = fake_claude.calls[0]
    assert call["output_config"]["format"]["schema"] == schema.render_schema("B")
    assert call["system"] == prompt.system_prompt("B")
    assert row["format"] == "B" and row["schema_ok"] is True
    assert row["prompt_version"] == prompt.prompt_version("B")


def test_an_answer_that_breaks_the_schema_is_kept_and_flagged(fake_claude):
    fake_claude.reply = {**VALID_B, "technique_label": "made_up"}
    row = client.analyse_alert(_alert(), fmt="B")
    assert row["parse_ok"] is True and row["schema_ok"] is False
    assert row["schema_errors"] == ["$.technique_label: 'made_up' is not an allowed value"]
    assert row["llm_output"]["technique_label"] == "made_up"
    assert len(fake_claude.calls) == 1       # never re-asked


def test_the_format_is_part_of_the_cache_key(fake_claude):
    assert client.cache_key_for(_alert(), fmt="A") != client.cache_key_for(_alert(), fmt="B")
    client.analyse_alert(_alert(), fmt="A")
    assert client.analyse_alert(_alert(), fmt="B")["cache_hit"] is False


def test_batch_records_the_format(fake_claude, session_dir, tmp_path):
    fake_claude.reply = VALID_B
    out = tmp_path / "b.jsonl"
    batch.run(session=str(session_dir), out=str(out), fmt="B")
    assert {r["format"] for r in read_jsonl(out)} == {"B"}
    meta = json.loads((tmp_path / "b_meta.json").read_text())["invocations"][-1]
    assert meta["format"] == "B" and meta["prompt_version"] == prompt.prompt_version("B")


# ── payload ──────────────────────────────────────────────────────────────────
@pytest.mark.parametrize("location,name", [
    ("/home/jesse/cjp-vm/juice-shop/data/logs/access.log.2026-09-30", "access.log"),
    ("/x/logs/body_field_access.log", "body_field_access.log"),
    ("access.log.2099-01-01", "access.log"),
    ("", ""),
])
def test_location_is_reduced_to_the_log_file_name(location, name):
    assert prompt.log_file_name(location) == name


def test_volatile_rule_counter_is_not_sent():
    alert = {**_alert(), "rule": {**_alert()["rule"], "firedtimes": 41}}
    summary, _ = prompt.build_alert_summary(alert)
    assert "firedtimes" not in summary["rule"] and summary["rule"]["id"] == alert["rule"]["id"]
    # the same alert fired at a different count is the same request
    again = {**alert, "rule": {**alert["rule"], "firedtimes": 7}}
    assert client.cache_key_for(alert) == client.cache_key_for(again)
    assert "juice" not in prompt.user_message(summary)


# ── CLI ──────────────────────────────────────────────────────────────────────
def test_cli_triage_format(monkeypatch):
    seen = {}
    monkeypatch.setattr(batch, "run", lambda **kw: seen.update(kw))
    cli.main(["triage", "--session", "s"])
    assert seen["fmt"] == "A"
    cli.main(["triage", "--session", "s", "--format", "b"])
    assert seen["fmt"] == "B"


@pytest.mark.parametrize("fmt", ["A", "B"])
def test_cli_prompt_show(capsys, fmt):
    cli.main(["prompt", "show", "--format", fmt])
    out = capsys.readouterr().out
    assert prompt.prompt_version(fmt) in out and prompt.system_prompt(fmt) in out
    cli.main(["prompt", "show", "--format", fmt, "--schema"])
    out = capsys.readouterr().out
    assert json.loads(out.split("\n", 2)[2]) == schema.render_schema(fmt)


# ── mapper join ──────────────────────────────────────────────────────────────
def test_mapper_carries_the_v2_fields(fake_claude, session_dir, tmp_path):
    from cjp.evaluate import mapper
    wp3 = tmp_path / "t.jsonl"
    batch.run(session=str(session_dir), out=str(wp3))
    rows, _ = mapper.map_alerts(str(session_dir), str(wp3), 1.5)
    row = rows[0]
    assert (row["llm_technique_label"], row["llm_disposition"], row["llm_candidate_labels"]) == \
        ("sql_injection", "escalate", [])
    assert (row["llm_format"], row["llm_schema_ok"]) == ("A", True)
    assert row["llm_prompt_version"] == prompt.prompt_version("A")


def test_baselines_cover_every_signature_with_a_valid_label():
    """X0's B-url-regex (taxonomy/baselines.yaml) must name a technique_label
    for every signature in the mapper's table, and nothing else."""
    import yaml
    from cjp.evaluate.mapper import SIGNATURES
    spec = yaml.safe_load((REPO_ROOT / "taxonomy" / "baselines.yaml").read_text())
    url = spec["url_regex"]
    assert set(url["label"]) == {label for label, _, _ in SIGNATURES}
    allowed = set(schema.technique_labels()) - {"other"}
    assert set(url["label"].values()) | {url["no_match"]} <= allowed
    assert set(spec["rule"]["label_by_group"].values()) <= allowed
