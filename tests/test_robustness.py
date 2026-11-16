"""Robustness (Plan P2.10): config validated at start-up, model profiles and
their request parameters, plain-language errors with the fix, failed calls
that --resume retries and scoring leaves out, and a complete .env.example."""

import json
import re

import anthropic
import httpx
import pytest
import yaml
from conftest import REPO_ROOT, read_jsonl

from cjp import cli, config, errors
from cjp.evaluate import mapper, score
from cjp.triage import batch, client, prompt


def _settings_doc() -> dict:
    return yaml.safe_load(config.SETTINGS_FILE.read_text())


def _validate(tmp_path, doc) -> tuple[list[str], list[str]]:
    path = tmp_path / "settings.yaml"
    path.write_text(yaml.safe_dump(doc))
    return config.validate(path)


# ── config ───────────────────────────────────────────────────────────────────
def test_the_tracked_settings_are_valid():
    assert config.validate() == ([], [])


@pytest.mark.parametrize("change, message", [
    (lambda d: d.pop("models"), "missing section 'models'"),
    (lambda d: d["models"]["sonnet"].update(effort="extreme"), "models.sonnet.effort"),
    (lambda d: d["models"]["haiku"].update(temperature=0), "unknown field"),
    (lambda d: d["triage"].update(model="opus"), "triage.model"),
    (lambda d: d["triage"].update(max_tokens=0), "triage.max_tokens"),
    (lambda d: d["api"].update(max_retries=-1), "api.max_retries"),
    (lambda d: d["scoring"].update(ci_level=95), "scoring.ci_level"),
    (lambda d: d["prices"].pop("retrieved"), "'source' and 'retrieved'"),
    (lambda d: d["prices"]["usd_per_mtok"]["claude-sonnet-5-5"].update(input="2"), "numeric"),
])
def test_settings_errors_name_the_field(tmp_path, change, message):
    doc = _settings_doc()
    change(doc)
    errs, _ = _validate(tmp_path, doc)
    assert any(message in e for e in errs), errs


def test_every_problem_is_listed_at_once(tmp_path):
    doc = _settings_doc()
    doc["triage"]["max_tokens"] = 0
    doc["api"]["timeout_seconds"] = 0
    errs, _ = _validate(tmp_path, doc)
    assert len(errs) == 2


def test_an_unpriced_model_is_a_warning(tmp_path):
    doc = _settings_doc()
    doc["models"]["haiku"]["id"] = "claude-haiku-9"
    errs, warns = _validate(tmp_path, doc)
    assert errs == [] and any("unpriced" in w for w in warns)


def test_unreadable_settings(tmp_path):
    bad = tmp_path / "settings.yaml"
    bad.write_text("models: [unclosed")
    assert "not valid YAML" in config.validate(bad)[0][0]
    assert "missing" in config.validate(tmp_path / "none.yaml")[0][0]


def test_environment_checks(monkeypatch):
    monkeypatch.setattr(config, "INDEXER_URL", "127.0.0.1:9200")
    monkeypatch.setattr(config, "VM_ROOT", "cjp-vm")
    monkeypatch.setenv("CJP_TRIAGE_EFFORT", "low")
    errs, warns = config.validate()
    assert any("INDEXER_URL" in e for e in errs) and any("VM_ROOT" in e for e in errs)
    assert any("CJP_TRIAGE_EFFORT" in w for w in warns)


def test_cli_stops_on_bad_config_before_running(monkeypatch, capsys):
    ran = []
    monkeypatch.setattr(config, "TRIAGE_MODEL_OVERRIDE", "opus")
    monkeypatch.setattr(cli, "_map", lambda args: ran.append(args))
    assert cli.main(["map", "--session", "x"]) == 1
    assert not ran
    assert "CJP_TRIAGE_MODEL=opus" in capsys.readouterr().err


# ── models and request parameters ───────────────────────────────────────────
def test_model_profiles():
    assert config.model_profile()["id"] == "claude-sonnet-5-5"
    assert config.model_profile("claude-haiku-4-5-20251001")["alias"] == "haiku"
    with pytest.raises(ValueError, match="not in config/settings.yaml"):
        config.model_profile("claude-sonnet-4")


def test_sonnet_request_is_unchanged_by_the_move_to_settings():
    # exactly the fields sent before P2.10, so earlier cache entries still match
    params = client.request_params({"x": 1}, "A")
    assert set(params) == {"model", "max_tokens", "thinking", "output_config", "system", "messages"}
    assert params["model"] == "claude-sonnet-5-5" and params["max_tokens"] == 1024
    assert params["thinking"] == {"type": "between_tools"}
    assert set(params["output_config"]) == {"effort", "format"}
    assert params["output_config"]["effort"] == "high"


def test_haiku_gets_only_the_parameters_it_accepts():
    params = client.request_params({"x": 1}, "B", model="haiku")
    assert params["model"] == "claude-haiku-4-5-20251001"
    assert "thinking" not in params and "effort" not in params["output_config"]


def test_the_model_is_part_of_the_cache_key():
    alert = read_jsonl(REPO_ROOT / "tests/fixtures/session_20990101_000000/wazuh_alerts.jsonl")[0]
    assert client.cache_key_for(alert) != client.cache_key_for(alert, model="haiku")


def test_the_client_uses_the_configured_retries(monkeypatch):
    client.get_client.cache_clear()
    try:
        c = client.get_client()
        assert c.max_retries == config.settings()["api"]["max_retries"]
    finally:
        client.get_client.cache_clear()


# ── errors with the fix ──────────────────────────────────────────────────────
@pytest.fixture(autouse=True)
def wazuh_urls(monkeypatch):
    """Distinct ports, as through the real tunnel (conftest makes both unreachable
    at the same address)."""
    monkeypatch.setattr(config, "WAZUH_URL", "https://127.0.0.1:55000")
    monkeypatch.setattr(config, "INDEXER_URL", "https://127.0.0.1:9200")


def _api_error(cls, status):
    request = httpx2_request()
    return cls("boom", response=_response(status, request), body=None)


def httpx2_request():
    import httpx2
    return httpx2.Request("POST", "https://api.anthropic.com/v1/messages")


def _response(status, request):
    import httpx2
    return httpx2.Response(status, request=request)


def test_tunnel_down_names_the_tunnel_command():
    request = httpx.Request("POST", f"{config.INDEXER_URL}/wazuh-alerts-4.x-*/_search")
    message = errors.explain(httpx.ConnectError("refused", request=request))
    assert "Wazuh indexer unreachable" in message and "ssh -N -L 9200" in message


def test_rejected_wazuh_credentials_name_the_variables():
    request = httpx.Request("POST", f"{config.WAZUH_URL}/security/user/authenticate")
    exc = httpx.HTTPStatusError("401", request=request, response=httpx.Response(401, request=request))
    assert "WAZUH_USER / WAZUH_PASS" in errors.explain(exc)


@pytest.mark.parametrize("cls, status, words", [
    (anthropic.AuthenticationError, 401, "ANTHROPIC_API_KEY"),
    (anthropic.NotFoundError, 404, "config/settings.yaml"),
    (anthropic.BadRequestError, 400, "does not accept"),
    (anthropic.RateLimitError, 429, "resume"),
])
def test_claude_errors_say_what_to_do(cls, status, words):
    assert words in errors.explain(_api_error(cls, status))


def test_unknown_errors_keep_their_traceback(monkeypatch):
    monkeypatch.setattr(cli, "_map", lambda args: (_ for _ in ()).throw(KeyError("bug")))
    with pytest.raises(KeyError):
        cli.main(["map", "--session", "x"])


def test_known_errors_print_one_line(monkeypatch, capsys):
    request = httpx.Request("GET", f"{config.WAZUH_URL}/agents")

    def down(args):
        raise httpx.ConnectError("refused", request=request)
    monkeypatch.setattr(cli, "_map", down)
    assert cli.main(["map", "--session", "x"]) == 1
    err = capsys.readouterr().err
    assert err.startswith("[cjp] Wazuh manager API unreachable") and "Traceback" not in err
    monkeypatch.setenv("CJP_DEBUG", "1")
    with pytest.raises(httpx.ConnectError):
        cli.main(["map", "--session", "x"])


# ── failed calls: retried by --resume, never scored ─────────────────────────
def test_a_failed_call_is_an_api_error_row_that_resume_retries(monkeypatch, fake_claude,
                                                                session_dir, tmp_path):
    real = client.analyse_alert
    calls = {"n": 0}

    def flaky(alert, **kwargs):
        calls["n"] += 1
        if calls["n"] == 2:
            raise anthropic.APIConnectionError(request=httpx2_request())
        return real(alert, **kwargs)
    monkeypatch.setattr(batch, "analyse_alert", flaky)
    out = tmp_path / "o.jsonl"
    batch.run(session=str(session_dir), out=str(out))
    rows = read_jsonl(out)
    assert len(rows) == 6 and sum(1 for r in rows if r.get("api_error")) == 1
    failed_id = next(r["wazuh_alert_id"] for r in rows if r.get("api_error"))
    assert failed_id not in batch.load_completed_ids(str(out))

    batch.run(session=str(session_dir), resume=str(out))
    rows = read_jsonl(out)
    assert len(rows) == 7 and rows[-1]["wazuh_alert_id"] == failed_id
    assert not rows[-1].get("api_error")
    # the mapper keeps the last row per alert, so the retry replaces the failure
    assert not mapper.load_wp3(str(out))[failed_id].get("api_error")


def test_pre_p2_10_exception_rows_count_as_api_errors():
    assert batch.is_api_error({"llm_output": {"error": "exception: timeout"}})
    assert not batch.is_api_error({"llm_output": {"error": "refusal"}})


def test_a_fatal_error_stops_the_batch_at_once(monkeypatch, session_dir, tmp_path, capsys):
    def rejected(alert, **kwargs):
        raise _api_error(anthropic.AuthenticationError, 401)
    monkeypatch.setattr(batch, "analyse_alert", rejected)
    out = tmp_path / "o.jsonl"
    batch.run(session=str(session_dir), out=str(out), fmt="B", repeat=2,
              alerts_file="body_field_wazuh_alerts.jsonl")
    assert len(read_jsonl(out)) == 1
    printed = " ".join(capsys.readouterr().out.split())
    assert "ANTHROPIC_API_KEY" in printed
    # the printed resume command asks the same question as the rows already written
    assert "--alerts-file body_field_wazuh_alerts.jsonl --repeat 2 --format B" in printed


def test_api_error_rows_are_left_out_of_scoring(session_dir):
    base = {"wazuh_alert_id": "a1", "is_attack": True, "matched_label": "sql_injection",
            "llm_parse_ok": False, "llm_format": "A", "llm_schema_ok": False}
    assert score.score_row(dict(base))["fine"] == "no_answer"
    assert score.score_row(dict(base, llm_api_error=True)) is None


# ── .env.example ─────────────────────────────────────────────────────────────
def test_env_example_documents_every_variable():
    read = set()
    for path in (REPO_ROOT / "cjp").rglob("*.py"):
        # getenv(  # S1-plain ⏎ "JUICE_LOG_PATH", …): a comment may sit in between
        read |= set(re.findall(r'getenv\(\s*(?:#[^\n]*\n\s*)?"([A-Z0-9_]+)"', path.read_text()))
    documented = set(re.findall(r"^#?\s*([A-Z0-9_]+)=", (REPO_ROOT / ".env.example").read_text(),
                                re.MULTILINE))
    assert read - set(config.RETIRED_ENV) <= documented, read - documented
    assert {"ANTHROPIC_API_KEY", "JUICE_LOG_PATH", "CJP_DEBUG"} <= read


def test_env_example_is_not_ignored():
    import subprocess
    rc = subprocess.run(["git", "check-ignore", "-q", ".env.example"], cwd=REPO_ROOT).returncode
    assert rc == 1      # 1 = not ignored
