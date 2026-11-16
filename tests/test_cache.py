"""The response cache (Plan P2.5): what enters the key, hits and misses, the
three cache modes, and that evaluation never reaches the API."""

import json
import subprocess
import sys

import pytest
from conftest import FIXTURE_SESSION, REPO_ROOT, read_jsonl

from cjp import cache, cli
from cjp.triage import batch, client, prompt


def _alert(i=0):
    return read_jsonl(FIXTURE_SESSION / "wazuh_alerts.jsonl")[i]


def _request(alert):
    return client.request_params(prompt.build_alert_summary(alert)[0])


# ── the key ─────────────────────────────────────────────────────────────────
def test_key_ignores_volatile_ids():
    # the Wazuh document id, @timestamp and the CID differ between two
    # collections of the same request; none of them reaches the model
    a = _alert()
    b = json.loads(json.dumps(a))
    b["id"], b["@timestamp"] = "9999999999.1", "2099-01-01T00:00:00.000Z"
    b["full_log"] = prompt.CID_RE.sub("wp1-20990202_020202-9-9", b["full_log"])
    assert b["full_log"] != a["full_log"]
    assert cache.cache_key(_request(a), 1) == cache.cache_key(_request(b), 1)


@pytest.mark.parametrize("change", [
    lambda r: r.update(model="claude-other"),
    lambda r: r.update(system=r["system"] + " "),                    # prompt
    lambda r: r.update(max_tokens=r["max_tokens"] + 1),
    lambda r: r.update(temperature=0),                               # any new parameter
    lambda r: r["messages"][0].update(content=r["messages"][0]["content"].replace("GET", "PUT")),
])
def test_key_covers_the_whole_request(change):
    request = _request(_alert())
    before = cache.cache_key(request, 1)
    change(request)
    assert cache.cache_key(request, 1) != before


def test_key_separates_repeats_and_ignores_dict_order():
    request = _request(_alert())
    assert cache.cache_key(request, 1) != cache.cache_key(request, 2)
    reordered = dict(reversed(list(request.items())))
    assert cache.cache_key(reordered, 1) == cache.cache_key(request, 1)


# ── hits, misses and modes ──────────────────────────────────────────────────
def test_second_call_is_replayed_from_the_cache(fake_claude, response_cache):
    fresh = client.analyse_alert(_alert())
    replay = client.analyse_alert(_alert())
    assert len(fake_claude.calls) == 1
    assert (fresh["cache_hit"], replay["cache_hit"]) == (False, True)
    assert fresh["cache_key"] == replay["cache_key"]
    # the replayed row is the fresh row, parsed again from the stored response
    assert {**fresh, "cache_hit": True} == replay

    entry = json.loads(cache.entry_path(fresh["cache_key"]).read_text())
    assert entry["request"] == fake_claude.calls[0]
    assert entry["response"]["id"] == "msg_fake_1"
    assert entry["prompt_version"] == prompt.prompt_version("A") and entry["format"] == "A"
    assert entry["repeat"] == 1
    assert cache.entry_path(fresh["cache_key"]).is_relative_to(response_cache)


def test_each_repeat_is_its_own_sample(fake_claude):
    client.analyse_alert(_alert(), repeat=1)
    row = client.analyse_alert(_alert(), repeat=2)
    assert len(fake_claude.calls) == 2 and row["repeat"] == 2 and not row["cache_hit"]


def test_refresh_calls_again_and_keeps_the_old_entry(fake_claude, response_cache):
    first = client.analyse_alert(_alert())
    fake_claude.reply = {"event_type": "second answer"}
    second = client.analyse_alert(_alert(), cache_mode="refresh")
    assert len(fake_claude.calls) == 2 and not second["cache_hit"]
    assert client.analyse_alert(_alert())["llm_output"] == {"event_type": "second answer"}
    files = sorted(p.name for p in cache.entry_path(first["cache_key"]).parent.iterdir())
    assert len(files) == 2 and any(".superseded-" in f for f in files)   # nothing overwritten


def test_cache_only_never_calls(fake_claude):
    with pytest.raises(cache.CacheMiss):
        client.analyse_alert(_alert(), cache_mode="only")
    assert fake_claude.calls == []
    client.analyse_alert(_alert())
    assert client.analyse_alert(_alert(), cache_mode="only")["cache_hit"] is True
    with pytest.raises(ValueError):
        client.analyse_alert(_alert(), cache_mode="sometimes")


def test_refusals_and_parse_failures_are_cached_as_answers(fake_claude):
    fake_claude.stop_reason = "refusal"
    fake_claude.stop_details = {"type": "refusal", "category": "cyber", "explanation": "e"}
    client.analyse_alert(_alert())
    replay = client.analyse_alert(_alert())
    assert len(fake_claude.calls) == 1 and replay["cache_hit"]
    assert replay["llm_output"] == {"error": "refusal", "category": "cyber", "explanation": "e"}


def test_an_entry_that_does_not_match_its_key_is_rejected(fake_claude):
    key = client.analyse_alert(_alert())["cache_key"]
    path = cache.entry_path(key)
    entry = json.loads(path.read_text())
    entry["request"]["model"] = "edited"
    path.write_text(json.dumps(entry))
    with pytest.raises(ValueError, match="does not match"):
        client.analyse_alert(_alert())


# ── the batch runner and the CLI ────────────────────────────────────────────
def test_batch_cache_only_writes_nothing_on_a_miss(fake_claude, session_dir, tmp_path, data_dir):
    out = tmp_path / "o.jsonl"
    batch.run(session=str(session_dir), out=str(out), cache_mode="only")
    batch.run(session=str(session_dir), variant="cold", cache_mode="only")
    assert not out.exists() and fake_claude.calls == []
    assert not list((data_dir / "outputs" / "wp3").glob(f"{session_dir.name}/cold_v*"))

    batch.run(session=str(session_dir), out=str(tmp_path / "warm.jsonl"))
    batch.run(session=str(session_dir), out=str(out), cache_mode="only")
    assert len(fake_claude.calls) == 6 and all(r["cache_hit"] for r in read_jsonl(out))
    meta = json.loads((tmp_path / "o_meta.json").read_text())["invocations"][-1]
    assert (meta["cache_hits"], meta["api_calls"], meta["tokens_billed"]) == (6, 0, 0)
    assert meta["cli_args"]["cache_mode"] == "only"


@pytest.mark.parametrize("flags,mode", [([], "use"), (["--no-cache"], "refresh"),
                                        (["--cache-only"], "only")])
def test_cli_cache_flags(monkeypatch, flags, mode):
    seen = {}
    monkeypatch.setattr(batch, "run", lambda **kw: seen.update(kw))
    cli.main(["triage", "--session", "s", "--repeat", "2", *flags])
    assert (seen["cache_mode"], seen["repeat"]) == (mode, 2)


def test_cli_cache_flags_are_exclusive():
    with pytest.raises(SystemExit):
        cli.build_parser().parse_args(["triage", "--no-cache", "--cache-only"])


def test_evaluation_cannot_reach_the_api():
    # re-scoring and re-reporting (map, metrics) read triage rows from files;
    # their modules do not even import the SDK
    code = ("import sys, cjp.evaluate.mapper, cjp.evaluate.metrics, cjp.evaluate.report, "
            "cjp.evaluate.charts, cjp.evaluate.score, cjp.evaluate.calibration; "
            "sys.exit('anthropic' in sys.modules)")
    assert subprocess.run([sys.executable, "-c", code], cwd=REPO_ROOT).returncode == 0
