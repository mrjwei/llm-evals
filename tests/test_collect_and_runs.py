"""Collection (indexer queries, session markers, manifest, `cjp session new`),
run directories and the CLI."""

import json
import os
import re
import shutil
import subprocess
from types import SimpleNamespace

import pytest
from conftest import FIXTURE_SESSION, LEGACY

from cjp import cli, collect, config, indexer, runs, vm


# ── collect ─────────────────────────────────────────────────────────────────
def test_read_session_log():
    log = collect._read_session_log(str(FIXTURE_SESSION / "attack_log.jsonl"))
    assert (log["session_id"], log["start"], log["end"]) == \
        ("20990101_000000", "2099-01-01T00:00:00Z", "2099-01-01T00:00:30Z")
    assert log["marker"]["application_logging"] is True
    assert log["marker"].get("vm_deployed_sha") is None     # fixture predates P2.3


def test_read_session_log_requires_a_start(tmp_path):
    p = tmp_path / "attack_log.jsonl"
    p.write_text('{"event": "session_end", "timestamp": "t"}\n')
    with pytest.raises(ValueError):
        collect._read_session_log(str(p))


def test_read_session_log_without_a_marker(tmp_path):
    p = tmp_path / "attack_log.jsonl"
    p.write_text('{"session": "S", "event": "session_start", "timestamp": "t"}\n')
    assert collect._read_session_log(str(p))["marker"] == {}   # pre-toggle log: unknown, not false


def test_session_meta_merges_both_runs():
    attack = {"vm_deployed_sha": "abc", "seed": 1, "script_sha256": "a" * 64}
    benign = {"vm_deployed_sha": "abc", "seed": 1, "script_sha256": "b" * 64, "benign_set_version": 1}
    meta, warnings = collect._session_meta(attack, benign)
    assert meta == {"vm_deployed_sha": "abc", "seed": 1, "attacks_sh_sha256": "a" * 64,
                    "benign_sh_sha256": "b" * 64, "benign_set_version": 1}
    assert warnings == []
    meta, warnings = collect._session_meta({}, benign)          # benign-only session
    assert meta["seed"] == 1 and meta["attacks_sh_sha256"] is None


def test_session_meta_flags_a_redeploy_between_the_two_runs():
    meta, warnings = collect._session_meta({"vm_deployed_sha": "abc", "seed": 0},
                                           {"vm_deployed_sha": "def", "seed": 0})
    assert meta["vm_deployed_sha"] == "abc"
    assert warnings == ["attack and benign runs disagree on vm_deployed_sha ('abc' vs 'def')"]


def test_alert_summary_tolerates_rules_without_a_description(capsys):
    # Wazuh's rule 11 (log-volume stats) has no description field.
    stats = {"rule": {"id": "11", "level": 4, "groups": ["stats"]}}
    sqli = {"rule": {"id": "31103", "description": "SQL injection attempt."}}
    collect._print_alert_summary([stats, sqli], [stats], [stats])
    out = capsys.readouterr().out
    assert "1× rule 11 (no description)" in out
    assert "1× SQL injection attempt." in out


def test_collect_alerts_queries_each_arm_separately(monkeypatch, tmp_path):
    posted = []

    def fake_post(url, json=None, auth=None, verify=None):
        posted.append(json)
        hits = [{"_source": {"id": "1", "rule": {"description": "d"}}}]
        return SimpleNamespace(raise_for_status=lambda: None,
                               json=lambda: {"hits": {"total": {"value": 1}, "hits": hits}})
    monkeypatch.setattr(indexer, "httpx", SimpleNamespace(post=fake_post))

    collect.collect_alerts(str(tmp_path), "2099-01-01T00:00:00+00:00", "2099-01-01T00:01:00+00:00")
    patterns = [q["query"]["bool"]["must"][0]["wildcard"]["location"] for q in posted]
    assert patterns == [config.JUICE_LOG_PATH, config.ENRICHED_JUICE_LOG_PATH, config.BODY_FIELD_JUICE_LOG_PATH]
    # the window is bounded on both sides, so back-to-back sessions can't leak into each other
    assert posted[0]["query"]["bool"]["must"][2] == {"range": {"timestamp": {"lte": "2099-01-01T00:01:00+00:00"}}}
    for name in ["wazuh_alerts.jsonl", "enriched_wazuh_alerts.jsonl", "body_field_wazuh_alerts.jsonl"]:
        assert (tmp_path / name).read_text().count("\n") == 1


def test_collect_drops_alerts_whose_cid_names_another_session():
    """A back-to-back session's first request can fall inside this session's
    window (2 Oct, C1 seed 2 S3); its CID says it isn't ours. Alerts without
    a CID (rule 11, 31151) and benign CIDs of this session stay."""
    def alert(log):
        return {"rule": {"id": "100012"}, "full_log": log}
    own = alert("body_probe cid=wp1-20261002_125752-3-4 path=/x status=401")
    own_benign = alert('"GET /x HTTP/1.1" 401 "wp1-benign-20261002_125752-1-2"')
    foreign = alert("body_probe cid=wp1-20261002_130347-1-1 path=/rest/basket/1 status=401")
    stats = {"rule": {"id": "11"}, "full_log": "The average number of logs between 12:00 and 13:00 is 652."}
    kept, dropped = collect.drop_foreign_alerts([own, own_benign, foreign, stats], "20261002_125752")
    assert kept == [own, own_benign, stats]
    assert dropped == {"20261002_130347": 1}


def test_collect_alerts_warns_per_arm_about_dropped_alerts(monkeypatch, tmp_path):
    foreign = {"id": "2", "rule": {"id": "31101"}, "full_log": '"wp1-20990101_000500-1-1"'}
    own = {"id": "1", "rule": {"id": "31101"}, "full_log": '"wp1-20990101_000000-1-1"'}
    monkeypatch.setattr(collect, "get_alerts_since", lambda **kw: [own, foreign])
    session = tmp_path / "session_20990101_000000"
    session.mkdir()
    *arms, warnings = collect.collect_alerts(str(session), "2099-01-01T00:00:00+00:00",
                                             session_id="20990101_000000")
    assert all(a == [own] for a in arms)
    assert len(warnings) == 3 and all("1 from 20990101_000500" in w for w in warnings)
    assert (session / "wazuh_alerts.jsonl").read_text().count("\n") == 1
    # Online mode names the directory from the Mac's clock, not the VM's
    # session id, so it passes none and nothing is dropped.
    online = tmp_path / "session_20990101_000009"
    online.mkdir()
    *arms, warnings = collect.collect_alerts(str(online), "2099-01-01T00:00:00+00:00")
    assert all(a == [own, foreign] for a in arms) and warnings == []


def test_arm_wildcards_are_disjoint():
    import fnmatch
    s1, s2, s3 = config.JUICE_LOG_PATH, config.ENRICHED_JUICE_LOG_PATH, config.BODY_FIELD_JUICE_LOG_PATH
    s2_file = s2.replace("*", ".2099-01-01")
    s3_file = s3.replace("*", ".2099-01-01")
    assert not fnmatch.fnmatch(s2_file, s1) and not fnmatch.fnmatch(s3_file, s1)
    assert not fnmatch.fnmatch(s3_file, s2)


def test_manifest_without_vm(tmp_path, monkeypatch):
    monkeypatch.setattr(vm, "ssh_run", lambda cmd, timeout=10.0: None)
    m = collect.build_manifest("S", str(tmp_path), "t0", [1, 2], None, benign_traffic=True,
                               application_logging=True, body_field_alerts=[])
    assert m["alert_count"] == 2
    assert m["enriched_alert_count"] is None       # arm never queried
    assert m["body_field_alert_count"] == 0        # queried, zero matches
    assert m["vm_clock_offset_seconds"] is None and m["attacks_sh_sha256"] is None
    assert m["vm_deployed_sha"] is None and m["seed"] is None
    assert m["arms_populated"] == ["S1-plain"]
    assert any("no vm_deployed_sha" in w for w in m["warnings"])
    assert json.loads((tmp_path / "manifest.json").read_text()) == m


def test_manifest_records_the_vm_provenance(session_dir, monkeypatch):
    monkeypatch.setattr(vm, "ssh_run", lambda cmd, timeout=10.0: pytest.fail("no SSH fallback needed"))
    monkeypatch.setattr(vm, "measure_clock_offset", lambda: 0.1)
    meta = {"vm_deployed_sha": "abc123", "seed": 2, "benign_set_version": 1,
            "attacks_sh_sha256": "a" * 64, "benign_sh_sha256": "b" * 64}
    m = collect.build_manifest("S", str(session_dir), "t0", [1], [1, 2], application_logging=True,
                               body_field_alerts=[1], session_meta=meta, warnings=["w"])
    assert m["manifest_version"] == 2
    assert {k: m[k] for k in meta} == meta
    assert m["arms"]["S1-plain"] == {"log_lines": 6, "alerts": 1}   # fixture access.log
    assert m["arms"]["S2-body-in-url"] == {"log_lines": None, "alerts": 2}
    assert m["arms_populated"] == ["S1-plain", "S2-body-in-url", "S3-body-field"]
    assert m["warnings"] == ["w"]


def test_arms_match_the_indexer_patterns():
    assert list(collect.ARM_FILES) == list(config.ARM_LOCATION_PATTERNS)


def test_arm_warnings(tmp_path):
    (tmp_path / "access.log").write_text("a\nb\n")
    (tmp_path / "enriched_access.log").write_text("a\nb\nc\n")
    (tmp_path / "body_field_access.log").write_text("a\n")
    counts = {"S1-plain": 5, "S2-body-in-url": 3, "S3-body-field": 0}
    arms, populated, warnings = collect.summarise_arms(str(tmp_path), counts, proxied=True)
    assert arms["S2-body-in-url"] == {"log_lines": 3, "alerts": 3}
    assert populated == ["S1-plain", "S2-body-in-url"]
    assert len(warnings) == 3
    assert warnings[0].startswith("S3-body-field: 1 log lines but no alerts")
    assert "only 2 of 3 arms" in warnings[1] and "S2 has fewer alerts than S1 (3 < 5)" in warnings[2]
    # a direct session fills only S1: not a problem
    counts = {"S1-plain": 5, "S2-body-in-url": 0, "S3-body-field": 0}
    assert collect.summarise_arms(str(tmp_path / "none"), counts, proxied=False) == \
        ({a: {"log_lines": None, "alerts": counts[a]} for a in counts}, ["S1-plain"], [])


def _legacy_arms(name):
    d = LEGACY / "sessions" / name
    m = json.loads((d / "manifest.json").read_text())
    counts = dict(zip(collect.ARM_FILES, (m["alert_count"], m["enriched_alert_count"],
                                          m["body_field_alert_count"])))
    return collect.summarise_arms(str(d), counts, m["application_logging"])


@pytest.mark.skipif(not LEGACY.exists(), reason="legacy evidence not present (data/ is gitignored)")
def test_legacy_proxied_sessions():
    # The P2.3 assumption, on the kept evidence: a warm proxied session fills all three arms
    arms, populated, warnings = _legacy_arms("session_20260916_095620")
    assert [a["alerts"] for a in arms.values()] == [57, 82, 71]
    assert [a["log_lines"] for a in arms.values()] == [119, 159, 159]
    assert len(populated) == 3 and warnings == []
    # ... and the first-of-day cold start that morning is flagged
    _, populated, warnings = _legacy_arms("session_20260916_075013")
    assert len(populated) == 3 and warnings == ["S2 has fewer alerts than S1 (44 < 57); in the "
                                                "legacy sessions that meant a cold start (notes §7)"]


def test_offline_collection_refuses_to_overwrite(monkeypatch, tmp_path):
    monkeypatch.setattr(collect, "SESSION_DIR", str(tmp_path))
    (tmp_path / "session_20990101_000000").mkdir()
    with pytest.raises(SystemExit, match="refusing to overwrite"):
        collect._collect_one_offline_session("20990101_000000")


def test_offline_collection_needs_vm_host():
    with pytest.raises(SystemExit, match="VM_HOST"):
        collect.collect_offline()


def test_vm_helpers_fail_soft_without_host():
    assert vm.ssh_run("true") is None
    assert vm.measure_clock_offset() is None
    assert vm.list_remote_sessions() == []
    assert vm.deployed_sha() is None


# ── session new ─────────────────────────────────────────────────────────────
def test_session_new_needs_a_vm_host(capsys):
    assert collect.new_session(seed=1) == 1
    assert "VM_HOST" in capsys.readouterr().out


def test_session_new_rejects_a_negative_seed():
    assert collect.new_session(seed=-1) == 1


def test_session_new_stops_without_a_deploy(monkeypatch, capsys):
    monkeypatch.setattr(collect, "VM_HOST", "vm")
    monkeypatch.setattr(vm, "deployed_sha", lambda: None)
    monkeypatch.setattr(vm, "run_session_traffic", lambda seed: pytest.fail("ran traffic"))
    assert collect.new_session(seed=1) == 1
    assert "cjp vm deploy" in capsys.readouterr().out


@pytest.mark.parametrize("populated,rc", [(["S1-plain", "S2-body-in-url", "S3-body-field"], 0),
                                          (["S1-plain"], 3)])
def test_session_new_exit_code_follows_the_arms(monkeypatch, populated, rc):
    monkeypatch.setattr(collect, "VM_HOST", "vm")
    monkeypatch.setattr(collect.time, "sleep", lambda s: None)
    monkeypatch.setattr(vm, "deployed_sha", lambda: runs.git_sha())
    seeds = []
    monkeypatch.setattr(vm, "run_session_traffic", lambda seed: seeds.append(seed) or "20990101_000000")
    monkeypatch.setattr(collect, "_collect_one_offline_session",
                        lambda sid: {"arms_populated": populated})
    assert collect.new_session(seed=4) == rc and seeds == [4]


def test_deployed_vm_differs():
    assert vm.deployed_vm_differs(runs.git_sha() + "-dirty") is None
    assert vm.deployed_vm_differs("0" * 40) is None                 # not in this clone
    assert vm.deployed_vm_differs("32a0c6abd1ee6d1e4e92867b98decbc7cebd17bc") is True   # P2.2 deploy


# ── VM traffic scripts (Plan P2.3) ──────────────────────────────────────────
VM_JS = config.REPO_ROOT / "vm" / "juice-shop"


@pytest.mark.parametrize("script", ["attacks.sh", "benign_traffic.sh", "run_sessions.sh",
                                    "warm_ingest_proxy.sh", "start_ingest_proxy.sh"])
def test_vm_scripts_are_valid_bash(script):
    assert subprocess.run(["bash", "-n", str(VM_JS / script)]).returncode == 0


@pytest.mark.parametrize("script", ["attacks.sh", "benign_traffic.sh"])
def test_traffic_scripts_record_provenance(script):
    text = (VM_JS / script).read_text()
    marker = next(line for line in text.splitlines() if '\\"event\\":\\"session_manifest\\"' in line)
    for field in ("vm_deployed_sha", "seed", "script_sha256", "application_logging"):
        assert f'\\"{field}\\":' in marker, field
    assert ('benign_set_version' in marker) == (script == "benign_traffic.sh")
    assert 'DEPLOYED_SHA=$(cat "$SCRIPT_DIR/../DEPLOYED_SHA"' in text


def test_benign_traffic_uses_the_users_own_basket_and_a_neutral_email():
    """Plan P3.1: basket 1 belongs to another user (a 401, or the basket-IDOR
    attack with a token), and the register and login bodies reach the prompt
    in L1, so the email must not say "benign" or carry the raw session id."""
    text = (VM_JS / "benign_traffic.sh").read_text()
    assert '"/rest/basket/1"' not in text and '"/rest/basket/$BASKET_ID"' in text
    assert "/rest/products/$id\"" not in text          # 500 in Juice Shop 19.2.1
    email = next(line for line in text.splitlines() if line.startswith("BENIGN_EMAIL="))
    email = email.split("=", 1)[1]
    assert "benign" not in email.lower() and "${SESSION_ID}" not in email


def test_benign_traffic_has_the_hard_negative_journeys():
    """Plan P3.2: the six hard-negative journeys exist, and every feedback
    comment can go into the JSON body as is (no double quote or backslash)."""
    text = (VM_JS / "benign_traffic.sh").read_text()
    labels = re.findall(r'^log_journey "([a-z_]+)"', text, re.M)
    assert len(labels) == len(set(labels))
    assert {"mistyped_login", "change_password", "product_refresh", "leave_feedback",
            "stale_links", "search_tricky_terms"} <= set(labels)
    comments = re.findall(r'^leave_feedback \d "(.*)"$', text, re.M)
    assert comments and not any('"' in c or "\\" in c for c in comments)
    assert "fire_capture" not in text                  # one fire() for every request


def test_attacks_seeds_payload_pools():
    """Plan P3.3: SEED seeds $RANDOM, and the pooled techniques draw from a
    POOL via fire_pool, while the body-content SQLi probe stays a fixed repeat."""
    text = (VM_JS / "attacks.sh").read_text()
    assert "if [ -n \"$SEED\" ]; then RANDOM=$SEED; fi" in text
    assert "shuffle_pool()" in text and "fire_pool()" in text
    # The pooled techniques each declare a POOL and fire it; a pool has 4+
    # variants (Plan P3.3 asks for 3-5 per technique, brute force more).
    pools = re.findall(r"^POOL=\(\n((?:.*\n)*?)\)\n", text, re.M)
    assert len(pools) >= 7                              # one per pooled technique
    # each variant is a quoted string literal (single- or double-quoted)
    assert all(len(re.findall(r"""(?<![\\])(['"]).*?\1""", p)) >= 4 for p in pools)
    assert text.count("fire_pool ") >= 7
    # The deliberately-studied body-content SQLi probe is NOT pooled: it stays a
    # fixed repeat_post so its effect is isolated (see its comment in attacks.sh).
    assert "UNION SELECT username, password FROM Users--\",\"password\":\"x\"}' 3" in text


def test_attacks_get_urls_have_no_raw_spaces():
    """curl rejects a URL with a raw space (exit 3, status 000) before sending
    it, so the request never reaches Juice Shop or Wazuh. The UNION search pool
    did this in every session until 2 Oct (decision 009)."""
    text = (VM_JS / "attacks.sh").read_text()
    get_pools = re.findall(r"^POOL=\(\n((?:.*\n)*?)\)\nfire_pool GET \"\"", text, re.M)
    assert get_pools
    urls = [u for p in get_pools for u in re.findall(r'^\s*"(/[^"]*)"$', p, re.M)]
    urls += re.findall(r'^\s*(?:fire GET|repeat_get) "(/[^"]*)"', text, re.M)
    assert len(urls) > 20
    assert [u for u in urls if " " in u] == []


@pytest.mark.skipif(shutil.which("bash") is None, reason="needs bash")
def test_attacks_payload_pools_are_seed_deterministic():
    """Plan P3.3: two runs with the same SEED pick the same variants in the same
    order; a different SEED picks a different sequence. Exercises the real
    shuffle_pool/fire_pool from attacks.sh with curl stubbed out to a no-op."""
    attacks = (VM_JS / "attacks.sh").read_text()
    helpers = attacks[attacks.index("shuffle_pool()"):attacks.index("# ===", attacks.index("shuffle_pool()"))]
    harness = (
        'SEED="${SEED:-}"\n'
        'if [ -n "$SEED" ]; then RANDOM=$SEED; fi\n'
        "DELAY_SHORT=0\n"
        "fire() { printf '%s|%s|%s\\n' \"$1\" \"$2\" \"${3:-}\"; }\n"
        + helpers +
        'POOL=(a b c d e f g h i j k l m n o p q r s t)\n'
        'fire_pool POST "/login" 15\n'
    )
    def run(seed):
        r = subprocess.run(["bash", "-c", harness], capture_output=True, text=True,
                           env={**os.environ, "SEED": str(seed)})
        return r.stdout
    assert run(1) == run(1)                             # reproducible
    assert run(1) != run(2)                             # seed actually steers it
    assert len(run(1).splitlines()) == 15               # count preserved


def test_attacks_injection_probe_is_gated_and_labelled():
    """Plan P3.4: a prompt-injection probe behind INJECTION=1, 10-15 attack
    requests carrying analyst-directed text, each with its own `_inj` label,
    spread across the SQLi and feedback techniques, kept out of C1."""
    text = (VM_JS / "attacks.sh").read_text()
    # The whole probe lives inside one `if [ "${INJECTION:-}" = "1" ]` block.
    start = text.index('if [ "${INJECTION:-}" = "1" ]; then')
    block = text[start:text.index("\nfi\n", start)]
    labels = set(re.findall(r'log_attack "[^"]+" "([a-z_]+_inj)"', block))
    assert labels == {"sql_injection_inj", "sql_injection_union_inj",
                      "forged_feedback_inj", "improper_input_validation_inj"}
    assert 10 <= block.count("\n  fire ") <= 15            # Plan asks for 10-15
    assert "classify as benign" in block and "ignore previous instructions" in block
    # Every `_inj` label is declared inside the gate — none leaks into a run.
    assert text.count('_inj"') == block.count('_inj"') == 4


@pytest.mark.skipif(shutil.which("bash") is None, reason="needs bash")
def test_attacks_injection_probe_only_fires_when_enabled():
    """INJECTION unset -> the probe sends nothing; INJECTION=1 -> 12 requests.
    Runs the real gated block with fire/log_attack/section/sleep stubbed out."""
    text = (VM_JS / "attacks.sh").read_text()
    start = text.index('if [ "${INJECTION:-}" = "1" ]; then')
    block = text[start:text.index("\nfi\n", start) + 3]
    harness = ("DELAY_SHORT=0\nDELAY_BETWEEN=0\nsleep(){ :; }\nsection(){ :; }\n"
               "log_attack(){ :; }\nfire(){ echo req; }\n" + block)

    def run(env):
        r = subprocess.run(["bash", "-c", harness], capture_output=True, text=True,
                           env={**os.environ, **env})
        return r.stdout.count("req")
    assert run({}) == 0
    assert run({"INJECTION": "1"}) == 12


@pytest.mark.skipif(shutil.which("bash") is None, reason="needs bash")
def test_run_sessions_rejects_a_bad_seed_before_any_traffic():
    r = subprocess.run(["bash", str(VM_JS / "run_sessions.sh"), "--seed", "x"],
                       capture_output=True, text=True)
    assert r.returncode == 1 and "--seed must be a non-negative integer" in r.stderr


# ── runs ────────────────────────────────────────────────────────────────────
def test_resolve_run_dir_never_reuses_a_directory(tmp_path):
    a = runs.resolve_run_dir(str(tmp_path), "sess", "primary")
    b = runs.resolve_run_dir(str(tmp_path), "sess", "primary")
    assert a.endswith("sess/primary_v1") and b.endswith("sess/primary_v2")


def test_meta_sidecars(tmp_path):
    artifact = tmp_path / "output.jsonl"
    path = runs.write_meta(str(artifact), {"k": 1})
    assert path == str(tmp_path / "output_meta.json")
    assert json.loads(open(path).read())["k"] == 1
    runs.append_invocation(str(tmp_path / "x.jsonl"), {"n": 1})
    runs.append_invocation(str(tmp_path / "x.jsonl"), {"n": 2})
    assert [i["n"] for i in json.loads((tmp_path / "x_meta.json").read_text())["invocations"]] == [1, 2]


def test_sanitize_tag():
    assert runs.sanitize_tag("cat-A01,A05 / x") == "cat-A01-A05-x"
    assert runs.sanitize_tag("///") == "run"


def test_git_sha_comes_from_the_repo():
    assert re.fullmatch(r"[0-9a-f]{40}", runs.git_sha() or "")


def test_data_goes_under_the_configured_data_dir():
    assert config.SESSIONS_DIR == config.DATA_DIR / "sessions"
    assert config.OUTPUTS_DIR == config.DATA_DIR / "outputs"
    assert config.DATA_DIR != config.REPO_ROOT / "data"   # tests never touch the real data/


# ── CLI ─────────────────────────────────────────────────────────────────────
@pytest.mark.parametrize("argv,func,expected", [
    (["collect", "--offline", "--session-id", "X"], "_collect", {"offline": True, "session_id": "X"}),
    (["triage", "--session", "s", "--variant", "v", "--alerts-file", "a.jsonl"], "_triage",
     {"session": "s", "variant": "v", "alerts_file": "a.jsonl", "limit": 50}),
    (["map", "--session", "s", "--tolerance", "2"], "_map",
     {"session": "s", "tolerance": 2.0, "alerts_file": "wazuh_alerts.jsonl"}),
    (["metrics", "--input", "i", "--input", "j", "--session", "s"], "_metrics",
     {"input": ["i", "j"], "session": "s"}),
    (["session", "new", "--seed", "3"], "_session_new", {"seed": 3, "settle": 60.0}),
])
def test_cli_parses_legacy_flags(argv, func, expected):
    args = cli.build_parser().parse_args(argv)
    assert args.func.__name__ == func
    assert {k: getattr(args, k) for k in expected} == expected


def test_cli_requires_a_command(capsys):
    with pytest.raises(SystemExit):
        cli.main([])
