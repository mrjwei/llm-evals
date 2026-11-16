"""`cjp doctor` (Plan P2.10, P2.8): every check reports a status and, when
not ok, the fix; checks that depend on a failed one are skipped, not failed
twice; the self-test treats skipped acceptance tests as a warning. The VM,
the Wazuh APIs and the Claude API are all stubbed: no network, no tokens."""

import subprocess
from types import SimpleNamespace

import pytest

from cjp import cli, config, doctor, indexer, vm


def by_name(checks):
    return {c.name: c for c in checks}


@pytest.fixture
def vm_up(monkeypatch):
    """A healthy VM: SSH, both APIs, the agent, Juice Shop, proxy, deploy."""
    monkeypatch.setattr(config, "VM_HOST", "vm.test")

    def ssh(command, timeout=10.0):
        if "curl" in command:
            return "200"
        if "start_ingest_proxy.sh status" in command:
            return "ingest proxy running (pid 42)"
        return ""
    monkeypatch.setattr(vm, "ssh_run", ssh)
    monkeypatch.setattr(vm, "deployed_sha", lambda: "a" * 40)
    monkeypatch.setattr(vm, "deployed_vm_differs", lambda sha: False)
    monkeypatch.setattr(vm, "check_agent_localfiles", lambda: (True, None))
    monkeypatch.setattr(indexer, "get_token", lambda: "t")

    class Resp:
        def __init__(self, body):
            self.body = body

        def raise_for_status(self):
            pass

        def json(self):
            return self.body

    def get(url, **kwargs):
        if url.endswith("/_cluster/health"):
            return Resp({"status": "green"})
        return Resp({"data": {"affected_items": [{"status": "active"}]}})
    monkeypatch.setattr("httpx.get", get)


def test_everything_ok_on_a_healthy_vm(vm_up):
    checks = doctor.check_vm()
    assert {c.status for c in checks} == {"ok"}, [c for c in checks if c.status != "ok"]
    assert list(by_name(checks)) == ["VM_HOST", "SSH", "manager API", "indexer", "agent",
                                     "agent log paths", "Juice Shop", "ingest proxy", "deployed vm/"]


def test_without_vm_host_the_rest_is_skipped(monkeypatch):
    monkeypatch.setattr(config, "VM_HOST", None)
    checks = doctor.check_vm()
    assert checks[0].status == "fail" and "VM_HOST" in checks[0].fix
    assert {c.status for c in checks[1:]} == {"skip"}


def test_tunnel_down_fails_the_apis_and_skips_the_agent(vm_up, monkeypatch):
    import httpx

    def refused(*args, **kwargs):
        raise httpx.ConnectError("refused", request=httpx.Request("GET", config.WAZUH_URL))
    monkeypatch.setattr(indexer, "get_token", refused)
    monkeypatch.setattr("httpx.get", refused)
    checks = by_name(doctor.check_vm())
    assert checks["manager API"].status == "fail" and "ssh -N -L" in checks["manager API"].fix
    assert checks["indexer"].status == "fail"
    assert checks["agent"].status == checks["agent log paths"].status == "skip"
    assert checks["Juice Shop"].status == "ok"      # SSH still works


def test_ssh_down_skips_the_vm_services(vm_up, monkeypatch):
    monkeypatch.setattr(vm, "ssh_run", lambda *a, **k: None)
    checks = by_name(doctor.check_vm())
    assert checks["SSH"].status == "fail" and "ssh-copy-id" in checks["SSH"].fix
    assert {checks[n].status for n in ("Juice Shop", "ingest proxy", "deployed vm/")} == {"skip"}


def test_agent_paths_print_the_sudo_command(vm_up, monkeypatch):
    monkeypatch.setattr(vm, "check_agent_localfiles", lambda: (False, "ssh -t jesse@vm \"sudo sed …\""))
    check = by_name(doctor.check_vm())["agent log paths"]
    assert check.status == "fail" and "sudo sed" in check.fix


@pytest.mark.parametrize("differs, status", [(True, "warn"), (None, "warn"), (False, "ok")])
def test_deployed_vm_against_this_checkout(vm_up, monkeypatch, differs, status):
    monkeypatch.setattr(vm, "deployed_vm_differs", lambda sha: differs)
    assert by_name(doctor.check_vm())["deployed vm/"].status == status


def test_proxy_down(vm_up, monkeypatch):
    monkeypatch.setattr(vm, "ssh_run", lambda c, timeout=10.0:
                        "ingest proxy not running" if "status" in c else "200")
    check = by_name(doctor.check_vm())["ingest proxy"]
    assert check.status == "fail" and "start_ingest_proxy.sh start" in check.fix


# ── Claude ───────────────────────────────────────────────────────────────────
def _models_api(monkeypatch, caps_for):
    from cjp.triage import client

    def retrieve(model_id):
        return SimpleNamespace(display_name=model_id.upper(),
                               to_dict=lambda: {"capabilities": caps_for(model_id)})
    fake = SimpleNamespace(models=SimpleNamespace(retrieve=retrieve))
    fake.with_options = lambda **kw: fake
    monkeypatch.setattr(client, "get_client", lambda: fake)


def test_models_are_checked_against_their_capabilities(monkeypatch):
    def caps(model_id):
        effort = model_id.startswith("claude-sonnet")
        return {"effort": {"supported": effort, "high": {"supported": effort}},
                "structured_outputs": {"supported": True}}
    _models_api(monkeypatch, caps)
    checks = by_name(doctor.check_claude())
    assert checks["API key"].status == "ok"
    assert checks["model sonnet"].status == checks["model haiku"].status == "ok"


def test_an_unsupported_effort_fails_with_the_setting_to_fix(monkeypatch):
    _models_api(monkeypatch, lambda m: {"effort": {"supported": False},
                                        "structured_outputs": {"supported": True}})
    check = by_name(doctor.check_claude())["model sonnet"]
    assert check.status == "fail" and "models.sonnet" in check.fix


def test_no_key_and_offline(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY")
    assert doctor.check_claude()[0].status == "fail"
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
    assert doctor.check_claude(offline=True)[0].status == "skip"


# ── self-test ────────────────────────────────────────────────────────────────
def _pytest_says(monkeypatch, rc, stdout):
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: SimpleNamespace(returncode=rc, stdout=stdout))


def test_selftest_green(monkeypatch):
    _pytest_says(monkeypatch, 0, "....\n232 passed in 6.1s\n")
    assert doctor.selftest().status == "ok"


def test_skipped_acceptance_tests_are_a_warning(monkeypatch):
    _pytest_says(monkeypatch, 0, "..s\nSKIPPED [3] tests/test_score.py:214: legacy evidence not "
                 "present (data/ is gitignored)\n229 passed, 3 skipped in 5s\n")
    check = doctor.selftest()
    assert check.status == "warn" and "legacy evidence not present" in check.detail
    assert "data/legacy" in check.fix


def test_selftest_failure_names_the_test(monkeypatch):
    _pytest_says(monkeypatch, 1, "F.\nFAILED tests/test_score.py::test_x - assert 1 == 2\n"
                 "1 failed, 231 passed in 5s\n")
    check = doctor.selftest()
    assert check.status == "fail" and "test_x" in check.detail


# ── the command ──────────────────────────────────────────────────────────────
def test_exit_code_and_output(monkeypatch, capsys):
    monkeypatch.setattr(doctor, "check_claude", lambda offline: [])
    assert doctor.main(offline=True) == 0
    out = capsys.readouterr().out
    assert "✓ config" in out and "· VM and Wazuh" in out

    monkeypatch.setattr(doctor, "check_config",
                        lambda: doctor.Check("local", "config", "fail", "bad", "fix it"))
    assert doctor.main(offline=True) == 1
    assert "fix: fix it" in capsys.readouterr().out


def test_doctor_runs_even_when_the_config_is_broken(monkeypatch):
    seen = []
    monkeypatch.setattr(config, "TRIAGE_MODEL_OVERRIDE", "opus")    # config.check() would fail
    monkeypatch.setattr(doctor, "main", lambda offline, run_selftest: seen.append((offline, run_selftest)) or 1)
    assert cli.main(["doctor", "--offline", "--selftest"]) == 1
    assert seen == [(True, True)]
