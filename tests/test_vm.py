"""`cjp vm deploy` pieces that can be checked without the VM (Plan P2.2)."""

import re
import subprocess

import pytest

from cjp import config, vm
from cjp.config import REPO_ROOT


def test_agent_paths_match_the_indexer_patterns():
    # If these drift apart, an arm's alerts are silently never collected.
    assert set(vm.expected_localfiles()) == set(config.ARM_LOCATION_PATTERNS.values())
    assert all(p.startswith(config.VM_ROOT + "/juice-shop/data/logs/") for p in vm.expected_localfiles())


def test_vm_scripts_no_longer_hardcode_the_old_checkout():
    for path in (REPO_ROOT / "vm").rglob("*"):
        if path.is_file() and path.suffix in {".sh", ".py", ".yml", ".xml"}:
            assert "juice-shop-wazuh/" not in path.read_text(), path   # a path into it


def test_deploy_script_is_valid_bash():
    assert subprocess.run(["bash", "-n", str(REPO_ROOT / "vm" / "deploy.sh")]).returncode == 0


def test_logtest_cases_are_well_formed():
    cases = [line for line in (REPO_ROOT / "vm/wazuh/logtest_cases.tsv").read_text().splitlines()
             if line and not line.startswith("#")]
    assert len(cases) >= 6
    for line in cases:
        expect, log_line = line.split("\t")
        assert re.fullmatch(r"\d+:\d+:[\w-]+", expect)
        assert log_line.strip()
    # every custom rule has a case, including the silent parent
    rules = {c.split(":")[0] for c in cases}
    assert {"100010", "100011", "100012"} <= rules


@pytest.fixture
def live_localfiles(monkeypatch):
    import cjp.indexer as indexer
    files = []
    monkeypatch.setattr(indexer, "get_agent_config",
                        lambda *a: {"localfile": [{"file": f} for f in files] + [{"command": "df -P"}]})
    return files


def test_agent_check_ok_when_paths_match(live_localfiles):
    live_localfiles += vm.expected_localfiles() + ["/var/log/dpkg.log"]
    assert vm.check_agent_localfiles() == (True, None)


def test_agent_check_prints_one_sudo_command_for_old_paths(live_localfiles):
    old = "/home/jesse/juice-shop-wazuh/juice-shop/data/logs/"
    live_localfiles += [old + "access.log*", old + "enriched_access.log*",
                        old + "body_field_access.log*", "/var/log/dpkg.log"]
    ok, fix = vm.check_agent_localfiles()
    assert ok is False
    assert fix.count("sudo sed") == 1 and fix.endswith('sudo systemctl restart wazuh-agent"')
    assert f"-e 's#{old}#{config.VM_ROOT}/juice-shop/data/logs/#'" in fix
    assert "/var/ossec/etc/ossec.conf" in fix and "-i.bak-cjp-" in fix


def test_agent_check_unknown_when_api_unreachable(monkeypatch):
    import cjp.indexer as indexer
    def boom(*a):
        raise ConnectionError("tunnel down")
    monkeypatch.setattr(indexer, "get_agent_config", boom)
    assert vm.check_agent_localfiles() == (None, None)


def test_rsync_excludes_runtime_state(monkeypatch):
    seen = {}
    monkeypatch.setattr(vm, "VM_HOST", "vmhost")
    monkeypatch.setattr(subprocess, "run", lambda cmd, **kw: seen.setdefault("cmd", cmd) and
                        subprocess.CompletedProcess(cmd, 0))
    assert vm.rsync_to_vm(dry_run=True)
    cmd = seen["cmd"]
    assert cmd[:3] == ["rsync", "-n", "-rlpti"] and "--delete" in cmd
    for e in ["data/", ".venv/", "DEPLOYED_SHA", ".deploy-backup/"]:
        assert f"--exclude={e}" in cmd
    assert cmd[-2] == f"{REPO_ROOT / 'vm'}/" and cmd[-1] == f"{config.VM_USER}@vmhost:{config.VM_ROOT}/"


def test_deploy_needs_a_vm_host():
    assert vm.deploy() == 1
