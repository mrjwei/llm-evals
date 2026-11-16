"""
`cjp doctor`: is every piece the pipeline needs working, and if not, what
fixes it (Plan P2.10, P2.8; the P2 acceptance check).

Each check returns a Check: a status (ok / warn / fail / skip), what it found,
and for anything not ok one command or sentence that fixes it, worded like
the errors in cjp.errors. The web app's health panel (Plan P6) calls
run_checks() and draws the same list as tiles.

Checks run in dependency order and skip what can't be known: without SSH
there is no point asking whether Juice Shop answers on the VM. Nothing here
spends API budget: the key and the model IDs are checked through the Models
API, which uses no tokens. Nothing changes state either: the Juice Shop probe
is `GET /`, which never reaches access.log (wazuh-and-vm-notes §11), and the
proxy is asked for its status, not sent a request.

`--selftest` also runs the offline test suite (Plan P2.8). Skipped tests are a
warning, not a pass: the golden and audit tests skip when data/legacy/ is
absent, and they are the P2 acceptance checks.
"""

import os
import re
import subprocess
import sys
import tempfile
from dataclasses import asdict, dataclass

from cjp import config, errors, vm

STATUSES = ("ok", "warn", "fail", "skip")
SYMBOLS = {"ok": "✓", "warn": "!", "fail": "✗", "skip": "·"}


@dataclass
class Check:
    group: str            # "local", "claude", "vm" or "tests"
    name: str
    status: str           # one of STATUSES
    detail: str
    fix: str | None = None

    def to_dict(self) -> dict:
        return asdict(self)


# ── local ────────────────────────────────────────────────────────────────────
def check_config() -> Check:
    errs, warns = config.validate()
    if errs:
        return Check("local", "config", "fail", "; ".join(errs),
                     "fix config/settings.yaml or .env (every variable is in .env.example)")
    if warns:
        return Check("local", "config", "warn", "; ".join(warns))
    return Check("local", "config", "ok", "config/settings.yaml, .env and the tracked inputs are valid")


def check_env_file() -> Check:
    if (config.REPO_ROOT / ".env").is_file():
        return Check("local", ".env", "ok", "present")
    return Check("local", ".env", "warn", "no .env in the repo root; only the defaults apply",
                 "cp .env.example .env, then fill in the key, passwords and VM_HOST")


def check_data_dir() -> Check:
    try:
        config.DATA_DIR.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(dir=config.DATA_DIR, prefix=".doctor-"):
            pass
    except OSError as e:
        return Check("local", "data dir", "fail", f"{config.DATA_DIR} is not writable ({e})",
                     "fix the permissions, or point CJP_DATA_DIR at a writable directory")
    return Check("local", "data dir", "ok", f"{config.DATA_DIR} is writable")


def check_git() -> Check:
    from cjp.runs import git_describe
    describe = git_describe()
    if describe is None:
        return Check("local", "git", "warn", "not a git checkout; runs record no git SHA",
                     "run cjp from the repo clone")
    if describe.endswith("-dirty"):
        return Check("local", "git", "warn", f"{describe}: uncommitted changes, so runs record "
                     "-dirty and can't be canonical without a decision record",
                     "commit (or stash) before a research run")
    return Check("local", "git", "ok", describe)


# ── Claude API ───────────────────────────────────────────────────────────────
def check_claude(offline: bool = False) -> list[Check]:
    """The API key, then every model in settings.yaml: does the ID exist for
    this key, and does it support the effort and structured outputs we send?"""
    key = os.getenv("ANTHROPIC_API_KEY") or ""
    if not key:
        return [Check("claude", "API key", "fail", "ANTHROPIC_API_KEY is not set",
                      "add ANTHROPIC_API_KEY=sk-ant-… to .env")]
    if offline:
        return [Check("claude", "API key", "skip", "set; not checked (--offline)")]
    try:
        models = config.settings()["models"]
    except Exception as e:    # check_config reports the cause
        return [Check("claude", "models", "skip", f"settings unreadable ({e})")]

    import anthropic

    from cjp.triage.client import get_client
    checks = []
    for alias, spec in models.items():
        try:
            info = get_client().with_options(max_retries=1, timeout=15).models.retrieve(spec["id"])
        except anthropic.AuthenticationError as e:
            return [Check("claude", "API key", "fail", "rejected by the Claude API",
                          errors.explain(e))]
        except anthropic.APIError as e:
            checks.append(Check("claude", f"model {alias}", "fail", f"{spec['id']}: "
                                f"{getattr(e, 'message', e)}", errors.explain(e)))
            continue
        caps = (info.to_dict().get("capabilities") or {})
        problems = []
        if spec.get("effort") and not (caps.get("effort") or {}).get(spec["effort"], {}).get("supported"):
            problems.append(f"effort {spec['effort']!r} not supported")
        if caps.get("structured_outputs", {}).get("supported") is False:
            problems.append("no structured outputs (output_config.format)")
        if problems:
            checks.append(Check("claude", f"model {alias}", "fail", f"{spec['id']}: "
                                + "; ".join(problems),
                                f"fix models.{alias} in config/settings.yaml"))
        else:
            checks.append(Check("claude", f"model {alias}", "ok", f"{spec['id']} ({info.display_name})"))
    if checks and all(c.status == "ok" for c in checks):
        checks.insert(0, Check("claude", "API key", "ok", "accepted (Models API; no tokens used)"))
    return checks


# ── VM, Wazuh, Juice Shop ────────────────────────────────────────────────────
def _skip_all(names: list[str], why: str) -> list[Check]:
    return [Check("vm", n, "skip", why) for n in names]


def check_vm() -> list[Check]:
    import httpx

    from cjp import indexer
    later = ["SSH", "manager API", "indexer", "agent", "agent log paths", "Juice Shop",
             "ingest proxy", "deployed vm/"]
    if not config.VM_HOST:
        return [Check("vm", "VM_HOST", "fail", "not set in .env", errors.ssh_fix())] + \
            _skip_all(later, "needs VM_HOST")
    checks = [Check("vm", "VM_HOST", "ok", f"{config.VM_USER}@{config.VM_HOST}")]

    ssh_ok = vm.ssh_run("true") is not None
    checks.append(Check("vm", "SSH", "ok", "key-based, non-interactive") if ssh_ok else
                  Check("vm", "SSH", "fail", f"cannot reach {config.VM_USER}@{config.VM_HOST}",
                        errors.ssh_fix()))

    manager_ok = False
    try:
        indexer.get_token()
        manager_ok = True
        checks.append(Check("vm", "manager API", "ok", config.WAZUH_URL))
    except Exception as e:
        checks.append(Check("vm", "manager API", "fail", f"{config.WAZUH_URL}: {type(e).__name__}",
                            errors.explain(e) or f"run: {errors.tunnel_command()}"))

    try:
        r = httpx.get(f"{config.INDEXER_URL}/_cluster/health", verify=False, timeout=5,
                      auth=(config.INDEXER_USER, config.INDEXER_PASS))
        r.raise_for_status()
        health = r.json().get("status")
        checks.append(Check("vm", "indexer", "ok" if health in ("green", "yellow") else "warn",
                            f"{config.INDEXER_URL}, cluster {health}",
                            None if health in ("green", "yellow") else
                            "on the VM: cd ~/wazuh-docker/single-node && docker compose ps"))
    except Exception as e:
        checks.append(Check("vm", "indexer", "fail", f"{config.INDEXER_URL}: {type(e).__name__}",
                            errors.explain(e) or f"run: {errors.tunnel_command()}"))

    if manager_ok:
        checks += _check_agent()
    else:
        checks += _skip_all(["agent", "agent log paths"], "needs the manager API")

    if ssh_ok:
        checks += _check_vm_services()
    else:
        checks += _skip_all(["Juice Shop", "ingest proxy", "deployed vm/"], "needs SSH")
    return checks


def _check_agent() -> list[Check]:
    import httpx

    from cjp import indexer
    agent = config.WAZUH_AGENT_ID
    detail = None
    try:
        r = httpx.get(f"{config.WAZUH_URL}/agents", params={"agents_list": agent}, verify=False,
                      timeout=5, headers={"Authorization": f"Bearer {indexer.get_token()}"})
        r.raise_for_status()
        items = r.json()["data"]["affected_items"]
        status = items[0]["status"] if items else "unknown"
    except Exception as e:
        status, detail = None, f"{type(e).__name__}: {e}"
    if status == "active":
        checks = [Check("vm", "agent", "ok", f"agent {agent} active")]
    else:
        checks = [Check("vm", "agent", "fail", f"agent {agent} is {status or detail}",
                        "on the VM (sudo, Jesse): sudo systemctl restart wazuh-agent")]
    ok, fix = vm.check_agent_localfiles()
    if ok:
        checks.append(Check("vm", "agent log paths", "ok", f"tails the three arms under {config.VM_ROOT}"))
    elif ok is False:
        checks.append(Check("vm", "agent log paths", "fail", "the agent does not tail the deployed "
                            "logs, so Wazuh would see no traffic", f"run (sudo, Jesse): {fix}"))
    else:
        checks.append(Check("vm", "agent log paths", "skip", "manager API did not answer"))
    return checks


def _check_vm_services() -> list[Check]:
    checks = []
    code = vm.ssh_run("curl -s -o /dev/null -w '%{http_code}' http://localhost:3000/")
    checks.append(Check("vm", "Juice Shop", "ok", "http://localhost:3000 answers 200") if code == "200"
                  else Check("vm", "Juice Shop", "fail", f"http://localhost:3000 answered {code or 'nothing'}",
                             f"on the VM: cd {config.VM_ROOT}/juice-shop && docker compose up -d "
                             "(or: cjp vm deploy)"))
    status = vm.ssh_run(f"bash {config.VM_ROOT}/juice-shop/start_ingest_proxy.sh status") or ""
    checks.append(Check("vm", "ingest proxy", "ok", status) if "running (pid" in status else
                  Check("vm", "ingest proxy", "fail", status or "status unknown",
                        f"on the VM: bash {config.VM_ROOT}/juice-shop/start_ingest_proxy.sh start "
                        "(or: cjp vm deploy)"))
    sha = vm.deployed_sha()
    if sha is None:
        checks.append(Check("vm", "deployed vm/", "fail", f"no {config.VM_ROOT}/DEPLOYED_SHA",
                            "cjp vm deploy"))
    else:
        differs = vm.deployed_vm_differs(sha)
        label = f"{sha[:12]}{sha[40:]}"
        if differs:
            checks.append(Check("vm", "deployed vm/", "warn", f"{label}; this checkout's vm/ differs",
                                "cjp vm deploy (commit vm/ first)"))
        elif differs is None:
            checks.append(Check("vm", "deployed vm/", "warn", f"{label}; can't compare with this "
                                "checkout (a -dirty deploy, or a commit this clone lacks)",
                                "cjp vm deploy"))
        else:
            checks.append(Check("vm", "deployed vm/", "ok", f"{label}, same vm/ as this checkout"))
    return checks


# ── self-test (Plan P2.8) ────────────────────────────────────────────────────
_SUMMARY = re.compile(r"(\d+) (passed|failed|skipped|errors?|xfailed|xpassed|deselected)")


def selftest() -> Check:
    """Run the offline test suite (no API calls, no VM, no writes to data/)."""
    try:
        import pytest  # noqa: F401
    except ImportError:
        return Check("tests", "pytest", "fail", "pytest is not installed",
                     "uv sync (installs the dev group, which has pytest)")
    proc = subprocess.run([sys.executable, "-m", "pytest", "-q", "-rs", "-p", "no:cacheprovider",
                           str(config.REPO_ROOT / "tests")], cwd=config.REPO_ROOT,
                          capture_output=True, text=True)
    tail = proc.stdout.strip().splitlines()
    counts = {k.rstrip("s") if k.startswith("error") else k: int(n)
              for n, k in _SUMMARY.findall(tail[-1] if tail else "")}
    summary = ", ".join(f"{n} {k}" for k, n in counts.items()) or "no summary"
    if proc.returncode != 0:
        failed = [line for line in tail if line.startswith(("FAILED", "ERROR"))][:5]
        return Check("tests", "pytest", "fail", summary + ("; " + "; ".join(failed) if failed else ""),
                     "uv run pytest -x for the first failure")
    if counts.get("skipped"):
        reasons = sorted({line.split(": ", 1)[-1] for line in tail if line.startswith("SKIPPED")})
        return Check("tests", "pytest", "warn", f"{summary}; skipped: {'; '.join(reasons)}",
                     "the golden and audit tests need data/legacy/ (gitignored; restore it from "
                     "the P0 archive) to run")
    return Check("tests", "pytest", "ok", summary)


# ── driver ───────────────────────────────────────────────────────────────────
def run_checks(offline: bool = False, run_selftest: bool = False) -> list[Check]:
    checks = [check_config(), check_env_file(), check_data_dir(), check_git()]
    checks += check_claude(offline)
    if offline:
        checks += [Check("vm", "VM and Wazuh", "skip", "not checked (--offline)")]
    else:
        checks += check_vm()
    if run_selftest:
        checks.append(selftest())
    return checks


def print_checks(checks: list[Check]) -> None:
    group = None
    for c in checks:
        if c.group != group:
            group = c.group
            print(f"\n{group}")
        print(f"  {SYMBOLS[c.status]} {c.name:<16} {c.detail}")
        if c.fix and c.status in ("warn", "fail"):
            print(f"    {'':<16} fix: {c.fix}")
    counts = {s: sum(1 for c in checks if c.status == s) for s in STATUSES}
    print("\n" + ", ".join(f"{n} {s}" for s, n in counts.items() if n))


def main(offline: bool = False, run_selftest: bool = False) -> int:
    """Exit code: 0 when nothing failed (warnings allowed), else 1."""
    checks = run_checks(offline, run_selftest)
    print_checks(checks)
    return 1 if any(c.status == "fail" for c in checks) else 0
