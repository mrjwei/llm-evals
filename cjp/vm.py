"""
Everything that talks to the UTM VM: SSH helpers (moved out of
wp2_collector.py in Plan P2.1), and `cjp vm deploy` / `cjp vm smoke`
(Plan P2.2). All SSH calls are non-interactive (BatchMode), so a missing key
fails fast instead of hanging on a password prompt.

Deploy = rsync the repo's vm/ to VM_ROOT (~/cjp-vm), run vm/deploy.sh there
(rules, logtest, Juice Shop container, proxy, DEPLOYED_SHA), check the
agent's <localfile> paths through the manager API, then smoke-test that one
request raises an alert in every SIEM evidence arm. Nothing here uses sudo:
the one step that needs it is printed for Jesse to run.

`cjp session new` (Plan P2.3) runs a session's traffic here, through
run_sessions.sh in the deployed VM_ROOT; cjp.collect then collects it.
"""

import re
import subprocess
import time
from datetime import datetime, timedelta, timezone

from cjp.config import (ARM_LOCATION_PATTERNS, REPO_ROOT, VM_DATA_DIR, VM_HOST, VM_ROOT,
                        VM_SESSIONS_DIR, VM_USER, WAZUH_AGENT_ID)

SSH_OPTS = ["-o", "BatchMode=yes", "-o", "ConnectTimeout=5"]


def ssh_run(command: str, timeout: float = 10.0) -> str | None:
    """Run a command on the VM over SSH. Returns stripped stdout, or None on
    any failure (no VM_HOST configured, host unreachable, non-zero exit, timeout)."""
    if not VM_HOST:
        return None
    try:
        result = subprocess.run(
            ["ssh", *SSH_OPTS, f"{VM_USER}@{VM_HOST}", command],
            capture_output=True, text=True, timeout=timeout
        )
        if result.returncode != 0:
            return None
        return result.stdout.strip()
    except (subprocess.TimeoutExpired, OSError):
        return None


def scp_dir_from_vm(remote_dir: str, local_dir: str, timeout: float = 60.0) -> bool:
    """Recursively copy a directory from the VM to local_dir via `scp -r`.
    local_dir must NOT already exist: scp -r nests the remote directory
    inside an existing destination (matching cp -r) rather than creating it
    fresh, so callers must check for a pre-existing local_dir themselves."""
    if not VM_HOST:
        return False
    try:
        result = subprocess.run(
            ["scp", "-r", *SSH_OPTS, f"{VM_USER}@{VM_HOST}:{remote_dir}", local_dir],
            capture_output=True, text=True, timeout=timeout
        )
        return result.returncode == 0
    except (subprocess.TimeoutExpired, OSError):
        return False


def measure_clock_offset() -> float | None:
    """
    Measure VM clock offset relative to this host, in seconds (VM - host).
    Brackets the SSH round trip with host timestamps and uses their midpoint
    to cancel out most of the round-trip network latency. Returns None if
    VM_HOST isn't configured or the VM isn't reachable — a session can still
    be collected without this, just without a recorded offset.
    """
    host_before = time.time()
    remote_epoch = ssh_run("date -u +%s.%N")
    host_after = time.time()

    if remote_epoch is None:
        return None
    try:
        remote_time = float(remote_epoch)
    except ValueError:
        return None

    host_midpoint = (host_before + host_after) / 2
    return round(remote_time - host_midpoint, 3)


def list_remote_sessions() -> list[str]:
    """List all session ids present in VM_SESSIONS_DIR, oldest first (the
    YYYYMMDD_HHMMSS naming scheme sorts lexicographically = chronologically).
    Empty list if VM_HOST is unset/unreachable or the directory doesn't exist."""
    output = ssh_run(f"ls {VM_SESSIONS_DIR} 2>/dev/null")
    if not output:
        return []
    return sorted(line.strip() for line in output.splitlines() if line.strip())


# ── cjp vm deploy (Plan P2.2) ───────────────────────────────────────────────
VM_SRC = REPO_ROOT / "vm"

# Never sent by rsync and never deleted by --delete on the VM: runtime state
# that deploy.sh or the running services create there.
RSYNC_EXCLUDES = [".venv/", "data/", "__pycache__/", ".deploy-backup/",
                  "DEPLOYED_SHA", "DEPLOYED.json", ".DS_Store"]


def _git(*args: str) -> str:
    return subprocess.run(["git", *args], cwd=REPO_ROOT, capture_output=True,
                          text=True, check=True).stdout.strip()


def _vm_git_state() -> tuple[str, str, bool]:
    """(sha, describe, dirty) for what gets deployed. `dirty` means vm/ has
    uncommitted or untracked changes, i.e. the VM would not match the SHA."""
    sha = _git("rev-parse", "HEAD")
    describe = _git("describe", "--tags", "--always")
    dirty = bool(_git("status", "--porcelain", "--", "vm/"))
    return sha, describe, dirty


def rsync_to_vm(dry_run: bool = False) -> bool:
    """Mirror vm/ to VM_ROOT. --delete removes files no longer in the repo,
    except the runtime state in RSYNC_EXCLUDES."""
    cmd = ["rsync", "-rlpti", "--delete", *[f"--exclude={e}" for e in RSYNC_EXCLUDES],
           "-e", "ssh " + " ".join(SSH_OPTS), f"{VM_SRC}/", f"{VM_USER}@{VM_HOST}:{VM_ROOT}/"]
    if dry_run:
        cmd.insert(1, "-n")
    return subprocess.run(cmd).returncode == 0


def expected_localfiles() -> list[str]:
    """The <location> paths in vm/wazuh/agent_localfile.xml."""
    return re.findall(r"<location>(.*?)</location>", (VM_SRC / "wazuh" / "agent_localfile.xml").read_text())


def check_agent_localfiles() -> tuple[bool | None, str | None]:
    """Compare the agent's live <localfile> paths (manager API) with
    vm/wazuh/agent_localfile.xml. Returns (ok, fix): ok is None when the API
    can't be reached; fix is the one sudo command to run on the VM, if any."""
    from cjp.indexer import get_agent_config
    try:
        live = [lf.get("file") for lf in
                get_agent_config(WAZUH_AGENT_ID, "logcollector", "localfile")["localfile"]]
    except Exception as e:  # tunnel down, agent disconnected, auth
        print(f"[vm] could not read agent {WAZUH_AGENT_ID}'s <localfile> config from the manager API: {e}")
        return None, None
    expected = expected_localfiles()
    missing = [e for e in expected if e not in live]
    if not missing:
        return True, None

    marker = "/juice-shop/data/logs/"
    new_prefix = f"{VM_ROOT}{marker}"
    old_prefixes = sorted({f[:f.index(marker)] + marker for f in live
                           if f and marker in f and f not in expected})
    print(f"[vm] the agent does not tail: {', '.join(missing)}")
    if not old_prefixes:
        return False, ("paste the <localfile> blocks from vm/wazuh/agent_localfile.xml into "
                       "/var/ossec/etc/ossec.conf (sudo), then: sudo systemctl restart wazuh-agent")
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d")
    seds = " ".join(f"-e 's#{old}#{new_prefix}#'" for old in old_prefixes)
    return False, (f"ssh -t {VM_USER}@{VM_HOST} \"sudo sed -i.bak-cjp-{stamp} {seds} "
                   f"/var/ossec/etc/ossec.conf && sudo systemctl restart wazuh-agent\"")


def smoke_test(timeout: float = 180.0) -> bool:
    """Send one request through the ingest proxy and wait until an alert
    carrying its marker arrives from every arm's log under VM_ROOT. The
    request (GET /rest/basket/1 without a token -> 401) fires stock rule
    31101 in S1 and S2 and custom rule 100012 in S3. Its Referer is a
    `cjp-smoke-…` marker, not a wp1- CID, so no session ever maps it."""
    from cjp.indexer import get_alerts_since
    marker = "cjp-smoke-" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")
    offset = measure_clock_offset() or 0.0
    since = (datetime.now(timezone.utc) + timedelta(seconds=offset - 30)).isoformat()
    status = ssh_run(f"curl -s -o /dev/null -w '%{{http_code}}' -H 'Referer: {marker}' "
                     f"http://localhost:8080/rest/basket/1")
    print(f"[smoke] sent GET /rest/basket/1 through the proxy (HTTP {status}), marker {marker}")
    if status != "401":
        print("[smoke] expected HTTP 401; is the ingest proxy up? (start_ingest_proxy.sh status)")
        return False

    found: dict[str, dict] = {}
    deadline = time.time() + timeout
    while len(found) < len(ARM_LOCATION_PATTERNS) and time.time() < deadline:
        time.sleep(5)
        for arm, pattern in ARM_LOCATION_PATTERNS.items():
            if arm in found:
                continue
            for a in get_alerts_since(after_timestamp=since, limit=500, location_pattern=pattern):
                if marker in a.get("full_log", ""):
                    found[arm] = a
                    print(f"[smoke] {arm}: rule {a['rule']['id']} from {a['location']}")
                    break
    for arm in ARM_LOCATION_PATTERNS:
        if arm not in found:
            print(f"[smoke] {arm}: no alert within {timeout:.0f}s (pattern {ARM_LOCATION_PATTERNS[arm]})")
    return len(found) == len(ARM_LOCATION_PATTERNS)


def deploy(allow_dirty: bool = False, smoke: bool = True, dry_run: bool = False) -> int:
    """`cjp vm deploy`. Returns a process exit code."""
    if not VM_HOST:
        print("[vm] VM_HOST is not set in .env")
        return 1
    if ssh_run("true") is None:
        print(f"[vm] cannot reach {VM_USER}@{VM_HOST} over SSH (key-based, BatchMode); "
              f"try: ssh {VM_USER}@{VM_HOST}")
        return 1
    sha, describe, dirty = _vm_git_state()
    if dirty:
        if not allow_dirty:
            print("[vm] vm/ has uncommitted changes, so the VM would not match any commit. "
                  "Commit them first, or pass --allow-dirty (recorded as <sha>-dirty).")
            return 1
        sha, describe = sha + "-dirty", describe + "-dirty"

    print(f"[vm] rsync vm/ -> {VM_USER}@{VM_HOST}:{VM_ROOT}/  ({describe}){' [dry run]' if dry_run else ''}", flush=True)
    if not rsync_to_vm(dry_run=dry_run):
        print("[vm] rsync failed")
        return 1
    if dry_run:
        return 0

    rc = subprocess.run(["ssh", *SSH_OPTS, f"{VM_USER}@{VM_HOST}",
                         f"bash {VM_ROOT}/deploy.sh {sha} {describe}"]).returncode
    if rc != 0:
        print(f"[vm] deploy.sh failed (exit {rc}); DEPLOYED_SHA was not written")
        return rc

    ok, fix = check_agent_localfiles()
    if ok is False:
        print("[vm] ACTION FOR JESSE: repoint the agent to the deployed logs with this one command:\n")
        print(f"    {fix}\n")
        print("[vm] then run: cjp vm smoke")
        return 2
    if ok is None:
        print("[vm] agent paths unverified (manager API unreachable; is the SSH tunnel up?)")
        return 2
    print(f"[vm] agent {WAZUH_AGENT_ID} tails the deployed logs under {VM_DATA_DIR}/logs")

    if smoke and not smoke_test():
        return 3
    print(f"[vm] deployed {describe} ({sha[:12]}) to {VM_ROOT}")
    return 0


# ── cjp session new: traffic (Plan P2.3) ───────────────────────────────────
def deployed_sha() -> str | None:
    """VM_ROOT/DEPLOYED_SHA: the commit `cjp vm deploy` last deployed
    completely (<sha>-dirty for an --allow-dirty deploy), or None."""
    return ssh_run(f"cat {VM_ROOT}/DEPLOYED_SHA 2>/dev/null") or None


def deployed_vm_differs(sha: str) -> bool | None:
    """Whether this checkout's vm/ (working tree) differs from vm/ at the
    deployed commit. None when that can't be known: a -dirty deploy, or a
    commit this clone doesn't have."""
    if sha.endswith("-dirty"):
        return None
    rc = subprocess.run(["git", "diff", "--quiet", sha, "--", "vm/"], cwd=REPO_ROOT,
                        capture_output=True).returncode
    return {0: False, 1: True}.get(rc)


def run_session_traffic(seed: int) -> str | None:
    """Run one session's traffic on the VM (warm-up, attacks.sh, then
    benign_traffic.sh, through the ingest proxy: run_sessions.sh's default)
    and return the new session id, or None. Output streams to the terminal.
    A dropped SSH connection stops the traffic with it."""
    before = set(list_remote_sessions())
    rc = subprocess.run(["ssh", *SSH_OPTS, "-o", "ServerAliveInterval=30", f"{VM_USER}@{VM_HOST}",
                         f"bash {VM_ROOT}/juice-shop/run_sessions.sh -n 1 -m both --seed {seed}"]
                        ).returncode
    if rc != 0:
        print(f"[session] run_sessions.sh failed on the VM (exit {rc})")
        return None
    new = sorted(set(list_remote_sessions()) - before)
    if len(new) != 1:
        print(f"[session] expected one new VM session, found {len(new)}: {new}")
        return None
    return new[0]
