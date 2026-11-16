"""
The Home page's health tiles (Plan P6 "Home"): `cjp doctor`'s checks, each
with one plain sentence on what it means for someone who has never used the
CLI, plus whether each triage source can run.

The checks themselves are doctor.run_checks(), unchanged, so the tiles and
`cjp doctor` can never disagree. This module only adds words and a summary.
"""

from datetime import datetime, timezone

from cjp import config, doctor

GROUP_TITLES = {
    "local": "This Mac",
    "claude": "Claude API",
    "vm": "Lab VM and Wazuh",
    "tests": "Self-test",
}

# What each check means, in words for a non-CLI user. Keyed by Check.name;
# model checks are "model <alias>" and share one sentence.
ABOUT = {
    "config": "The pipeline's settings files are valid.",
    ".env": "Your local settings file (API key, passwords, VM address) exists.",
    "data dir": "The app can save triage results on this Mac.",
    "git": "The code version is recorded with every result.",
    "API key": "The app can use Claude to triage alerts.",
    "models": "The Claude models the app uses are configured.",
    "model": "This Claude model is available to your API key.",
    "VM_HOST": "The app knows where the lab VM is.",
    "SSH": "The app can reach the lab VM.",
    "manager API": "The app can sign in to Wazuh.",
    "indexer": "The app can read alerts from Wazuh.",
    "agent": "Wazuh is receiving the web server's logs.",
    "agent log paths": "Wazuh watches the right log files.",
    "Juice Shop": "The lab web app (OWASP Juice Shop) is running.",
    "ingest proxy": "The proxy that records request bodies is running.",
    "deployed vm/": "The VM runs the same code as this Mac.",
    "VM and Wazuh": "The lab VM and Wazuh.",
    "pytest": "The pipeline's own tests pass.",
}

# Which checks each triage source (Plan P6 "Source picker") needs. "triage
# model" stands for `model <alias>` of the default triage model.
SOURCE_NEEDS = {
    "demo": ("config", "data dir", "API key", "triage model"),
    "upload": ("config", "data dir", "API key", "triage model"),
    "live": ("config", "data dir", "API key", "triage model", "indexer"),
}


def about(name: str) -> str:
    return ABOUT["model"] if name.startswith("model ") else ABOUT.get(name, "")


def _triage_model_check() -> str | None:
    try:
        return f"model {config.model_profile()['alias']}"
    except Exception:       # broken settings: the config check fails and says why
        return None


def readiness(checks: list[doctor.Check]) -> dict:
    """{source: {status, blocking}} per triage source. `fail` when a check it
    needs failed, `unknown` when one was skipped or not run (offline, or
    after an earlier failure), else `ok`. Warnings don't block."""
    by_name = {c.name: c for c in checks}
    model = _triage_model_check()
    out = {}
    for source, needs in SOURCE_NEEDS.items():
        names = [model if n == "triage model" else n for n in needs]
        failed = [n for n in names if n and n in by_name and by_name[n].status == "fail"]
        unknown = [n or "triage model" for n in names
                   if n not in by_name or by_name[n].status == "skip"]
        status = "fail" if failed else "unknown" if unknown else "ok"
        out[source] = {"status": status, "blocking": failed or unknown}
    return out


def overall(checks: list[doctor.Check]) -> str:
    statuses = {c.status for c in checks}
    return "fail" if "fail" in statuses else "warn" if "warn" in statuses else "ok"


def report(offline: bool = False) -> dict:
    """The health panel's data: every check, grouped, with its plain sentence."""
    checks = doctor.run_checks(offline=offline)
    groups: list[dict] = []
    for c in checks:
        if not groups or groups[-1]["id"] != c.group:
            groups.append({"id": c.group, "title": GROUP_TITLES.get(c.group, c.group), "checks": []})
        groups[-1]["checks"].append(c.to_dict() | {"about": about(c.name)})
    return {
        "checked_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "offline": offline,
        "overall": overall(checks),
        "counts": {s: sum(1 for c in checks if c.status == s) for s in doctor.STATUSES},
        "ready": readiness(checks),
        "groups": groups,
    }
