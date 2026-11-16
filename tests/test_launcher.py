"""`Start Triage.command` (Plan P6.8): the double-click launcher. Run on a
copy of the repo's shape with stub `uv` and `npm` that record their calls:
it syncs the packages, builds the UI only when dist/ is missing or older
than its sources, then hands over to `uv run --frozen cjp ui`."""

import os
import shutil
import subprocess
import time
from pathlib import Path

import pytest

from cjp import config

LAUNCHER = config.REPO_ROOT / "Start Triage.command"
STUB = """#!/bin/bash
echo "{name} $*" >> "$CALLS"
case "$*" in
  ci*) mkdir -p node_modules && touch node_modules/.package-lock.json ;;
  "run build"*) mkdir -p dist && touch dist/index.html ;;
esac
"""


def fallback_has(tool: str) -> bool:
    """The launcher also looks in these dirs, so a "missing tool" case can't
    be staged on a Mac that has the tool there."""
    return any((Path(d) / tool).exists() for d in ("/opt/homebrew/bin", "/usr/local/bin"))


@pytest.fixture
def repo(tmp_path):
    root = tmp_path / "repo"
    (root / "web/ui/src").mkdir(parents=True)
    for f in ("web/ui/src/main.tsx", "web/ui/index.html", "web/ui/package.json", "web/ui/package-lock.json",
              "web/ui/vite.config.ts"):
        (root / f).write_text("x")
    shutil.copy(LAUNCHER, root / LAUNCHER.name)
    return root


def run(repo, tmp_path, tools=("uv", "npm")):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(exist_ok=True)
    for tool in tools:
        (bin_dir / tool).write_text(STUB.format(name=tool))
        (bin_dir / tool).chmod(0o755)
    calls = tmp_path / "calls.txt"
    env = {"PATH": f"{bin_dir}:/usr/bin:/bin", "HOME": str(tmp_path), "CALLS": str(calls)}
    result = subprocess.run(["/bin/bash", str(repo / LAUNCHER.name)], env=env, capture_output=True, text=True,
                            stdin=subprocess.DEVNULL, timeout=30)
    lines = calls.read_text().splitlines() if calls.exists() else []
    return result, lines


def age(path: Path, seconds: float) -> None:
    t = time.time() - seconds
    os.utime(path, (t, t))


def test_launcher_is_an_executable_bash_script():
    assert LAUNCHER.is_file() and os.access(LAUNCHER, os.X_OK)
    assert LAUNCHER.read_text().startswith("#!/bin/bash\n")
    assert subprocess.run(["/bin/bash", "-n", str(LAUNCHER)]).returncode == 0


def test_first_start_installs_builds_and_runs_cjp_ui(repo, tmp_path):
    result, calls = run(repo, tmp_path)
    assert result.returncode == 0, result.stdout + result.stderr
    assert calls == ["uv sync --frozen --quiet", "npm ci --no-audit --no-fund --loglevel=error",
                     "npm run build --silent", "uv run --frozen cjp ui"]
    assert "building the interface" in result.stdout


def test_an_up_to_date_build_is_not_rebuilt(repo, tmp_path):
    for f in (repo / "web/ui").rglob("*"):
        age(f, 60)
    (repo / "web/ui/dist").mkdir()
    (repo / "web/ui/dist/index.html").write_text("built")
    _, calls = run(repo, tmp_path)
    assert calls == ["uv sync --frozen --quiet", "uv run --frozen cjp ui"]


def test_a_changed_source_is_rebuilt_without_reinstalling(repo, tmp_path):
    (repo / "web/ui/node_modules").mkdir()
    (repo / "web/ui/node_modules/.package-lock.json").write_text("{}")
    (repo / "web/ui/dist").mkdir()
    (repo / "web/ui/dist/index.html").write_text("built")
    for f in [*(repo / "web/ui").glob("*.*"), repo / "web/ui/dist/index.html"]:
        age(f, 60)                                   # dist newer than the lock file...
    age(repo / "web/ui/node_modules/.package-lock.json", 30)
    (repo / "web/ui/src/main.tsx").write_text("changed")   # ...but older than this source
    _, calls = run(repo, tmp_path)
    assert calls == ["uv sync --frozen --quiet", "npm run build --silent", "uv run --frozen cjp ui"]


@pytest.mark.skipif(fallback_has("uv"), reason="uv is installed in a fallback dir on this Mac")
def test_no_uv_says_how_to_get_it(repo, tmp_path):
    result, calls = run(repo, tmp_path, tools=("npm",))
    assert result.returncode == 1 and calls == []
    assert "uv is not installed" in result.stdout


@pytest.mark.skipif(fallback_has("npm"), reason="npm is installed in a fallback dir on this Mac")
def test_no_node_still_starts_and_says_why(repo, tmp_path):
    result, calls = run(repo, tmp_path, tools=("uv",))
    assert calls == ["uv sync --frozen --quiet", "uv run --frozen cjp ui"]
    assert "Node.js is not installed" in result.stdout
