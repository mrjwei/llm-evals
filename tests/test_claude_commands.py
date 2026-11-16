"""The Claude Code commands (Plan P2.9) are thin wrappers over cjp: every
`uv run cjp …` they tell Claude to run must be a command cjp accepts, so a
renamed flag breaks this test instead of the command."""

import re

import pytest
from conftest import REPO_ROOT

from cjp import cli

COMMANDS = REPO_ROOT / ".claude" / "commands"
# What $ARGUMENTS stands for in each command, for parsing.
EXAMPLE_ARGS = {"doctor.md": "--offline", "new-session.md": "--seed 1",
                "run-experiment.md": "X1"}


@pytest.mark.parametrize("name", sorted(EXAMPLE_ARGS))
def test_each_command_only_runs_real_cjp_commands(name):
    text = (COMMANDS / name).read_text()
    assert text.startswith("---\ndescription: ")
    calls = re.findall(r"`uv run cjp ([^`]+)`", text)
    assert calls, name
    for call in calls:
        argv = call.replace("$ARGUMENTS", EXAMPLE_ARGS[name]).replace("<run>", "X1-test/r").split()
        cli.build_parser().parse_args(argv)     # SystemExit (test failure) on an unknown flag


def test_paid_runs_are_never_pre_approved():
    front = (COMMANDS / "run-experiment.md").read_text().split("---")[1]
    allowed = re.search(r"allowed-tools: (.*)", front).group(1)
    assert "experiment run" not in allowed and "experiment:*" not in allowed
