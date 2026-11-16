---
description: Run one experiment end to end with cjp experiment run (dry run, Jesse's OK, then the run)
argument-hint: "<ID> [--resume <run>]"
# Only read-only commands are pre-approved: `cjp experiment run` (dry or paid) still asks
# for permission, a second check next to Jesse's OK in step 3.
allowed-tools: Bash(uv run cjp experiment list:*), Bash(uv run cjp experiment status:*), Bash(uv run cjp corpus verify:*)
---
Run experiment `$ARGUMENTS` with `cjp experiment run` (Plan P5, decision 008). Paid API calls need Jesse's explicit OK every time (CLAUDE.local.md: never spend API budget silently).

1. Run `uv run cjp experiment list`. Check that the experiment exists and its corpus is frozen. If not, stop and say what is missing (corpus: `cjp corpus freeze`, Plan P3.5).
2. Run `uv run cjp experiment run $ARGUMENTS --dry-run`. It writes nothing and spends nothing. Show the plan and estimate tables word for word.
3. If the plan's `to call` total is above 0: **stop**. Ask Jesse to approve that number of paid calls and the cost bound (`cost ≤`). Do not continue without an explicit yes in this conversation. If it is 0 (everything cached), continue without asking.
4. After the OK, run `uv run cjp experiment run $ARGUMENTS --yes`. `--yes` only skips the prompt Jesse just answered; the estimate prints again. If its numbers are higher than the ones approved, stop and ask again.
5. Report the run address, status and headline, the path of its `report.md`, and the cache counts (`cjp experiment status <run>`). D1 and X0 make no API call, so steps 3–4 never stop for them. For X1 and X2 the report ends with the METHODS §6 contrasts; for X4 it shows the flip rates.
6. If the run ended `failed`, show the error and its `--resume` command. A fatal cause (key, model, rejected request) needs a fix first. Resuming makes paid calls again, so it goes back to step 2 with `--resume <run>`.
7. Do not mark runs canonical, supersede or prune them: those are Jesse's calls. Remind Jesse that Plan P5 wants a short log entry per run (what ran, the headline, anything odd), and that once he pins the run (`uv run cjp runs mark-canonical <run>`), `uv run cjp results build` regenerates the figures from the pins without any API call (decision 012).
