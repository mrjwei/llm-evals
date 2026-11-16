---
description: Run and collect one proxied session on the VM with cjp session new
argument-hint: "--seed N"
allowed-tools: Bash(uv run cjp doctor:*), Bash(uv run cjp session new:*)
---
Collect one session with `cjp session new` (Plan P2.3). It takes about 5 minutes and makes no API calls.

1. `$ARGUMENTS` must contain `--seed N`. If it doesn't, ask Jesse which seed to use (corpus C1 uses seeds 1–3, Plan P3.5).
2. Run `uv run cjp doctor`. If any check fails, stop and show its fix (see /doctor); do not start traffic on a broken setup.
3. Run `uv run cjp session new $ARGUMENTS` and let it finish.
4. Report the exit code: `0` all three arms have alerts; `1` failed (show the error); `3` collected, but an arm has no alerts (show the `warnings` in the new session's `manifest.json`).
5. Report the session ID and, from `data/sessions/session_<id>/manifest.json`: `vm_deployed_sha`, `seed`, and alerts and log lines per arm.
6. Do not freeze a corpus, re-collect, or delete or overwrite anything under `data/`. Freezing is a separate decision (`cjp corpus freeze`).
