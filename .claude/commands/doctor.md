---
description: Check the whole pipeline with cjp doctor (config, API key, models, VM, Wazuh, Juice Shop, proxy)
argument-hint: "[--offline] [--selftest]"
allowed-tools: Bash(uv run cjp doctor:*)
---
Run `uv run cjp doctor $ARGUMENTS` from the repo root and report what it found. It uses no API tokens and changes nothing.

- List each `✗` (fail) and `!` (warn) check with the `fix:` line cjp printed, word for word. Do not paraphrase commands.
- A fix that needs sudo on the VM (agent restart, `ossec.conf`) is for Jesse: print the one command, never run it or script around it.
- If the tunnel is down, show the tunnel command from the output. Do not start it yourself unless Jesse asks.
- Do not edit files to make a check pass. Exit code 0 means nothing failed; warnings (e.g. uncommitted code) are allowed.
- With `--selftest`, a skipped-tests warning means `data/legacy/` is missing, so the P2 acceptance tests did not run. Say so.
