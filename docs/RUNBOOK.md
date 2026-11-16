# Runbook

How to set up and run the pipeline with the `cjp` CLI. Reference doc: **rewritten in place** when commands change, ≤200 lines (Plan §2.4). The research path is four commands: `cjp doctor` (is everything up?), `cjp session new` (traffic + collection), `cjp corpus freeze` (fix the input data) and `cjp experiment run <ID>` (triage, map, score, report, at one address). `cjp triage | map | metrics` remain for one-off work on a single session, and `cjp ui` opens the local web app. Why things work this way: [ARCHITECTURE.md](ARCHITECTURE.md) and [reference/wazuh-and-vm-notes.md](reference/wazuh-and-vm-notes.md).

## Contents

- [1. One-time setup](#1-one-time-setup)
- [2. Collect a session (WP1 + WP2)](#2-collect-a-session-wp1--wp2)
- [3. Freeze a corpus](#3-freeze-a-corpus)
- [4. Run an experiment](#4-run-an-experiment)
- [5. Runs and canonical results](#5-runs-and-canonical-results)
- [6. One-off triage, mapping and metrics](#6-one-off-triage-mapping-and-metrics)
- [7. Claude Code commands](#7-claude-code-commands)
- [8. When something looks wrong](#8-when-something-looks-wrong)
- [9. The web app](#9-the-web-app)

## 1. One-time setup

**On the VM**, the Wazuh stack (third-party, in Docker) must be up:

```bash
cd ~/wazuh-docker/single-node
docker compose -f generate-indexer-certs.yml run --rm generator   # first time only
docker compose up -d && docker compose ps                         # all healthy before continuing
```

Everything else on the VM (Juice Shop, the ingest proxy, the custom rules, the log directories) is deployed **from the Mac**, after the macOS setup below:

```bash
cjp vm deploy --dry-run      # what rsync would change in ~/cjp-vm
cjp vm deploy                # rsync vm/ → ~/cjp-vm, run vm/deploy.sh, check the agent, smoke-test all three arms
```

It is idempotent, so run it after every change to `vm/` (commit first: it refuses uncommitted `vm/` changes). If the agent's `<localfile>` paths don't point at `~/cjp-vm`, it prints **one sudo command** for Jesse and exits 2; run it, then `cjp vm smoke`. Details: [wazuh-and-vm-notes §12](reference/wazuh-and-vm-notes.md#12-deploying-vm-with-cjp-vm-deploy).

**On macOS:**

```bash
uv sync                      # .venv/ with Python 3.12, exactly as pinned in uv.lock, plus `cjp` (editable)
source .venv/bin/activate    # or prefix each command with `uv run`
cjp --help                   # one subcommand per pipeline step
uv run pytest                # offline test suite: no API calls, no VM, never writes to data/
```

Change dependencies with `uv add <pkg>` (dev-only: `uv add --dev <pkg>`); it updates `pyproject.toml` and `uv.lock` together. Never edit them by hand. The old `venv/` (pip, unpinned) was retired in Plan P1.4.

`.env` in the repo root (read by `cjp/config.py`, whatever the working directory): `cp .env.example .env`, then fill in the API key, the two Wazuh passwords and `VM_HOST`. `.env.example` documents every variable and its default. Models, request parameters, retries and prices are not in `.env`: they are part of the method and live in the tracked `config/settings.yaml` ([decision 007](decisions/007-robustness-and-model-settings.md)).

This needs key-based SSH to the VM. Open the tunnel (leave it running), then check everything:

```bash
ssh -N -L 9200:localhost:9200 -L 55000:localhost:55000 jesse@<vm-ip>
cjp doctor                   # config, API key + models (no tokens), SSH, manager API, indexer, agent, Juice Shop, proxy, deployed SHA
cjp doctor --selftest        # … plus the test suite; --offline skips everything that needs the network
```

Each check prints ✓ / ! / ✗ / · and, for anything not ok, the command that fixes it. Exit code 0 means nothing failed. Every other `cjp` command validates `config/settings.yaml` and `.env` first and stops with the full list of problems; a known failure (tunnel down, key rejected, …) prints one line with the fix instead of a traceback (`CJP_DEBUG=1` shows the traceback too).

## 2. Collect a session (WP1 + WP2)

**One command (recommended), from macOS**, after `cjp vm deploy`:

```bash
cjp session new --seed 1     # ~8 min: warm-up → attacks + benign traffic, proxied → settle 60 s → collect
```

It runs `run_sessions.sh` in `~/cjp-vm`, then collects the new session. It warns when this checkout's `vm/` differs from the deployed one. Exit codes: `0` all three arms have alerts, `1` failed, `3` collected but an arm has none (read the manifest's `warnings`).

**By hand:** run traffic on the VM, collect later.

```bash
# VM
cd ~/cjp-vm/juice-shop
bash run_sessions.sh -n 3 --seed 1      # proxied by default; seeds 1, 2, 3; -m attacks|benign|both
#   or: SEED=1 bash attacks.sh; SEED=1 bash benign_traffic.sh   (benign joins the session if run within 60 min)

# macOS
cjp collect --offline                   # pulls every VM session not yet in data/sessions/
cjp collect --offline --session-id <id> # or just one
```

`cjp collect` without `--offline` is the legacy online mode: it blocks while you run traffic, and its manifest has no VM provenance.

Every session lands in `data/sessions/session_<id>/`: `attack_log.jsonl`, `benign_log.jsonl`, `access.log`, `ingest_log.jsonl`, `enriched_access.log`, `body_field_access.log`, the three `*wazuh_alerts.jsonl` files and `manifest.json`. The manifest's fields are in [ARCHITECTURE §6](ARCHITECTURE.md#6-outputs-and-provenance). The collector refuses to overwrite an existing session directory. The pre-cleanup sessions kept as evidence are in `data/legacy/2026-09/sessions/` (legacy-evidence); pass that path to `--session` to replay one.

`JUICE_URL=http://localhost:3000 bash run_sessions.sh` gives a direct session, which fills only S1 and has no request bodies.

## 3. Freeze a corpus

Experiments never read `data/sessions/` directly; they read a frozen corpus, so every run sees the same bytes ([decision 008](decisions/008-experiment-runner-and-corpus.md)).

```bash
cjp corpus freeze C1 --sessions session_<a> session_<b> session_<c> --note "seeds 1-3, proxied"
cjp corpus verify C1          # every file against corpus.json's sha256; also done before every run
cjp corpus list
```

The sessions are copied read-only into `data/corpus/C1/sessions/`, and `corpus.json` records each file's sha256 plus each session's seed, deployed SHA and arms. Freezing warns about a session with fewer than three populated arms or no `ingest_log.jsonl`; read the warnings before using the corpus. A corpus is never overwritten: a change means a new ID (C2) and a decision record. The one exception, before `prereg-C1` only, is [decision 009](decisions/009-recollect-c1-before-prereg.md). The sha256 of `corpus.json` goes into the `prereg-C1` tag message (Plan §2.5).

## 4. Run an experiment

`experiments/<ID>.yaml` holds the question, RQ, corpus, conditions and repeats, frozen at `prereg-C1` ([METHODS §4](METHODS.md#4-experiments-and-conditions)); a change needs a decision record. A condition ID says what it runs: `S1-plain__L1-alert+body__FA__sonnet` is the alerts of arm S1, plus `ingest_log` bodies (`L0-alert`: none), format A, the `sonnet` model from `config/settings.yaml`. `kind: siem` (D1) maps and scores without an LLM. `kind: baseline` (X0) answers each alert from a lookup table (`taxonomy/baselines.yaml`) and scores it like the LLM. Neither calls the API, so neither asks. Run order: D1 and X0 (free), then X1, X2, X3, X4 ([METHODS §4](METHODS.md#4-experiments-and-conditions)).

```bash
cjp experiment list                     # every YAML, and whether its corpus is frozen
cjp experiment run X1 --dry-run         # plan + estimate; nothing written, nothing spent
cjp experiment run X1                   # same plan, then asks [y/N] before the first paid call
cjp experiment status [<run>]           # progress per condition and repeat; no arg: latest run per experiment
cjp experiment run X1 --resume <run>    # continue a failed or interrupted run in place
```

- **The plan** shows, per condition, the alerts (sessions × repeats), those already answered (resume), those the cache answers, and the paid calls left. A request that recurs in another session is paid for once. **The estimate** counts input tokens with `count_tokens` (free, no model call) on up to 5 requests per condition; `--no-count` estimates from characters instead. Output is bounded by `max_tokens` and cost by list price, so the figure is an upper bound.
- **Never spend silently.** Run `--dry-run` first and get an OK; the real run asks again unless `--yes`. `--cache-only` refuses to start if any alert is uncached, and `--no-cache` calls for every alert (old entries kept as superseded).
- **Output:** `data/runs/<ID>-<slug>/<run>/report.md` (one row per condition: coverage, selective accuracy with CI, strict, coarse, escalation recall, FP dismissal, high-confidence wrong, cost per alert, API errors). X1 and X2 add a contrasts table, B − A with a paired 95% CI, with a bold difference when the interval excludes 0 (also in `contrasts.json`). X4 adds the injection flip rates. Each condition has `conditions/<c>/report.md`, `metrics.json`, `scores.jsonl` and `charts/`, and `rep<N>/<session>/verdicts.jsonl` and `mapped.jsonl` below. `INDEX.md` is regenerated.
- **Failures:** a fatal error (bad key, unknown model) or three failed calls in a row stop the run and mark it `failed`, with the `--resume` command. A run that finishes with unanswered alerts (`api_error`) is also `failed`, never `complete`. `--resume` works only if the YAML, models, `max_tokens` and cache mode are unchanged (`config_hash`). Otherwise start a new run.

## 5. Runs and canonical results

Research runs live in `data/runs/<experiment>/<run>/` ([ARCHITECTURE §6](ARCHITECTURE.md#6-outputs-and-provenance)). `cjp experiment run` creates them. A run is named by its address (`X1-evidence/2026-10-09T1030_ab12cd`) or by its bare run ID.

```bash
cjp runs index                                   # regenerate data/runs/INDEX.md (also automatic after every change)
cjp runs mark-canonical <run> [--note …]         # pin a complete run as its experiment's canonical run
cjp runs supersede <old run> --by <new run>      # mark, don't delete; same experiment, the new run must be complete
cjp runs prune                                   # list superseded runs (path · action · reason), ask, delete
cjp results build                                # regenerate results/tables, results/figures, results/manifest.json
```

- Open `data/runs/INDEX.md` to see what ran, its status and headline, and which runs are canonical. Never edit it: it is rewritten.
- `results/canonical.yaml` is **tracked** ([decision 012](decisions/012-canonical-pins-and-results-build.md)). `figures` lists the figure and table set, and which experiments each reads; edit it by hand to add or drop one. `pins` holds one run per experiment: `mark-canonical` pins under the run's experiment ID, and every figure that reads that experiment follows the pin. Review the diff and commit it. Re-pinning moves the key and prints the old run.
- `cjp results build` reads only the pinned runs' stored outputs: no API call, no re-scoring. Each figure's footer names its runs. It checks every pin (complete, the right experiment, `git describe` starting `prereg-C1` without `-dirty`). It writes what it can, lists the problems in `results/manifest.json`, and exits 1 if there are any, so it can be run after each experiment. It never deletes: a file it did not write is reported as stale. A `from` entry that names a rating batch (F8 ← X5) is read from `data/ratings/` instead of a pin, and the hand-written `results/tables/H1_heuristic.csv` is reported until every criterion is scored ([decision 022](decisions/022-single-rater-review-and-f8.md)). Commit `results/` with the pins.
- `prune` never deletes a pinned run: re-pin first. A pin on a superseded or missing run shows under *Pin problems* in `INDEX.md`.
- `run.json` records `git describe`. A `-dirty` suffix means the run used uncommitted code, and a canonical run like that needs a decision record (Plan P5).

## 6. One-off triage, mapping and metrics

For one session outside an experiment (debugging a prompt change, a legacy re-score). Output goes to `data/outputs/<wp>/<session>/<tag>_v<N>/` with a `_meta.json` sidecar; nothing is overwritten. **`cjp triage` calls the API on cache misses**: it prints how many alerts the cache answers first, and `--cache-only` guarantees no spend.

```bash
cjp triage --session data/sessions/session_<id> --variant <tag> [--alerts-file body_field_wazuh_alerts.jsonl] \
           [--format A|B] [--model haiku] [--repeat N] [--resume <output.jsonl>] [--no-cache | --cache-only]
cjp map --session data/sessions/session_<id> --wp3 <triage output.jsonl> [--alerts-file …]
cjp metrics --input <map output, repeat 1> [--input <repeat 2> …] --session data/sessions/session_<id>
cjp prompt show --format A [--schema]   # the exact prompt / JSON Schema sent, with version hashes; no API call
```

- Always pass `--session`: without it `cjp triage` reads the live indexer, which is not reproducible. Bodies from `ingest_log.jsonl` are attached automatically (there is no L0 switch; use an experiment for that).
- `--resume` skips alerts already answered and retries `api_error` rows. Pass the same `--alerts-file`, `--repeat`, `--format` and `--model`: a stopped batch prints the exact command. The client retries rate limits, 5xx and dropped connections itself (`api.max_retries`).
- `cjp metrics`: one `--input` per repeat (the same repeat twice is refused). `--session` supplies the techniques with zero alerts, the benign population and the request clusters: pass the original session, not a body-stripped copy ([decision 006](decisions/006-scoring-and-metrics.md)). Legacy v1 rows are scored with `taxonomy/legacy_synonyms.json`. Metric definitions: [ARCHITECTURE §7](ARCHITECTURE.md#7-evaluation-metrics). Prices live in `config/settings.yaml` with their `retrieved` date.

## 7. Claude Code commands

Three tracked commands in `.claude/commands/` wrap `cjp` for Claude Code (Plan P2.9). They contain no logic of their own, and a test checks that every `cjp` call in them parses:

| Command | Does |
|---|---|
| `/doctor [--offline] [--selftest]` | `cjp doctor`, then relays each failing check's fix word for word; sudo fixes are printed for Jesse, never run |
| `/new-session --seed N` | `cjp doctor` first, then `cjp session new`; reports the exit code and the manifest's SHA, seed and alerts per arm |
| `/run-experiment <ID> [--resume <run>]` | `cjp experiment list`, the `--dry-run`, **stops for Jesse's explicit OK** on any paid call, then runs with `--yes` and reports the run |

Only read-only `cjp` commands are pre-approved in their `allowed-tools`, so a paid run also asks for permission. `/make-note` and `/clear-session` are personal and stay gitignored. The old `/run-wp3`, `/run-wp4-mapper` and `/run-wp4-metrics` were retired in Plan P1.3.

## 8. When something looks wrong

| Symptom | Check |
|---|---|
| Anything | `cjp doctor` first: it names the broken piece and prints the fix |
| `[cjp] configuration problems:` | Fix the listed fields in `config/settings.yaml` or `.env` (see `.env.example`) |
| No alerts at all | Tunnel up? `_count` query and `agent_control -l` ([notes §10](reference/wazuh-and-vm-notes.md#10-health-checks)). Then `cjp vm smoke` |
| `cjp vm deploy` exits 2 | The agent doesn't tail `~/cjp-vm`: run the printed sudo command, then `cjp vm smoke` |
| `cjp vm deploy` says logtest FAIL | A rule change broke a case in `vm/wazuh/logtest_cases.tsv`; the old rules were restored and the manager was not restarted |
| One arm's alerts are missing | Agent `<localfile>` for that log, and its `location` wildcard in `cjp/config.py` |
| Arm 2/3 worse than Arm 1, or a manifest warning "S2 has fewer alerts than S1" | First proxied session of the day? ([cold start](reference/wazuh-and-vm-notes.md#7-cold-start-on-new-daily-log-files)) |
| Manifest warning "log lines but no alerts" | The agent isn't tailing that arm's log: `cjp vm smoke` |
| Manifest has no `vm_deployed_sha` | The traffic didn't run from a `cjp vm deploy` in `~/cjp-vm` |
| Alerts from another session, or a manifest warning "dropped N alert(s) whose CID names another session" | Back-to-back sessions: the 2 s window buffer caught the neighbour's first request. Offline collect drops it and the mapper never scores it ([decision 010](decisions/010-c1-unscored-alerts.md)); nothing to do |
| `cjp experiment run` says the corpus no longer matches | A file under `data/corpus/<ID>/` changed: `cjp corpus verify <ID>` names it. Restore it, or freeze a new corpus ID |
| An experiment run ended `failed` | `cjp experiment status <run>`, fix the cause, then the `--resume` command in its `error` |
| `INDEX.md` lists a *Pin problem* | The pinned run was superseded or deleted: `cjp runs mark-canonical <new run> --as <key>` |
| A run stays `running` in `INDEX.md` | Its process was killed before it could mark itself failed: `cjp experiment run <ID> --resume <run>` |
| A new rule never fires | `wazuh-logtest` on a real line; [regex gotchas](reference/wazuh-and-vm-notes.md#6-wazuh-regex-and-rule-gotchas) |

## 9. The web app

```bash
cjp ui [--port 8740] [--no-browser]   # http://127.0.0.1:8738/ by default (this Mac only), opens the browser; Ctrl-C stops it
cd web/ui && npm ci && npm run build   # once, and after every UI change (Node ≥ 22.12); `npm test` runs the UI tests
npm run dev                  # UI work: hot reload on http://127.0.0.1:5173/, /api passed to a running `cjp ui --no-browser`
cjp rating make-batch | status | export-pack <batch> | import <file>   # the X5 batch (P7.1 defaults, --dry-run); progress; an offline file for a remote rater; their download back in
```

**Without a terminal:** double-click `Start Triage.command` in Finder. It syncs the Python packages, builds the UI when `dist/` is missing or older than its sources (needs Node), then runs `cjp ui`, which opens the browser; closing its window stops the app. Starting it a second time on the same port just opens the browser on the running app. Unlike other commands it starts even when the config is broken, and the problem shows as a red health tile. Home shows the `cjp doctor` checks, each with a plain sentence and the fix, and which triage sources can run (`/api/health`; `?offline=true` skips the network). Until the UI is built, `/` says how to build it.

**Triage** (results in `data/triage_jobs/<job-id>/`). Pick a demo session, upload a Wazuh alerts `.jsonl` (plus the proxy's `ingest_log.jsonl` for bodies), or give a live window. **Prepare and estimate** captures the alerts and shows the paid calls and the most they can cost; nothing is sent yet. **Run** asks you to approve exactly those calls. A job whose answers are all cached (any X1 or X2 condition, demo or live) runs free with no dialog. Live jobs need the tunnel, and their bodies need SSH to the VM. A job that stops, fails or was cut off by quitting `cjp ui` shows `stopped`, `failed` or `interrupted`: **Resume** estimates what is left, and answered alerts are kept.

**Queue and verdicts.** Alerts sit in three lanes (to act on, needs a human, not triaged yet), sorted escalate first. The A/B toggle re-sorts by the other format, and you can filter by label, disposition and source. A verdict shows how often its confidence level was right in the pinned evaluation runs, and warns about instruction-like text. **CSV** and **JSON** download the verdicts. Agree/disagree goes to the job's `feedback.jsonl` and is never research data. The address bar holds the view, so a reload keeps it. After re-pinning a run (`cjp runs mark-canonical`), the calibration numbers follow with no restart. The same actions are `/api/triage/*`.

**Rate** (expert rating, [decisions 018](decisions/018-rating-batches-and-offline-pack.md) and [021](decisions/021-x5-batch-allocation.md)). `cjp rating make-batch` writes `data/ratings/X5/` from the pinned X1 and X2 runs: 48 items plus 6 calibration. It prints counts per cell and stratum, never which item is which, and raters never open `key.json`. Pick a batch and say whether you are rater A or B. The calibration items come first (rate those together), then your own order, one item per screen. Each click is saved in `data/ratings/<batch>/ratings/rater-<A|B>.json`, so you can stop and come back (the address keeps your place). A rater away from this Mac gets the pack instead: it opens in any browser with no network, autosaves in that browser, and **Download ratings** gives the JSON to import. An import never replaces scores a rater already has. When every rater is done, `cjp results build` writes F8 (`results/tables/F8_rating_*.csv`); with one rater it reports no κ (decision 022).

**Results** lists every run in `data/runs/` with its status, headline and canonical pin, filtered by experiment and RQ; open one to read its `report.md` and each condition's, with the charts. It only reads. Design and safety rules: [ARCHITECTURE §9 Web app](ARCHITECTURE.md#9-web-app).
