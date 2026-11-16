# Docs index

Where to find things in `docs/`. The rules for each doc type are in [decision 001](decisions/001-docs-policy.md) and Plan §2.4. This index is hand-maintained until `cjp docs index` generates it (Plan P2); after that, don't edit it by hand.

## Contents

- [Start here](#start-here)
- [Reference](#reference)
- [Decisions](#decisions)
- [Not in this repo](#not-in-this-repo)

## Start here

- [METHODS.md](METHODS.md) for the pre-registered method, then [ARCHITECTURE.md](ARCHITECTURE.md) for how the code implements it.
- [RUNBOOK.md](RUNBOOK.md) to run it.

## Reference

Rewritten in place to stay current, never appended.

| Doc | What it covers |
|---|---|
| [ARCHITECTURE.md](ARCHITECTURE.md) | How the current pipeline is built: topology, data flow, the three SIEM evidence arms, mapping, LLM triage (prompt v2, output formats A/B, model settings, payload, retries and `api_error` rows) and the response cache, sessions, corpora, the experiment runner and the run registry, evaluation metrics (three-way scoring, disposition, severity, calibration, cost, clustered bootstrap), X0 baselines, X4 flip rate, paired contrasts, `cjp results build`, `cjp` package layout, the web app's API, its safety rules, triage jobs and their queue, verdicts and export, rating batches, blinding and the offline pack, the X5 batch draw, the X5 rating analysis (F8) and the H1 table check, the read-only runs browser, the UI (build, Home, the Triage, Rate and Results pages) |
| [RUNBOOK.md](RUNBOOK.md) | Setup (`uv sync`, `.env` from `.env.example`, tunnel, `cjp doctor`), `cjp session new`, `cjp corpus freeze`, `cjp experiment run` (dry run, cost estimate, resume, status), `cjp runs` (index, canonical pins per experiment, prune) and `cjp results build` (incl. F8 from a rating batch and the H1 check), one-off `cjp triage / map / metrics` and `cjp prompt show`, the Claude Code commands, `cjp ui` and building its UI, the Triage page (prepare, approve, run, resume, queue, verdicts, export), the Rate page and `cjp rating make-batch / status / export-pack / import`, the Results page, the `Start Triage.command` launcher |
| [reference/practitioner-study-protocol.md](reference/practitioner-study-protocol.md) | The practitioner study WP5 first planned, as a future-work protocol for the report appendix (Plan P7.5): design, participants, session procedure, measures, analysis, ethics and data handling, threats; not run |
| [reference/wazuh-and-vm-notes.md](reference/wazuh-and-vm-notes.md) | VM layout (`~/cjp-vm`), agent and manager config, `wazuh-logtest`, OSRegex gotchas, cold start, SSH tunnel, health checks, `cjp vm deploy` |
| [METHODS.md](METHODS.md) | The pre-registered method, frozen at `prereg-C1`: RQs, testbed, corpora C1 and C1-inj (sha256), experiments D1 and X0–X4, outcome rules and metric formulas (primary/secondary), injection flip rate, baselines, clustered and paired bootstrap, expert rating protocol, limitations, what the tag freezes and what counts as a deviation |

## Decisions

Short records, never edited; a later record supersedes an earlier one.

| # | Decision | Date |
|---|---|---|
| [001](decisions/001-docs-policy.md) | Documentation policy: split by audience, no status file | 2026-09-30 |
| [002](decisions/002-git-tags.md) | Git tags: three milestone tags, annotated and never moved | 2026-09-30 |
| [003](decisions/003-triage-model-sonnet-5-5.md) | Triage model `claude-sonnet-5-5`: thinking off (`between_tools`), no temperature, refusals recorded, no fallback | 2026-09-30 |
| [004](decisions/004-response-cache.md) | Response cache keyed by the exact request + repeat; every answer kept, nothing overwritten | 2026-09-30 |
| [005](decisions/005-prompt-v2-and-output-formats.md) | Prompt v2: closed-set labels incl. non-testbed techniques and `none`, Format B = FA's decision prefix, schema-enforced output, payload trimmed | 2026-10-01 |
| [006](decisions/006-scoring-and-metrics.md) | Scoring: correct / wrong / abstained / no answer, fine and coarse, disposition, bootstrap over distinct requests, calibration, list-price cost; grounding and the category filter dropped | 2026-10-01 |
| [007](decisions/007-robustness-and-model-settings.md) | Robustness: models and request parameters in `settings.yaml`, SDK retries, failed calls retried by `--resume` and never scored, config checked at start-up, `cjp doctor` | 2026-10-01 |
| [008](decisions/008-experiment-runner-and-corpus.md) | Experiment runner and frozen corpora: condition IDs that specify the run, plan + estimate + ask before paying, resume in place, failed calls keep a run incomplete | 2026-10-01 |
| [009](decisions/009-recollect-c1-before-prereg.md) | Corpus C1 re-collected before pre-registration: the UNION search technique was never delivered (raw spaces, curl exit 3); old C1 archived, same ID kept | 2026-10-02 |
| [010](decisions/010-c1-unscored-alerts.md) | C1 keeps rule-11 and back-to-back overlap alerts, unscored; an alert whose CID names another session is never attributed (mapper `other_session`) and offline collect drops it | 2026-10-03 |
| [011](decisions/011-pre-registration.md) | Pre-registration: label set confirmed (SDE → A01), coarse `uncertain` abstained, cost per correct label and per correct disposition, severity band as a secondary metric, `_inj` ground truth, X0 baselines pre-registered, paired contrasts, what `prereg-C1` freezes | 2026-10-03 |
| [012](decisions/012-canonical-pins-and-results-build.md) | One canonical run per experiment, the figure set in `results/canonical.yaml`, `cjp results build` from stored outputs with provenance checks; P5 analysis code in new modules only | 2026-10-03 |
| [013](decisions/013-web-app-local-api.md) | Web app: one process on 127.0.0.1, Host allow-list, no CORS, `X-CJP-Request` header on state-changing requests, CSP, health tiles = `cjp doctor` + plain words and per-source readiness | 2026-10-04 |
| [014](decisions/014-triage-jobs.md) | Triage jobs: inputs captured once with CIDs redacted, the research request (cache shared, demo jobs free), only approved paid calls, lock-file liveness and resume, both formats per job by default | 2026-10-04 |
| [015](decisions/015-triage-queue-and-verdicts.md) | Triage queue and verdicts: lanes by one format ("Needs a human" for uncertain, low confidence, no answer), calibration chip from the pinned X1/X2/X3 runs, the instruction-like-text flag, formula-safe CSV and JSON export, append-only product feedback | 2026-10-04 |
| [016](decisions/016-web-ui-build-and-safety.md) | Web UI: sources tracked and `dist/` built locally, nothing from another origin, every string rendered as text (grep-tested), one fetch wrapper with the guard header | 2026-10-04 |
| [017](decisions/017-triage-page-approval-and-state.md) | Triage page: prepare before run, the dialog approves exactly the paid calls it showed, free runs send 0, resume re-estimates, blocked sources can't submit, queue state in the URL (`?alert=`), one format at a time | 2026-10-04 |
| [018](decisions/018-rating-batches-and-offline-pack.md) | Rating: batch folder with items exactly {item, alert, body, answer} and the key never read, calibration first then a seeded shuffle per rater, scores only and autosaved, rubric change refused past the calibration round, hash-only-CSP offline pack, import never replaces scores | 2026-10-04 |
| [019](decisions/019-rubric-r2-anchor-quoting.md) | Rubric R2 anchors quoted: YAML read `no`/`yes` as booleans and split at commas; words unchanged, a deviation in bytes only, anchors now validated | 2026-10-04 |
| [020](decisions/020-results-browser.md) | Results browser: run registry read live, only `report.md` and `.png` inside a run served, Markdown rendered as React elements with raw HTML skipped, links and charts kept in the run, filters and open report in the URL, run page loaded on demand | 2026-10-04 |
| [021](decisions/021-x5-batch-allocation.md) | X5 rating batch: 3 cells × 4 strata (attack correct / wrong / abstained, benign) at equal n, 6 calibration items on top (54), each request cluster once, every item checked against its answer's cache key, counts-only printout | 2026-10-04 |
| [022](decisions/022-single-rater-review-and-f8.md) | X5 reported as a single-rater review (METHODS §7 fallback, no κ); readings of the analysis; F8 built from the rating batch with its checks; the H1 table's format and source (Okazawa et al. Table I, verbatim) | 2026-10-11 |


## Not in this repo

The internal plan (`PLAN.md`), the dated work log and the pre-cleanup history are kept in the private working repo. References to "Plan §…" or "Plan P…" in code comments and docs point there. Results (`results/tables`, `results/figures`, `results/manifest.json`) are held back until the paper is published; see [results/README.md](../results/README.md).
