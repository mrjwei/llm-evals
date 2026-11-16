# 008 · Experiment runner and frozen corpora: condition IDs that say what they run, ask before paying, resume in place

**Date:** 2026-10-01 · **Status:** in effect from P2 (`feat/p2-experiment-run`); the experiment YAMLs are drafts until P4 freezes them · **Affects:** Plan §2.3, P3.5, P4, P5; [decision 004](004-response-cache.md), [006](006-scoring-and-metrics.md), [007](007-robustness-and-model-settings.md); [ARCHITECTURE §6](../ARCHITECTURE.md#6-outputs-and-provenance)

## Contents

- [Context](#context) · [Decision](#decision) · [Consequences](#consequences)

## Context

P2.4 built the run registry but deferred `cjp experiment run` until the cache (P2.5), prompt v2 (P2.6) and the scorer (P2.7) existed. P2.9's `/run-experiment` and P5 both depend on it, and P3.5 needs `cjp corpus freeze`. No plan task names either, and both fall due now.

## Decision

1. **A corpus is frozen once:** read-only copies in `data/corpus/<ID>/sessions/`, plus `corpus.json` with the sha256 of every file, each session's seed, deployed SHA and arms, and freeze-time warnings (arms missing, no `ingest_log.jsonl`). It is never overwritten. Every run verifies it first and refuses a corpus that has changed.
2. **The condition ID is the specification:** `<S-level>__<L-level>__<FA|FB>__<model alias>`, for example `S1-plain__L1-alert+body__FA__sonnet`. S picks the alerts file and L whether `ingest_log` bodies are attached (L0 never sends them, even when the session has them). The alias resolves through `config/settings.yaml`. A `kind: siem` experiment (D1) has bare S-levels and no LLM, and `reps` must be 1. Unknown parts are errors that name the part.
3. **Layout:** `conditions/<c>/rep<N>/<session>/{verdicts,mapped}.jsonl`, and per condition `metrics.json`, `scores.jsonl`, `report.md` and `charts/`. The run's `report.md` has one row per condition. SIEM metrics are per session; triage metrics pool every session and repeat, with clusters that span sessions (decision 006 rule 4).
4. **Paid calls are never silent.** The plan counts alerts, answers already in the cache, and paid calls, counting a request repeated across sessions once. It estimates input tokens with `count_tokens` (free) on up to 5 distinct requests per condition, scaled by length. It bounds output by `max_tokens` and cost by list price. `--dry-run` stops there. A real run asks `[y/N]` before the first paid call unless `--yes`, and `--cache-only` refuses to start on any miss.
5. **Resume in place:** `--resume <run>` reopens a `failed` or interrupted run only if `config_hash` is unchanged (YAML, models, `max_tokens`, cache mode). It triages only the alerts without an answer and records each resume with its `git describe`. A run with `api_error` rows left is marked `failed`, with the resume command, never `complete`.
6. **The cache mode enters `config_hash`** (P2.5 follow-up), so a cache-only re-run is a separate run with the same numbers.

## Consequences

- P5 runs each experiment with `cjp experiment run <ID> --dry-run`, gets Jesse's OK, then runs without the flag. `/run-experiment` (P2.9) wraps exactly this.
- **Not built:** X0 baselines (M9: URL regex, Wazuh rule description), which need `cjp/evaluate/baselines.py`, and X4's flip-rate comparison (F7). Both are P5 work and need their own runner kind.
- `experiments/{D1,X1,X2,X3,X4}.yaml` are drafts (`draft: true`). P4 reviews them, removes the flag and freezes them with `prereg-C1`.
