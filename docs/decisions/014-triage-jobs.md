# 014 · Triage jobs: captured inputs, the research request, approved calls only

**Date:** 2026-10-04 · **Status:** in effect from P6.2 (`feat/p6-triage-jobs`) · **Affects:** Plan P6, §2.3; [ARCHITECTURE §9](../ARCHITECTURE.md#9-web-app); [RUNBOOK §9](../RUNBOOK.md#9-the-web-app)

## Contents

- [Context](#context) · [Decision](#decision) · [Consequences](#consequences)

## Context

Plan P6.2 asks for triage jobs in `data/triage_jobs/<job-id>/` from three sources (a demo C1 session with ground truth hidden, an uploaded `.jsonl`, a live Wazuh window), with a bodies toggle, an estimate before and the actual cost after, and a background run with progress and resume through the response cache. `cjp/triage/` is frozen at `prereg-C1`, and its batch loop has no progress hook or stop flag. CLAUDE.local says API budget is never spent silently. The P6.1 log left open how the verdict's Format A/B toggle works.

## Decision

1. **New module `cjp/triage_jobs.py`**, with routes in `web/api/triage.py`. It reuses `analyse_alert`, `api_error_row`, `make_jobs`, `load_completed_ids`, `cache_key_for` and `experiment.estimate` unchanged. The per-alert loop keeps `batch.triage_jobs()`'s rules (a fatal error, or three failures in a row, stops it) and adds progress and a stop flag.
2. **Inputs are captured once, at creation:** `alerts.jsonl` and `bodies.jsonl`, with every correlation ID redacted. A live job resumes on the same alerts. A demo job copies no attack or benign log.
3. **The request is the research request:** repeat 1, the same payload and the same cache key as `cjp triage` and `cjp experiment run`. Redacting before storing is idempotent with the prompt's own redaction, so demo jobs on X1 or X2 conditions replay their cached answers for $0.
4. **Approved calls only.** Creating a job plans and estimates, then stops at `planned`. `start` takes `max_calls`, the paid calls the person approved, and refuses (409) a job that needs more. One job runs at a time.
5. **Liveness by a lock file.** The worker holds `flock` on the job's `.lock`. A job whose process died reads as `interrupted`, never as stuck `running`. Starting a stopped, failed or interrupted job again resumes it: answered alerts are skipped and `api_error` rows retried. Each start is recorded with its approved calls and `git describe`.
6. **Every job triages in both formats by default** (P6.1's option (a), Jesse's choice), one `verdicts_<F>.jsonl` each. The verdict's A/B toggle then shows two real answers, not FB derived from FA, which is what H1 compares. It doubles a live job's calls, and the estimate shows that before anything is spent. A job may still ask for one format.
7. **Cost:** the estimate is `experiment.estimate`'s upper bound (output ≤ `max_tokens`). After a run, `actual.cost_usd` is this job's own paid calls at list price, and `answers_cost_usd` is what every answer cost to obtain, cached or not (decision 006).

## Consequences

- `cjp/indexer.py` `get_alerts_since()` gains an optional `agent` filter. Without it the query is unchanged.
- Jobs share the response cache with research runs, as decision 004 intends: an identical request is one sample, however it was asked.
- Live bodies need SSH to the VM (one `grep -F` of the ingest log by CID). Without SSH the job runs without bodies and says so.
