# 007 · Robustness: model settings tracked, failed calls retried and never scored, config checked at start-up

**Date:** 2026-10-01 · **Status:** in effect from P2.10 · **Affects:** Plan P2.8, P2.10, X3; [decision 003](003-triage-model-sonnet-5-5.md) (model unchanged); [decision 006](006-scoring-and-metrics.md) rule 1 (clarified, not changed); [ARCHITECTURE §5](../ARCHITECTURE.md#5-llm-triage-wp3)

## Contents

- [Context](#context) · [Decision](#decision) · [Consequences](#consequences)

## Context

Plan P2.10 asks for retries, resume, clear errors and config checked at start-up. Three gaps showed up while building it. The model ID and effort came from environment variables, so the method depended on a shell. The request parameters were Sonnet 5.5's: Haiku 4.5 (X3) accepts neither `between_tools` nor `effort` (Models API, 1 Oct), so every X3 call would have been a 400. And a call that raised was written as a row with `parse_ok: false`. `--resume` then skipped that alert, and the scorer counted it as `no_answer`, which charges an outage to the model's strict accuracy.

## Decision

1. **Models live in `config/settings.yaml`** (tracked): an alias per model (`sonnet`, `haiku`, the suffix of a condition ID), its ID from the models list, and the request parameters it accepts. `triage.model` is the default, and `CJP_TRIAGE_MODEL` may override it with an alias or listed ID only. `CJP_TRIAGE_EFFORT` is retired. For Sonnet the request is byte-identical to before (checked: the same 32 cache keys on the fixture session), so the cache stays valid.
2. **Retries are the SDK's own:** connection errors, 408, 409, 429 and 5xx, exponential backoff honouring `retry-after`, `api.max_retries` = 6, timeout 120 s. There is no second retry loop of our own.
3. **A call that still fails is an `api_error` row.** It records the failure, but it is not an answer. `--resume` retries it, and readers keep the last row per alert. Scoring leaves it out; the report and `metrics.json` count it. A refusal, truncation or invalid answer stays `no_answer` (decision 006 rule 1): that is the model's output. A fatal error (bad key, unknown model, rejected request) stops the batch at once, and three other failures in a row stop it too. Either way the exact resume command is printed.
4. **Every command checks the config first** (`config.validate()`: settings fields, URLs, required files). It lists every problem and runs nothing. Known failures print one line with the fix (`cjp/errors.py`; `CJP_DEBUG=1` for the traceback). Unknown ones keep their traceback, because they are bugs.
5. **`cjp doctor`** checks config, key and models (through the Models API, which uses no tokens, including whether each model supports the effort we send), then SSH, the manager API, the indexer, the agent and its log paths, Juice Shop, the proxy and the deployed SHA. It prints a fix for each failure and changes nothing. `--selftest` runs pytest; skipped tests are a warning, because the skipped ones are the acceptance checks.

## Consequences

- X3 can run on Haiku without code changes. Its answers are cached under different keys, as they should be.
- A strict-accuracy denominator now excludes outages. If a condition still has `api_error` rows at the end, resume it before reporting.
- A new model needs a settings entry, checked by `cjp doctor`, before anything can call it.
