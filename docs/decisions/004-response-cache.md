# 004 · Response cache: keyed by the exact request, every answer kept

**Date:** 2026-09-30 · **Status:** in effect from P2.5; the key design is Claude Code's, for Jesse to confirm at the P2 checkpoint · **Affects:** Plan P2.5, M7, P8 `results build`; [ARCHITECTURE §5](../ARCHITECTURE.md#5-llm-triage-wp3)

## Contents

- [Context](#context) · [Decision](#decision) · [Consequences](#consequences)

## Context

Plan P2.5 asks for a cache keyed by "prompt, format, model, temperature, alert content minus volatile IDs, repeat number", so that re-running, re-scoring and re-reporting never pay for the same answer twice, and so `cjp results build` can regenerate every figure from cache alone (P8). A hand-picked key tuple has one failure mode that matters: a request field left out of the key replays an answer given to a *different* request, silently. `max_tokens`, `thinking` and `output_config` are already such fields, and P2.6 adds an output schema.

## Decision

1. **Key = sha256 of the exact `messages.create` request + the repeat number + a key version** (`cjp/cache.py`). The request contains the prompt, format, model, every sampling or thinking parameter and the alert payload, so all of the plan's components are covered and a new parameter cannot be forgotten.
2. **"Minus volatile IDs" means minus what the model never sees.** The Wazuh document `id` and `@timestamp` are not in the payload, and every CID is redacted before hashing. Fields that *are* sent, e.g. `rule.firedtimes`, stay in the key: replaying an answer across different payloads would misstate what the model was given.
3. **Every model answer is cached,** including refusals, `max_tokens` truncations and unparseable output. They are results; re-asking until an answer parses would select results. Exceptions (network, 5xx) are not answers and are not cached.
4. **Nothing is overwritten.** `--no-cache` calls again and moves the old entry aside as `<key>.superseded-<time>.json`. Each entry stores its request, so it can be audited and a mismatched entry is refused.
5. **Each repeat is its own entry.** Repeats 1–3 are three samples (M7, [decision 003](003-triage-model-sonnet-5-5.md)), never one answer reused three times.

## Consequences

- Replaying a frozen session is free and exact. `--cache-only` guarantees zero spend: it stops before writing if any alert is missing.
- Any change to the prompt, model or parameters misses the cache by construction; old entries remain for old runs.
- Each output row records `repeat`, `cache_key` and `cache_hit`, so a run can show which answers were fresh.
- METHODS (P4) states that a repeated run replays cached samples unless `--no-cache` is given.
