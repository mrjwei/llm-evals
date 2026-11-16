# 003 · Triage model: Claude Sonnet 5.5, thinking off, no temperature

**Date:** 2026-09-30 · **Status:** accepted (Jesse) · **Affects:** Plan M7 and P2.6; [ARCHITECTURE §5](../ARCHITECTURE.md#5-llm-triage-wp3)

## Contents

- [Context](#context) · [Decision](#decision) · [Consequences](#consequences)

## Context

Every legacy run used `claude-sonnet-5` with `thinking: {type: "disabled"}` and no sampling parameters. Jesse chose `claude-sonnet-5-5`, the current Sonnet, for all new runs, and the `anthropic` SDK moved to 1.x at the same time. Sonnet 5.5 changes three things this pipeline relies on:

- `thinking: {type: "disabled"}` returns a 400. The thinking-off setting is `{type: "between_tools"}`, which is valid only at effort `high` or below.
- Non-default `temperature` / `top_p` / `top_k` return a 400, so Plan M7's "temperature 0" cannot be sent.
- Safety declines arrive as HTTP 200 with `stop_reason: "refusal"` and a category.

## Decision

1. Model `claude-sonnet-5-5` (`CJP_TRIAGE_MODEL`). The ID was checked with `models.retrieve` on 30 Sep. Each output row records `response.model`.
2. Thinking stays off, as in the legacy runs: `between_tools`, with `output_config.effort` set explicitly to `high` (`CJP_TRIAGE_EFFORT`, the API default). Adaptive thinking at low effort, which the migration guide suggests trying first, is a method change. If it is wanted, it becomes an experiment condition decided at P4, not a silent default.
3. No sampling parameters. Plan M7's variance control is the **3 repeats per condition** and their spread, not temperature 0.
4. A refusal is recorded as a failed row with its category and explanation. No server-side fallback to another model is configured: a row answered by a different model would silently mix models inside one condition. Refusals are counted and reported instead.

## Consequences

- New runs are not comparable one-to-one with legacy runs, which used a different model and are reported as legacy only (Plan §6 risks). `PROMPT_VERSION` is unchanged (`1cce404d`) until P2.6.
- P2.6's "temperature defaults to 0" is superseded by point 3. METHODS (P4) states it as a limitation: outputs are not greedy-decoded, and repeats measure the run-to-run spread.
- The refusal rate per condition becomes a reported number. With security payloads, a `cyber` decline is plausible and should be visible, not hidden.
- Changing the model or thinking mode later needs a new record that supersedes this one.
