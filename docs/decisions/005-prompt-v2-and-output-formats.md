# 005 · Prompt v2: closed-set labels, two output formats, no testbed specifics

**Date:** 2026-10-01 · **Status:** in effect from P2.6; the label set (points 1–2) is Claude Code's proposal, for Jesse to confirm before the P4 freeze · **Affects:** Plan M2–M4, M12, P2.6, P2.7, P4; [ARCHITECTURE §5](../ARCHITECTURE.md#5-llm-triage-wp3)

## Contents

- [Context](#context) · [Decision](#decision) · [Consequences](#consequences)

## Context

The legacy prompt (`1cce404d`) asked for a free-text `event_type`, which was then scored by lenient substring matching. It also named the testbed's two shared endpoints together with their candidate labels, which leaks the testbed design and would not transfer to real users (Plan M4). P2.6 replaces it with a closed-set label (M2), a disposition (M3) and an environment-agnostic prompt, and adds a minimal format for X2. The details below are choices the plan left open.

## Decision

1. **One label file, `taxonomy/labels.yaml`,** feeds the schema enum, the label list in the prompt and the scorer. Labels have general names: the testbed's `forged_feedback` becomes `user_impersonation`, `error_probing` becomes `forced_browsing`, and `sql_injection_union` is `sql_injection` (a variant, not a technique). A `ground_truth` map translates the testbed's labels to taxonomy labels.
2. **The answer set is not the testbed's technique list.** Besides the 13 labels the testbed generates, it has 5 common web techniques the testbed never sends (`os_command_injection`, `csrf`, `open_redirect`, `xxe`, `insecure_deserialization`). A list of exactly the testbed's techniques would be a smaller version of the M4 leak. There are three special values: `uncertain` (abstain; candidates listed), `other`, and **`none`** (legitimate activity). `none` is an addition to the plan: without it, a benign alert has no truthful label.
3. **Format B = the first four decision fields of Format A, in the same order** (`technique_label`, `disposition`, `confidence`, `recommended_action`). FA inserts `candidate_labels` after the label and adds `event_type`, `severity`, `reasoning`, `evidence` and `cognitive_notes` after the decision. So X2 changes only what follows the decision, not the order in which the decision is generated.
4. **The schema is enforced by structured outputs** (`output_config.format`, sent with `between_tools` thinking at effort `high`). The API accepted this shape for both formats (`count_tokens`, 1 Oct). Field descriptions go only in the system prompt: repeating them in the schema cost about 300 input tokens per call. `cjp/triage/schema.py` validates every answer again, including the one cross-field rule the schema can't express (`uncertain` ⇔ 2+ candidates). A failing answer is kept with `schema_ok: false`, never re-asked ([decision 004](004-response-cache.md)).
5. **Payload.** `rule.firedtimes` is dropped: it counts since the manager started and made the same alert a different request in each session. `location` is reduced to the log file's name, because the full path named the application. Testbed names inside the evidence itself (e.g. the app's e-mail domain in request bodies, stack-trace paths in error pages) are left as they are: removing them would alter the evidence the conditions compare. This is the memorisation limitation (M12).
6. **Every row records** `prompt_id`, `prompt_version` (hash of the exact system prompt, one per format), `format` and `schema_version`. The v1 prompt is kept byte for byte in `prompts/legacy/triage_v1.txt`, so every version ever recorded resolves to a file.

## Consequences

- Scoring (P2.7) is by exact match on `technique_label`, with `uncertain` counted as abstained. The 5 extra labels make wrong-but-specific answers possible where the testbed-only list would have hidden them.
- Input grows from about 1.5k to 3.9k tokens per alert (FA; FB about 3.0k), mostly the label list and the schema, which the API adds to the prompt. P5's dry runs price this.
- `sensitive_data_exposure` keeps attacks.sh's A04 tag; OWASP 2025 maps CWE-200 to A01. Decide at P4 which the report uses.
- A change to `labels.yaml`, `triage_v2.md` or a format file changes `prompt_version` or `schema_version` and misses the cache by construction. After `prereg-C1` it needs a new decision record.
