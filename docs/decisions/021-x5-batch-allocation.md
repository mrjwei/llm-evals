# 021 · X5 rating batch: equal strata, 6 extra calibration items, each request once

**Date:** 2026-10-04 · **Status:** in effect from P7.1 (`exp/p7-rating`) · **Affects:** Plan P7.1–P7.3; [METHODS §7](../METHODS.md#7-expert-rating-and-heuristic-evaluation); [decision 018](018-rating-batches-and-offline-pack.md)

## Contents

- [Context](#context) · [Decision](#decision) · [Consequences](#consequences)

## Context

METHODS §7 fixes what the X5 batch is stratified over (S1×L0 and S1×L1, correct / wrong / abstained, benign-triggered alerts, FA vs FB), its size (`--n 48`, seed 7) and the 6-item calibration round. It does not fix how many items go in each stratum, whether the calibration items count towards the 48, or how a row is chosen when the same request was answered in 3 sessions × 3 repeats. Jesse chose the allocation on 4 Oct. In the pinned runs the scarcest stratum, S1×L0 attack-correct, has 7 distinct requests.

## Decision

1. **Three cells.** X1 `S1-plain__L0-alert__FA__sonnet`, X1 `S1-plain__L1-alert+body__FA__sonnet` and X2 `S1-plain__L1-alert+body__FB__sonnet`. X2's FA half is a cache replay of X1's, so X2 adds only FB.
2. **Equal allocation.** Each cell gets n/12 items in each of four strata: attack-correct, attack-wrong, attack-abstained (the fine outcome), and benign (any outcome). With n = 48 that is 4 per stratum and 16 per cell. Wrong answers are over-sampled compared with the runs, so outcomes and formats can be compared at equal n. Mean scores are reported per stratum, never pooled as if the batch were representative.
3. **Calibration comes on top: 48 analysed + 6 = 54 items.** Each cell gets one benign item and one attack item. The attack outcome rotates (L0 abstained, L1 FA wrong, FB correct), so the round covers every outcome. These 6 items are excluded from analysis.
4. **Each request at most once in the batch.** The draw works on request clusters (METHODS §6), so a rater never sees the same request again in another session, repeat, evidence level or format. The scarcest stratum is filled first. Within a cluster, one row (session × repeat) is picked at random, so repeats are pooled.
5. **What the model was sent, proven.** Each item is rebuilt from the frozen corpus by `build_alert_summary()` and must match the verdict's cache key, or the batch is refused. The body is split into `body`. The answer is the stored `llm_output`.
6. **Blind to the maker as well.** `make-batch` prints counts only, never an item's stratum. Jesse is rater A, so he does not open `key.json` until both raters finish (METHODS §8 limitation).

## Consequences

- This implements METHODS §7 and changes nothing frozen at `prereg-C1`. The allocation is a sampling choice made before any rating.
- Per stratum and cell, n = 4. Analysis by cell or by outcome pools the other factor, and the CIs will be wide (P7.3).
- The same seed and pins always give the same items. A redraw needs a new batch ID, because a batch is never replaced.
