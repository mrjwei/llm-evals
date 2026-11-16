# 022 · X5 as a single-rater review; F8 built from the rating batch; the H1 table

**Date:** 2026-10-11 · **Status:** in effect from P7.2 (`exp/p7-rating`) · **Affects:** Plan P7.2–P7.4; [METHODS §7](../METHODS.md#7-expert-rating-and-heuristic-evaluation), [§8](../METHODS.md#8-limitations); decisions [012](012-canonical-pins-and-results-build.md), [018](018-rating-batches-and-offline-pack.md), [021](021-x5-batch-allocation.md)

## Contents

- [Context](#context) · [Decision](#decision) · [Consequences](#consequences)

## Context

On 11 Oct Jesse (rater A) finished all 54 X5 items in the app, under rubric v1 (`81d2c19f`). There is no time left for rater B (the supervisor) to rate before the results freeze. METHODS §7 pre-registers this case: "If the second rater cannot rate, Jesse rates alone and the result is reported as a single-rater review." It does not say how the analysis, the calibration round or `cjp results build` handle it. The H1 table (P7.4) is written by hand and had no format.

## Decision

1. **Single-rater review.** This is the pre-registered fallback, not a deviation, so METHODS is unchanged. The 6 calibration items, which Jesse rated alone, stay out of the analysis. The anchor wording was not changed, so rubric v1 holds. The agreement table lists every item with "not computable" and the reason. If a complete `rater-B.json` exists at a later build, κ is computed and each item's score becomes the mean of the two raters.
2. **Readings where METHODS §7 leaves room.** "Per condition and format" means per cell (S1×L0 FA, S1×L1 FA, S1×L1 FB). The "scored outcome" is the stratum: the fine outcome for attacks, with benign as one group. "Confidence" is the LLM's stated level. Each 95% CI is a percentile bootstrap over items, with the METHODS §6 settings; every item is a distinct request cluster (decision 021). "Ground truth" for R5 is the expected disposition (decision 006: escalate attacks, dismiss benign). R5 agreement is a share of items, with a CI, shown next to the LLM's own match on the same items, plus 3×3 cross-tabs.
3. **F8 reads the batch, not a pin.** In `results/canonical.yaml`, `F8_rating` has `from: [X5]`. A name that is a rating batch in `data/ratings/` and not a pin is analysed by `cjp/rating_analysis.py`. The build checks three things: the batch was drawn from the runs pinned now, every started rater file is complete, and each rater's rubric is the current one. The manifest records each rater file's sha256.
4. **H1 table format.** `results/tables/H1_heuristic.csv` has one row per criterion and rater: `criterion, text, rater, score_FA, score_FB, observation_FA, observation_FB`. The text is Table I of Okazawa et al. (WOSOC 2026, doi 10.14722/wosoc.2026.23012), taken from the PDF's text layer (`wosoc26-04.pdf`, sha256 `ab8a1268…`) and checked word for word. Scores use the paper's scale, 5 = fully satisfies to 1 = does not satisfy. The build never writes this file. It reports the file as a problem until every criterion is scored for both formats.
5. **Unblinding.** Rating is closed, so Jesse may now open `key.json` and the per-item tables.

## Consequences

- The report states that X5 is a single-rater review by the system's designer (METHODS §8), with no inter-rater agreement. Means are reported per cell or per stratum, never pooled as if the batch were representative.
- `cjp results build` exits 1 until H1 is filled in. That is the intended reminder before `results-freeze-v1`.
