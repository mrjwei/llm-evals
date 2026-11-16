# 019 · Rubric R2 anchors quoted (YAML fix, no wording change)

**Date:** 2026-10-04 · **Status:** in effect from P6.6 (`feat/p6-rate`) · **Affects:** `rubric/rating_rubric.yaml` (frozen at `prereg-C1`, [decision 011](011-pre-registration.md)); [METHODS §9](../METHODS.md#9-frozen-artefacts-and-deviations)

## Contents

- [Context](#context) · [Decision](#decision) · [Consequences](#consequences)

## Context

The P6.6 Rate page is the first code that parses the rubric's anchors. As frozen at `prereg-C1`, R2's line reads:

```yaml
anchors: {1: no, needs the raw logs to do anything, 3: partly, 5: yes, everything needed is here}
```

In a YAML flow mapping, the commas end each entry, and unquoted `no` and `yes` are booleans. So R2 parsed as `{1: false, 3: "partly", 5: true}` plus two stray keys. A rater would have seen "true" under 5 and nothing useful under 1. R1, R3, R4 and R5 parse as written. No rating existed yet, and nothing else reads the anchors.

## Decision

1. Quote R2's two anchor strings. The words, scales, items and `version: 1` are unchanged, and a comment in the file points here.
2. `cjp.rating.load_rubric()` refuses an anchor whose key is not a point on the item's scale or whose text is not a non-empty string. A test pins R2's anchors to the words in the file.

This is a deviation only in bytes: the file's sha256 changes, and the text a rater reads is now the pre-registered text. It is not the one anchor-wording pass that the calibration round allows (METHODS §7), and it does not use it up.

## Consequences

- `prereg-C1` is not moved (decision 002). Anyone comparing the tag with `main` finds this record from the file's comment.
- Rater files record the new sha256. None existed before the fix, so nothing is mixed.
