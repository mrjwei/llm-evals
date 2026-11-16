# 018 · Rating: blind batches, per-rater order, autosave, offline pack

**Date:** 2026-10-04 · **Status:** in effect from P6.6 (`feat/p6-rate`) · **Affects:** Plan P6 "Rate", P7.1–P7.3; [METHODS §7](../METHODS.md#7-expert-rating-and-heuristic-evaluation); [ARCHITECTURE §9](../ARCHITECTURE.md#9-web-app)

## Contents

- [Context](#context) · [Decision](#decision) · [Consequences](#consequences)

## Context

Plan P6.6 builds the rating queue that P7 needs. METHODS §7 fixes the rubric (R1–R5), the blinding (alert and output only), the 6-item calibration round and the two raters. P7.1 makes the batch with `cjp rating make-batch`. Still open were the batch's file layout, how blinding is enforced rather than promised, the order each rater sees, how scores are saved, and how a rater without the app takes part.

## Decision

1. **A batch is a folder**, `data/ratings/<batch>/`: `batch.json` (items, calibration item IDs, the rubric version and sha256), `items.jsonl`, `key.json`, and `ratings/rater-A.json` and `rater-B.json`. `cjp/rating.py` `create_batch()` writes it for `make-batch` and refuses to replace an existing one.
2. **Blind by construction.** An item is exactly `{item, alert, body, answer}`, and `create_batch()` refuses any other field. Item IDs are opaque. The key (run, condition, alert, repeat, outcome) is in `key.json`, which no route, page or pack reads. A test checks that no response contains it.
3. **Order.** Calibration items come first, in batch order, because both raters do them together. The rest are shuffled per rater with `Random("<batch>:<rater>")`, so the app and the pack agree, and the rater's file stores the order.
4. **Scores only, saved per click.** Each change POSTs only the changed scores, and the server checks them against the rubric: R1–R4 whole numbers on their scale, R5 one of its three choices. There are no comments or timings (Plan P7.0). An item is complete when all five are set. The position is `?n=` in the URL and is pinned on arrival, so finishing an item never moves the screen.
5. **The rubric may change only in the calibration round.** Each rater file records the rubric's version and sha256. If the rubric changes, a save is refused once that rater has scored any item outside the calibration round. Otherwise the record moves to the new rubric. One rater's scores never mix two wordings.
6. **Offline pack.** `cjp rating export-pack <batch>` writes one HTML file. The data is JSON with `<`, `>`, `&` and U+2028/9 escaped. Plain JS builds every element with `textContent`. The CSP is `default-src 'none'` and allows only the pack's own script and style, by hash, with `connect-src 'none'`. Scores autosave in `localStorage` and leave through "Download ratings".
7. **Import never replaces scores.** `cjp rating import <file>` checks the batch, rater, items, scores and rubric (rule 5), then writes the rater's file. It refuses if that rater already has scores, unless the file is identical (then it reports "unchanged").

## Consequences

- P7.1 only has to choose the items (the stratification is METHODS §7's) and call `create_batch()`.
- A rater uses the app or the pack, not both: an import does not merge.
- Clearing `localStorage` loses unsaved pack scores. The pack says to download often when the browser can't save.
