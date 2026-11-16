# 015 · Triage queue and verdicts: lanes, calibration from the pins, the instruction flag, feedback

**Date:** 2026-10-04 · **Status:** in effect from P6.3 (`feat/p6-queue-api`) · **Affects:** Plan P6; [ARCHITECTURE §9](../ARCHITECTURE.md#9-web-app); [RUNBOOK §9](../RUNBOOK.md#9-the-web-app)

## Contents

- [Context](#context) · [Decision](#decision) · [Consequences](#consequences)

## Context

Plan P6.3 asks for:
- the queue's sort order, a "Needs a human" lane and filters
- calibration per confidence level from the canonical X1 run
- a flag for instruction-like text (X4)
- CSV and JSON export, and storage for product feedback

P6.2 jobs hold both formats' answers. What the P5 runs showed about calibration is held back until the paper is published.

## Decision

1. **New module `cjp/triage_queue.py`.** It only reads job files and writes `feedback.jsonl`. It never calls a model and never touches `data/runs/`.
2. **Lanes, by one format at a time** (default: the job's first format; the A/B toggle re-sorts):
   - `human`: an `uncertain` label, `low` confidence, or no usable answer (an API error, a refusal, an off-schema answer)
   - `pending`: not answered yet
   - `queue`: everything else

   Sort order is escalate → needs_more_info → dismiss, then severity, then Wazuh rule level, then time. Format B has no severity field, so it borrows Format A's for the same alert.
3. **"Source" filter = the log the alert came from** (`agent: location`). A job has a single source kind, so filtering on that would do nothing. Jesse confirmed this reading on 4 Oct.
4. **Calibration comes from the pinned X1, X2 and X3 runs.** The Plan names X1 only. For each verdict, the nearest condition is chosen by model, then format, arm and bodies, so Format B reads X2's FB and Haiku reads X3. The fields that differ are listed. Each level shows how often the label and the disposition were right, with n. A level with fewer than 20 committed answers is marked as too few to judge. With no pins, there is no chip and a note explains why.
5. **The instruction-like-text flag is a regex heuristic.** It covers X4's five phrasings plus common injection forms, and each pattern is also tried URL-decoded. It scans the request body, the response body and the log line. It reports where the phrase was found and which phrase. On the real corpora it flags 12/12 injected requests and 0 of 773 clean ones.
6. **Export:**
   - Export order is the queue order: the `queue` lane, then `human`, then `pending`.
   - The CSV has both formats side by side. A cell starting with `= + - @` gets a leading `'`, because log text is attacker-controlled and the file will be opened in a spreadsheet.
   - The JSON export holds the full items.
7. **Feedback** is appended to the job's `feedback.jsonl`, tagged `"purpose": "product feedback"`. The latest entry per alert and format wins, and `null` clears it. No evaluation code reads it (Plan P6 "Export").

## Consequences

- The chip shows evaluation numbers on C1. A live alert is not C1, so the UI must say "in evaluation", never "probability".
- The flag can be evaded by rephrasing, so the UI must call it a warning, not a guarantee. Re-pinning a run (decision 012) changes the chip with no code change.
