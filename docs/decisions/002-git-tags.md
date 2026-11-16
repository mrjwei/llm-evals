# 002 · Git tags: three milestone tags, annotated and never moved

**Date:** 2026-09-30 · **Status:** accepted · **Extends:** the 17 Aug choice of "annotated tags plus per-row `git_sha`" (project history §2)

## Contents

- [Context](#context) · [Decision](#decision) · [Consequences](#consequences)

## Context

The plan already names three tags (`pre-cleanup-2026-09-30`, `prereg-C1`, `results-freeze-v1`) but had no rules for them. Four feature tags from 17 Aug also exist. The question was whether tags are needed at all, given that every run will record its git SHA. The repo has no remote, so each tag exists only on Jesse's Mac.

## Decision

Keep tags, but only for states that a document must be able to *name*. The rules are in Plan §2.5 Git tags. In short:

1. There are three tags, one each for P0, P4 and P8. Phases are not tagged: the merge commit and the SHA in each log entry already identify them.
2. Tags are annotated and never moved. A change creates a new `-r2` tag plus a decision record.
3. The `prereg-C1` message carries the corpus hash, and the tag gets an outside timestamp (a remote push, or an email to the supervisor) before P5.
4. `run.json` records `git describe --tags --always --dirty`.

## Consequences

- **Pre-registration becomes checkable.** The claim "metrics and labels were fixed before results" rests on the order of `prereg-C1` and the first X-run. A SHA alone can't show that order, and a moved tag would erase it. That is why rule 2 exists.
- **A local tag proves little to outsiders**, because tagger dates can be set freely. The outside timestamp in rule 3 costs one email.
- **`git describe` makes provenance readable.** `prereg-C1-4-gab12cd-dirty` says "four commits after pre-registration, with uncommitted code". A bare SHA says none of that. P5's acceptance check relies on it.
- There is one more thing to remember at P4 and P8. Claude Code prints the command, and Jesse runs it.
