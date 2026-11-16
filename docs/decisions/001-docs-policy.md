# 001 · Documentation policy: split by audience, no status file

**Date:** 2026-09-30 · **Status:** accepted · **Supersedes:** the STATUS.md-centred layout (tag `pre-cleanup-2026-09-30`)

## Contents

- [Context](#context) · [Decision](#decision) · [Consequences](#consequences)

## Context

By 30 Sep, `docs/` held 15 files (~3,000 lines). Status lived in several places at once: `STATUS.md` (31 commits), a gitignored `PROGRESS.md` (924 lines), the sprint diary in `CLAUDE.local.md`, and a checklist inside each dated plan. They drifted apart. A merged branch was never recorded, one doc cited an `outputs/` path that didn't exist, and `STATUS.md` caused a merge conflict because every branch edited it. The dated plan docs were also appended to after the fact, so none of them showed what was decided when.

## Decision

1. **Commit what a reader of the code or the method needs; keep personal working notes out.** README, ARCHITECTURE, RUNBOOK, METHODS, reference notes, decision records, log entries, the project history and the plan are tracked. Meeting notes, todo lists and day-to-day scratch notes stay in the Obsidian vault (`~/projects/Notes/IFN738/`) or in gitignored local files.
2. **Follow the doc types in Plan §2.4**:
   - reference docs are rewritten in place, with length caps
   - `METHODS.md` is frozen at pre-registration
   - `log/` gets one new file per update, never edited afterwards
   - `decisions/` records are never edited; a new record supersedes an old one
   - `docs/README.md` is an index
3. **No STATUS.md.** Status is the plan's checkboxes (PLAN.md, the only file edited for status), plus `data/runs/INDEX.md` once it exists (P2.4), plus the latest log entry.
4. **Retire old docs by condensing, not by carrying them forward.** Their content was merged into history/2026-09-30_project-history.md and the reference docs. The originals stay reachable at tag `pre-cleanup-2026-09-30`, and the untracked PROGRESS.md is in the out-of-repo archive.

## Consequences

- Each branch carries its own doc changes, so docs and code stay in step on merge. Moving everything out of the repo would have lost that link.
- Append-only logs and decisions can't conflict, because every branch adds new files instead of editing shared ones.
- The full narrative of July–September is one `git show` away rather than in `docs/`, which makes it slightly less convenient to browse.
- If the repo is shared or submitted, the retired supervisor-meeting and planning docs are still in git history. Review them before publishing.
