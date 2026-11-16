# 017 · Triage page: approve what was shown, state in the URL

**Date:** 2026-10-04 · **Status:** in effect from P6.5 (`feat/p6-triage-ui`) · **Affects:** Plan P6 "Triage"; [ARCHITECTURE §9](../ARCHITECTURE.md#9-web-app); [RUNBOOK §9](../RUNBOOK.md#9-the-web-app)

## Contents

- [Context](#context) · [Decision](#decision) · [Consequences](#consequences)

## Context

Plan P6.5 builds the Triage page on the P6.2–P6.3 API. The server already refuses a start that needs more paid calls than `max_calls` ([decision 014](014-triage-jobs.md)). Which number the page sends decides whether "approved" means what the person actually read. Decision 015 set how the calibration chip and the instruction flag must be worded. Two more questions were open: how a stopped job resumes, and how the queue's view survives a reload.

## Decision

1. **Preparing a job is its own step.** "Prepare and estimate" creates a `planned` job: the alerts are captured and the cost estimated, and nothing goes to Claude. The job page shows the estimate before any Run button does anything.
2. **The approval dialog sends exactly what it showed.** The dialog keeps a snapshot of the job it displays (paid calls, the most they can cost, input tokens, cached answers), and "Approve N paid calls and run" sends that N. A refusal (409) says so and offers "Estimate again".
3. **Free runs skip the dialog.** When every answer is cached, Run sends `max_calls: 0`, so the server would refuse any paid call.
4. **Resume re-estimates first.** For a stopped, failed or interrupted job, Resume asks for a new estimate of what is left. The dialog then shows those calls, not the whole job's.
5. **A source the health checks block can't be submitted.** The page names the failing checks and links to Home for the fix.
6. **The queue's state is in the URL**: `?format=&lane=&label=&disposition=&source=&alert=`. A reload or a shared link reopens the same view. The alert is a query parameter, not a path segment, because Wazuh alert IDs contain a dot and the server answers unknown dotted paths as missing files. Opening an alert adds a history step, so Back returns to the queue. Changing a filter replaces the current step.
7. **One format at a time, everywhere.** The A/B toggle in the queue and the one in the verdict are the same setting, so the list and the open answer always match. A verdict whose formats disagree says so and summarises the other answer.
8. **Wording.**
   - Calibration reads "In evaluation on C1, "high" answers had the right label N of M times…", followed by "a track record on test data, not a probability for this alert". It names the condition, and any setting that differs from the job's.
   - The flag reads "a pattern check: … no warning does not mean safe".
   - Feedback says it "is never used as research data".

## Consequences

- vitest pins rules 2–4 and 8 (`JobRun.test.tsx`, `triage.test.ts`, `VerdictView.test.tsx`).
- A shared job link works only on the Mac whose `data/triage_jobs/` holds the job. The app is local by design (decision 013).
