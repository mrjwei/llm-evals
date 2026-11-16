# 020 · Results browser: read-only, report.md rendered as elements, confined to the run

**Date:** 2026-10-04 · **Status:** in effect from P6.7 (`feat/p6-results`) · **Affects:** Plan P6 "Results"; [ARCHITECTURE §9](../ARCHITECTURE.md#9-web-app); refines [decision 016](016-web-ui-build-and-safety.md) rule 3

## Contents

- [Context](#context) · [Decision](#decision) · [Consequences](#consequences)

## Context

Plan P6.7 lists the runs with experiment, RQ, status, headline and a canonical badge, and opens each `report.md` with its charts. Decision 016 said a rendered `report.md` would need a sanitiser and a new decision, because no raw HTML may reach the page. Reports are written by `cjp` from scored data, but their tables quote model output and labels, so they are treated like any other text.

## Decision

1. **Read the registry live.** `/api/runs` reads every `run.json` and `results/canonical.yaml` (the sources `INDEX.md` is generated from), not the Markdown of `INDEX.md`. It lists every status, newest first, with the pin keys per run and any pin that names a missing run.
2. **Serve only what a report shows.** `…/report?doc=` returns a file named `report.md`, and `…/files/<path>` a `.png`, both resolved inside that run's folder. Scores, verdicts, `run.json` files, the cache and other runs are never served. Nothing writes.
3. **Markdown becomes React elements, with no HTML in between.** `react-markdown` with `remark-gfm` (tables) builds elements directly, and `skipHtml` drops raw HTML. No sanitiser is needed because no HTML string is ever produced. Decision 016's grep test still holds for `web/ui/src`.
4. **Links and images stay in the run.** A relative link to another `report.md` of the same run opens in the page (`?doc=`). A relative `.png` loads through the files route. An `http(s)` link opens in a new tab with `rel="noreferrer noopener"`. Anything else (another run, an absolute path, `javascript:`, a remote image) is shown as plain text.
5. **Filters and the open report are in the URL** (`?experiment=&rq=`, `?doc=`), as on the Triage page (decision 017).
6. **The run page loads on demand.** The Markdown parser is in its own chunk (React `lazy`, same origin, so the CSP allows it), and the first page load stays at about 160 kB gzip.

## Consequences

- A report that links outside its run shows the link text only. Today's reports link only within the run.
- The paper still cites `results/` only (Plan §2.3). This page shows where those numbers come from but does not replace `cjp results build`.
