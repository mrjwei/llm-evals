# 012 · Canonical pins per experiment; `results/` built from them; P5 analysis code

**Date:** 2026-10-03 · **Status:** in effect from P5 (`feat/p5-analysis`) · **Affects:** Plan §2.3 rule 4, P5, P8; [decision 008](008-experiment-runner-and-corpus.md), [011](011-pre-registration.md); [METHODS §5.5, §5.6, §6](../METHODS.md#5-scoring-and-metrics); [ARCHITECTURE §6](../ARCHITECTURE.md#6-outputs-and-provenance)

## Contents

- [Context](#context) · [Decision](#decision) · [Consequences](#consequences)

## Context

Plan §2.3 pins each figure to one run (`F3_calibration ← run`), and P2.4 built `mark-canonical --as F3` that way. Several P5 figures read more than one experiment: F5 (cost vs quality) reads X0, X1 and X3, and the X0-vs-X1 and X3-vs-X1 contrasts need two runs each. With per-figure pins, the same experiment could be pinned to different runs in two figures without anyone noticing. P5 also needs the code that implements three pre-registered rules: the X0 baselines, the X4 flip rate and the paired contrasts.

## Decision

1. **One canonical run per experiment.** `results/canonical.yaml` has `pins` keyed by experiment ID (`cjp runs mark-canonical <run>` defaults the key to the run's experiment), and a hand-edited `figures` section: each figure or table key (F1–F7, T1, T2), its title and the experiments it reads (`from`). Writing a pin keeps `figures` as it is. Re-pinning an experiment moves every figure that reads it.
2. **`cjp results build`** reads only the pinned runs' stored `metrics.json` and `scores.jsonl`. It makes no API call and does not re-score, so a figure always shows its run report's numbers. It writes `results/tables/<key>*.csv`, `results/figures/<key>.png` (whose footer names each run, its corpus sha256 and its `git describe`) and `results/manifest.json`.
3. **The build checks, not judges.** Each pin must exist, be complete, belong to its experiment, and come from a clean `prereg-C1` descendant (Plan P5 acceptance). Problems go into the manifest and make the exit code 1. Outputs are still written, so the build can be run after every experiment. It never deletes: a file it did not write is listed as stale (`H1_heuristic.csv`, P7.4, is exempt).
4. **Analysis code is new modules only:** `cjp/evaluate/baselines.py`, `injection.py` and `contrasts.py`. The frozen `score.py`, `metrics.py`, `mapper.py` and `report.py` are unchanged. A baseline writes a verdict row in the triage format, so the unchanged mapper and scorer hold it to the LLM's rules.
5. **Readings of METHODS where its wording leaves room:** "S1 vs S2 vs S3" is the three pairwise contrasts. A contrast is B − A on every primary rate both sides define (fine and coarse coverage, selective and strict accuracy, escalation recall, FP dismissal, high-confidence wrong, and cost per correct label as a ratio of cluster sums). X4's "non-`escalate` / scored" counts a no-answer as not escalated, and its injected − clean difference is a point value (descriptive, §5.5). Baselines cost 0, not "unpriced".

## Consequences

- `T2_contrasts` (METHODS §6) joins the Plan's F1–F7 and T1 in the figure set.
- `numpy` becomes a direct dependency (it was already present through matplotlib) for the vectorised paired bootstrap.
- `--as` still accepts a free key, but `results build` only reads pins keyed by an experiment ID.
