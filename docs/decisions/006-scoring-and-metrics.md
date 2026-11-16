# 006 · Scoring and metrics: three-way outcomes, request-clustered bootstrap, list-price cost

**Date:** 2026-10-01 · **Status:** in effect from P2.7; the scoring rules are Claude Code's proposal, for Jesse to confirm before the P4 freeze · **Affects:** Plan M1, M3, M5, M7, M8, M10, P2.7, P4; [ARCHITECTURE §7](../ARCHITECTURE.md#7-evaluation-metrics)

## Contents

- [Context](#context) · [Decision](#decision) · [Consequences](#consequences)

## Context

The legacy scorer matched free-text `event_type` against a synonym table, so the v1 hedge ("Ambiguous /rest/user/login attempt (SQLi/brute-force/…)") was credited as correct (audit A4.1). It dropped benign alerts (A4.3), had no calibration (A4.4) or uncertainty (A4.5), and its grounding score measured copying (A4.8). Plan P2.7 names the metrics. This record fixes the choices it left open, so METHODS (P4) can state them as formulas.

## Decision

1. **Every answer gets one outcome per question:** `correct`, `wrong`, `abstained` or `no_answer`. `uncertain` and `needs_more_info` are abstentions and never count as correct. A refusal, truncation, unparseable or schema-invalid answer is `no_answer`: it is not an abstention, and it counts against strict accuracy. `other` and `none` on an attack alert are wrong.
2. **Technique label (fine)** is scored by exact match after `labels.yaml`'s `ground_truth` map, on attack alerts. **Coarse** maps both sides to their coarse group first (M5). `uncertain` stays abstained at the coarse level even when every candidate is in one group: Format B has no candidates, so crediting them would favour Format A in X2. Benign alerts are scored by disposition, plus the share labelled `none`.
3. **Rates.** Coverage = committed / scored. Selective accuracy = correct / committed. Strict accuracy = correct / scored. Escalation recall = `escalate` / attack alerts. False-positive dismissal = `dismiss_false_positive` / benign alerts. The `needs_more_info` rate is reported per class. Aggregate and unattributed alerts have no ground truth and are not scored.
4. **Uncertainty (M7):** 95% percentile bootstrap, 2,000 resamples, seed 0 (`config/settings.yaml`). It resamples **distinct requests**: the key is the sha256 of method, URL and request body as sent. All alerts of one request, all its repeats, and the same request in another session of the corpus move together. A session without `ingest_log.jsonl` clusters on method and URL only, which merges requests and widens the interval. `cjp experiment run` should therefore pass the corpus session, not a body-stripped copy. Repeats are pooled, and the per-repeat values give a min–max spread.
5. **Calibration (M8):** per reported confidence level, the counts, selective accuracy and the share of committed answers that are wrong. The headline is the share of `high` answers that are wrong. This is done for the fine label on attack alerts and for disposition on all alerts. Three verbal levels give no probability, so no ECE is computed.
6. **Cost:** tokens × the list price in `config/settings.yaml` (source URL and retrieval date), whether or not the answer was replayed from the cache. Cost per correct answer = total cost of all triaged rows / correct fine answers on attack alerts. A model with no price is reported as unpriced, never guessed.
7. **Legacy (v1) rows** are scored only to reproduce the audit. An `event_type` starting "Ambiguous" is abstained. Otherwise the legacy synonym table is used, fixed, with no flag to swap it. Their disposition is not scored.
8. **Removed:** evidence grounding (M10; the raters judge evidence, R3), and `cjp metrics --wp3 / --synonym / --category`. The category filter is what hid the login hedges in the 24 Sep figure; every label is now shown.

## Consequences

- On the audit's legacy runs, the scorer gives no_body 27 abstained and 20/21 committed correct, and with_body 33/48. It also reproduces A4.4's 12 of 32 high-confidence answers wrong (tested).
- A rule change here after `prereg-C1` needs a new decision record, and results then report both versions.
- For Jesse before P4: rule 2's coarse treatment of `uncertain`, and whether cost per correct answer should use disposition instead.
