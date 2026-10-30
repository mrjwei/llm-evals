# AI Evaluation in My Capstone

This repo reproduces my evaluation work in my capstone project, which investigates not just the accuracy of LLMs in SOC alert triage, but also the reliability and usefulness of their outputs.

## Six layers

### 1. Ground truth

It answers, "What is the right answer for each alert?". To build the ground truth, I added a correlation ID to the Referer header of the raw access logs. The ID joins every Wazuh alert to the scripted request that caused it.

### 2. Scoring

Each answer gets correct/wrong/abstained/no_answer, separately for the fine label, the coarse label, the disposition, and (Format A) the severity.

### 3. Metrics

- Coverage
- Selective and strict accuracy
- Escalation recall
- FP dismissal
- The share of high-confidence answers that are wrong
- Cost per correct answer

### 4. Uncertainty

A 95% bootstrap confidence interval that resamples distinct requests, not alerts: 2000 resamples, seed 0. Three repeats give a min-max spread.

### 5. Comparisons

Comparing:

- Evidence
- Format
- Model
- Baseline

with paired bootstrap. A change counts as a difference only when its interval excludes zero.

### 6. Human judgment

This answers one of my research questions: "Would a SOC analyst find the output useful?" I rated 48 stratified outputs on 5 rubrics, plus a heuristic review of the Triage UI against 11 published SOC criteria.
