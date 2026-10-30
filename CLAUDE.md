# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Status

The repo only has `README.md` so far. It has no code, dependencies, build, lint or test setup yet. Update this file once those exist.

## Purpose

This repo reproduces the evaluation work from a capstone project on LLMs in SOC alert triage. The project measures accuracy, but also how reliable and useful the outputs are. The evaluation has six layers, and each layer builds on the one before it:

1. **Ground truth**: a correlation ID goes into the Referer header of the raw access logs. It joins each Wazuh alert to the scripted request that caused it, and that join defines the correct answer for each alert.
2. **Scoring**: each model answer is scored as `correct` / `wrong` / `abstained` / `no_answer`. Fine label, coarse label and disposition are each scored separately. Severity is also scored, but only for Format A.
3. **Metrics**: coverage, selective and strict accuracy, escalation recall, FP dismissal, the share of high-confidence answers that are wrong, and cost per correct answer.
4. **Uncertainty**: 95% bootstrap CIs with 2000 resamples and seed 0. Resampling is over **distinct requests, not alerts**, because several alerts can come from the same request. Three repeated runs give a min–max spread.
5. **Comparisons**: evidence, format, model and baseline variants are compared with a paired bootstrap. A change counts as a difference only if its CI excludes zero.
6. **Human judgment**: 48 stratified outputs are rated on 5 rubrics. The Triage UI also gets a heuristic review against 11 published SOC criteria.

## Invariants to preserve

- Bootstrap resampling is done per request, not per alert. Fixed parameters: 2000 resamples, seed 0, 95% CI.
- Keep `abstained` and `no_answer` as separate outcomes from `wrong`. Coverage, selective accuracy and strict accuracy are computed differently because of that split.
