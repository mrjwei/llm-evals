# Practitioner study protocol (future work)

The study that WP5 first planned, written as a protocol for the report's appendix (Plan P7.5). It has **not been run** and has no ethics approval. The capstone replaced it with an expert and analytical evaluation: X5 rating, expected-decision scoring and the H1 heuristic evaluation ([METHODS §7](../METHODS.md#7-expert-rating-and-heuristic-evaluation)). Reference doc: rewritten in place, ≤200 lines.

## Contents

- [1. Why it is future work](#1-why-it-is-future-work)
- [2. Aim and questions](#2-aim-and-questions)
- [3. Design](#3-design)
- [4. Participants and recruitment](#4-participants-and-recruitment)
- [5. Materials](#5-materials)
- [6. Session procedure](#6-session-procedure)
- [7. Measures](#7-measures)
- [8. Analysis](#8-analysis)
- [9. Ethics and data handling](#9-ethics-and-data-handling)
- [10. Threats to validity](#10-threats-to-validity)

## 1. Why it is future work

The original WP5 planned practitioner validation: SOC practitioners rating a sample of verdicts with a two-rater rubric, comparing the full output format with a minimal one, plus qualitative practitioner interviews. It needed human-research ethics approval, which was not in place in time. RQ2 asks how far an analyst can *safely rely* on the output. The capstone answers it with calibration metrics, expected-decision scoring and researcher ratings. Only a practitioner study can show how analysts actually rely on it.

## 2. Aim and questions

Aim: measure whether the triage output helps working analysts make correct escalation decisions, and whether its design (Format A vs B, stated confidence, abstention) changes how far they rely on it.

- **P1.** Do analysts decide more accurately with the LLM's verdict than with the raw alert alone?
- **P2.** Do analysts follow wrong verdicts (over-reliance), and does stated confidence or abstention change that?
- **P3.** Does the full (A) or minimal (B) format lead to better decisions, faster decisions or higher rated actionability?
- **P4.** How usable is the Triage interface for SOC work, on Okazawa et al.'s 11 criteria?

## 3. Design

Within-subjects, three conditions per participant: **raw alert only** (control), **Format A** and **Format B**. Each participant triages three blocks of alerts, one block per condition. Block order and the assignment of alert sets to conditions are counterbalanced (Latin square), so no alert appears twice for one participant.

- **Alert sets:** drawn from the frozen corpus C1 with the X5 strata (attack: LLM correct, wrong or abstained; benign), so over-reliance can be measured on known-wrong verdicts. Each set has 12 alerts, 3 per stratum, matched on technique.
- **Verdicts:** the stored answers of the pinned X1 and X2 runs, served through the response cache. The study makes no new API calls, and every participant sees the same output for the same alert.
- **Blinding:** participants are not told which verdicts are wrong or what the strata are.

## 4. Participants and recruitment

- **Who:** practising SOC analysts (Tier 1–2) or incident responders with at least 6 months of alert-triage experience. A second, clearly separated group of security students may be added for comparison.
- **How many:** 8–12 analysts. This is enough for within-subject comparisons and thematic saturation in the interviews, not for population estimates.
- **Recruitment:** industry contacts and CyberCon networking, through an invitation that the research team does not send to its own reports or students.

## 5. Materials

These already exist in this repository:

- The Triage web app (`cjp ui`), loaded with a demo job per alert set, with the Format A/B toggle hidden and the format fixed per block.
- The rating rubric R1–R5 (`rubric/rating_rubric.yaml`) and the Rate page or offline pack (decision 018) for per-item ratings.
- `rubric/expected_decisions.yaml` for ground-truth dispositions.
- The H1 instrument (`results/tables/H1_heuristic.csv` format, decision 022) for the post-task usability rating.

Still needed: a raw-alert-only view (the Triage verdict panel hidden), a participant information sheet, a consent form, and a decision log that records each participant's disposition and time per alert.

## 6. Session procedure

One session per participant, about 75 minutes, in person or by screen share:

1. **Consent and briefing (10 min).** Information sheet, consent, the task, and a note that the system can be wrong.
2. **Practice (5 min).** Two practice alerts, not analysed.
3. **Three triage blocks (3 × 12 min).** For each alert the participant chooses escalate, dismiss or need more info, and states their confidence (low/medium/high). In the A and B blocks they also score R1–R4.
4. **Usability rating (10 min).** The 11 Okazawa et al. criteria, scored 1–5 for Format A and B, with free-text observations.
5. **Semi-structured interview (10 min).** When did you trust or check the verdict? What made you override it? What was missing? Was the confidence useful? A or B, and why?

## 7. Measures

| Measure | Definition | Question |
|---|---|---|
| Decision accuracy | Participant disposition = expected disposition | P1, P3 |
| Over-reliance | Share of LLM-wrong items where the participant follows the LLM's disposition | P2 |
| Appropriate reliance | Follows correct verdicts, overrides wrong ones | P2 |
| Confidence calibration | Participant accuracy within each of their confidence levels | P2 |
| Time per alert | Seconds from opening an alert to deciding | P3 |
| Rubric R1–R4 | As in X5 | P3 |
| H1 scores | 1–5 per criterion and format | P4 |
| Interview themes | Coded reasons for trusting, checking or overriding | P2–P4 |

## 8. Analysis

- **Accuracy and reliance:** mixed-effects logistic regression with condition as a fixed effect and participant and alert as random effects. Paired differences are reported with bootstrap CIs over participants. Pre-register the model and the contrasts (control vs A, control vs B, A vs B) before the first session, as for C1 (decision 011).
- **Time:** mixed-effects model on log time.
- **Rubric and H1:** per-condition means with CIs; agreement between the participants' R5 and the X5 single-rater review.
- **Interviews:** reflexive thematic analysis by two coders, with the codebook and the agreement reported.

## 9. Ethics and data handling

- **Approval:** a QUT human research ethics application (low-risk pathway expected [assumption: check with QUT's research ethics office]) before any recruitment.
- **Data:** decisions, ratings, timings and de-identified interview notes under participant codes. Audio only with separate consent, transcribed and then deleted. No employer names and no real alert data from participants' organisations.
- **Storage:** QUT-managed storage, not this repository. The repository holds only the instruments and the analysis code.
- **Withdrawal:** participants can withdraw until their data are anonymised; this cut-off is stated on the information sheet.

## 10. Threats to validity

- **Testbed realism:** one web application, scripted attacks, and Juice Shop strings an analyst may recognise ([METHODS §8](../METHODS.md#8-limitations)).
- **Small n** and a convenience sample. Results are indicative.
- **Learning effects** across blocks are reduced by counterbalancing, not removed.
- **Lab setting:** no time pressure or alert volume like a real shift. Okazawa et al.'s simulated operational environment would address this.
