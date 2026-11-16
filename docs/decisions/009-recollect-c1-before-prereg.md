# 009 · Corpus C1 re-collected before pre-registration: the UNION technique was never delivered

**Date:** 2026-10-02 · **Status:** in effect from P3.5 · **Affects:** Plan P3.5, P4, §2.5; [decision 008](008-experiment-runner-and-corpus.md) rule 1; [RUNBOOK §3 Freeze a corpus](../RUNBOOK.md#3-freeze-a-corpus)

## Contents

- [Context](#context) · [Decision](#decision) · [Archive manifest](#archive-manifest) · [Consequences](#consequences)

## Context

C1 (seeds 1–3) and C1-inj were frozen on 2 Oct. All acceptance checks passed, but in every session the six `sql_injection_union` requests show status `000`. In the `attacks.sh` pool their search URLs carried raw spaces. curl 8.5 on the VM rejects such a URL before sending it (exit 3), so no request reached Juice Shop, its access log or Wazuh. Session `20260930_121903` and the legacy sessions show the same `000`, so P3.3 did not cause it. One of 14 techniques was missing from the testbed, and every arm reported it "missed" although Wazuh never had a chance to see it. The `_inj` variant, which writes spaces as `%20`, was delivered and detected.

## Decision

1. **Fix the traffic, not the scoring.** The UNION pool writes spaces as `%20` (commit `8905d84`). A test fails if any GET URL in `attacks.sh` contains a raw space.
2. **Re-collect C1 and C1-inj** with the same commands (seeds 1–3, then one `INJECTION=1` session), after `cjp vm deploy`.
3. **Keep the ID C1.** No run has read the old C1 and `prereg-C1` is not tagged, so nothing cites it. The old corpora are moved to the archive, not deleted, and the new ones are frozen under the same IDs. This exception to decision 008 rule 1 applies only before the tag. After `prereg-C1`, a changed corpus always gets a new ID.

## Archive manifest

Approved by Jesse on 2026-10-02.

| Path | Action | Reason |
|---|---|---|
| `data/corpus/C1/` (corpus.json `fabb45bf…`) | move to `../_archive/2026-10-02_corpus-C1-r0/C1/` | `sql_injection_union` never delivered |
| `data/corpus/C1-inj/` (corpus.json `378bce7b…`) | move to `../_archive/2026-10-02_corpus-C1-r0/C1-inj/` | collected from the same `attacks.sh` |

The source sessions in `data/sessions/` (`20261002_111010`, `_111552`, `_112146`, `_121137`) stay where they are. They are superseded by the re-collection and are not used by any experiment.

## Consequences

- C1 rises from 13 to 14 delivered techniques. D1's technique recall for each arm can now count UNION SQLi as detected.
- The legacy results (WP4, Aug–Sep) also never delivered this technique. Any comparison with them in the report has to say so.
