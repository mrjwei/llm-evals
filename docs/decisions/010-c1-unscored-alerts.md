# 010 · C1 keeps its two stray alert types, unscored; another session's CID is never attributed

**Date:** 2026-10-03 · **Status:** in effect from P3 close; P4 METHODS states it · **Affects:** Plan P3.5, P4; [decision 009](009-recollect-c1-before-prereg.md); [ARCHITECTURE §4 Ground truth and alert mapping](../ARCHITECTURE.md#4-ground-truth-and-alert-mapping); [wazuh notes §9](../reference/wazuh-and-vm-notes.md#9-clock-skew-and-the-alert-window)

## Contents

- [Context](#context) · [Decision](#decision) · [Consequences](#consequences)

## Context

The frozen C1 holds alerts that no request of its own session caused:

- **Rule 11** (Wazuh's hourly log-volume alert, no description, no CID): 1 in seed 1's S2 file. The mapper already leaves it `unattributed`.
- **Back-to-back overlap:** seed 3's first request (`GET /rest/basket/1`, CID `wp1-20261002_130347-1-1`) falls inside seed 2's window because of the 2 s end buffer. It appears in **all three** of seed 2's arms. The 2 Oct log said S3 only, which was wrong. In S3 it was unattributed. In S1 and S2 the mapper found no ground truth for the CID, fell through to the signature tier and labelled it `idor` with `is_attack = True`. D1 therefore counted one extra true-positive alert in each of those arms.

## Decision

1. **C1 is not re-collected or edited.** Both alert types stay in the files, and the triage conditions see them, as an analyst would.
2. **Neither is scored.** Rule 11 already isn't. The mapper gains a tier: an alert whose CID names a session that this session's own logs don't carry gets `match_method = other_session` and `is_attack = None`. It never falls through to the time or signature tiers, because the neighbouring session scores it.
3. **`cjp collect` (offline) drops such alerts from now on** and writes one warning per affected arm to the manifest, so `corpus freeze` shows it. Online mode keeps everything: its directory is named from the Mac's clock, not the VM's session id.
4. **Legacy results never delivered UNION SQLi** ([decision 009](009-recollect-c1-before-prereg.md)). METHODS says so, and any comparison with August–September figures does too.

## Consequences

- The D1 run `2026-10-03T0617_12fffc` predates rule 2. Its S1 and S2 precision each include the extra true positive, so it is re-run and superseded. Recall is unchanged, because seed 2 detects `idor` with its own requests.
- Every X-run spends one triage call per condition and repeat on each of these alerts. Their verdicts are kept but not scored.
- Checked across C1, C1-inj and every legacy session: only C1 seed 2's overlap alert becomes `other_session`.
