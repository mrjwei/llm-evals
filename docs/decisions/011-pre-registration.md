# 011 · Pre-registration: open choices settled, X0 and severity added, what `prereg-C1` freezes

**Date:** 2026-10-03 · **Status:** in effect from P4. The `expected_decisions.yaml` values are Claude Code's proposal for Jesse to review before the tag · **Affects:** Plan P4, M9, M11; decisions [005](005-prompt-v2-and-output-formats.md), [006](006-scoring-and-metrics.md), [008](008-experiment-runner-and-corpus.md); [METHODS](../METHODS.md)

## Contents

- [Context](#context) · [Decision](#decision) · [Consequences](#consequences)

## Context

P4 freezes the method before any X-run (Plan M11). Decisions 005 and 006 left four choices for Jesse. Going through the YAMLs also found two gaps. X4's `_inj` labels had no ground-truth mapping, so every injected alert would have been left unscored. X0 existed only as a row in the plan.

## Decision

1. **Label set confirmed** as in decision 005: 18 labels plus `none`, `other` and `uncertain`. `sensitive_data_exposure` is tagged **A01**, because OWASP Top 10:2025 lists CWE-200 under Broken Access Control, and 2025's A04 is Cryptographic Failures. attacks.sh keeps its legacy tag. The OWASP tag appears in report tables only.
2. **Coarse `uncertain` stays abstained** (decision 006 rule 2 confirmed), so X2 compares FA and FB on equal terms.
3. **Cost is reported two ways:** per correct fine label (primary, unchanged) and per correct disposition over all alerts (secondary). This amends decision 006 rule 6.
4. **Expected decisions** (`rubric/expected_decisions.yaml`): every attack label expects `escalate` and benign expects `dismiss`. The scorer refuses the file if it ever disagrees with decision 006 rule 3. Each label has a two-level severity band (NIST SP 800-61 impact factors, OWASP). FA's severity is scored against it as a **secondary** metric. `reference_actions` guide raters (R1) and are never matched against model text.
5. **`_inj` labels map to their base technique** in `labels.yaml`. Scored rows keep the raw label (`truth_raw`), so X4 can compare injected alerts with clean ones (METHODS §5.5).
6. **X0 is pre-registered:** `experiments/X0.yaml` (kind `baseline`, one condition per arm × B-url-regex | B-rule) and `taxonomy/baselines.yaml` (each baseline's label and disposition). The runner stays P5 work (decision 008), and `cjp experiment run X0` refuses until it exists.
7. **Contrasts:** the named contrasts in METHODS §6 get a paired cluster-bootstrap difference. There are no p-values.
8. **Frozen at `prereg-C1`:** the files in METHODS §9, plus C1's sha256 in the tag message. Code added later only to implement a rule METHODS defines is not a deviation. Any other change needs a decision record, and both figures are reported.

## Consequences

- The prompt and schema hashes are unchanged (FA `b5c5f509`/`d480aff8`, FB `a9e5d4ef`/`6b058835`), so cache keys and D1 are unaffected.
- P5 builds three things against fixed definitions: `cjp/evaluate/baselines.py` (X0), the X4 flip rate and the paired contrasts.
- `rubric/rating_rubric.yaml` is frozen except for one anchor-wording pass in the P7 calibration round, which must be recorded.
- Before tagging, Jesse reviews the severity bands and checks two citations marked `[assumption]`: SP 800-61's impact tables, and Wazuh's level classification in `baselines.yaml`.
