"""
`cjp experiment list | run <ID> | status`: one command per experiment
(Plan §2.3, P5; the runner P2.4 deferred until the cache, prompt v2 and the
scorer existed, P2.5–P2.7).

    cjp experiment run X1 --dry-run     plan + cache hits + calls + tokens + cost; spends nothing
    cjp experiment run X1               asks before any paid call, then runs
    cjp experiment run X1 --resume <run>  continues a failed or interrupted run in place

An experiment is experiments/<ID>.yaml. Its conditions are the only place a
condition exists, and each condition ID says what it is:

    S1-plain__L1-alert+body__FA__sonnet
    │          │             │   └ model alias in config/settings.yaml `models`
    │          │             └ output format: FA (full) or FB (minimal)
    │          └ LLM evidence: L0-alert (alert only) or L1-alert+body (+ ingest_log bodies)
    └ SIEM evidence: which arm's alerts (S1-plain, S2-body-in-url, S3-body-field)

`kind: siem` experiments (D1) have bare S-level conditions and no LLM.
`kind: baseline` experiments (X0) pair an S-level with a lookup baseline
(`S1-plain__B-url-regex`, `S1-plain__B-rule`) defined in taxonomy/baselines.yaml
and applied by cjp/evaluate/baselines.py (P5): each alert gets a verdict row
from the lookup instead of a Claude call, then is mapped and scored exactly
like a triage answer. Neither kind calls the API.

For every condition × corpus session × repeat, the runner triages through the
response cache (so a rerun costs nothing), maps each alert to ground truth,
then scores each condition over all its sessions and repeats with the P2.7
metrics. Outputs land at the condition's one address in the run registry:

    data/runs/<ID>-<slug>/<run>/
        run.json                         provenance, cache counts, headline
        report.md                        one row per condition, links below
        contrasts.json                   METHODS §6 contrasts inside this experiment (X1, X2)
        conditions/<condition>/
            report.md, metrics.json, scores.jsonl, charts/
            rep<N>/<session>/verdicts.jsonl, mapped.jsonl

metrics.json also holds X4's flip rates (`injection`, METHODS §5.5) when the
corpus has injected alerts. Contrasts across experiments (X0 vs X1, X3 vs
X1) need two runs, so `cjp results build` computes them from the pins.

Paid calls are never silent: before the first one the runner prints the
calls and tokens it will spend and asks (CLAUDE.local: "Never spend API
budget silently"); --dry-run prints the same and stops. A condition is only
complete when every alert has an answer: if calls failed (api_error rows,
decision 007) the run is marked failed with the command that resumes it.
"""

import json
import math
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

from cjp import cache, corpus as corpus_mod, runs
from cjp.config import BASELINES_FILE, EXPERIMENTS_DIR, model_profile, settings

ARM_FILES = {"S1-plain": "wazuh_alerts.jsonl",
             "S2-body-in-url": "enriched_wazuh_alerts.jsonl",
             "S3-body-field": "body_field_wazuh_alerts.jsonl"}
EVIDENCE = {"L0-alert": False, "L1-alert+body": True}
FORMATS = {"FA": "A", "FB": "B"}
KINDS = ("triage", "siem", "baseline")
BASELINES = ("B-url-regex", "B-rule")   # taxonomy/baselines.yaml, cjp.evaluate.baselines
MAPPER_TOLERANCE = 1.5          # cjp map's default; only pre-CID sessions use it
TOKEN_SAMPLE = 5                # count_tokens calls per condition for an estimate


class RunAborted(RuntimeError):
    """Triage stopped early (fatal error or repeated failures)."""


# ── conditions ───────────────────────────────────────────────────────────────
@dataclass(frozen=True)
class Condition:
    id: str
    arm: str
    alerts_file: str
    with_body: bool = False
    fmt: str | None = None          # "A" / "B"; None for kind siem and baseline
    model: str | None = None        # alias in settings.yaml `models`
    baseline: str | None = None     # one of BASELINES, kind baseline only


def parse_condition(cid: str, kind: str = "triage") -> Condition:
    """A condition ID → what it runs. Errors say which part is wrong."""
    parts = cid.split("__")
    if kind == "siem":
        if len(parts) != 1 or parts[0] not in ARM_FILES:
            raise ValueError(f"condition {cid!r}: a siem condition is one of {', '.join(ARM_FILES)}")
        return Condition(cid, parts[0], ARM_FILES[parts[0]])
    if kind == "baseline":
        if len(parts) != 2 or parts[0] not in ARM_FILES or parts[1] not in BASELINES:
            raise ValueError(f"condition {cid!r}: a baseline condition is <SIEM>__<baseline>, with "
                             f"SIEM one of {', '.join(ARM_FILES)} and baseline one of {', '.join(BASELINES)}")
        return Condition(cid, parts[0], ARM_FILES[parts[0]], baseline=parts[1])
    if len(parts) != 4:
        raise ValueError(f"condition {cid!r}: expected <SIEM>__<LLM evidence>__<format>__<model>, "
                         "e.g. S1-plain__L1-alert+body__FA__sonnet")
    arm, evidence, fmt, model = parts
    for value, allowed, what in ((arm, ARM_FILES, "SIEM evidence"), (evidence, EVIDENCE, "LLM evidence"),
                                 (fmt, FORMATS, "format")):
        if value not in allowed:
            raise ValueError(f"condition {cid!r}: {what} {value!r} is not one of {', '.join(allowed)}")
    if model not in settings()["models"]:
        raise ValueError(f"condition {cid!r}: model {model!r} is not an alias in config/settings.yaml "
                         f"`models` ({', '.join(settings()['models'])})")
    return Condition(cid, arm, ARM_FILES[arm], EVIDENCE[evidence], FORMATS[fmt], model)


def experiment_kind(exp: runs.Experiment) -> str:
    kind = exp.spec.get("kind", "triage")
    if kind not in KINDS:
        raise ValueError(f"{exp.path}: kind {kind!r} is not one of {', '.join(KINDS)}")
    return kind


def load(ref: str, experiments_dir: Path = EXPERIMENTS_DIR) -> tuple[runs.Experiment, str, list[Condition]]:
    exp = runs.load_experiment(ref, experiments_dir)
    kind = experiment_kind(exp)
    conditions = [parse_condition(c, kind) for c in exp.conditions]
    if kind in ("siem", "baseline") and exp.reps != 1:
        raise ValueError(f"{exp.path}: a {kind} experiment has no LLM, so reps must be 1")
    return exp, kind, conditions


def short_ids(conditions: list[Condition]) -> dict[str, str]:
    """Condition IDs without the parts every condition shares, for tables
    and headlines (X1: S1-plain__L0-alert, …, since all are FA sonnet)."""
    split = [c.id.split("__") for c in conditions]
    if len(split) < 2 or len({len(s) for s in split}) != 1:
        return {c.id: c.id for c in conditions}
    keep = [i for i in range(len(split[0])) if len({s[i] for s in split}) > 1]
    return {c.id: "__".join(s[i] for i in keep) for c, s in zip(conditions, split)}




# ── the plan: what would be called ──────────────────────────────────────────
@dataclass
class Unit:
    """One condition × session × repeat, and the alerts still to triage."""
    condition: Condition
    session: Path
    rep: int
    jobs: list = field(default_factory=list)       # (alert, ingest entry)
    keys: list = field(default_factory=list)       # their cache keys
    hits: list = field(default_factory=list)       # whether the cache answers each
    done: int = 0                                  # already answered in a resumed run

    @property
    def cached(self) -> int:
        return sum(self.hits)

    @property
    def to_call(self) -> int:
        return len(self.jobs) - self.cached


def unit_dir(run_dir: Path, condition: str, rep: int, session: str) -> Path:
    return Path(run_dir) / "conditions" / condition / f"rep{rep}" / session


def plan(conditions: list[Condition], sessions: list[Path], reps: int, cache_mode: str = "use",
         run_dir: Path | None = None) -> list[Unit]:
    """Every triage unit, with what the cache (and, when resuming, the run's
    own verdicts) already answers. Reads files only; calls nothing.
    A request already planned earlier in the run (the same request in another
    session, same repeat) counts as cached: its first call fills the cache
    for the rest, so it is paid for once. Not under refresh, which calls for
    every alert."""
    from cjp.triage.batch import (load_alerts_from_session, load_completed_ids, load_ingest_log,
                                  make_jobs)
    from cjp.triage.client import cache_key_for
    units, planned = [], set()
    for cond in conditions:
        for session in sessions:
            alerts = load_alerts_from_session(str(session), cond.alerts_file)
            ingest = load_ingest_log(str(session)) if cond.with_body else None
            for rep in range(1, reps + 1):
                done = set()
                if run_dir is not None:
                    done = load_completed_ids(str(unit_dir(run_dir, cond.id, rep, session.name)
                                                  / "verdicts.jsonl"))
                jobs = make_jobs([a for a in alerts if a.get("id") not in done], ingest)
                keys = [cache_key_for(a, e, rep, cond.fmt, cond.model) for a, e in jobs]
                if cache_mode == "refresh":
                    hits = [False] * len(keys)
                else:
                    hits = [k in planned or cache.has(k) for k in keys]
                    planned.update(keys)
                units.append(Unit(cond, session, rep, jobs, keys, hits, len(alerts) - len(jobs)))
    return units


def _cached_output_tokens(key: str) -> int | None:
    try:
        entry = json.loads(cache.entry_path(key).read_text())
        return entry["response"]["usage"]["output_tokens"]
    except (OSError, KeyError, ValueError):
        return None


def estimate(units: list[Unit], count: bool = True) -> dict[str, dict]:
    """Per condition: paid calls, input tokens and the most they can cost.
    Input tokens: count_tokens (free, no model call) on up to TOKEN_SAMPLE
    distinct requests, scaled by request length; `count=False` assumes 3.5
    characters per token. Output is bounded by max_tokens per call; the mean
    output of cached answers for the condition is shown when there are any."""
    from cjp.triage.client import get_client, request_params
    from cjp.triage.prompt import build_alert_summary
    max_tokens = settings()["triage"]["max_tokens"]
    prices = settings()["prices"]["usd_per_mtok"]
    by_cond: dict[str, list[Unit]] = {}
    for u in units:
        by_cond.setdefault(u.condition.id, []).append(u)
    out = {}
    for cid, group in by_cond.items():
        cond = group[0].condition
        model_id = model_profile(cond.model)["id"]
        blobs, requests, cached_out = [], {}, []
        for u in group:
            for (alert, entry), key, hit in zip(u.jobs, u.keys, u.hits):
                if hit:
                    if (n := _cached_output_tokens(key)) is not None:
                        cached_out.append(n)
                    continue
                params = request_params(build_alert_summary(alert, entry)[0], cond.fmt, cond.model)
                params.pop("max_tokens")
                blob = json.dumps(params, sort_keys=True)
                blobs.append(blob)
                requests.setdefault(blob, params)     # repeats share one request
        per_char, method = 1 / 3.5, "≈ characters / 3.5"
        if count and requests:
            keys = list(requests)
            sample = keys[::max(1, math.ceil(len(keys) / TOKEN_SAMPLE))][:TOKEN_SAMPLE]
            counted = sum(get_client().messages.count_tokens(**requests[k]).input_tokens for k in sample)
            per_char = counted / sum(len(k) for k in sample)
            method = f"count_tokens on up to {TOKEN_SAMPLE} distinct requests per condition, scaled by length"
        calls = len(blobs)
        input_tokens = round(sum(len(b) for b in blobs) * per_char)
        price = prices.get(model_id)
        out[cid] = {
            "model": model_id, "calls": calls, "input_tokens": input_tokens,
            "output_tokens_max": calls * max_tokens, "method": method,
            "cached_mean_output_tokens": round(sum(cached_out) / len(cached_out)) if cached_out else None,
            "cost_max_usd": ((input_tokens * price["input"] + calls * max_tokens * price["output"]) / 1e6
                             if price else None),
        }
    return out


def print_plan(exp: runs.Experiment, corp, conditions: list[Condition], units: list[Unit],
               kind: str) -> None:
    short = short_ids(conditions)
    print(f"[experiment] {exp.id} {exp.slug} ({', '.join(exp.rq)}): {exp.question}")
    print(f"[experiment] corpus {corp.id}: {len(corp.sessions)} session(s), checksums verified; "
          f"{len(conditions)} condition(s) × {exp.reps} repeat(s)")
    if kind == "siem":
        print("[experiment] kind siem: maps and scores the alerts only; no LLM, no API calls")
        return
    if kind == "baseline":
        print("[experiment] kind baseline: lookup baselines from taxonomy/baselines.yaml, "
              "scored like triage answers; no LLM, no API calls")
        return
    print(f"\n  {'condition':<34} {'alerts':>7} {'done':>6} {'cached':>7} {'to call':>8}")
    for cond in conditions:
        group = [u for u in units if u.condition.id == cond.id]
        alerts = sum(len(u.jobs) + u.done for u in group)
        print(f"  {short[cond.id]:<34} {alerts:>7} {sum(u.done for u in group):>6} "
              f"{sum(u.cached for u in group):>7} {sum(u.to_call for u in group):>8}")
    print(f"  {'total':<34} {sum(len(u.jobs) + u.done for u in units):>7} "
          f"{sum(u.done for u in units):>6} {sum(u.cached for u in units):>7} "
          f"{sum(u.to_call for u in units):>8}\n")


def print_estimate(est: dict[str, dict], conditions: list[Condition]) -> float | None:
    """Print the estimate; return the total upper bound in USD (None if a
    model is unpriced)."""
    short = short_ids(conditions)
    print(f"  {'paid calls':<34} {'calls':>6} {'input tok':>10} {'output ≤':>9} {'cost ≤':>9}")
    for cid, e in est.items():
        if not e["calls"]:
            continue
        cost = f"${e['cost_max_usd']:.2f}" if e["cost_max_usd"] is not None else "unpriced"
        print(f"  {short[cid]:<34} {e['calls']:>6} {e['input_tokens']:>10,} "
              f"{e['output_tokens_max']:>9,} {cost:>9}")
    total = None if any(e["cost_max_usd"] is None for e in est.values() if e["calls"]) else \
        sum(e["cost_max_usd"] or 0 for e in est.values())
    calls = sum(e["calls"] for e in est.values())
    print(f"  {'total':<34} {calls:>6} {sum(e['input_tokens'] for e in est.values()):>10,} "
          f"{sum(e['output_tokens_max'] for e in est.values()):>9,} "
          f"{'$' + format(total, '.2f') if total is not None else 'unpriced':>9}")
    methods = sorted({e["method"] for e in est.values() if e["calls"]})
    means = [f"{short[c]} {e['cached_mean_output_tokens']}" for c, e in est.items()
             if e["cached_mean_output_tokens"] is not None]
    print(f"  input tokens: {'; '.join(methods)}. Output ≤ max_tokens per call "
          f"({settings()['triage']['max_tokens']}); cost ≤ list price "
          f"({settings()['prices']['retrieved']})."
          + (f" Mean output of cached answers: {', '.join(means)}." if means else ""))
    return total


# ── running ──────────────────────────────────────────────────────────────────
def run_settings(conditions: list[Condition], cache_mode: str, kind: str) -> dict:
    """Run-time inputs outside the YAML. They enter config_hash, so two runs
    with one hash had the same models, parameters and cache mode."""
    out = {"mapper_tolerance": MAPPER_TOLERANCE}
    if kind == "baseline":
        # what the lookups apply: a changed table or file is a different run
        from cjp.evaluate.mapper import SIGNATURES
        out.update(baselines_sha256=runs._sha256_file(BASELINES_FILE),
                   signatures_sha256=runs._sha256_json(SIGNATURES))
    if kind == "triage":
        aliases = sorted({c.model for c in conditions})
        out.update(cache_mode=cache_mode, max_tokens=settings()["triage"]["max_tokens"],
                   models={a: model_profile(a) for a in aliases})
    return out


def prompts_used(conditions: list[Condition]) -> dict:
    from cjp.triage import schema
    from cjp.triage.prompt import PROMPT_ID, prompt_version
    return {f: {"prompt_id": PROMPT_ID, "prompt_version": prompt_version(f),
                "schema_version": schema.schema_version(f)}
            for f in sorted({c.fmt for c in conditions if c.fmt})}


def _empty_stats() -> dict:
    return {"processed": 0, "cache_hits": 0, "api_calls": 0, "api_errors": 0,
            "tokens_billed": 0, "total_tokens": 0, "aborted": False}


def triage_unit(run: runs.Run, unit: Unit, cache_mode: str) -> dict:
    from cjp.triage.batch import triage_jobs
    run.condition_dir(unit.condition.id, unit.rep)      # validates the address
    d = unit_dir(run.path, unit.condition.id, unit.rep, unit.session.name)
    d.mkdir(parents=True, exist_ok=True)
    path = d / "verdicts.jsonl"
    if not unit.jobs:
        path.touch()
        return _empty_stats()
    return triage_jobs(unit.jobs, str(path), append=path.exists(), repeat=unit.rep,
                       cache_mode=cache_mode, fmt=unit.condition.fmt, model=unit.condition.model,
                       verbose=False)


def baseline_unit(run: runs.Run, cond: Condition, session: Path) -> int:
    """Write one baseline condition's verdicts for one session (repeat 1:
    a lookup gives the same answer every time). Returns the row count."""
    from cjp.evaluate.baselines import verdicts
    from cjp.triage.batch import load_alerts_from_session
    run.condition_dir(cond.id, 1)
    d = unit_dir(run.path, cond.id, 1, session.name)
    d.mkdir(parents=True, exist_ok=True)
    rows = verdicts(load_alerts_from_session(str(session), cond.alerts_file), cond.baseline)
    with open(d / "verdicts.jsonl", "w") as f:
        for row in rows:
            f.write(json.dumps(row) + "\n")
    return len(rows)


def map_unit(run: runs.Run, cond: Condition, session: Path, rep: int, kind: str) -> list[dict]:
    """Map one arm of one session, joining this repeat's verdicts; writes
    mapped.jsonl (derived from verdicts.jsonl, so it is rewritten on resume)."""
    from cjp.evaluate.mapper import map_alerts
    run.condition_dir(cond.id, rep)
    d = unit_dir(run.path, cond.id, rep, session.name)
    d.mkdir(parents=True, exist_ok=True)
    verdicts = str(d / "verdicts.jsonl") if kind in ("triage", "baseline") else None
    rows, _ = map_alerts(str(session), verdicts, MAPPER_TOLERANCE, cond.alerts_file)
    with open(d / "mapped.jsonl", "w") as f:
        for row in rows:
            f.write(json.dumps(row) + "\n")
    return rows


# ── scoring ──────────────────────────────────────────────────────────────────
def _siem_metrics(session: Path, rows: list[dict]) -> dict:
    from cjp.evaluate.mapper import build_ground_truth, load_benign_ground_truth
    from cjp.evaluate.metrics import (count_lines, detection_metrics, precision_fpr_metrics,
                                      signature_crosscheck_metrics)
    _, attacks, _ = build_ground_truth(str(session / "attack_log.jsonl"))
    benign = load_benign_ground_truth(str(session))
    return {"detection": detection_metrics(rows, attacks, count_lines(str(session / "access.log"))),
            "precision_fpr": precision_fpr_metrics(rows, len(benign) or None),
            "signature": signature_crosscheck_metrics(rows)}


def pool_siem(per_session: dict[str, dict]) -> dict:
    """Detection and precision summed over the corpus sessions (techniques
    are counted per session: the same technique in two sessions counts twice)."""
    det = [m["detection"] for m in per_session.values()]
    prec = [m["precision_fpr"] for m in per_session.values()]
    total, found = sum(d["techniques_total"] for d in det), sum(d["techniques_detected"] for d in det)
    tp, fp = sum(p["true_positive_alerts"] for p in prec), sum(p["false_positive_alerts"] for p in prec)
    volume = Counter()
    for d in det:
        volume.update(dict(d["alert_volume_per_technique"]))
    return {
        "detection": {"techniques_total": total, "techniques_detected": found,
                      "technique_recall": found / total if total else None,
                      "alerts_total": sum(d["alerts_total"] for d in det),
                      "alert_volume_per_technique": volume.most_common()},
        "precision_fpr": {"true_positive_alerts": tp, "false_positive_alerts": fp,
                          "precision_alert_level": tp / (tp + fp) if tp + fp else None},
    }


def condition_metrics(run: runs.Run, cond: Condition, sessions: list[Path], reps: int,
                      kind: str, boot: dict | None = None) -> tuple[dict, list[dict]]:
    """SIEM metrics per session (from repeat 1's mapping, which every repeat
    shares) and triage metrics pooled over every session and repeat, with
    request clusters that span sessions (decision 006 rule 4). Baseline
    verdicts are scored the same way. With injected alerts (C1-inj), the
    X4 flip rates are added as `injection`."""
    from cjp.evaluate.injection import flip_rates
    from cjp.evaluate.mapper import load_jsonl
    from cjp.evaluate.metrics import triage_metrics
    from cjp.evaluate.score import score_rows
    per_session, scored, api_errors = {}, [], 0
    for session in sessions:
        for rep in range(1, reps + 1):
            rows = load_jsonl(str(unit_dir(run.path, cond.id, rep, session.name) / "mapped.jsonl"))
            if rep == 1:
                per_session[session.name] = _siem_metrics(session, rows)
            if kind in ("triage", "baseline"):
                api_errors += sum(1 for r in rows if r.get("llm_api_error"))
                for s in score_rows(rows, str(session), repeat=rep):
                    scored.append({"session": session.name, **s})
    scores = kind in ("triage", "baseline")
    return {"git_sha": runs.git_sha(), "condition": cond.id, "sessions": per_session,
            "pooled_siem": pool_siem(per_session),
            "triage": triage_metrics(scored, boot, api_errors=api_errors) if scores else None,
            "injection": flip_rates(scored, boot) if scores else None,
            }, scored


def _value(est: dict | None) -> float | None:
    return est.get("value") if est else None


def summarise(metrics: dict) -> dict:
    """The numbers run.json and the run report show per condition."""
    pooled = metrics["pooled_siem"]
    out = {"techniques_detected": pooled["detection"]["techniques_detected"],
           "techniques_total": pooled["detection"]["techniques_total"],
           "alerts": pooled["detection"]["alerts_total"],
           "siem_precision": pooled["precision_fpr"]["precision_alert_level"]}
    t = metrics["triage"]
    if t:
        sel = t["fine"]["selective_accuracy"]
        out.update(rows=t["rows"], api_errors=t["api_errors"],
                   coverage=_value(t["fine"]["coverage"]), selective_accuracy=_value(sel),
                   selective_ci=sel.get("ci") if sel else None,
                   strict_accuracy=_value(t["fine"]["strict_accuracy"]),
                   coarse_selective_accuracy=_value(t["coarse"]["selective_accuracy"]),
                   escalation_recall=_value(t["disposition"]["escalation_recall"]),
                   fp_dismissal=_value(t["disposition"]["fp_dismissal_rate"]),
                   high_confidence_wrong=t["calibration"]["high_confidence_wrong"],
                   cost_per_alert_usd=t["cost"]["cost_per_alert_usd"])
    if inj := metrics.get("injection"):
        out.update(injected_not_escalated=_value(inj["injected"]["disposition_flip"]),
                   clean_not_escalated=_value(inj["clean"]["disposition_flip"]),
                   injected_labelled_none=_value(inj["injected"]["label_flip"]))
    return out


def _pct(v) -> str:
    return f"{v:.1%}" if v is not None else "n/a"


def headline(conditions: list[Condition], summaries: dict[str, dict], kind: str) -> str:
    short = short_ids(conditions)
    if kind == "siem":
        return " · ".join(f"{short[c.id]} {summaries[c.id]['techniques_detected']}/"
                          f"{summaries[c.id]['techniques_total']} techniques" for c in conditions)
    def one(c):
        s = summaries[c.id]
        text = f"{short[c.id]}: selective {_pct(s['selective_accuracy'])}, coverage {_pct(s['coverage'])}"
        if "injected_not_escalated" in s:
            text += (f", injected not escalated {_pct(s['injected_not_escalated'])} "
                     f"(clean {_pct(s['clean_not_escalated'])})")
        return text
    return "; ".join(one(c) for c in conditions)


def write_condition(run: runs.Run, exp: runs.Experiment, corp, cond: Condition, metrics: dict,
                    scored: list[dict], kind: str) -> Path:
    """conditions/<c>/: metrics.json, scores.jsonl, charts/, report.md."""
    from cjp.evaluate import report
    from cjp.evaluate.charts import generate_charts
    d = run.path / "conditions" / cond.id
    d.mkdir(parents=True, exist_ok=True)
    (d / "metrics.json").write_text(json.dumps(metrics, indent=2, default=str) + "\n")
    with open(d / "scores.jsonl", "w") as f:
        for row in scored:
            f.write(json.dumps(row) + "\n")
    chart_metrics = {**metrics["pooled_siem"], "triage": metrics["triage"]}
    charts = {name: str(Path(p).relative_to(d)) if p else None
              for name, p in generate_charts(chart_metrics, str(d / "charts")).items()}

    lines = [f"# {exp.id} {exp.slug} · {cond.id}", "",
             f"Run [{run.id}](../../report.md) · corpus {corp.id} (`corpus.json` sha256 "
             f"`{corp.sha256[:12]}`) · {len(metrics['sessions'])} session(s) × {exp.reps} repeat(s) · "
             f"code `{run.meta.get('git_describe')}`", ""]
    if kind == "triage":
        lines += [f"SIEM evidence `{cond.arm}`; LLM evidence: "
                  f"{'the alert plus request/response bodies' if cond.with_body else 'the alert only'}; "
                  f"format {cond.fmt}; model `{model_profile(cond.model)['id']}`.", ""]
    if kind == "baseline":
        lines += [f"SIEM evidence `{cond.arm}`; lookup baseline `{cond.baseline}` "
                  "(taxonomy/baselines.yaml, METHODS §5.6): no model call, no confidence, no cost. "
                  "Scored by the same rules as the LLM.", ""]
    if kind in ("triage", "baseline"):
        lines += _injection_lines(metrics.get("injection"))
        lines += report._triage_sections(metrics["triage"], charts)
    else:
        lines += report._embed(charts, "headline_summary", "Headline metrics")
    pooled = metrics["pooled_siem"]["detection"]
    lines += ["## SIEM detection over the corpus", "",
              f"{pooled['techniques_detected']}/{pooled['techniques_total']} techniques detected "
              f"(summed over sessions), {pooled['alerts_total']} alerts.", ""]
    lines += report._embed(charts, "alert_volume", "Alert volume per technique")
    for name, m in metrics["sessions"].items():
        lines += [f"## SIEM · {name}", ""]
        lines += ["#" + line if line.startswith("## ") else line
                  for line in report._siem_sections(m, {})]
    (d / "report.md").write_text("\n".join(lines).rstrip() + "\n")
    return d / "report.md"


def _injection_lines(inj: dict | None) -> list[str]:
    """X4's flip rates (METHODS §5.5) as a report section; nothing without
    injected alerts."""
    if not inj:
        return []
    from cjp.evaluate.report import _md_table, _rate
    i, c = inj["injected"], inj["clean"]

    def diff(v):
        return f"{v * 100:+.1f} pp" if v is not None else "n/a"
    lines = ["## Injection flip rate (X4)", "",
             "Injected = alerts of requests carrying analyst-directed text (`*_inj`); clean = the same "
             f"base techniques without it ({', '.join(inj['base_techniques'])}). Descriptive: "
             "12 injected requests (METHODS §5.5).", ""]
    lines += _md_table(["Rate", "Injected", "Clean", "Injected − clean"], [
        ["Not escalated (disposition flip)", _rate(i["disposition_flip"]), _rate(c["disposition_flip"]),
         diff(inj["disposition_flip_difference"])],
        ["Labelled `none` (label flip)", _rate(i["label_flip"]), _rate(c["label_flip"]),
         diff(inj["label_flip_difference"])],
    ])
    lines += ["", "Injected dispositions: " + ", ".join(f"{k} {n}" for k, n in sorted(i["dispositions"].items()))
              + "; labels: " + ", ".join(f"{k} {n}" for k, n in sorted(i["labels"].items())) + ".", ""]
    lines += _md_table(["Technique", "Injected alerts", "not escalated", "`none`",
                        "Clean alerts", "not escalated", "`none`"],
                       [[t["technique"], str(t["injected_alerts"]), str(t["injected_not_escalated"]),
                         str(t["injected_labelled_none"]), str(t["clean_alerts"]),
                         str(t["clean_not_escalated"]), str(t["clean_labelled_none"])]
                        for t in inj["by_technique"]])
    return lines + [""]


RATE_NAMES = {
    "fine_coverage": "Coverage (fine)", "fine_selective_accuracy": "Selective accuracy (fine)",
    "fine_strict_accuracy": "Strict accuracy (fine)", "coarse_coverage": "Coverage (coarse)",
    "coarse_selective_accuracy": "Selective accuracy (coarse)",
    "coarse_strict_accuracy": "Strict accuracy (coarse)", "escalation_recall": "Escalation recall",
    "fp_dismissal": "FP dismissal", "high_confidence_wrong": "High-confidence wrong",
    "cost_per_correct_fine_usd": "Cost per correct label",
}


def format_contrast_value(rate: str, v: float, signed: bool = False) -> str:
    """A rate as a percentage (a difference in percentage points), a cost in USD."""
    if rate.endswith("_usd"):
        sign = ("+" if v >= 0 else "-") if signed else ("-" if v < 0 else "")
        return f"{sign}${abs(v):.4f}"
    return f"{v * 100:+.1f} pp" if signed else f"{v:.1%}"


def _contrast_lines(rows: list[dict]) -> list[str]:
    """METHODS §6 contrasts as a report section."""
    if not rows:
        return []
    from cjp.evaluate.report import _md_table
    lines = ["## Contrasts (METHODS §6)", "",
             "B − A with a 95% paired cluster bootstrap over distinct requests. **Bold** marks an "
             "interval that excludes 0, the only case called a difference. No p-values.", ""]
    table = []
    for r in rows:
        fmt = lambda v, signed=False: format_contrast_value(r["rate"], v, signed)  # noqa: E731
        ci = f"[{fmt(r['ci'][0], True)}, {fmt(r['ci'][1], True)}]" if r["ci"] else "n/a"
        diff = fmt(r["diff"], True)
        table.append([r["question"], RATE_NAMES.get(r["rate"], r["rate"]), fmt(r["a"]), fmt(r["b"]),
                      f"**{diff}**" if r["excludes_zero"] else diff, ci])
    lines += _md_table(["Contrast", "Rate", "A", "B", "B − A", "95% CI"], table)
    return lines + [""]


def write_run_report(run: runs.Run, exp: runs.Experiment, corp, conditions: list[Condition],
                     summaries: dict[str, dict], kind: str, contrast_rows: list[dict] | None = None,
                     injection: dict[str, dict] | None = None) -> Path:
    short = short_ids(conditions)
    m = run.meta
    cache_line = ""
    if kind == "triage":
        c = m.get("cache") or {}
        cache_line = (f" · cache hits {c.get('cache_hits', 0)}, API calls {c.get('api_calls', 0)}, "
                      f"tokens billed {c.get('tokens_billed', 0):,}")
    lines = [f"# {exp.id} {exp.slug} · run {run.id}", "", f"> {exp.question}", "",
             f"{', '.join(exp.rq)} · corpus {corp.id} (`corpus.json` sha256 `{corp.sha256[:12]}`, "
             f"{len(corp.sessions)} session(s)) · {exp.reps} repeat(s) · code `{m.get('git_describe')}`"
             f"{cache_line}", ""]
    if kind == "siem":
        lines += ["| Condition | Techniques detected | Alerts | Precision (alert-level) |",
                  "|---|---|---|---|"]
        for c in conditions:
            s = summaries[c.id]
            lines.append(f"| [{short[c.id]}](conditions/{c.id}/report.md) | "
                         f"{s['techniques_detected']}/{s['techniques_total']} | {s['alerts']} | "
                         f"{_pct(s['siem_precision'])} |")
    else:
        lines += ["| Condition | Coverage | Selective accuracy [95% CI] | Strict accuracy | "
                  "Coarse selective | Escalation recall | FP dismissal | High-conf. wrong | "
                  "Cost / alert | API errors |",
                  "|---|---|---|---|---|---|---|---|---|---|"]
        for c in conditions:
            s = summaries[c.id]
            ci = s["selective_ci"]
            sel = _pct(s["selective_accuracy"]) + (f" [{ci[0]:.1%}–{ci[1]:.1%}]" if ci else "")
            hcw = s["high_confidence_wrong"] or {}
            cost = f"${s['cost_per_alert_usd']:.4f}" if s["cost_per_alert_usd"] is not None else "n/a"
            lines.append(f"| [{short[c.id]}](conditions/{c.id}/report.md) | {_pct(s['coverage'])} | "
                         f"{sel} | {_pct(s['strict_accuracy'])} | "
                         f"{_pct(s['coarse_selective_accuracy'])} | {_pct(s['escalation_recall'])} | "
                         f"{_pct(s['fp_dismissal'])} | {_pct(hcw.get('rate'))} | {cost} | "
                         f"{s['api_errors']} |")
        lines += ["", "Rates are on the fine technique label over attack alerts, pooled over every "
                  "session and repeat; intervals resample distinct requests (decision 006)."]
        if kind == "baseline":
            lines += ["", "Lookup baselines have no confidence and make no model call, so "
                      "high-confidence wrong and cost are n/a (METHODS §5.6)."]
        for c in conditions:
            if (injection or {}).get(c.id):
                lines += ["", f"### {short[c.id]}", ""] + _injection_lines(injection[c.id])
        lines += [""] + _contrast_lines(contrast_rows or [])
    if any(short[c.id] != c.id for c in conditions):
        lines += ["", "Conditions in full: " + ", ".join(f"`{c.id}`" for c in conditions) + "."]
    path = run.path / "report.md"
    path.write_text("\n".join(lines) + "\n")
    return path


def _add_counts(previous: dict | None, stats: Counter) -> dict:
    out = Counter(previous or {})
    out.update(stats)
    return dict(out)


def run(ref: str, *, dry_run: bool = False, resume: str | None = None, cache_mode: str = "use",
        yes: bool = False, count: bool = True, confirm=input,
        experiments_dir: Path = EXPERIMENTS_DIR, runs_dir: Path | None = None,
        corpus_dir: Path | None = None) -> int:
    """`cjp experiment run`. Returns a process exit code: 0 complete (or dry
    run done), 1 not run, failed or incomplete."""
    from cjp.config import CORPUS_DIR, RUNS_DIR
    runs_dir, corpus_dir = Path(runs_dir or RUNS_DIR), Path(corpus_dir or CORPUS_DIR)
    if cache_mode not in cache.CACHE_MODES:
        raise ValueError(f"cache_mode must be one of {cache.CACHE_MODES}")
    exp, kind, conditions = load(ref, experiments_dir)
    corp = corpus_mod.load(exp.corpus, corpus_dir)
    problems = corpus_mod.verify(corp)
    if problems:
        print(f"[experiment] corpus {corp.id} no longer matches its checksums; nothing run:")
        for p in problems[:20]:
            print(f"  - {p}")
        return 1

    rsettings = run_settings(conditions, cache_mode, kind)
    existing = None
    if resume:
        existing = runs.find_run(resume, runs_dir)
        if existing.meta["experiment"] != exp.id:
            print(f"[experiment] {existing.address} is a run of {existing.meta['experiment']}, not {exp.id}")
            return 1
        if existing.meta["config_hash"] != runs.config_hash(exp, rsettings):
            print(f"[experiment] {existing.address} was made with other inputs (the YAML, models or "
                  "cache mode changed since); start a new run instead")
            return 1
        if existing.status not in ("failed", "running"):
            print(f"[experiment] {existing.address} is {existing.status}; only a failed or "
                  "interrupted run can be resumed")
            return 1

    units = plan(conditions, corp.sessions, exp.reps, cache_mode,
                 existing.path if existing else None) if kind == "triage" else []
    print_plan(exp, corp, conditions, units, kind)
    calls = sum(u.to_call for u in units)
    total_cost = None
    if calls:
        total_cost = print_estimate(estimate(units, count), conditions)
    if dry_run:
        print("\n[experiment] dry run: nothing written, nothing spent")
        return 0
    if calls and cache_mode == "only":
        print(f"[experiment] --cache-only: {calls} alert(s) have no cached answer; nothing run")
        return 1
    if calls and not yes:
        bound = f", at most ${total_cost:.2f}" if total_cost is not None else ""
        if confirm(f"\nMake {calls} paid API call(s){bound}? [y/N] ").strip().lower() != "y":
            print("[experiment] nothing run")
            return 1

    if existing:
        existing.reopen(runs.config_hash(exp, rsettings))
        context = runs.running(existing)
    else:
        model_ids = {c.id: model_profile(c.model)["id"] for c in conditions if c.model}
        prompts = prompts_used(conditions)
        context = runs.start_run(
            exp, prompt_hash=",".join(f"{f}={p['prompt_version']}" for f, p in prompts.items()) or None,
            model=(next(iter(set(model_ids.values()))) if len(set(model_ids.values())) == 1
                   else model_ids or None),
            temperature=None, settings=rsettings, runs_dir=runs_dir, corpus_dir=corpus_dir)
    short = short_ids(conditions)
    try:
        with context as r:
            r.update(kind=kind, corpus_sessions=[s.name for s in corp.sessions],
                     prompts=prompts_used(conditions))
            print(f"[experiment] run {r.address}")
            stats = Counter()
            for i, u in enumerate(units, 1):
                print(f"[experiment] {i}/{len(units)} {short[u.condition.id]} rep{u.rep} "
                      f"{u.session.name}: {len(u.jobs)} to triage ({u.cached} cached)", flush=True)
                s = triage_unit(r, u, cache_mode)
                aborted = s.pop("aborted")
                stats.update(s)
                if aborted:
                    r.update(cache=_add_counts(r.meta.get("cache"), stats))
                    raise RunAborted(f"triage stopped at {u.condition.id} rep{u.rep} "
                                     f"{u.session.name}; fix the cause above, then: "
                                     f"cjp experiment run {exp.id} --resume {r.address}")
            r.update(cache=_add_counts(r.meta.get("cache"), stats))
            if kind == "baseline":
                for cond in conditions:
                    for session in corp.sessions:
                        baseline_unit(r, cond, session)

            summaries, all_scored, injection = {}, {}, {}
            for cond in conditions:
                for session in corp.sessions:
                    for rep in range(1, exp.reps + 1):
                        map_unit(r, cond, session, rep, kind)
                metrics, scored = condition_metrics(r, cond, corp.sessions, exp.reps, kind)
                write_condition(r, exp, corp, cond, metrics, scored, kind)
                summaries[cond.id] = summarise(metrics)
                all_scored[(exp.id, cond.id)] = scored
                if metrics.get("injection"):
                    injection[cond.id] = metrics["injection"]
            contrast_rows = []
            if kind == "triage":
                from cjp.evaluate.contrasts import compute
                contrast_rows = compute(all_scored, only={exp.id})
                (r.path / "contrasts.json").write_text(json.dumps(contrast_rows, indent=2) + "\n")
            r.update(conditions_summary=summaries)
            report_path = write_run_report(r, exp, corp, conditions, summaries, kind,
                                           contrast_rows, injection)
            missing = sum(s.get("api_errors", 0) for s in summaries.values())
            if missing:
                r.fail(f"{missing} alert(s) have no answer (API errors); resume: "
                       f"cjp experiment run {exp.id} --resume {r.address}")
                print(f"[experiment] incomplete: {r.meta['error']}")
                return 1
            r.finish(headline(conditions, summaries, kind))
    except RunAborted as e:
        print(f"[experiment] {e}")
        return 1
    print(f"[experiment] complete: {r.meta['headline']}")
    print(f"[experiment] report: {report_path}")
    return 0


# ── list and status ──────────────────────────────────────────────────────────
def list_experiments(experiments_dir: Path = EXPERIMENTS_DIR, corpus_dir: Path | None = None) -> int:
    from cjp.config import CORPUS_DIR
    corpus_dir = Path(corpus_dir or CORPUS_DIR)
    paths = sorted(Path(experiments_dir).glob("*.yaml"))
    if not paths:
        print(f"[experiment] no experiment files in {experiments_dir}")
        return 0
    bad = 0
    for path in paths:
        try:
            exp, kind, conditions = load(path.stem, experiments_dir)
        except (ValueError, FileNotFoundError) as e:
            print(f"  {path.stem:<4} ✗ {e}")
            bad += 1
            continue
        frozen = (corpus_dir / exp.corpus / "corpus.json").is_file()
        draft = " (draft)" if exp.spec.get("draft") else ""
        print(f"  {exp.id:<4} {exp.slug:<16} {', '.join(exp.rq):<9} {kind:<8} "
              f"{len(conditions)} condition(s) × {exp.reps} rep(s), corpus {exp.corpus}"
              f"{'' if frozen else ' (not frozen yet)'}{draft}")
        print(f"       {exp.question}")
    return 1 if bad else 0


def status(ref: str | None = None, runs_dir: Path | None = None) -> int:
    """With a run: progress per condition and repeat. Without: the latest
    run of each experiment."""
    from cjp.config import RUNS_DIR
    from cjp.triage.batch import load_completed_ids
    runs_dir = Path(runs_dir or RUNS_DIR)
    if ref is None:
        latest = {}
        for r in runs.list_runs(runs_dir):
            latest[r.meta["experiment"]] = r
        if not latest:
            print("[experiment] no runs yet")
        for exp_id, r in sorted(latest.items()):
            print(f"  {r.address:<40} {r.status:<10} {r.meta.get('headline') or r.meta.get('error') or ''}")
        return 0
    r = runs.find_run(ref, runs_dir)
    m = r.meta
    print(f"{r.address}: {r.status} · corpus {m['corpus']['id']} · code {m.get('git_describe')}")
    if m.get("headline") or m.get("error"):
        print(f"  {m.get('headline') or m.get('error')}")
    if m.get("cache"):
        c = m["cache"]
        print(f"  cache hits {c.get('cache_hits', 0)}, API calls {c.get('api_calls', 0)}, "
              f"api errors {c.get('api_errors', 0)}, tokens billed {c.get('tokens_billed', 0):,}")
    for cond in m["conditions"]:
        for rep in range(1, m["reps"] + 1):
            rep_dir = r.path / "conditions" / cond / f"rep{rep}"
            parts = []
            for session in m.get("corpus_sessions") or []:
                verdicts = rep_dir / session / "verdicts.jsonl"
                n = len(load_completed_ids(str(verdicts))) if verdicts.exists() else 0
                parts.append(f"{session} {n}")
            print(f"  {cond} rep{rep}: " + (", ".join(parts) or "nothing yet"))
    return 0
