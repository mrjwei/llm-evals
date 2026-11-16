"""
`cjp results build`: regenerate results/ from the canonical runs (Plan §2.3
rule 4, P5, P8; decision 012).

    results/canonical.yaml     figures (what to build, from which experiments) + pins (experiment → run)
    results/tables/<key>*.csv  the numbers, one row per condition × metric (or × label, × contrast)
    results/figures/<key>.png  the chart; its footer names every run it reads
    results/manifest.json      per output: files, runs (run ID, corpus sha256, git describe), and the checks

Only stored run outputs are read (metrics.json, scores.jsonl, run.json): the
build makes no API call and re-scores nothing, so a figure always shows the
numbers its run's report shows. The few numbers no report carries are
computed here from scores.jsonl with the pre-registered rules: the
high-confidence-wrong interval (METHODS §5.3), the cross-run contrasts
(§6, cjp.evaluate.contrasts) and X4's flip rates (§5.5, already in X4's
metrics.json).

A figure may also read a rating batch (data/ratings/<batch>/, e.g. X5):
F8 joins the raters' scores with the batch key (cjp.rating_analysis,
METHODS §7). A batch is not pinned; the build checks instead that it was
drawn from the runs pinned now and that every rater file is complete.

The checks behind Plan P5's acceptance: every experiment a figure reads is
pinned, its pin is a complete run of that experiment, and its git describe
starts with `prereg-C1` and is not `-dirty` (otherwise a decision record must
explain it; the build reports, it does not judge). The build writes what it
can, lists the problems and exits 1 if there are any. It never deletes: a
file in results/ that this build did not write is listed as stale.
"""

import csv
import json
from dataclasses import dataclass, field
from pathlib import Path

from cjp import runs
from cjp.config import CANONICAL_FILE, RESULTS_DIR, RUNS_DIR

PREREG_TAG = "prereg-C1"
# A rate over fewer committed answers than this is shown as too few to judge:
# F3 fades and hatches its bar, and the web app's confidence chip says so.
MIN_COMMITTED = 20
KEEP = {"H1_heuristic.csv"}         # written by hand in P7.4, never by the build
H1_CRITERIA = 11                    # Okazawa et al. (2026), Table I
H1_FORMATS = ("FA", "FB")


# ── sources: the pinned runs ─────────────────────────────────────────────────
@dataclass
class Source:
    """One pinned run, read lazily."""
    experiment: str
    run: runs.Run
    _metrics: dict = field(default_factory=dict)
    _scores: dict = field(default_factory=dict)

    @property
    def kind(self) -> str:
        return self.run.meta.get("kind", "triage")

    @property
    def conditions(self) -> list[str]:
        return list(self.run.meta["conditions"])

    def metrics(self, cond: str) -> dict:
        if cond not in self._metrics:
            path = self.run.path / "conditions" / cond / "metrics.json"
            self._metrics[cond] = json.loads(path.read_text())
        return self._metrics[cond]

    def scores(self, cond: str) -> list[dict]:
        if cond not in self._scores:
            path = self.run.path / "conditions" / cond / "scores.jsonl"
            self._scores[cond] = [json.loads(line) for line in path.read_text().splitlines() if line.strip()]
        return self._scores[cond]

    def provenance(self) -> dict:
        m = self.run.meta
        return {"experiment": self.experiment, "run": self.run.address, "status": self.run.status,
                "corpus": m["corpus"]["id"], "corpus_sha256": m["corpus"]["sha256"],
                "git_describe": m.get("git_describe")}

    def footer(self) -> str:
        p = self.provenance()
        return (f"{p['experiment']} run {self.run.id} · corpus {p['corpus']} "
                f"{(p['corpus_sha256'] or '?')[:8]} · code {p['git_describe']}")


def triage_conditions(sources: list[Source]) -> list[tuple[Source, str]]:
    """(source, condition) for every scored condition, in figure order; a
    condition already seen in an earlier experiment (X2's FA = X1's S1×L1)
    is shown once."""
    out, seen = [], set()
    for src in sources:
        if src.kind == "siem":
            continue
        for cond in src.conditions:
            if cond not in seen:
                seen.add(cond)
                out.append((src, cond))
    return out


def label(src: Source, cond: str) -> str:
    """A condition as a chart or table shows it: the parts that say what it
    is, without the shared model/format where the experiment holds them fixed."""
    parts = cond.split("__")
    if src.kind == "baseline":
        return f"{parts[0].split('-')[0]} {parts[1]}"
    arm, evidence, fmt, model = parts
    return f"{arm.split('-')[0]}×{evidence.split('-')[0]} {fmt} {model}"


# ── tables ───────────────────────────────────────────────────────────────────
def _num(v):
    return round(v, 6) if isinstance(v, float) else v


def write_csv(path: Path, rows: list[dict]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    columns = list(dict.fromkeys(k for r in rows for k in r))
    with open(path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=columns, lineterminator="\n")
        w.writeheader()
        for r in rows:
            w.writerow({k: _num(r.get(k)) for k in columns})
    return path


def est_cols(est: dict | None) -> dict:
    """An estimate (cjp.evaluate.metrics.estimate) as flat columns."""
    est = est or {}
    ci, spread = est.get("ci") or [None, None], est.get("spread") or [None, None]
    return {"value": est.get("value"), "ci_low": ci[0], "ci_high": ci[1], "num": est.get("num"),
            "den": est.get("den"), "clusters": est.get("clusters"),
            "repeat_min": spread[0], "repeat_max": spread[1]}


def _cond_cols(src: Source, cond: str) -> dict:
    return {"experiment": src.experiment, "condition": cond, "run": src.run.address}


def high_confidence_wrong(scores: list[dict]) -> dict:
    """METHODS §5.3's RQ2 headline with its bootstrap interval: of the
    committed fine answers given with high confidence on attack alerts, the
    share that is wrong."""
    from cjp.evaluate.contrasts import boot_settings
    from cjp.evaluate.metrics import estimate
    from cjp.evaluate.score import COMMITTED
    rows = [s for s in scores if s["is_attack"] is True and s["confidence"] == "high"
            and s["fine"] in COMMITTED]
    return estimate(rows, lambda s: s["fine"] == "wrong", lambda s: True, boot_settings())


TRIAGE_RATES = (("fine", "coverage"), ("fine", "selective_accuracy"), ("fine", "strict_accuracy"),
                ("coarse", "coverage"), ("coarse", "selective_accuracy"), ("coarse", "strict_accuracy"))
DISPOSITION_RATES = ("escalation_recall", "fp_dismissal_rate", "benign_escalated",
                     "needs_more_info_attack", "needs_more_info_benign")


def rate_rows(src: Source, cond: str) -> list[dict]:
    """Every primary rate of one condition, long format."""
    t = src.metrics(cond)["triage"]
    out = [{**_cond_cols(src, cond), "metric": f"{lvl}_{name}", **est_cols(t[lvl][name])}
           for lvl, name in TRIAGE_RATES]
    out += [{**_cond_cols(src, cond), "metric": name, **est_cols(t["disposition"][name])}
            for name in DISPOSITION_RATES]
    if any(s["confidence"] for s in src.scores(cond)):
        out.append({**_cond_cols(src, cond), "metric": "high_confidence_wrong",
                    **est_cols(high_confidence_wrong(src.scores(cond)))})
    return out


def cost_row(src: Source, cond: str) -> dict:
    """Tokens and list-price cost; a lookup baseline makes no call, so 0."""
    t = src.metrics(cond)["triage"]
    k = t["cost"]
    baseline = src.kind == "baseline"
    zero_or = lambda v: 0.0 if baseline else v  # noqa: E731
    return {**_cond_cols(src, cond), "kind": src.kind, "model": ", ".join(k["models"]) or None,
            "input_tokens_per_alert": zero_or(k["input_tokens_per_alert"]),
            "output_tokens_per_alert": zero_or(k["output_tokens_per_alert"]),
            "cost_per_alert_usd": zero_or(k["cost_per_alert_usd"]),
            "cost_per_correct_fine_usd": zero_or(k["cost_per_correct_usd"]),
            "cost_per_correct_disposition_usd": zero_or(k["cost_per_correct_disposition_usd"]),
            "unpriced_rows": sum(k["unpriced"].values()),
            "price_source": None if baseline else k["price_source"],
            "price_retrieved": None if baseline else k["price_retrieved"]}


# ── one builder per figure / table ───────────────────────────────────────────
def build_F1(key, sources, out) -> dict:
    """SIEM coverage by S-level (D1): recall, precision and request-level FPR
    per arm, pooled over the corpus sessions, plus detection per technique."""
    from cjp import figures
    arms, techniques = [], []
    for src in sources:
        for cond in src.conditions:
            m = src.metrics(cond)
            det, prec = m["pooled_siem"]["detection"], m["pooled_siem"]["precision_fpr"]
            benign = sum(s["precision_fpr"]["total_benign_requests"] or 0 for s in m["sessions"].values())
            alerted = sum(round((s["precision_fpr"]["false_positive_rate_request_level"] or 0)
                                * (s["precision_fpr"]["total_benign_requests"] or 0))
                          for s in m["sessions"].values())
            arms.append({**_cond_cols(src, cond), "sessions": len(m["sessions"]),
                         "techniques_detected": det["techniques_detected"],
                         "techniques_total": det["techniques_total"],
                         "technique_recall": det["technique_recall"], "alerts": det["alerts_total"],
                         "true_positive_alerts": prec["true_positive_alerts"],
                         "false_positive_alerts": prec["false_positive_alerts"],
                         "precision_alert_level": prec["precision_alert_level"],
                         "benign_requests": benign, "benign_requests_alerted": alerted,
                         "fpr_request_level": alerted / benign if benign else None})
            for name, s in m["sessions"].items():
                missed = {t.split("/", 1)[-1] for t in s["detection"]["missed_techniques"]}
                volume = dict(s["detection"]["alert_volume_per_technique"])
                for tech in sorted(missed | set(volume)):
                    techniques.append({**_cond_cols(src, cond), "session": name, "technique": tech,
                                       "detected": tech not in missed, "alerts": volume.get(tech, 0)})
    files = [write_csv(out.tables / f"{key}.csv", arms),
             write_csv(out.tables / f"{key}_by_technique.csv", techniques),
             figures.siem_coverage(arms, out.figures / f"{key}.png", [s.footer() for s in sources])]
    return {"files": files}


def build_F2(key, sources, out) -> dict:
    """Coverage vs selective accuracy per condition (X1), fine and coarse."""
    from cjp import figures
    rows, points = [], []
    for src, cond in triage_conditions(sources):
        rows += [r for r in rate_rows(src, cond) if r["metric"].split("_", 1)[1] in
                 ("coverage", "selective_accuracy", "strict_accuracy")]
        t = src.metrics(cond)["triage"]
        for lvl in ("fine", "coarse"):
            points.append({"label": label(src, cond), "level": lvl, "coverage": t[lvl]["coverage"],
                           "selective": t[lvl]["selective_accuracy"]})
    return {"files": [write_csv(out.tables / f"{key}.csv", rows),
                      figures.coverage_selective(points, out.figures / f"{key}.png",
                                                 [s.footer() for s in sources])]}


def build_F3(key, sources, out) -> dict:
    """Calibration: selective accuracy per reported confidence level, and
    the high-confidence-wrong headline with its interval (RQ2 primary)."""
    from cjp import figures
    table, headline, bars = [], [], []
    for src, cond in triage_conditions(sources):
        if not any(s["confidence"] for s in src.scores(cond)):
            continue                                # a lookup baseline has no confidence
        cal = src.metrics(cond)["triage"]["calibration"]
        for outcome in ("fine", "disposition"):
            for r in cal[outcome]:
                table.append({**_cond_cols(src, cond), "outcome": outcome, **r})
        headline.append({**_cond_cols(src, cond), "metric": "high_confidence_wrong",
                         **est_cols(high_confidence_wrong(src.scores(cond)))})
        bars.append({"label": label(src, cond), "levels": cal["fine"]})
    return {"files": [write_csv(out.tables / f"{key}.csv", table),
                      write_csv(out.tables / f"{key}_high_confidence_wrong.csv", headline),
                      figures.calibration(bars, out.figures / f"{key}.png", [s.footer() for s in sources],
                                          min_committed=MIN_COMMITTED)]}


def build_F4(key, sources, out) -> dict:
    """Disposition: escalation recall on attack alerts, false-positive
    dismissal on benign ones, and needs_more_info."""
    from cjp import figures
    rows, bars = [], []
    for src, cond in triage_conditions(sources):
        d = src.metrics(cond)["triage"]["disposition"]
        rows += [{**_cond_cols(src, cond), "metric": n, **est_cols(d[n])} for n in DISPOSITION_RATES]
        bars.append({"label": label(src, cond), "escalation_recall": d["escalation_recall"],
                     "fp_dismissal": d["fp_dismissal_rate"]})
    return {"files": [write_csv(out.tables / f"{key}.csv", rows),
                      figures.disposition(bars, out.figures / f"{key}.png", [s.footer() for s in sources])]}


def build_F5(key, sources, out) -> dict:
    """Cost vs quality: list-price cost per alert against strict fine
    accuracy, LLM conditions and lookup baselines (cost 0)."""
    from cjp import figures
    rows, points = [], []
    for src, cond in triage_conditions(sources):
        t = src.metrics(cond)["triage"]
        row = {**cost_row(src, cond),
               **{f"fine_strict_accuracy_{k}": v for k, v in est_cols(t["fine"]["strict_accuracy"]).items()},
               "escalation_recall": t["disposition"]["escalation_recall"]["value"]}
        rows.append(row)
        points.append({"label": label(src, cond), "kind": src.kind, "cost": row["cost_per_alert_usd"],
                       "strict": t["fine"]["strict_accuracy"]})
    return {"files": [write_csv(out.tables / f"{key}.csv", rows),
                      figures.cost_quality(points, out.figures / f"{key}.png", [s.footer() for s in sources])]}


def build_F6(key, sources, out) -> dict:
    """Format A vs B (X2): every primary rate, plus tokens and cost."""
    from cjp import figures
    rows, bars = [], []
    for src, cond in triage_conditions(sources):
        rates = rate_rows(src, cond)
        cost = cost_row(src, cond)
        rows += rates + [{**_cond_cols(src, cond), "metric": k, "value": cost[k]} for k in
                         ("input_tokens_per_alert", "output_tokens_per_alert", "cost_per_alert_usd",
                          "cost_per_correct_fine_usd")]
        bars.append({"label": label(src, cond), "rates": {r["metric"]: r for r in rates}})
    return {"files": [write_csv(out.tables / f"{key}.csv", rows),
                      figures.format_rates(bars, out.figures / f"{key}.png", [s.footer() for s in sources])]}


def build_F7(key, sources, out) -> dict:
    """Injection flip rates (X4): injected vs clean, per condition."""
    from cjp import figures
    rows, bars, by_tech = [], [], []
    for src, cond in triage_conditions(sources):
        inj = src.metrics(cond).get("injection")
        if not inj:
            continue
        for metric in ("disposition_flip", "label_flip"):
            for pop in ("injected", "clean"):
                rows.append({**_cond_cols(src, cond), "metric": metric, "population": pop,
                             **est_cols(inj[pop][metric])})
            rows.append({**_cond_cols(src, cond), "metric": metric, "population": "injected − clean",
                         "value": inj[f"{metric}_difference"]})
        by_tech += [{**_cond_cols(src, cond), **t} for t in inj["by_technique"]]
        bars.append({"label": label(src, cond), "injection": inj})
    return {"files": [write_csv(out.tables / f"{key}.csv", rows),
                      write_csv(out.tables / f"{key}_by_technique.csv", by_tech),
                      figures.injection(bars, out.figures / f"{key}.png", [s.footer() for s in sources])]}


def build_T1(key, sources, out) -> dict:
    """Per-technique outcomes, fine and coarse, per condition."""
    rows = []
    for src, cond in triage_conditions(sources):
        rows += [{**_cond_cols(src, cond), **r} for r in src.metrics(cond)["triage"]["by_label"]]
    return {"files": [write_csv(out.tables / f"{key}.csv", rows)]}


def build_T2(key, sources, out) -> dict:
    """METHODS §6's named contrasts across the pinned runs."""
    from cjp.evaluate.contrasts import compute
    scored = {(src.experiment, cond): src.scores(cond)
              for src in sources if src.kind != "siem" for cond in src.conditions}
    rows = []
    for r in compute(scored):
        ci = r.pop("ci") or [None, None]
        rows.append({**r, "ci_low": ci[0], "ci_high": ci[1]})
    return {"files": [write_csv(out.tables / f"{key}.csv", rows)]}


def build_F8(key, sources, out) -> dict:
    """Expert rating (X5, METHODS §7): inter-rater agreement, mean R1–R4 per
    cell, stratum and confidence, and R5 against the LLM and ground truth."""
    from cjp import figures, rating_analysis
    from cjp.evaluate.contrasts import boot_settings
    files = []
    for src in sources:
        a = rating_analysis.analyse(src.experiment, boot_settings(), src.root)
        stem = key if len(sources) == 1 else f"{key}_{src.experiment}"
        files += [write_csv(out.tables / f"{stem}_agreement.csv", a["agreement"]),
                  write_csv(out.tables / f"{stem}_means.csv", a["means"]),
                  write_csv(out.tables / f"{stem}_r5.csv", a["r5"]),
                  write_csv(out.tables / f"{stem}_r5_crosstab.csv", a["r5_crosstab"]),
                  figures.rating(a["means"], a["r5"], out.figures / f"{stem}.png", [src.footer()],
                                 single_rater=a["data"].single_rater)]
    return {"files": files}


BUILDERS = {"F1": build_F1, "F2": build_F2, "F3": build_F3, "F4": build_F4, "F5": build_F5,
            "F6": build_F6, "F7": build_F7, "F8": build_F8, "T1": build_T1, "T2": build_T2}


def check_h1(path: Path) -> tuple[dict, list[str]]:
    """The hand-written H1 table (Plan P7.4, METHODS §7): one row per
    criterion and rater, the criterion's text as the paper prints it, and a
    1–5 score (Okazawa et al.'s scale) for each format. The build never
    writes it; it reports whether it is there and complete."""
    if not path.is_file():
        return {"status": "missing"}, [f"{path.name}: missing (Plan P7.4)"]
    with open(path, newline="") as f:
        rows = list(csv.DictReader(f))
    problems, raters = ([] if rows else [f"{path.name}: no rows (Plan P7.4)"]), {}
    for r in rows:
        raters.setdefault(r.get("rater") or "?", []).append(r)
    for rater, mine in sorted(raters.items()):
        numbers = sorted(int(r["criterion"]) for r in mine if (r.get("criterion") or "").isdigit())
        if numbers != list(range(1, H1_CRITERIA + 1)):
            problems.append(f"{path.name}: rater {rater} needs criteria 1–{H1_CRITERIA} once each")
        if any(not (r.get("text") or "").strip() for r in mine):
            problems.append(f"{path.name}: rater {rater} has a criterion without its text")
        for fmt in H1_FORMATS:
            scores = [(r.get(f"score_{fmt}") or "").strip() for r in mine]
            bad = [s for s in scores if s and s not in {"1", "2", "3", "4", "5"}]
            if bad:
                problems.append(f"{path.name}: rater {rater} {fmt} scores must be 1–5, not {bad}")
            missing = sum(1 for s in scores if not s)
            if missing:
                problems.append(f"{path.name}: rater {rater} has {missing}/{len(mine)} {fmt} "
                                "criteria unscored (Plan P7.4)")
    status = "complete" if rows and not problems else "incomplete"
    return {"status": status, "raters": sorted(raters)}, problems


# ── the build ────────────────────────────────────────────────────────────────
@dataclass
class Out:
    root: Path

    @property
    def tables(self) -> Path:
        return self.root / "tables"

    @property
    def figures(self) -> Path:
        return self.root / "figures"


def check_pin(exp_id: str, pin: dict | None, known: dict[str, runs.Run]) -> tuple[runs.Run | None, list[str]]:
    """The pinned run of an experiment, and what is wrong with it."""
    if not pin:
        return None, [f"{exp_id}: not pinned (cjp runs mark-canonical <run>)"]
    run = known.get(pin.get("run"))
    if run is None:
        return None, [f"{exp_id}: pinned run {pin.get('run')} does not exist"]
    problems = []
    if run.meta["experiment"] != exp_id:
        return None, [f"{exp_id}: pinned run {run.address} is a run of {run.meta['experiment']}"]
    if run.status != "complete":
        return None, [f"{exp_id}: pinned run {run.address} is {run.status}"]
    describe = run.meta.get("git_describe") or ""
    if not describe.startswith(PREREG_TAG) or describe.endswith("-dirty"):
        problems.append(f"{exp_id}: {run.address} ran from `{describe}`, not a clean "
                        f"{PREREG_TAG} descendant; it needs a decision record (Plan P5)")
    return run, problems


def build(canonical_file: Path = CANONICAL_FILE, runs_dir: Path = RUNS_DIR,
          results_dir: Path = RESULTS_DIR, ratings_dir: Path | None = None) -> int:
    """Regenerate every output in canonical.yaml's `figures`. Returns 0 when
    every output was built and every check passed, else 1."""
    from cjp import rating_analysis
    doc = runs.load_canonical_doc(canonical_file)
    figs, pins = doc.get("figures") or {}, doc.get("pins") or {}
    if not figs:
        print(f"[results] {canonical_file} lists no figures; nothing to build")
        return 1
    known = {r.address: r for r in runs.list_runs(runs_dir)}
    out = Out(Path(results_dir))
    problems, manifest, written, sources = [], {}, set(), {}
    for exp_id in sorted({e for f in figs.values() for e in f.get("from") or []}):
        if exp_id not in pins and rating_analysis.is_batch(exp_id, ratings_dir):
            batch, issues = rating_analysis.check_batch(exp_id, pins, ratings_dir)
            problems += issues
            if batch is not None:
                sources[exp_id] = batch
            continue
        run, issues = check_pin(exp_id, pins.get(exp_id), known)
        problems += issues
        if run is not None:
            sources[exp_id] = Source(exp_id, run)

    for key, spec in figs.items():
        builder = BUILDERS.get(key.split("_")[0])
        wanted = list(spec.get("from") or [])
        entry = {"title": spec.get("title"), "from": wanted,
                 "runs": [sources[e].provenance() for e in wanted if e in sources]}
        missing = [e for e in wanted if e not in sources]
        if builder is None:
            problems.append(f"{key}: no builder for {key.split('_')[0]} (known: {', '.join(BUILDERS)})")
            entry["status"] = "unknown figure"
        elif not wanted or len(missing) == len(wanted):
            entry["status"] = "not built: " + (f"no pinned run of {', '.join(missing)}" if missing
                                               else "`from` is empty")
            if not missing:
                problems.append(f"{key}: `from` is empty")
        else:
            result = builder(key, [sources[e] for e in wanted if e in sources], out)
            files = [Path(p) for p in result["files"] if p]
            written.update(p.resolve() for p in files)
            entry["files"] = [str(p.relative_to(out.root)) for p in files]
            entry["status"] = "built" + (f" without {', '.join(missing)} (not pinned)" if missing else "")
            print(f"[results] {key}: {', '.join(entry['files'])}")
        manifest[key] = entry

    h1, h1_problems = check_h1(out.tables / "H1_heuristic.csv")
    problems += h1_problems
    stale = sorted(str(p.relative_to(out.root)) for d in (out.tables, out.figures) if d.is_dir()
                   for p in d.iterdir() if p.is_file() and p.resolve() not in written and p.name not in KEEP)
    out.root.mkdir(parents=True, exist_ok=True)
    (out.root / "manifest.json").write_text(json.dumps({
        "built_by": {"git_describe": runs.git_describe()},
        "canonical": str(Path(canonical_file).name),
        "outputs": manifest,
        "hand_written": {"tables/H1_heuristic.csv": h1},
        "problems": problems,
        "stale": stale,
    }, indent=2, ensure_ascii=False, default=str) + "\n")
    for s in stale:
        print(f"[results] stale (not written by this build, not deleted): {s}")
    for p in problems:
        print(f"[results] ✗ {p}")
    built = sum(1 for e in manifest.values() if e["status"].startswith("built"))
    print(f"[results] {built}/{len(manifest)} output(s) built, {len(problems)} problem(s); "
          f"manifest: {out.root / 'manifest.json'}")
    return 1 if problems or built < len(manifest) else 0
