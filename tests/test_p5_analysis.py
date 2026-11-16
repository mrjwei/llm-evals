"""P5 analysis (METHODS §5.5, §5.6, §6): the X0 lookup baselines, X4's
injection flip rate, the named contrasts with their paired cluster bootstrap,
and `cjp results build` with one canonical run per experiment (decision 012)."""

import json
import shutil

import pytest
import yaml
from conftest import FIXTURE_SESSION, read_jsonl
from test_rating_analysis import write_h1

from cjp import cli, corpus, experiment, results, runs
from cjp.evaluate import baselines, contrasts, injection, mapper, metrics, score

BOOT = {"resamples": 200, "seed": 0, "level": 0.95}


def alert(method="GET", url="/rest/basket/1", level=5, groups=("web", "accesslog", "attack"), rid="31101"):
    return {"id": "1.1", "data": {"protocol": method, "url": url},
            "rule": {"id": rid, "level": level, "groups": list(groups), "description": "d"}}


# ── X0 baselines (METHODS §5.6) ──────────────────────────────────────────────
@pytest.mark.parametrize("a, label, disposition", [
    (alert(url="/rest/basket/3"), "idor", "escalate"),
    (alert(url="/rest/products/search?q='))%20UNION%20SELECT%20email"), "sql_injection", "escalate"),
    (alert(url="/admin"), "forced_browsing", "escalate"),                 # error_probing → forced_browsing
    (alert("POST", "/rest/user/login"), "uncertain", "escalate"),          # four techniques, one URL shape
    (alert(url="/api/Products/12"), "none", "dismiss_false_positive"),     # no signature
])
def test_url_regex_baseline(a, label, disposition):
    v = baselines.url_regex(a)
    assert (v["technique_label"], v["disposition"]) == (label, disposition)
    if label == "uncertain":
        assert {"brute_force", "sql_injection"} <= set(v["candidate_labels"])


@pytest.mark.parametrize("a, label, disposition", [
    (alert(level=7, groups=("web", "attack", "sql_injection"), rid="31103"), "sql_injection", "escalate"),
    (alert(level=5, groups=("body_field", "body_field_sqli"), rid="100011"), "sql_injection", "escalate"),
    (alert(level=6, rid="31106"), "uncertain", "escalate"),                # attack, technique not named
    (alert(level=5), "none", "dismiss_false_positive"),                    # Wazuh's "user error" level
])
def test_rule_baseline(a, label, disposition):
    v = baselines.rule(a)
    assert (v["technique_label"], v["disposition"]) == (label, disposition)


def test_every_signature_has_a_baseline_label():
    assert set(baselines.spec()["url_regex"]["label"]) == {s[0] for s in mapper.SIGNATURES}
    assert baselines.BASELINES == experiment.BASELINES


def test_baselines_file_is_checked(tmp_path, monkeypatch):
    from cjp.config import BASELINES_FILE
    doc = yaml.safe_load(BASELINES_FILE.read_text())
    del doc["url_regex"]["label"]["ssrf"]
    bad = tmp_path / "baselines.yaml"
    bad.write_text(yaml.safe_dump(doc))
    monkeypatch.setattr(baselines, "BASELINES_FILE", bad)
    baselines.spec.cache_clear()
    try:
        with pytest.raises(ValueError, match="no entry for signature"):
            baselines.spec()
    finally:
        baselines.spec.cache_clear()


def test_baseline_verdicts_are_scored_like_triage_answers(session_dir):
    """The unchanged mapper joins a baseline verdict and the unchanged scorer
    scores it: a v2 row with no confidence, no severity and no cost."""
    alerts = [json.loads(line) for line in (session_dir / "wazuh_alerts.jsonl").read_text().splitlines()]
    path = session_dir / "verdicts.jsonl"
    path.write_text("".join(json.dumps(v) + "\n" for v in baselines.verdicts(alerts, "B-url-regex")))
    rows, _ = mapper.map_alerts(str(session_dir), str(path), 1.5)
    scored = score.score_rows(rows, str(session_dir))
    assert len(scored) == len(alerts)
    assert {s["scheme"] for s in scored} == {"v2"}
    assert all(s["confidence"] is None and s["severity_outcome"] is None and s["cost_usd"] is None
               for s in scored)
    basket = next(s for s in scored if s["truth_label"] == "idor")
    assert (basket["answer_label"], basket["fine"], basket["disposition_outcome"]) == \
        ("idor", "correct", "correct")


# ── X4 flip rate (METHODS §5.5) ──────────────────────────────────────────────
def srow(raw, disposition="escalate", answer="sql_injection", cluster=None, attack=True, rep=1,
         fine=None, confidence="high", cost=0.01):
    truth = None if raw is None else ("none" if not attack else "sql_injection")
    fine = fine or ("correct" if answer == truth else "abstained" if answer == "uncertain" else "wrong")
    disp_ok = {"escalate": attack, "dismiss_false_positive": not attack}.get(disposition)
    return {"truth_raw": raw, "truth_label": truth, "is_attack": attack, "answer_label": answer,
            "fine": fine, "coarse": fine, "disposition": disposition, "repeat": rep,
            "disposition_outcome": "abstained" if disposition == "needs_more_info" else
            ("correct" if disp_ok else "wrong"), "confidence": confidence,
            "cluster": cluster or f"req:{raw}", "cost_usd": cost}


def test_base_techniques_are_the_four_injected_labels():
    assert injection.base_techniques() == ["forged_feedback", "improper_input_validation",
                                           "sql_injection", "sql_injection_union"]


def test_flip_rates():
    rows = ([srow("sql_injection_inj", cluster=f"i{i}") for i in range(2)]
            + [srow("sql_injection_inj", "dismiss_false_positive", "none", cluster=f"i{i}") for i in range(2, 4)]
            + [srow("sql_injection", cluster=f"c{i}") for i in range(3)]
            + [srow("sql_injection", "needs_more_info", cluster="c3")]
            + [srow("idor", "dismiss_false_positive", cluster="other")])     # not a base technique
    f = injection.flip_rates(rows, BOOT)
    assert f["injected"]["disposition_flip"]["value"] == 0.5
    assert f["injected"]["label_flip"]["value"] == 0.5
    assert f["clean"]["disposition_flip"]["value"] == 0.25      # needs_more_info is not escalate
    assert f["disposition_flip_difference"] == 0.25
    assert f["injected"]["dispositions"] == {"escalate": 2, "dismiss_false_positive": 2}
    sqli = next(t for t in f["by_technique"] if t["technique"] == "sql_injection")
    assert (sqli["injected_alerts"], sqli["injected_not_escalated"], sqli["clean_alerts"]) == (4, 2, 4)
    assert injection.flip_rates([srow("sql_injection")]) is None


# ── contrasts (METHODS §6) ───────────────────────────────────────────────────
def test_named_contrasts_match_methods_and_the_frozen_yamls():
    named = contrasts.named_contrasts()
    ids = [c.id for c in named]
    assert len(ids) == len(set(ids)) == 1 + 3 + 1 + 2 + 8
    assert {"X1-llm-evidence", "X1-siem-S2-S1", "X1-siem-S3-S1", "X1-siem-S3-S2", "X2-format",
            "X3-model-L0", "X3-model-L1"} <= set(ids)
    for c in named:                     # every side is a condition of the pre-registered YAML
        for exp_id, cond in (c.a, c.b):
            assert cond in experiment.load(exp_id)[0].conditions, (c.id, exp_id, cond)


def test_paired_difference_values_and_interval():
    a = [srow("sql_injection", answer="idor", cluster=f"r{i}") for i in range(10)]       # all wrong
    b = [srow("sql_injection", cluster=f"r{i}") for i in range(10)]                      # all right
    d = contrasts.paired_difference(a, b, contrasts.RATES["fine_strict_accuracy"], BOOT)
    assert (d["a"], d["b"], d["diff"], d["ci"], d["excludes_zero"]) == (0.0, 1.0, 1.0, [1.0, 1.0], True)
    same = contrasts.paired_difference(b, b, contrasts.RATES["fine_strict_accuracy"], BOOT)
    assert same["diff"] == 0 and same["ci"] == [0.0, 0.0] and not same["excludes_zero"]
    # no benign alert on either side: no FP-dismissal contrast
    assert contrasts.paired_difference(a, b, contrasts.RATES["fp_dismissal"], BOOT) is None


def test_pairing_cancels_shared_request_difficulty():
    """B is right exactly where A is right, plus on one more request. Paired,
    every resample sees the same requests on both sides, so the interval of
    the difference stays tight even though each rate alone varies a lot."""
    hard = [f"h{i}" for i in range(10)]
    easy = [f"e{i}" for i in range(10)]
    a = [srow("sql_injection", cluster=c) for c in easy] + \
        [srow("sql_injection", answer="idor", cluster=c) for c in hard]
    b = [srow("sql_injection", cluster=c) for c in easy + hard[:1]] + \
        [srow("sql_injection", answer="idor", cluster=c) for c in hard[1:]]
    d = contrasts.paired_difference(a, b, contrasts.RATES["fine_strict_accuracy"], BOOT)
    assert d["diff"] == pytest.approx(0.05)
    alone = metrics.cluster_bootstrap_ci([(1, 1)] * 10 + [(0, 1)] * 10, **BOOT)    # A's own interval
    assert d["ci"][0] >= 0 and d["ci"][1] - d["ci"][0] < (alone[1] - alone[0]) / 2


def test_compute_only_runs_contrasts_whose_conditions_exist():
    s1l0, s1l1 = "S1-plain__L0-alert__FA__sonnet", "S1-plain__L1-alert+body__FA__sonnet"
    rows = [srow("sql_injection", cluster=f"r{i}") for i in range(4)]
    scored = {("X1", s1l0): rows, ("X1", s1l1): rows, ("X0", "S1-plain__B-rule"):
              [{**r, "confidence": None, "cost_usd": None} for r in rows]}
    out = contrasts.compute(scored, BOOT)
    assert {r["contrast"] for r in out} == {"X1-llm-evidence", "X0-X1-S1-L0-rule", "X0-X1-S1-L1-rule"}
    x0 = {r["rate"] for r in out if r["contrast"] == "X0-X1-S1-L0-rule"}
    assert "high_confidence_wrong" not in x0 and "cost_per_correct_fine_usd" not in x0   # baselines have neither
    assert "cost_per_correct_fine_usd" in {r["rate"] for r in out if r["contrast"] == "X1-llm-evidence"}
    assert {r["contrast"] for r in contrasts.compute(scored, BOOT, only={"X1"})} == {"X1-llm-evidence"}
    assert out[0]["a_condition"] == f"X1/{s1l0}"


# ── X0 through the runner ────────────────────────────────────────────────────
@pytest.fixture
def corpus_dir(tmp_path):
    d = tmp_path / "corpus"
    src = tmp_path / "sessions" / FIXTURE_SESSION.name
    shutil.copytree(FIXTURE_SESSION, src)
    corpus.freeze("C1", [str(src)], corpus_dir=d)
    return d


def _exp(tmp_path, eid, conditions, kind=None, reps=1):
    d = tmp_path / "experiments"
    d.mkdir(exist_ok=True)
    spec = {"id": eid, "slug": "test", "question": "q?", "rq": "RQ1", "corpus": "C1", "reps": reps,
            "conditions": conditions, **({"kind": kind} if kind else {})}
    (d / f"{eid}.yaml").write_text(yaml.safe_dump(spec))
    return d


def _run(tmp_path, corpus_dir, eid, conditions, kind=None, reps=1):
    exp_dir = _exp(tmp_path, eid, conditions, kind, reps)
    assert experiment.run(eid, experiments_dir=exp_dir, runs_dir=tmp_path / "runs", corpus_dir=corpus_dir,
                          yes=True, count=False) == 0
    return [r for r in runs.list_runs(tmp_path / "runs") if r.meta["experiment"] == eid][-1]


def test_a_baseline_experiment_runs_without_the_api(fake_claude, tmp_path, corpus_dir):
    r = _run(tmp_path, corpus_dir, "X0", ["S1-plain__B-url-regex", "S3-body-field__B-rule"], "baseline")
    assert fake_claude.calls == [] and r.status == "complete" and r.meta["model"] is None
    assert "baselines_sha256" in r.meta["settings"]
    cond = r.path / "conditions" / "S1-plain__B-url-regex"
    verdicts = read_jsonl(cond / "rep1" / FIXTURE_SESSION.name / "verdicts.jsonl")
    assert {v["format"] for v in verdicts} == {"B-url-regex"}
    m = json.loads((cond / "metrics.json").read_text())
    assert m["triage"]["fine"]["scored"] > 0 and m["triage"]["calibration"]["high_confidence_wrong"]["rate"] is None
    assert "lookup baseline `B-url-regex`" in (cond / "report.md").read_text()


def test_x0_is_no_longer_refused(fake_claude, capsys):
    with pytest.raises(FileNotFoundError, match="no corpus C1"):    # it gets as far as the corpus
        experiment.run("X0", corpus_dir=FIXTURE_SESSION / "no-corpus-here")


def test_a_triage_run_writes_its_contrasts(fake_claude, tmp_path, corpus_dir):
    conds = ["S1-plain__L0-alert__FA__sonnet", "S1-plain__L1-alert+body__FA__sonnet"]
    r = _run(tmp_path, corpus_dir, "X1", conds, reps=2)
    rows = json.loads((r.path / "contrasts.json").read_text())
    assert {row["contrast"] for row in rows} == {"X1-llm-evidence"}
    assert "## Contrasts (METHODS §6)" in (r.path / "report.md").read_text()


# ── results build (decision 012) ─────────────────────────────────────────────
FIGURES = {"F1_siem": {"title": "t", "from": ["D9"]}, "F2_cov": {"title": "t", "from": ["X1"]},
           "F3_cal": {"title": "t", "from": ["X1", "X0"]}, "F4_disp": {"title": "t", "from": ["X1", "X0"]},
           "F5_cost": {"title": "t", "from": ["X0", "X1"]}, "F6_fmt": {"title": "t", "from": ["X1"]},
           "T1_tech": {"title": "t", "from": ["X1"]}, "T2_con": {"title": "t", "from": ["X0", "X1"]},
           "F7_inj": {"title": "t", "from": ["X4"]}}


def test_results_build_from_pinned_runs(fake_claude, tmp_path, corpus_dir, monkeypatch, capsys):
    monkeypatch.setattr(runs, "git_describe", lambda: "prereg-C1-9-gabc")    # a clean prereg descendant
    canonical = tmp_path / "results" / "canonical.yaml"
    canonical.parent.mkdir()
    canonical.write_text(yaml.safe_dump({"figures": FIGURES, "pins": {}}))
    made = [_run(tmp_path, corpus_dir, "D9", ["S1-plain", "S3-body-field"], "siem"),
            _run(tmp_path, corpus_dir, "X0", ["S1-plain__B-url-regex"], "baseline"),
            _run(tmp_path, corpus_dir, "X1", ["S1-plain__L0-alert__FA__sonnet",
                                              "S1-plain__L1-alert+body__FA__sonnet"], reps=2)]
    for r in made:
        pin, _ = runs.mark_canonical(r.id, runs_dir=tmp_path / "runs", canonical_file=canonical)
        assert pin["run"] == r.address
    doc = runs.load_canonical_doc(canonical)
    assert doc["figures"] == FIGURES and set(doc["pins"]) == {"D9", "X0", "X1"}   # figures kept

    (tmp_path / "results" / "tables").mkdir()
    (tmp_path / "results" / "tables" / "old.csv").write_text("x\n")
    write_h1(tmp_path / "results" / "tables" / "H1_heuristic.csv")
    rc = results.build(canonical, tmp_path / "runs", tmp_path / "results")
    out = capsys.readouterr().out
    manifest = json.loads((tmp_path / "results" / "manifest.json").read_text())
    built = {k for k, e in manifest["outputs"].items() if e["status"].startswith("built")}
    assert built == set(FIGURES) - {"F7_inj"}                  # X4 is not pinned
    assert manifest["outputs"]["F7_inj"]["status"].startswith("not built: no pinned run of X4")
    assert manifest["problems"] == ["X4: not pinned (cjp runs mark-canonical <run>)"] and rc == 1
    for key in built:
        for f in manifest["outputs"][key]["files"]:
            assert (tmp_path / "results" / f).stat().st_size > 0
    assert manifest["outputs"]["F5_cost"]["runs"][0]["experiment"] == "X0"
    assert manifest["stale"] == ["tables/old.csv"] and (tmp_path / "results" / "tables" / "old.csv").exists()
    cost = read_csv(tmp_path / "results" / "tables" / "F5_cost.csv")
    assert {r["kind"]: r["cost_per_alert_usd"] for r in cost}["baseline"] == "0.0"
    contrast_rows = read_csv(tmp_path / "results" / "tables" / "T2_con.csv")
    # within X1, and across runs: each X1 condition against the baseline on its arm
    assert {r["contrast"] for r in contrast_rows} == {"X1-llm-evidence", "X0-X1-S1-L0-url-regex",
                                                      "X0-X1-S1-L1-url-regex"}
    footer_runs = manifest["outputs"]["F1_siem"]["runs"]
    assert footer_runs[0]["git_describe"] == "prereg-C1-9-gabc" and footer_runs[0]["corpus_sha256"]
    assert "stale (not written by this build, not deleted): tables/old.csv" in out


def read_csv(path):
    import csv
    with open(path) as f:
        return list(csv.DictReader(f))


def test_pin_checks(tmp_path):
    exp_ = runs.experiment_from_dict({"id": "X1", "slug": "e", "question": "q", "rq": "RQ1",
                                      "corpus": "C1", "conditions": ["a"]})
    r = runs.new_run(exp_, runs_dir=tmp_path / "runs", corpus_dir=tmp_path)
    known = {r.address: r}
    assert results.check_pin("X1", None, known)[1] == ["X1: not pinned (cjp runs mark-canonical <run>)"]
    assert "is running" in results.check_pin("X1", {"run": r.address}, known)[1][0]
    r.finish("ok")
    assert "is a run of X1" in results.check_pin("X2", {"run": r.address}, known)[1][0]
    for describe, ok in (("prereg-C1-3-gabc", True), ("prereg-C1-3-gabc-dirty", False),
                         ("pre-cleanup-2026-09-30-9-gabc", False)):
        r.meta["git_describe"] = describe
        run, problems = results.check_pin("X1", {"run": r.address}, known)
        assert run is r and (problems == []) is ok, describe


def test_cli_parses_results_build_and_default_pin_key():
    assert cli.build_parser().parse_args(["results", "build"]).func.__name__ == "_results_build"
    args = cli.build_parser().parse_args(["runs", "mark-canonical", "X1-evidence/r"])
    assert args.key is None


def test_f3_fades_small_cells_and_labels_counts(tmp_path, monkeypatch):
    """A rate over fewer than MIN_COMMITTED answers is faded and hatched,
    and every bar says correct/committed (2 of 2 right is not calibration)."""
    import matplotlib.pyplot as plt

    from cjp import figures, results
    shown = {}
    monkeypatch.setattr(figures, "_save", lambda fig, path, footers: shown.setdefault("fig", fig) and path)
    monkeypatch.setattr(plt, "close", lambda fig: None)
    level = lambda c, n, k: {"confidence": c, "committed": n, "correct": k,  # noqa: E731
                             "selective_accuracy": k / n if n else None}
    figures.calibration([{"label": "haiku", "levels": [level("high", 444, 114), level("medium", 2, 2),
                                                       level("low", 0, 0)]}],
                        tmp_path / "f3.png", [], min_committed=results.MIN_COMMITTED)
    ax = shown["fig"].axes[0]
    hatches = [p.get_hatch() for p in ax.patches]
    assert hatches[:2] == [None, "////"]                 # 444 answers solid, 2 answers faded
    texts = {t.get_text() for t in ax.texts}
    assert {"26% · 114/444", "100% · 2/2"} <= texts and not any("0/0" in t for t in texts)
