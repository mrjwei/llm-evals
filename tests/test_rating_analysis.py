"""X5 rating analysis (Plan P7.3, METHODS §7, decision 022): agreement, means
and R5, on a synthetic batch, and as F8 of `cjp results build`."""

import csv
import json

import pytest
import yaml

from cjp import rating, rating_analysis, results
from cjp.rating_batch import CELL_NAMES, STRATA

BOOT = {"resamples": 200, "seed": 0, "level": 0.95}
RUNS = {"X1": "X1-evidence/2026-01-01T0000_aaaaaa", "X2": "X2-format/2026-01-01T0000_bbbbbb"}


def make_batch(root, per=2):
    """3 cells × 4 strata × `per` analysed items, plus 2 calibration items."""
    items, key, n = [], {}, 0
    for cell in CELL_NAMES:
        for stratum in STRATA:
            for _ in range(per + (1 if cell == CELL_NAMES[0] and stratum in STRATA[:2] else 0)):
                calibration = cell == CELL_NAMES[0] and stratum in STRATA[:2] and \
                    not any(k["cell"] == cell and k["stratum"] == stratum and k["calibration"] for k in key.values())
                item_id = f"x{n:04d}"
                n += 1
                items.append({"item": item_id, "alert": {"rule": "r"}, "body": None, "answer": {"a": 1}})
                attack = stratum != "benign"
                key[item_id] = {"cell": cell, "stratum": stratum, "calibration": calibration,
                                "is_attack": attack, "confidence": ("low", "medium", "high")[n % 3],
                                "disposition": "escalate" if stratum == "attack-correct" else "needs_more_info"}
    cal = [i for i, k in key.items() if k["calibration"]]
    rating.create_batch("X5", items, {"runs": RUNS, "corpus": {"X1": {"id": "C1", "sha256": "ab" * 32}},
                                      "made_with_code": "prereg-C1-1-gabc", "items": key},
                        calibration=cal, root=root)
    return key


def rate(root, rater, key, fn):
    rating.start("X5", rater, root)
    for item_id, k in key.items():
        rating.save("X5", rater, item_id, fn(k), root)


def a_scores(k):
    good = k["stratum"] == "attack-correct"
    return {"R1": 5 if good else 2, "R2": 4, "R3": 3, "R4": 4 if good else 2,
            "R5": "escalate" if k["is_attack"] else "dismiss_false_positive"}


def write_h1(path, score="4", rows=11):
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["criterion", "text", "rater", "score_FA", "score_FB", "observation_FA", "observation_FB"])
        for i in range(1, rows + 1):
            w.writerow([i, f"criterion {i}", "A", score, "3", "", ""])
    return path


def test_check_h1(tmp_path):
    path = tmp_path / "H1_heuristic.csv"
    assert results.check_h1(path) == ({"status": "missing"}, ["H1_heuristic.csv: missing (Plan P7.4)"])
    assert results.check_h1(write_h1(path)) == ({"status": "complete", "raters": ["A"]}, [])
    status, problems = results.check_h1(write_h1(path, score=""))
    assert status["status"] == "incomplete" and problems == [
        "H1_heuristic.csv: rater A has 11/11 FA criteria unscored (Plan P7.4)"]
    _, problems = results.check_h1(write_h1(path, score="6", rows=10))
    assert problems == ["H1_heuristic.csv: rater A needs criteria 1–11 once each",
                        "H1_heuristic.csv: rater A FA scores must be 1–5, not " + str(["6"] * 10)]
    path.write_text("criterion,text,rater,score_FA,score_FB\n")
    assert results.check_h1(path)[1] == ["H1_heuristic.csv: no rows (Plan P7.4)"]


def test_the_shipped_h1_template_holds_the_eleven_criteria():
    _, problems = results.check_h1(results.Path(__file__).parents[1] / "results" / "tables" / "H1_heuristic.csv")
    assert not [p for p in problems if "unscored" not in p]


def test_weighted_kappa():
    assert rating_analysis.weighted_kappa([1, 2, 3, 4, 5], [1, 2, 3, 4, 5], 1, 5) == pytest.approx(1.0)
    # one-step disagreements cost far less than the unweighted κ says
    a, b = [1, 2, 3, 4, 5, 3], [2, 2, 3, 5, 5, 3]
    assert rating_analysis.weighted_kappa(a, b, 1, 5) > 0.85
    assert rating_analysis.weighted_kappa([1, 5], [5, 1], 1, 5) < 0
    assert rating_analysis.weighted_kappa([3, 3], [3, 3], 1, 5) == 1.0       # no spread, full agreement
    assert rating_analysis.weighted_kappa([], [], 1, 5) is None


def test_single_rater_means_r5_and_no_kappa(tmp_path):
    key = make_batch(tmp_path)
    rate(tmp_path, "A", key, a_scores)
    a = rating_analysis.analyse("X5", BOOT, tmp_path)
    data = a["data"]
    assert data.raters == ["A"] and data.single_rater and len(data.items) == 24     # calibration left out
    assert all(r["value"] is None and "single-rater" in r["note"] for r in a["agreement"])
    means = {(m["grouping"], m["group"], m["rubric_item"]): m for m in a["means"]}
    assert means[("stratum", "attack-correct", "R1")]["value"] == 5
    assert means[("stratum", "attack-wrong", "R1")]["value"] == 2
    assert means[("cell", "S1xL0-FA", "R1")]["n"] == 8
    m = means[("all", "all", "R4")]
    assert m["value"] == pytest.approx((6 * 4 + 18 * 2) / 24) and m["ci_low"] <= m["value"] <= m["ci_high"]
    r5 = {(r["grouping"], r["group"], r["rater"], r["comparison"]): r for r in a["r5"]}
    assert r5[("all", "all", "A", "rater R5 = expected")]["value"] == 1.0
    assert r5[("all", "all", "LLM", "LLM disposition = expected")]["num"] == 6   # only attack-correct escalated
    assert r5[("stratum", "benign", "A", "rater R5 = LLM disposition")]["value"] == 0.0
    cross = {(c["against"], c["rater_R5"], c["other"]): c["items"] for c in a["r5_crosstab"]}
    assert cross[("expected", "escalate", "escalate")] == 18
    assert sum(v for (against, *_), v in cross.items() if against == "LLM disposition") == 24


def test_two_raters_give_kappa_and_averaged_scores(tmp_path):
    key = make_batch(tmp_path)
    rate(tmp_path, "A", key, a_scores)
    rate(tmp_path, "B", key, lambda k: {**a_scores(k), "R1": 4 if k["stratum"] == "attack-correct" else 2})
    a = rating_analysis.analyse("X5", BOOT, tmp_path)
    kappa = {r["rubric_item"]: r for r in a["agreement"]}
    assert kappa["R5"]["value"] == pytest.approx(1.0) and kappa["R5"]["percent_agreement"] == 1.0
    assert 0 < kappa["R1"]["value"] < 1 and kappa["R1"]["note"] is None
    means = {(m["grouping"], m["group"], m["rubric_item"]): m["value"] for m in a["means"]}
    assert means[("stratum", "attack-correct", "R1")] == 4.5


def test_check_batch(tmp_path, monkeypatch):
    key = make_batch(tmp_path)
    pins = {e: {"run": r} for e, r in RUNS.items()}
    src, problems = rating_analysis.check_batch("X5", pins, tmp_path)
    assert src is None and problems == ["X5: no rater has finished the batch"]
    rate(tmp_path, "A", key, a_scores)
    rating.start("X5", "B", tmp_path)                                   # started, not finished
    src, problems = rating_analysis.check_batch("X5", {**pins, "X2": {"run": "X2-format/other"}}, tmp_path)
    assert problems == ["X5: rater B has not scored every item",
                        f"X5: drawn from X2 run {RUNS['X2']}, but X2's pin is X2-format/other"]
    assert src.data.raters == ["A"]
    assert "single-rater review" in src.footer() and src.provenance()["drawn_from"] == RUNS


def test_results_build_writes_f8_from_the_batch(tmp_path, monkeypatch, capsys):
    key = make_batch(tmp_path / "ratings")
    rate(tmp_path / "ratings", "A", key, a_scores)
    canonical = tmp_path / "results" / "canonical.yaml"
    canonical.parent.mkdir()
    write_h1(tmp_path / "results" / "tables" / "H1_heuristic.csv")
    canonical.write_text(yaml.safe_dump({"figures": {"F8_rating": {"title": "t", "from": ["X5"]}},
                                         "pins": {e: {"run": r} for e, r in RUNS.items()}}))
    rc = results.build(canonical, tmp_path / "runs", tmp_path / "results", tmp_path / "ratings")
    manifest = json.loads((tmp_path / "results" / "manifest.json").read_text())
    entry = manifest["outputs"]["F8_rating"]
    assert rc == 0 and manifest["problems"] == [] and entry["status"] == "built"
    assert sorted(entry["files"]) == ["figures/F8_rating.png", "tables/F8_rating_agreement.csv",
                                      "tables/F8_rating_means.csv", "tables/F8_rating_r5.csv",
                                      "tables/F8_rating_r5_crosstab.csv"]
    assert entry["runs"][0]["kind"] == "rating" and entry["runs"][0]["raters"]["A"]["complete"]
    with open(tmp_path / "results" / "tables" / "F8_rating_agreement.csv") as f:
        assert {r["rubric_item"] for r in csv.DictReader(f)} == {"R1", "R2", "R3", "R4", "R5"}
