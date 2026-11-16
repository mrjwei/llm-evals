"""cjp rating make-batch (Plan P7.1, decision 021): the stratified, blind X5
batch drawn from the pinned X1 and X2 runs."""

import json
import random
import shutil

import pytest
import yaml

from cjp import corpus, experiment, rating, rating_batch, runs
from cjp.cli import build_parser
from cjp.rating_batch import Demand
from tests.conftest import FIXTURE_SESSION, read_jsonl

FB_REPLY = {"technique_label": "sql_injection", "disposition": "escalate", "confidence": "high",
            "recommended_action": "Block it."}


# ── the draw ─────────────────────────────────────────────────────────────────
def test_demands_are_equal_per_cell_and_stratum_plus_six_calibration():
    d = rating_batch.demands(48)
    assert len(d) == 54 and sum(x.calibration for x in d) == 6
    for c in range(3):
        for s in rating_batch.STRATA:
            assert sum(1 for x in d if (x.cell, x.stratum, x.calibration) == (c, s, False)) == 4
    cal = [(x.cell, x.stratum) for x in d if x.calibration]
    assert {s for _, s in cal} == {"attack-abstained", "attack-wrong", "attack-correct", "benign"}
    for bad in (0, 47, 50):
        with pytest.raises(ValueError, match="multiple of 12"):
            rating_batch.demands(bad)


@pytest.mark.parametrize("row, expected", [
    ({"is_attack": True, "fine": "correct"}, "attack-correct"),
    ({"is_attack": True, "fine": "abstained"}, "attack-abstained"),
    ({"is_attack": False, "fine": "wrong"}, "benign"),
    ({"is_attack": True, "fine": "no_answer"}, None),        # nothing to rate
    ({"is_attack": None, "fine": None}, None)])               # unscored
def test_stratum(row, expected):
    assert rating_batch.stratum(row) == expected


def _pool(clusters, cell=0, stratum="attack-wrong"):
    return {(cell, stratum): {c: [{"session": "s", "repeat": r, "wazuh_alert_id": f"{c}.{r}", "cluster": c}
                                  for r in (1, 2)] for c in clusters}}


def test_allocate_uses_each_request_once_and_fills_the_scarcest_first():
    # Cell 0 can only use a or b; cell 1 can use a–d. Filling cell 1 first
    # at random could take a and b; scarcest-first never does.
    pools = {**_pool(["a", "b"], 0), **_pool(["a", "b", "c", "d"], 1)}
    want = [Demand(0, "attack-wrong", False)] * 2 + [Demand(1, "attack-wrong", False)] * 2
    for seed in range(30):
        out = rating_batch.allocate(pools, list(want), random.Random(seed))
        clusters = [row["cluster"] for _, row in out]
        assert len(set(clusters)) == 4
        assert {row["cluster"] for d, row in out if d.cell == 0} == {"a", "b"}


def test_allocate_is_seeded_and_says_which_stratum_ran_out():
    pools = _pool([f"c{i}" for i in range(10)])
    want = [Demand(0, "attack-wrong", False)] * 3
    draw = lambda seed: [r["wazuh_alert_id"] for _, r in rating_batch.allocate(pools, list(want), random.Random(seed))]
    assert draw(7) == draw(7) and draw(7) != draw(8)
    with pytest.raises(ValueError, match="S1xL0-FA attack-wrong: no request left .*2 distinct"):
        rating_batch.allocate(_pool(["a", "b"]), [Demand(0, "attack-wrong", False)] * 3, random.Random(0))


# ── end to end, on the fixture session through the real runner ───────────────
@pytest.fixture
def pinned(fake_claude, tmp_path, monkeypatch):
    """X1 (L0 and L1, FA) and X2 (FB) run on a corpus made from the fixture
    session, with alert .5's Referer set to the CID of the session's one
    ingest_log row, so its L1 request carries a body. Both runs pinned."""
    src = tmp_path / "sessions" / FIXTURE_SESSION.name
    shutil.copytree(FIXTURE_SESSION, src)
    alerts = read_jsonl(src / "wazuh_alerts.jsonl")
    for a in alerts:
        if a["id"] == "4070908800.5":
            a["full_log"] = a["full_log"].replace('"-" "curl', '"wp1-20990101_000000-3-1" "curl')
    (src / "wazuh_alerts.jsonl").write_text("".join(json.dumps(a) + "\n" for a in alerts))
    corpus_dir = tmp_path / "corpus"
    corpus.freeze("C1", [str(src)], corpus_dir=corpus_dir)

    monkeypatch.setattr(runs, "git_describe", lambda: "prereg-C1-9-gabc")
    exp_dir = tmp_path / "experiments"
    exp_dir.mkdir()
    canonical = tmp_path / "canonical.yaml"
    for eid, conds, reply in (("X1", [c for e, c in rating_batch.CELLS if e == "X1"], None),
                              ("X2", [rating_batch.CELLS[2][1]], FB_REPLY)):
        if reply:
            fake_claude.reply = reply
        (exp_dir / f"{eid}.yaml").write_text(yaml.safe_dump(
            {"id": eid, "slug": "t", "question": "q?", "rq": "RQ2", "corpus": "C1", "reps": 1,
             "conditions": conds}))
        assert experiment.run(eid, experiments_dir=exp_dir, runs_dir=tmp_path / "runs",
                              corpus_dir=corpus_dir, yes=True, count=False) == 0
        run = [r for r in runs.list_runs(tmp_path / "runs") if r.meta["experiment"] == eid][-1]
        runs.mark_canonical(run.address, runs_dir=tmp_path / "runs", canonical_file=canonical)
    # The fixture has 4 scored requests per cell (.1/.2 attack-wrong, .5
    # attack-correct, .3 benign), so the test asks for 4 distinct ones.
    monkeypatch.setattr(rating_batch, "demands", lambda n: [
        Demand(0, "attack-wrong", False), Demand(1, "attack-correct", False),
        Demand(2, "benign", False), Demand(0, "attack-wrong", True)])
    return {"canonical_file": canonical, "runs_dir": tmp_path / "runs", "corpus_dir": corpus_dir,
            "root": tmp_path / "ratings"}


def test_make_batch_writes_a_blind_batch_of_what_the_model_saw(pinned):
    s = rating_batch.make_batch(["X2", "X1"], 12, 7, "X5-t", **pinned)
    assert s["items"] == 4 and s["calibration"] == 1 and s["path"] == pinned["root"] / "X5-t"
    batch = rating.Batch("X5-t", pinned["root"])
    key = json.loads((s["path"] / "key.json").read_text())
    assert batch.calibration == [i for i, k in key["items"].items() if k["calibration"]]
    assert key["seed"] == 7 and key["runs"]["X1"].startswith("X1-") and key["corpus"]["X1"]["id"] == "C1"

    by_cell = {}
    for item in batch.items:
        assert set(item) == {"item", "alert", "body", "answer"} and item["item"].startswith("x")
        k = key["items"][item["item"]]
        by_cell[(k["cell"], k["stratum"])] = item
        text = json.dumps(item)
        assert "wp1-" not in text and "ground_truth" not in text and "4070908800" not in text
        assert set(item["alert"]) == {"timestamp", "rule", "data", "full_log", "location", "agent"}
    # L1 FA: alert .5 carries its body, split out of the alert; L0 never has one
    l1 = by_cell[("S1xL1-FA", "attack-correct")]
    assert l1["body"]["request_body"].startswith('{"email"') and l1["alert"]["location"] == "access.log"
    assert by_cell[("S1xL0-FA", "attack-wrong")]["body"] is None
    assert set(by_cell[("S1xL1-FB", "benign")]["answer"]) == set(FB_REPLY)

    with pytest.raises(ValueError, match="already exists"):
        rating_batch.make_batch(["X1", "X2"], 12, 7, "X5-t", **pinned)
    again = rating_batch.make_batch(["X1", "X2"], 12, 7, "X5-u", **pinned)
    assert (again["path"] / "items.jsonl").read_text() == (s["path"] / "items.jsonl").read_text()


def test_dry_run_writes_nothing_and_from_is_fixed(pinned):
    s = rating_batch.make_batch(["X1", "X2"], 12, 7, "X5-t", dry_run=True, **pinned)
    assert s["path"] is None and not pinned["root"].exists()
    assert s["counts"]["S1xL0-FA calibration"] == 1 and s["available"]["S1xL0-FA attack-wrong"] == 2
    with pytest.raises(ValueError, match="--from must be X1,X2"):
        rating_batch.make_batch(["X1", "X3"], 12, 7, "X5-t", **pinned)


def test_a_request_that_is_not_what_the_model_answered_is_refused(pinned):
    run = [r for r in runs.list_runs(pinned["runs_dir"]) if r.meta["experiment"] == "X1"][0]
    path = next((run.path / "conditions" / rating_batch.CELLS[1][1]).rglob("verdicts.jsonl"))
    rows = read_jsonl(path)
    for r in rows:
        r["cache_key"] = "0" * 64
    path.write_text("".join(json.dumps(r) + "\n" for r in rows))
    with pytest.raises(ValueError, match="cache key differs"):
        rating_batch.make_batch(["X1", "X2"], 12, 7, "X5-t", **pinned)
    assert not pinned["root"].exists()


def test_cli_parses_make_batch_with_the_plan_defaults():
    args = build_parser().parse_args(["rating", "make-batch"])
    assert (args.sources, args.n, args.seed, args.batch, args.dry_run) == ("X1,X2", 48, 7, "X5", False)
