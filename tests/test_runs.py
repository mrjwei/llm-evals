"""The run registry (Plan §2.3, P2.4): experiment YAMLs, run.json, condition
directories, status changes, INDEX.md, canonical pins and prune."""

import json
import re

import pytest
import yaml

from cjp import cli, runs

SPEC = {
    "id": "X1", "slug": "evidence",
    "question": "How does evidence change correctness?",
    "rq": ["RQ1", "RQ2"], "corpus": "C1", "reps": 3,
    "conditions": ["S1-plain__L0-alert__FA__sonnet", "S1-plain__L1-alert+body__FA__sonnet"],
}
COND = SPEC["conditions"][1]


@pytest.fixture
def reg(tmp_path):
    """Isolated runs dir, corpus dir and canonical file."""
    return {"runs_dir": tmp_path / "runs", "corpus_dir": tmp_path / "corpus",
            "canonical": tmp_path / "results" / "canonical.yaml"}


@pytest.fixture
def exp():
    return runs.experiment_from_dict(dict(SPEC))


def _new(exp, reg, **kw):
    return runs.new_run(exp, runs_dir=reg["runs_dir"], corpus_dir=reg["corpus_dir"], **kw)


def _complete(exp, reg, headline="ok"):
    run = _new(exp, reg)
    run.finish(headline)
    return run


# ── experiments ──────────────────────────────────────────────────────────────
def test_load_experiment_by_id(tmp_path):
    (tmp_path / "X1.yaml").write_text(yaml.safe_dump(SPEC))
    e = runs.load_experiment("X1", experiments_dir=tmp_path)
    assert (e.dir_name, e.rq, e.reps, e.conditions) == \
        ("X1-evidence", ("RQ1", "RQ2"), 3, tuple(SPEC["conditions"]))


def test_experiment_file_name_must_match_its_id(tmp_path):
    (tmp_path / "X2.yaml").write_text(yaml.safe_dump(SPEC))
    with pytest.raises(ValueError, match="must be X1.yaml"):
        runs.load_experiment(tmp_path / "X2.yaml")


@pytest.mark.parametrize("change,message", [
    ({"id": "x1"}, "must look like X1"),
    ({"slug": "Evidence Run"}, "slug"),
    ({"rq": "Q1"}, "rq"),
    ({"conditions": []}, "empty"),
    ({"conditions": ["a", "a"]}, "duplicate"),
    ({"conditions": ["../escape"]}, "safe directory name"),
    ({"reps": 0}, "reps"),
    ({"corpus": None}, "corpus"),
])
def test_experiment_validation(change, message):
    with pytest.raises(ValueError, match=message):
        runs.experiment_from_dict({**SPEC, **change})


def test_config_hash_ignores_key_order():
    a = runs.experiment_from_dict(dict(SPEC))
    b = runs.experiment_from_dict(dict(reversed(list(SPEC.items()))))
    assert a.config_hash == b.config_hash
    assert runs.experiment_from_dict({**SPEC, "reps": 1}).config_hash != a.config_hash


# ── run.json ─────────────────────────────────────────────────────────────────
def test_new_run_records_its_own_meaning(exp, reg):
    (reg["corpus_dir"] / "C1").mkdir(parents=True)
    (reg["corpus_dir"] / "C1" / "corpus.json").write_text('{"sessions": []}')
    run = _new(exp, reg, prompt_hash="p" * 64, model="claude-sonnet-5-5", settings={"cache": True})
    m = json.loads((run.path / "run.json").read_text())
    assert re.fullmatch(r"X1-evidence/\d{4}-\d{2}-\d{2}T\d{4}_[0-9a-f]{6}", run.address)
    assert (m["question"], m["rq"], m["experiment"], m["status"]) == \
        (SPEC["question"], ["RQ1", "RQ2"], "X1", "running")
    assert m["corpus"]["id"] == "C1" and re.fullmatch(r"[0-9a-f]{64}", m["corpus"]["sha256"])
    assert m["prompt_hash"] == "p" * 64 and m["model"] == "claude-sonnet-5-5"
    assert m["temperature"] is None                      # API default (decision 003)
    assert m["git_sha"] == runs.git_sha() and m["git_describe"]
    assert m["config_hash"] != exp.config_hash           # settings enter the hash
    assert (reg["runs_dir"] / "INDEX.md").is_file()


def test_missing_corpus_is_recorded_as_null(exp, reg, capsys):
    assert _new(exp, reg).meta["corpus"] == {"id": "C1", "sha256": None}
    assert "no corpus checksum" in capsys.readouterr().out


def test_runs_never_share_a_directory(exp, reg):
    assert len({_new(exp, reg).path for _ in range(5)}) == 5


def test_condition_dir_only_for_the_experiments_conditions(exp, reg):
    run = _new(exp, reg)
    assert run.condition_dir(COND, 3) == run.path / "conditions" / COND / "rep3"
    assert (run.path / "conditions" / COND / "rep3").is_dir()
    with pytest.raises(ValueError, match="exist only in experiment YAMLs"):
        run.condition_dir("S9-made-up", 1)
    with pytest.raises(ValueError, match="out of range"):
        run.condition_dir(COND, 4)


def test_finish_and_fail(exp, reg):
    run = _new(exp, reg)
    run.finish("Coverage 62%;\n selective accuracy 0.95")
    assert runs.find_run(run.id, reg["runs_dir"]).meta["headline"] == \
        "Coverage 62%; selective accuracy 0.95"
    with pytest.raises(ValueError, match="not running"):
        run.fail("late")
    with pytest.raises(ValueError, match="headline"):
        _new(exp, reg).finish("  ")


def test_start_run_marks_a_crash_failed(exp, reg):
    with pytest.raises(RuntimeError):
        with runs.start_run(exp, runs_dir=reg["runs_dir"], corpus_dir=reg["corpus_dir"]):
            raise RuntimeError("API down")
    with runs.start_run(exp, runs_dir=reg["runs_dir"], corpus_dir=reg["corpus_dir"]):
        pass                                             # forgot finish()
    errors = sorted(r.meta["error"] for r in runs.list_runs(reg["runs_dir"]))
    assert all(r.status == "failed" for r in runs.list_runs(reg["runs_dir"]))
    assert errors == ["RuntimeError: API down", "ended without a headline (finish() was not called)"]


def test_find_run(exp, reg):
    run = _new(exp, reg)
    assert runs.find_run(run.address, reg["runs_dir"]).path == run.path
    assert runs.find_run(run.id, reg["runs_dir"]).path == run.path
    with pytest.raises(LookupError):
        runs.find_run("X1-evidence/nope", reg["runs_dir"])


# ── supersede, pins, INDEX.md ───────────────────────────────────────────────
def test_supersede_marks_and_keeps(exp, reg):
    old, new = _complete(exp, reg), _complete(exp, reg)
    running = _new(exp, reg)
    with pytest.raises(ValueError, match="must be complete"):
        runs.supersede(old.id, running.id, reg["runs_dir"], reg["canonical"])
    with pytest.raises(ValueError, match="itself"):
        runs.supersede(old.id, old.id, reg["runs_dir"], reg["canonical"])
    other = _complete(runs.experiment_from_dict({**SPEC, "id": "X2", "slug": "format"}), reg)
    with pytest.raises(ValueError, match="different experiments"):
        runs.supersede(old.id, other.id, reg["runs_dir"], reg["canonical"])
    runs.supersede(old.id, new.id, reg["runs_dir"], reg["canonical"])
    with pytest.raises(ValueError, match="already superseded"):
        runs.supersede(old.id, new.id, reg["runs_dir"], reg["canonical"])
    m = runs.find_run(old.id, reg["runs_dir"]).meta
    assert m["status"] == "superseded" and m["superseded_by"] == new.address
    assert old.path.is_dir()
    assert f"superseded by `{new.id}`" in (reg["runs_dir"] / "INDEX.md").read_text()


def test_a_stale_running_run_needs_a_later_replacement(exp, reg):
    earlier = _complete(exp, reg)
    stale = _new(exp, reg)                               # process killed, never finished
    with pytest.raises(ValueError, match="only a later run"):
        runs.supersede(stale.id, earlier.id, reg["runs_dir"], reg["canonical"])
    later = _complete(exp, reg)
    assert runs.supersede(stale.id, later.id, reg["runs_dir"], reg["canonical"]).status == "superseded"


def test_mark_canonical_writes_the_tracked_pin_file(exp, reg):
    a, b = _complete(exp, reg), _complete(exp, reg)
    with pytest.raises(ValueError, match="only a complete run"):
        runs.mark_canonical(_new(exp, reg).id, "F3", runs_dir=reg["runs_dir"],
                            canonical_file=reg["canonical"])
    with pytest.raises(ValueError, match="pin key"):
        runs.mark_canonical(a.id, "fig 3", runs_dir=reg["runs_dir"], canonical_file=reg["canonical"])
    pin, old = runs.mark_canonical(a.id, "F3_calibration", note="main figure",
                                   runs_dir=reg["runs_dir"], canonical_file=reg["canonical"])
    assert old is None and pin["run"] == a.address
    pin, old = runs.mark_canonical(b.address, "F3_calibration", runs_dir=reg["runs_dir"],
                                   canonical_file=reg["canonical"])
    assert old["run"] == a.address
    text = reg["canonical"].read_text()
    assert text.startswith("# Which run each report figure")
    assert runs.load_canonical(reg["canonical"])["F3_calibration"]["run"] == b.address


def test_index_shows_pins_and_pin_problems(exp, reg):
    a, b = _complete(exp, reg, "fine | with a pipe"), _complete(exp, reg)
    runs.mark_canonical(a.id, "F3", runs_dir=reg["runs_dir"], canonical_file=reg["canonical"])
    runs.supersede(a.id, b.id, reg["runs_dir"], reg["canonical"])
    index = (reg["runs_dir"] / "INDEX.md").read_text()
    row = next(line for line in index.splitlines() if line.startswith(f"| [{a.id}]"))
    assert "fine \\| with a pipe" in row and "| F3 |" in row
    assert f"- `F3` → `{a.address}`: run is superseded" in index
    assert "1 complete, 1 superseded." in index


def test_index_with_no_runs(tmp_path):
    assert "No runs yet." in runs.write_index(tmp_path / "runs", tmp_path / "c.yaml").read_text()


def test_index_links_the_report_when_there_is_one(exp, reg):
    run = _complete(exp, reg)
    (run.path / "report.md").write_text("# report\n")
    assert f"]({run.address}/report.md)" in runs.write_index(reg["runs_dir"], reg["canonical"]).read_text()


# ── prune ────────────────────────────────────────────────────────────────────
def test_prune_asks_and_never_deletes_a_pinned_run(exp, reg, capsys):
    a, b, c = _complete(exp, reg), _complete(exp, reg), _complete(exp, reg)
    runs.mark_canonical(b.id, "T1", runs_dir=reg["runs_dir"], canonical_file=reg["canonical"])
    runs.supersede(a.id, c.id, reg["runs_dir"], reg["canonical"])
    runs.supersede(b.id, c.id, reg["runs_dir"], reg["canonical"])     # pin left behind
    kw = {"runs_dir": reg["runs_dir"], "canonical_file": reg["canonical"]}
    assert runs.prune(**kw, confirm=lambda _: "n") == 0 and a.path.is_dir()
    out = capsys.readouterr().out
    assert f"{a.path} · delete · superseded by {c.address}" in out
    assert f"keep {b.address}: superseded but pinned as T1" in out
    assert runs.prune(**kw, confirm=lambda _: "y") == 1
    assert not a.path.exists() and b.path.is_dir() and c.path.is_dir()
    assert runs.prune(**kw, yes=True) == 0


# ── CLI ──────────────────────────────────────────────────────────────────────
@pytest.mark.parametrize("argv,func,expected", [
    (["runs", "index"], "_runs_index", {}),
    (["runs", "mark-canonical", "X1-evidence/r", "--as", "F3"], "_runs_mark_canonical",
     {"run": "X1-evidence/r", "key": "F3", "note": None}),
    (["runs", "supersede", "a", "--by", "b"], "_runs_supersede", {"run": "a", "by": "b"}),
    (["runs", "prune"], "_runs_prune", {"yes": False}),
])
def test_cli_parses_runs_commands(argv, func, expected):
    args = cli.build_parser().parse_args(argv)
    assert args.func.__name__ == func
    assert {k: getattr(args, k) for k in expected} == expected


def test_cli_runs_errors_are_messages_not_tracebacks(capsys):
    assert cli.main(["runs", "mark-canonical", "X1-evidence/nope", "--as", "F3"]) == 1
    assert "no run X1-evidence/nope" in capsys.readouterr().out
    assert cli.main(["runs", "index"]) == 0
