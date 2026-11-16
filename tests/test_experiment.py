"""Corpora and `cjp experiment` (Plan §2.3, P3.5, P5): condition IDs, freezing
and verifying a corpus, the plan and estimate, and whole runs over a corpus
with a fake Claude client: cache reuse across sessions and repeats, the
question before paid calls, resume after a failure, and failed calls that
keep a run from completing."""

import json
import os
import shutil
import stat

import anthropic
import pytest
import yaml
from conftest import FIXTURE_SESSION, read_jsonl

from cjp import cli, corpus, experiment, runs
from cjp.triage import batch

S1_L0 = "S1-plain__L0-alert__FA__sonnet"
S3_L1 = "S3-body-field__L1-alert+body__FB__sonnet"
S1_ALERTS, S3_ALERTS = 6, 2        # alerts in the fixture session's S1 and S3 files


# ── condition IDs ────────────────────────────────────────────────────────────
def test_parse_condition():
    c = experiment.parse_condition(S3_L1)
    assert (c.arm, c.alerts_file, c.with_body, c.fmt, c.model) == \
        ("S3-body-field", "body_field_wazuh_alerts.jsonl", True, "B", "sonnet")
    assert experiment.parse_condition("S2-body-in-url", "siem").alerts_file == "enriched_wazuh_alerts.jsonl"


@pytest.mark.parametrize("cid, words", [
    ("S1-plain__L0-alert__FA", "expected <SIEM>"),
    ("S4-x__L0-alert__FA__sonnet", "SIEM evidence 'S4-x'"),
    ("S1-plain__L2-all__FA__sonnet", "LLM evidence"),
    ("S1-plain__L0-alert__FC__sonnet", "format"),
    ("S1-plain__L0-alert__FA__opus", "model 'opus'"),
])
def test_bad_condition_ids_say_which_part(cid, words):
    with pytest.raises(ValueError, match=words):
        experiment.parse_condition(cid)


def test_short_ids_drop_the_shared_parts():
    conds = [experiment.parse_condition(c) for c in
             (S1_L0, "S1-plain__L1-alert+body__FA__sonnet", "S2-body-in-url__L0-alert__FA__sonnet")]
    assert list(experiment.short_ids(conds).values()) == \
        ["S1-plain__L0-alert", "S1-plain__L1-alert+body", "S2-body-in-url__L0-alert"]


def test_the_preregistered_experiment_files_load():
    """Plan P4: every experiment in the §1.3 registry that runs from a YAML is
    frozen (no draft flag) and loads."""
    paths = sorted(p.stem for p in experiment.EXPERIMENTS_DIR.glob("*.yaml"))
    assert paths == ["D1", "X0", "X1", "X2", "X3", "X4"]
    for ref in paths:
        exp, kind, conditions = experiment.load(ref)
        assert "draft" not in exp.spec and conditions and exp.corpus in ("C1", "C1-inj")
    assert experiment.load("X4")[0].corpus == "C1-inj"


def test_baseline_conditions_parse():
    c = experiment.parse_condition("S3-body-field__B-rule", "baseline")
    assert (c.alerts_file, c.baseline, c.model) == ("body_field_wazuh_alerts.jsonl", "B-rule", None)
    with pytest.raises(ValueError, match="baseline one of"):
        experiment.parse_condition("S1-plain__B-lookup", "baseline")
    # running one: tests/test_p5_analysis.py


# ── corpus ───────────────────────────────────────────────────────────────────
@pytest.fixture
def sessions(tmp_path):
    """Two sessions: copies of the fixture under different names."""
    out = []
    for name in ("session_20990101_000000", "session_20990102_000000"):
        dst = tmp_path / "sessions" / name
        shutil.copytree(FIXTURE_SESSION, dst)
        out.append(dst)
    return out


@pytest.fixture
def corpus_dir(tmp_path, sessions):
    d = tmp_path / "corpus"
    corpus.freeze("C1", [str(s) for s in sessions], note="test", corpus_dir=d)
    return d


def _make_writable(path):
    for p in path.rglob("*"):
        if p.is_file():
            p.chmod(p.stat().st_mode | stat.S_IWUSR)


def test_freeze_copies_checksums_and_locks(corpus_dir):
    c = corpus.load("C1", corpus_dir)
    assert [s.name for s in c.sessions] == ["session_20990101_000000", "session_20990102_000000"]
    assert corpus.verify(c) == []
    files = c.meta["sessions"][0]["files"]
    assert "wazuh_alerts.jsonl" in files and len(files[next(iter(files))]) == 64
    copy = c.sessions[0] / "wazuh_alerts.jsonl"
    assert not os.access(copy, os.W_OK)
    # the fixture has no manifest, so freezing warns instead of failing silently
    assert any("no manifest.json" in w for w in c.meta["warnings"])


def test_verify_finds_changed_missing_and_added_files(corpus_dir):
    c = corpus.load("C1", corpus_dir)
    _make_writable(c.path)
    (c.sessions[0] / "wazuh_alerts.jsonl").write_text("{}\n")
    (c.sessions[1] / "access.log").unlink()
    (c.sessions[1] / "extra.txt").write_text("x")
    problems = corpus.verify(c)
    assert any("wazuh_alerts.jsonl: changed" in p for p in problems)
    assert any("access.log: missing" in p for p in problems)
    assert any("extra.txt: added" in p for p in problems)


def test_a_corpus_is_never_overwritten(corpus_dir, sessions):
    with pytest.raises(FileExistsError, match="never overwritten"):
        corpus.freeze("C1", [str(sessions[0])], corpus_dir=corpus_dir)
    with pytest.raises(ValueError, match="must look like C1"):
        corpus.freeze("corpus1", [str(sessions[0])], corpus_dir=corpus_dir)
    (corpus_dir / ".C2.partial").mkdir()
    with pytest.raises(FileExistsError, match="interrupted freeze"):
        corpus.freeze("C2", [str(sessions[0])], corpus_dir=corpus_dir)


# ── runs over a corpus ───────────────────────────────────────────────────────
def _experiment(tmp_path, conditions, reps=2, kind=None, eid="X9"):
    d = tmp_path / "experiments"
    d.mkdir(exist_ok=True)
    spec = {"id": eid, "slug": "test", "question": "Does it work?", "rq": "RQ1",
            "corpus": "C1", "reps": reps, "conditions": conditions}
    if kind:
        spec["kind"] = kind
    (d / f"{eid}.yaml").write_text(yaml.safe_dump(spec))
    return d


def _run(tmp_path, corpus_dir, exp_dir, **kwargs):
    kwargs.setdefault("yes", True)
    kwargs.setdefault("count", False)
    return experiment.run("X9", experiments_dir=exp_dir, runs_dir=tmp_path / "runs",
                          corpus_dir=corpus_dir, **kwargs)


def test_a_whole_run(fake_claude, tmp_path, corpus_dir, capsys):
    exp_dir = _experiment(tmp_path, [S1_L0, S3_L1])
    assert _run(tmp_path, corpus_dir, exp_dir) == 0
    (r,) = runs.list_runs(tmp_path / "runs")
    assert r.status == "complete" and "selective" in r.meta["headline"]
    # the two sessions are copies, so session 2 replays session 1's answers:
    # one paid call per alert and repeat, the rest from the cache
    assert len(fake_claude.calls) == (S1_ALERTS + S3_ALERTS) * 2
    assert r.meta["cache"]["cache_hits"] == (S1_ALERTS + S3_ALERTS) * 2
    assert r.meta["settings"]["models"]["sonnet"]["id"] == "claude-sonnet-5-5"
    assert set(r.meta["prompts"]) == {"A", "B"} and r.meta["corpus"]["sha256"]

    cond = r.path / "conditions" / S3_L1
    for rep in (1, 2):
        for s in r.meta["corpus_sessions"]:
            rows = read_jsonl(cond / f"rep{rep}" / s / "verdicts.jsonl")
            assert len(rows) == S3_ALERTS and {x["repeat"] for x in rows} == {rep}
            assert {x["format"] for x in rows} == {"B"}
            assert (cond / f"rep{rep}" / s / "mapped.jsonl").is_file()
    metrics = json.loads((cond / "metrics.json").read_text())
    assert metrics["triage"]["repeats"] == [1, 2] and set(metrics["sessions"]) == set(r.meta["corpus_sessions"])
    assert {row["session"] for row in read_jsonl(cond / "scores.jsonl")} == set(r.meta["corpus_sessions"])
    report = (r.path / "report.md").read_text()
    assert f"conditions/{S1_L0}/report.md" in report and "Selective accuracy" in report
    assert "S1-plain__L0-alert" in (tmp_path / "runs" / "INDEX.md").read_text() or r.id in \
        (tmp_path / "runs" / "INDEX.md").read_text()

    # a second run from the cache alone costs nothing and gives the same numbers
    assert _run(tmp_path, corpus_dir, exp_dir, cache_mode="only") == 0
    assert len(fake_claude.calls) == (S1_ALERTS + S3_ALERTS) * 2
    first, second = runs.list_runs(tmp_path / "runs")
    assert first.meta["headline"] == second.meta["headline"]
    assert first.meta["config_hash"] != second.meta["config_hash"]      # cache mode is an input


def test_l0_sends_no_bodies_and_l1_does(fake_claude, tmp_path, corpus_dir):
    exp_dir = _experiment(tmp_path, ["S3-body-field__L0-alert__FA__sonnet",
                                     "S3-body-field__L1-alert+body__FA__sonnet"], reps=1)
    assert _run(tmp_path, corpus_dir, exp_dir) == 0
    contents = [c["messages"][0]["content"] for c in fake_claude.calls]
    assert sum("request_body" in c for c in contents) == 1   # one S3 alert has an ingest entry


def test_dry_run_and_a_no_spend_nothing(fake_claude, tmp_path, corpus_dir, capsys):
    exp_dir = _experiment(tmp_path, [S1_L0])
    assert _run(tmp_path, corpus_dir, exp_dir, dry_run=True) == 0
    out = capsys.readouterr().out
    assert "to call" in out and "cost ≤" in out and "nothing spent" in out
    assert not (tmp_path / "runs").exists() and fake_claude.calls == []

    assert _run(tmp_path, corpus_dir, exp_dir, yes=False, confirm=lambda q: "n") == 1
    assert fake_claude.calls == [] and runs.list_runs(tmp_path / "runs") == []

    assert _run(tmp_path, corpus_dir, exp_dir, cache_mode="only") == 1
    assert "no cached answer" in capsys.readouterr().out and fake_claude.calls == []


def test_the_question_names_calls_and_cost(fake_claude, tmp_path, corpus_dir):
    asked = []
    exp_dir = _experiment(tmp_path, [S1_L0], reps=1)
    _run(tmp_path, corpus_dir, exp_dir, yes=False, confirm=lambda q: asked.append(q) or "y")
    assert asked and f"{S1_ALERTS} paid API call(s), at most $" in asked[0]


def test_a_tampered_corpus_is_refused(fake_claude, tmp_path, corpus_dir, capsys):
    c = corpus.load("C1", corpus_dir)
    _make_writable(c.path)
    (c.sessions[0] / "wazuh_alerts.jsonl").write_text("{}\n")
    assert _run(tmp_path, corpus_dir, _experiment(tmp_path, [S1_L0])) == 1
    assert "no longer matches its checksums" in capsys.readouterr().out and fake_claude.calls == []


def test_resume_after_a_fatal_error(fake_claude, monkeypatch, tmp_path, corpus_dir, capsys):
    from cjp.triage import client
    real = client.analyse_alert
    state = {"n": 0, "fail": True}

    def flaky(alert, **kwargs):
        state["n"] += 1
        if state["fail"] and state["n"] == 4:
            import httpx2
            req = httpx2.Request("POST", "https://api.anthropic.com/v1/messages")
            raise anthropic.AuthenticationError("bad key", response=httpx2.Response(401, request=req),
                                                body=None)
        return real(alert, **kwargs)
    monkeypatch.setattr(batch, "analyse_alert", flaky)
    exp_dir = _experiment(tmp_path, [S1_L0], reps=1)
    assert _run(tmp_path, corpus_dir, exp_dir) == 1
    (r,) = runs.list_runs(tmp_path / "runs")
    assert r.status == "failed" and f"--resume {r.address}" in r.meta["error"]

    state["fail"] = False
    calls_before = len(fake_claude.calls)
    assert _run(tmp_path, corpus_dir, exp_dir, resume=r.address) == 0
    r = runs.find_run(r.address, tmp_path / "runs")
    assert r.status == "complete" and len(r.meta["resumes"]) == 1
    # only the alerts without an answer were triaged again (3 answered before the failure)
    assert len(fake_claude.calls) - calls_before == S1_ALERTS - 3
    rows = batch.load_completed_ids(str(experiment.unit_dir(r.path, S1_L0, 1, r.meta["corpus_sessions"][0])
                                        / "verdicts.jsonl"))
    assert len(rows) == S1_ALERTS

    # a resume with other inputs is refused
    assert _run(tmp_path, corpus_dir, exp_dir, resume=r.address, cache_mode="refresh") == 1


def test_failed_calls_keep_the_run_from_completing(fake_claude, monkeypatch, tmp_path, corpus_dir):
    from cjp.triage import client
    real = client.analyse_alert
    state = {"n": 0}

    def one_outage(alert, **kwargs):
        state["n"] += 1
        if state["n"] == 2:
            import httpx2
            raise anthropic.APIConnectionError(
                request=httpx2.Request("POST", "https://api.anthropic.com/v1/messages"))
        return real(alert, **kwargs)
    monkeypatch.setattr(batch, "analyse_alert", one_outage)
    exp_dir = _experiment(tmp_path, [S1_L0], reps=1)
    assert _run(tmp_path, corpus_dir, exp_dir) == 1
    (r,) = runs.list_runs(tmp_path / "runs")
    assert r.status == "failed" and "1 alert(s) have no answer" in r.meta["error"]
    summary = r.meta["conditions_summary"][S1_L0]
    assert summary["api_errors"] == 1
    assert _run(tmp_path, corpus_dir, exp_dir, resume=r.id) == 0
    assert runs.find_run(r.id, tmp_path / "runs").meta["conditions_summary"][S1_L0]["api_errors"] == 0


def test_a_siem_experiment_needs_no_llm(fake_claude, tmp_path, corpus_dir):
    exp_dir = _experiment(tmp_path, ["S1-plain", "S3-body-field"], reps=1, kind="siem")
    assert _run(tmp_path, corpus_dir, exp_dir) == 0
    (r,) = runs.list_runs(tmp_path / "runs")
    assert fake_claude.calls == [] and "techniques" in r.meta["headline"]
    assert r.meta["model"] is None and r.meta["prompt_hash"] is None


def test_siem_experiments_have_one_repeat(tmp_path):
    exp_dir = _experiment(tmp_path, ["S1-plain"], reps=3, kind="siem")
    with pytest.raises(ValueError, match="reps must be 1"):
        experiment.load("X9", exp_dir)


def test_status_shows_progress(fake_claude, tmp_path, corpus_dir, capsys):
    exp_dir = _experiment(tmp_path, [S1_L0], reps=1)
    _run(tmp_path, corpus_dir, exp_dir)
    capsys.readouterr()
    (r,) = runs.list_runs(tmp_path / "runs")
    assert experiment.status(r.id, tmp_path / "runs") == 0
    assert f"{S1_L0} rep1: session_20990101_000000 {S1_ALERTS}" in capsys.readouterr().out


@pytest.mark.parametrize("argv, func", [
    (["experiment", "run", "X1", "--dry-run"], "_experiment_run"),
    (["experiment", "list"], "_experiment_list"),
    (["experiment", "status"], "_experiment_status"),
    (["corpus", "freeze", "C1", "--sessions", "a", "b"], "_corpus_freeze"),
    (["corpus", "verify", "C1"], "_corpus_verify"),
])
def test_cli_parses_experiment_and_corpus_commands(argv, func):
    assert cli.build_parser().parse_args(argv).func.__name__ == func


def test_cli_user_errors_are_one_line(capsys):
    assert cli.main(["experiment", "run", "X77"]) == 1
    assert capsys.readouterr().out.startswith("[experiment] no experiment file")
