"""Triage jobs (Plan P6.2): the three sources, ground truth left behind, the
same request (so the same cache entry) as the experiments, an estimate before
any call, the approved-calls guard, progress, actual cost, stop, failure,
resume and interruption, and the `/api/triage` routes. A fake Claude client;
no network."""

import json
import shutil
import subprocess
import sys
import time

import anthropic
import pytest
from conftest import FIXTURE_SESSION, read_jsonl
from fastapi.testclient import TestClient

from cjp import config, corpus, indexer, triage_jobs, vm
from cjp.triage import batch
from cjp.triage.client import cache_key_for
from cjp.triage.prompt import extract_cid
from web.api import app as webapp

S1_ALERTS, S3_ALERTS = 6, 2        # alerts in the fixture session's S1 and S3 files
DEMO_S3 = {"kind": "demo", "arm": "S3-body-field"}


@pytest.fixture(autouse=True)
def dirs(tmp_path, monkeypatch):
    """A C1 corpus of the fixture session, and an empty jobs directory."""
    src = tmp_path / "sessions" / FIXTURE_SESSION.name
    shutil.copytree(FIXTURE_SESSION, src)
    corpus.freeze("C1", [str(src)], corpus_dir=tmp_path / "corpus")
    monkeypatch.setattr(config, "CORPUS_DIR", tmp_path / "corpus")
    monkeypatch.setattr(config, "TRIAGE_JOBS_DIR", tmp_path / "jobs")
    yield tmp_path
    triage_jobs._active.clear()


def job_path(meta):
    return config.TRIAGE_JOBS_DIR / meta["id"]


def create(source=None, **kwargs):
    kwargs.setdefault("formats", ["A"])         # one format keeps the counts simple
    return triage_jobs.create(source or {"kind": "demo"}, count=False, **kwargs)


def test_both_formats_by_default():
    meta = triage_jobs.create({"kind": "demo"}, count=False)
    assert meta["options"]["formats"] == ["A", "B"] and meta["estimate"]["calls"] == 2 * S1_ALERTS


# ── sources ──────────────────────────────────────────────────────────────────
def test_demo_leaves_ground_truth_behind_and_keeps_the_request(fake_claude):
    meta = create(DEMO_S3, formats=["A", "B"])
    path = job_path(meta)
    assert sorted(p.name for p in path.iterdir()) == ["alerts.jsonl", "bodies.jsonl", "job.json"]
    stored = (path / "alerts.jsonl").read_text() + (path / "bodies.jsonl").read_text()
    assert "wp1-" not in stored and "benign" not in stored         # CIDs redacted, incl. data.cid
    assert meta["source"] == {"kind": "demo", "corpus": "C1", "session": FIXTURE_SESSION.name,
                              "arm": "S3-body-field"}
    assert meta["alerts"] == S3_ALERTS and meta["bodies_matched"] == 1
    assert meta["status"] == "planned" and fake_claude.calls == []  # nothing called yet

    # the stored inputs make the very request the experiments send
    originals = batch.load_alerts_from_session(str(FIXTURE_SESSION), "body_field_wazuh_alerts.jsonl")
    ingest = batch.load_ingest_log(str(FIXTURE_SESSION))
    expected = {cache_key_for(a, ingest.get(extract_cid(a["full_log"])), 1, f, "sonnet")
                for a in originals for f in "AB"}
    alerts, bodies = triage_jobs._inputs(path)
    items = triage_jobs._plan(alerts, bodies, ["A", "B"], "sonnet")
    assert {i.key for i in items} == expected


def test_bodies_off_stores_none():
    meta = create(DEMO_S3, bodies=False)
    assert not (job_path(meta) / "bodies.jsonl").exists() and meta["bodies_matched"] == 0


def test_bad_sources_say_what_is_wrong():
    with pytest.raises(ValueError, match="no session"):
        create({"kind": "demo", "session": "session_x"})
    with pytest.raises(ValueError, match="arm"):
        create({"kind": "demo", "arm": "S9"})
    with pytest.raises(ValueError, match="takes"):
        create({"kind": "demo", "minutes": 5})
    with pytest.raises(ValueError, match="kind"):
        create({"kind": "sql"})
    with pytest.raises(ValueError, match="formats"):
        create(formats=["C"])
    with pytest.raises(ValueError, match="model"):
        create(model="gpt")
    assert not config.TRIAGE_JOBS_DIR.exists()                    # no job left behind


def test_upload_parses_names_ids_and_bodies():
    alert = json.loads((FIXTURE_SESSION / "body_field_wazuh_alerts.jsonl").read_text().splitlines()[0])
    no_id = {k: v for k, v in alert.items() if k != "id"}
    content = "\n".join(json.dumps(a) for a in (alert, alert, no_id)) + "\n\n"
    meta = create({"kind": "upload", "content": content, "filename": "../../etc/alerts.jsonl",
                   "ingest_log": (FIXTURE_SESSION / "ingest_log.jsonl").read_text()})
    assert meta["source"]["filename"] == "alerts.jsonl" and meta["source"]["ingest_log"]
    assert [a["id"] for a in read_jsonl(job_path(meta) / "alerts.jsonl")] == [alert["id"], "line-3"]
    assert meta["warnings"] == ["dropped 1 alert(s) whose ID repeats an earlier one"]
    assert meta["bodies_matched"] == 2

    with pytest.raises(ValueError, match=r"line\(s\) 2, 3 are not valid"):
        create({"kind": "upload", "content": json.dumps(alert) + "\nnot json\n[1]\n"})
    with pytest.raises(LookupError, match="no alerts"):
        create({"kind": "upload", "content": "\n"})


def test_live_window_rules():
    from datetime import datetime, timezone
    now = datetime(2026, 10, 4, 12, 0, tzinfo=timezone.utc)
    assert triage_jobs.live_window(30, now=now)[0] == datetime(2026, 10, 4, 11, 30, tzinfo=timezone.utc)
    t0, t1 = triage_jobs.live_window(start="2026-10-04T10:00:00+10:00", now=now)
    assert t0.hour == 0 and t1 == now
    for kwargs, words in (({"minutes": 0}, "minutes"), ({"minutes": 5, "start": "x"}, "not both"),
                          ({}, "needs minutes"), ({"start": "2026-10-04T10:00"}, "time zone"),
                          ({"start": "2026-10-04T10:00Z", "end": "2026-10-04T09:00Z"}, "after start")):
        with pytest.raises(ValueError, match=words):
            triage_jobs.live_window(**kwargs, now=now)


def test_live_queries_the_window_and_reads_bodies_from_the_vm(monkeypatch):
    alerts = read_jsonl(FIXTURE_SESSION / "body_field_wazuh_alerts.jsonl")
    asked, commands = {}, []
    monkeypatch.setattr(indexer, "get_alerts_since", lambda *a, **k: asked.update(args=a, **k) or alerts)
    entry = (FIXTURE_SESSION / "ingest_log.jsonl").read_text().strip()
    monkeypatch.setattr(vm, "ssh_run", lambda cmd, timeout=10: commands.append(cmd) or entry)
    meta = create({"kind": "live", "minutes": 15, "arm": "S3-body-field", "agent": "001", "limit": 2})
    assert asked["location_pattern"] == config.BODY_FIELD_JUICE_LOG_PATH
    assert asked["agent"] == "001" and asked["limit"] == 2
    assert meta["bodies_matched"] == 1 and meta["source"]["kind"] == "live"
    assert "holds at least 2 alerts" in meta["warnings"][0]
    assert "'\"wp1-20990101_000000-3-1\"'" in commands[0]          # each CID quoted, exact match
    assert "wp1-" not in (job_path(meta) / "bodies.jsonl").read_text()

    monkeypatch.setattr(vm, "ssh_run", lambda cmd, timeout=10: None)
    meta = create({"kind": "live", "minutes": 15, "arm": "S3-body-field"})
    assert meta["bodies_matched"] == 0 and "could not read" in meta["warnings"][-2]
    with pytest.raises(ValueError, match="agent"):
        create({"kind": "live", "minutes": 5, "agent": "x; rm -rf /"})
    monkeypatch.setattr(indexer, "get_alerts_since", lambda *a, **k: [])
    with pytest.raises(LookupError, match="no S1-plain alerts"):
        create({"kind": "live", "minutes": 5})


def test_indexer_agent_filter_only_when_asked(monkeypatch):
    sent = []

    class Reply:
        def raise_for_status(self):
            pass

        def json(self):
            return {"hits": {"hits": [], "total": {"value": 0}}}
    monkeypatch.setattr(indexer.httpx, "post", lambda url, json, **k: sent.append(json) or Reply())
    indexer.get_alerts_since("a", "b")
    indexer.get_alerts_since("a", "b", agent="001")
    assert len(sent[0]["query"]["bool"]["must"]) == 3
    assert sent[1]["query"]["bool"]["must"][3]["bool"]["should"][0] == {"term": {"agent.id": "001"}}


# ── running ──────────────────────────────────────────────────────────────────
def test_estimate_then_run_then_a_second_job_is_free(fake_claude):
    meta = create(formats=["A", "B"])
    est = meta["estimate"]
    assert est["calls"] == 2 * S1_ALERTS and est["cached"] == 0 and est["cost_max_usd"] > 0
    assert set(est["by_format"]) == {"A", "B"}

    done = triage_jobs.run(meta["id"], max_calls=est["calls"])
    assert done["status"] == "complete" and done["error"] is None
    assert done["progress"] == {"total": 2 * S1_ALERTS, "answered": 2 * S1_ALERTS}
    a = done["actual"]
    assert (a["calls"], a["cache_hits"], a["input_tokens"], a["output_tokens"]) == \
        (2 * S1_ALERTS, 0, 100 * 2 * S1_ALERTS, 20 * 2 * S1_ALERTS)
    assert a["cost_usd"] == pytest.approx(2 * S1_ALERTS * (100 * 2.0 + 20 * 10.0) / 1e6)
    rows = read_jsonl(job_path(meta) / "verdicts_B.jsonl")
    assert len(rows) == S1_ALERTS and {r["format"] for r in rows} == {"B"}

    again = create(formats=["A", "B"])
    assert again["estimate"]["calls"] == 0 and again["estimate"]["cost_max_usd"] == 0
    calls = len(fake_claude.calls)
    done = triage_jobs.run(again["id"], max_calls=0)
    assert len(fake_claude.calls) == calls
    assert done["actual"]["calls"] == 0 and done["actual"]["cost_usd"] == 0
    assert done["actual"]["answers_cost_usd"] == pytest.approx(a["cost_usd"])


def test_no_more_calls_than_approved_and_one_job_at_a_time(fake_claude):
    meta = create()
    with pytest.raises(triage_jobs.JobConflict, match="needs 6 paid call"):
        triage_jobs.start(meta["id"], max_calls=5)
    assert triage_jobs.load(meta["id"])["status"] == "planned" and fake_claude.calls == []

    other = create()
    batch_ = triage_jobs.start(meta["id"], max_calls=6)
    with pytest.raises(triage_jobs.JobConflict, match="is running"):
        triage_jobs.start(other["id"], max_calls=6)
    with pytest.raises(triage_jobs.JobConflict, match="running"):
        triage_jobs.start(meta["id"], max_calls=6)
    triage_jobs.execute(batch_)
    with pytest.raises(triage_jobs.JobConflict, match="is complete"):
        triage_jobs.start(meta["id"], max_calls=6)


def _auth_error():
    import httpx2
    req = httpx2.Request("POST", "https://api.anthropic.com/v1/messages")
    return anthropic.AuthenticationError("bad key", response=httpx2.Response(401, request=req), body=None)


def test_a_fatal_error_fails_the_job_and_starting_again_resumes(fake_claude, monkeypatch):
    from cjp.triage import client
    real, state = client.analyse_alert, {"n": 0, "fail": True}

    def flaky(alert, **kwargs):
        state["n"] += 1
        if state["fail"] and state["n"] == 3:
            raise _auth_error()
        return real(alert, **kwargs)
    monkeypatch.setattr(client, "analyse_alert", flaky)
    meta = create()
    done = triage_jobs.run(meta["id"], max_calls=6)
    assert done["status"] == "failed" and "ANTHROPIC_API_KEY" in done["error"]
    assert done["progress"]["answered"] == 2 and done["actual"]["failed_calls"] == 1

    assert triage_jobs.reestimate(meta["id"], count=False)["estimate"]["calls"] == 4
    state["fail"] = False
    done = triage_jobs.run(meta["id"], max_calls=4)
    assert done["status"] == "complete" and done["error"] is None
    assert len(fake_claude.calls) == S1_ALERTS                     # the 2 answered were not re-asked
    assert len(batch.load_completed_ids(str(job_path(meta) / "verdicts_A.jsonl"))) == S1_ALERTS


def test_stop_after_the_call_in_flight_then_resume(fake_claude, monkeypatch):
    from cjp.triage import client
    real = client.analyse_alert
    meta = create()
    batch_ = triage_jobs.start(meta["id"], max_calls=6)

    def stop_after_two(alert, **kwargs):
        if len(fake_claude.calls) == 1:
            triage_jobs.stop(meta["id"])
        return real(alert, **kwargs)
    monkeypatch.setattr(client, "analyse_alert", stop_after_two)
    done = triage_jobs.execute(batch_)
    assert done["status"] == "stopped" and done["progress"]["answered"] == 2
    with pytest.raises(triage_jobs.JobConflict, match="not running"):
        triage_jobs.stop(meta["id"])
    assert triage_jobs.run(meta["id"], max_calls=4)["status"] == "complete"
    assert len(fake_claude.calls) == S1_ALERTS


def test_a_job_whose_process_died_reads_as_interrupted(fake_claude):
    """Another process runs the job while it holds the lock; once it dies,
    however it dies, the job reads as interrupted and can be resumed."""
    meta = create()
    path = job_path(meta)
    raw = json.loads((path / "job.json").read_text())
    (path / "job.json").write_text(json.dumps({**raw, "status": "running"}))
    holder = subprocess.Popen([sys.executable, "-c",
                               "import fcntl, sys, time; f = open(sys.argv[1], 'w'); "
                               "fcntl.flock(f, fcntl.LOCK_EX); print('locked', flush=True); time.sleep(60)",
                               str(path / ".lock")], stdout=subprocess.PIPE, text=True)
    try:
        assert holder.stdout.readline().strip() == "locked"
        assert triage_jobs.load(meta["id"])["status"] == "running"
        with pytest.raises(triage_jobs.JobConflict, match="is running"):
            triage_jobs.start(meta["id"], max_calls=6)
    finally:
        holder.kill()
        holder.wait()
    assert triage_jobs.load(meta["id"])["status"] == "interrupted"
    assert triage_jobs.list_jobs()[0]["status"] == "interrupted"
    done = triage_jobs.run(meta["id"], max_calls=6)
    assert done["status"] == "complete" and done["starts"][0]["approved_calls"] == 6


def test_job_ids_never_name_a_path():
    for bad in ("../../etc", "2026-10-04T0000_zzzzzz", "", "2026-10-04T0000_abcdef/../x"):
        with pytest.raises(triage_jobs.JobNotFound):
            triage_jobs.load(bad)


# ── API ──────────────────────────────────────────────────────────────────────
@pytest.fixture
def api(tmp_path):
    return TestClient(webapp.create_app(ui_dist=tmp_path / "dist"), base_url="http://127.0.0.1",
                      headers={webapp.REQUEST_HEADER: "1"})


def test_api_create_start_poll_and_list(api, fake_claude):
    sources = api.get("/api/triage/sources").json()
    assert sources["demo"]["corpora"][0]["id"] == "C1" and sources["formats"] == ["A", "B"]

    r = api.post("/api/triage/jobs", json={"source": {"kind": "demo"}})
    assert r.status_code == 201, r.text
    job = r.json()
    assert job["status"] == "planned" and fake_claude.calls == []
    assert job["options"]["formats"] == ["A", "B"]

    assert api.post(f"/api/triage/jobs/{job['id']}/start", json={"max_calls": 0}).status_code == 409
    r = api.post(f"/api/triage/jobs/{job['id']}/start", json={"max_calls": job["estimate"]["calls"]})
    assert r.status_code == 202
    for _ in range(100):
        job = api.get(f"/api/triage/jobs/{job['id']}").json()
        if job["status"] != "running":
            break
        time.sleep(0.05)
    assert job["status"] == "complete" and job["actual"]["calls"] == 2 * S1_ALERTS
    assert [j["id"] for j in api.get("/api/triage/jobs").json()] == [job["id"]]


def test_api_errors_and_the_guard(api, fake_claude):
    assert api.get("/api/triage/jobs/2026-01-01T0000_abcdef").status_code == 404
    assert api.post("/api/triage/jobs/2026-01-01T0000_abcdef/stop").status_code == 404
    r = api.post("/api/triage/jobs", json={"source": {"kind": "demo", "session": "nope"}})
    assert r.status_code == 400 and "no session" in r.json()["detail"]
    assert api.post("/api/triage/jobs", json={"source": {"kind": "ftp"}}).status_code == 422
    assert api.post("/api/triage/jobs", json={"source": {"kind": "demo"}, "formats": ["C"]}
                    ).status_code == 422
    unguarded = TestClient(api.app, base_url="http://127.0.0.1")
    assert unguarded.post("/api/triage/jobs", json={"source": {"kind": "demo"}}).status_code == 403
    assert not config.TRIAGE_JOBS_DIR.exists()


def test_api_live_with_the_tunnel_down_says_how_to_fix_it(api):
    r = api.post("/api/triage/jobs", json={"source": {"kind": "live", "minutes": 5}})
    assert r.status_code == 502 and "tunnel" in r.json()["detail"]
