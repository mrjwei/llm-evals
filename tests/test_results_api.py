"""The Results page's API (Plan P6.7): every run with its pins, one run's
facts and conditions, its report.md files as text and its charts. Read-only,
and confined to report.md and .png files inside the run's own folder."""

import pytest
from fastapi.testclient import TestClient

from cjp import config, runs
from web.api import app as webapp

SPEC = {"id": "X1", "slug": "evidence", "question": "How does evidence change correctness?",
        "rq": ["RQ1", "RQ2"], "corpus": "C1", "reps": 1,
        "conditions": ["S1-plain__L0-alert__FA__sonnet", "S1-plain__L1-alert+body__FA__sonnet"]}
PNG = b"\x89PNG\r\n\x1a\n" + b"\0" * 16


@pytest.fixture
def reg(tmp_path, monkeypatch):
    runs_dir, canonical = tmp_path / "runs", tmp_path / "results" / "canonical.yaml"
    monkeypatch.setattr(config, "RUNS_DIR", runs_dir)
    monkeypatch.setattr(config, "CANONICAL_FILE", canonical)
    kw = {"runs_dir": runs_dir, "corpus_dir": tmp_path / "corpus"}
    x1 = runs.new_run(runs.experiment_from_dict(SPEC), **kw)
    x1.finish("S1-plain__L0-alert: selective 74.0%")
    cond = x1.path / "conditions" / SPEC["conditions"][1]
    (cond / "charts").mkdir(parents=True)
    (cond / "charts" / "calibration.png").write_bytes(PNG)
    (cond / "report.md").write_text("# cond\n\n![Calibration](charts/calibration.png)\n\n[Run](../../report.md)\n")
    (cond / "scores.jsonl").write_text('{"truth_label": "sql_injection"}\n')
    (x1.path / "report.md").write_text(f"# X1\n\n| a | b |\n|---|---|\n| 1 | 2 |\n\n[c](conditions/{SPEC['conditions'][1]}/report.md)\n")
    x2 = runs.new_run(runs.experiment_from_dict({**SPEC, "id": "X2", "slug": "format", "rq": ["RQ2"]}), **kw)
    x2.fail("boom")
    runs.mark_canonical(x1.address, runs_dir=runs_dir, canonical_file=canonical)
    return {"x1": x1, "x2": x2, "cond": cond}


@pytest.fixture
def client(reg, tmp_path):
    return TestClient(webapp.create_app(ui_dist=tmp_path / "dist"), base_url="http://127.0.0.1")


def test_lists_every_run_with_pins_and_filters(client, reg):
    body = client.get("/api/runs").json()
    assert [r["experiment"] for r in body["runs"]] == ["X2", "X1"]          # newest first
    x1 = next(r for r in body["runs"] if r["experiment"] == "X1")
    assert x1["address"] == reg["x1"].address and x1["canonical"] == ["X1"] and x1["status"] == "complete"
    assert x1["headline"] == "S1-plain__L0-alert: selective 74.0%" and x1["has_report"] and x1["corpus"] == "C1"
    x2 = next(r for r in body["runs"] if r["experiment"] == "X2")
    assert x2["status"] == "failed" and x2["error"] == "boom" and x2["canonical"] == []
    assert body["experiments"] == ["X1", "X2"] and body["rqs"] == ["RQ1", "RQ2"]
    assert body["pin_problems"] == []


def test_one_run_and_its_reports(client, reg):
    addr = reg["x1"].address
    run = client.get(f"/api/runs/{addr}").json()
    assert run["question"] == SPEC["question"]
    assert run["conditions"] == [{"id": SPEC["conditions"][0], "has_report": False},
                                 {"id": SPEC["conditions"][1], "has_report": True}]
    top = client.get(f"/api/runs/{addr}/report").json()
    assert top["doc"] == "report.md" and top["markdown"].startswith("# X1")
    doc = f"conditions/{SPEC['conditions'][1]}/report.md"
    assert client.get(f"/api/runs/{addr}/report", params={"doc": doc}).json()["doc"] == doc
    png = client.get(f"/api/runs/{addr}/files/conditions/{SPEC['conditions'][1]}/charts/calibration.png")
    assert png.status_code == 200 and png.headers["content-type"] == "image/png" and png.content == PNG


@pytest.mark.parametrize("doc", ["run.json", f"conditions/{SPEC['conditions'][1]}/scores.jsonl",
                                 "../../../../etc/passwd", "../X2-format/report.md", "/etc/report.md",
                                 f"conditions/{SPEC['conditions'][0]}/report.md"])
def test_only_report_md_inside_the_run(client, reg, doc):
    assert client.get(f"/api/runs/{reg['x1'].address}/report", params={"doc": doc}).status_code == 404


@pytest.mark.parametrize("rel", ["run.json", "report.md", f"conditions/{SPEC['conditions'][1]}/scores.jsonl",
                                 "..%2F..%2Fx.png", "nope.png"])
def test_only_pngs_inside_the_run(client, reg, rel):
    assert client.get(f"/api/runs/{reg['x1'].address}/files/{rel}").status_code == 404


@pytest.mark.parametrize("addr", ["X1-evidence/nope", "x1/2026-10-04T0851_c60a81", "X9-none/2026-10-04T0851_c60a81",
                                  "..%2F..%2Fetc/2026-10-04T0851_c60a81"])
def test_unknown_or_malformed_run(client, addr):
    assert client.get(f"/api/runs/{addr}").status_code == 404


def test_results_api_is_read_only(client, reg):
    assert client.post("/api/runs", headers={"X-CJP-Request": "1"}).status_code == 405
