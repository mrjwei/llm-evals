"""Expert rating (Plan P6.6, METHODS §7): batches in data/ratings/<batch>/,
a per-rater order with the calibration round first, autosaved scores checked
against the rubric, the rubric-change guard, the offline pack (escaped data,
hash-only CSP, no network) and importing its download. Blindness: no route
or pack ever carries key.json."""

import base64
import hashlib
import json
import re

import pytest
from fastapi.testclient import TestClient

from cjp import cli, config, rating
from web.api import app as webapp

SECRET = "GROUND-TRUTH-sql_injection-S1-plain__L1"
HOSTILE = '</script><img src=x onerror=alert(1)><!--  '


def make_items(n=8):
    items = []
    for i in range(n):
        items.append({
            "item": f"it{i:02d}",
            "alert": {"id": f"17909.{i}", "timestamp": "2026-10-02T12:52:12.670+0000",
                      "rule": {"id": "31101", "level": 5, "description": "Web server 400 error code."},
                      "full_log": f'172.19.0.1 - - "GET /rest/basket/{i} HTTP/1.1" 401 {HOSTILE}'},
            "body": {"request_body": "", "response_body": "UnauthorizedError"} if i % 2 else None,
            "answer": {"technique_label": "uncertain", "candidate_labels": ["idor"], "disposition": "needs_more_info",
                       "confidence": "low", "recommended_action": "Check the access log."},
        })
    return items


@pytest.fixture
def root(tmp_path, monkeypatch):
    root = tmp_path / "ratings"
    monkeypatch.setattr(config, "RATINGS_DIR", root)
    rating.create_batch("X5-test", make_items(), key={"it00": {"truth": SECRET}}, calibration=["it03", "it05"])
    return root


@pytest.fixture
def client(root, tmp_path):
    return TestClient(webapp.create_app(ui_dist=tmp_path / "dist"), base_url="http://127.0.0.1")


POST = {"X-CJP-Request": "1"}
FULL = {"R1": 4, "R2": 3, "R3": 5, "R4": 2, "R5": "escalate"}


def rate_all(batch="X5-test", rater="A", ids=None):
    for item_id in ids or rating.Batch(batch).order(rater):
        rating.save(batch, rater, item_id, FULL)


# ── rubric ───────────────────────────────────────────────────────────────────
def test_rubric_anchors_are_the_words_in_the_file():
    rubric = rating.load_rubric()
    r2 = next(i for i in rubric["items"] if i["id"] == "R2")
    assert r2["anchors"] == {"1": "no, needs the raw logs to do anything", "3": "partly",
                             "5": "yes, everything needed is here"}
    assert [o["value"] for o in rubric["items"][4]["options"]] == \
        ["escalate", "dismiss_false_positive", "needs_more_info"]


def test_a_malformed_anchor_is_refused(tmp_path):
    bad = tmp_path / "rubric.yaml"
    bad.write_text(config.RATING_RUBRIC_FILE.read_text().replace(
        "'no, needs the raw logs to do anything'", "no, needs the raw logs to do anything"))
    with pytest.raises(ValueError, match="R2 anchors"):
        rating.load_rubric(bad)


# ── batches ──────────────────────────────────────────────────────────────────
def test_create_batch_refuses_unblind_or_bad_items_and_never_replaces(root):
    bad = make_items(1)[0] | {"condition": "S1-plain__L1-alert+body__FA__sonnet"}
    with pytest.raises(ValueError, match="must not see"):
        rating.create_batch("b1", [bad], key={})
    with pytest.raises(ValueError, match="opaque"):
        rating.create_batch("b2", [make_items(1)[0] | {"item": "a/b"}], key={})
    with pytest.raises(ValueError, match="repeated"):
        rating.create_batch("b3", make_items(1) * 2, key={})
    with pytest.raises(ValueError, match="calibration"):
        rating.create_batch("b4", make_items(2), key={}, calibration=["nope"])
    with pytest.raises(ValueError, match="never replaced"):
        rating.create_batch("X5-test", make_items(2), key={})
    with pytest.raises(ValueError, match="letters"):
        rating.create_batch("../evil", make_items(2), key={})
    meta = json.loads((root / "X5-test" / "batch.json").read_text())
    assert meta["items"] == 8 and meta["calibration"] == ["it03", "it05"]
    assert meta["rubric"]["sha256"] == hashlib.sha256(config.RATING_RUBRIC_FILE.read_bytes()).hexdigest()


def test_order_puts_calibration_first_and_shuffles_the_rest_per_rater(root):
    batch = rating.Batch("X5-test")
    a, b = batch.order("A"), batch.order("B")
    assert a[:2] == b[:2] == ["it03", "it05"]
    assert sorted(a) == sorted(b) == sorted(batch.by_id)
    assert a[2:] != b[2:]                         # each rater has their own order
    assert a == rating.Batch("X5-test").order("A")  # and keeps it


def test_unknown_batch_rater_or_item(root):
    for bad in ("nope", "../X5-test", "X5.test", ""):
        with pytest.raises(rating.RatingNotFound):
            rating.Batch(bad)
    with pytest.raises(rating.RatingNotFound):
        rating.start("X5-test", "C")
    with pytest.raises(rating.RatingNotFound):
        rating.item("X5-test", "it99")
    with pytest.raises(rating.RatingNotFound, match="has not started"):
        rating.session("X5-test", "A")


# ── a rater's session and autosave ───────────────────────────────────────────
def test_start_is_idempotent_and_saves_partial_then_complete_scores(root):
    s = rating.start("X5-test", "A")
    assert s["progress"] == {"complete": 0, "total": 8, "next": 0, "calibration_complete": 0,
                             "started_at": s["progress"]["started_at"], "updated_at": None, "via": "app"}
    first = s["order"][0]
    r = rating.save("X5-test", "A", first, {"R1": 4})
    assert r["record"]["R1"] == 4 and r["progress"]["complete"] == 0
    r = rating.save("X5-test", "A", first, {"R2": 3, "R3": 5, "R4": 2, "R5": "escalate"})
    assert r["record"]["R1"] == 4 and rating.complete(r["record"])
    assert r["progress"]["complete"] == 1 and r["progress"]["next"] == 1
    assert r["progress"]["calibration_complete"] == 1
    again = rating.start("X5-test", "A")
    assert again["order"] == s["order"] and again["ratings"][first]["R5"] == "escalate"
    r = rating.save("X5-test", "A", first, {"R5": None})       # a score can be cleared
    assert r["progress"]["complete"] == 0
    doc = json.loads((root / "X5-test" / "ratings" / "rater-A.json").read_text())
    assert set(doc["ratings"][first]) == {"R1", "R2", "R3", "R4", "R5", "saved_at"}   # scores only


@pytest.mark.parametrize("scores, message", [
    ({"R1": 6}, "1 to 5"), ({"R1": 0}, "1 to 5"), ({"R2": 2.5}, "whole"), ({"R3": True}, "whole"),
    ({"R4": "5"}, "whole"), ({"R5": "ignore"}, "escalate"), ({"R6": 1}, "not a rubric item"),
    ({"note": "x"}, "not a rubric item")])
def test_save_checks_every_score_against_the_rubric(root, scores, message):
    rating.start("X5-test", "B")
    with pytest.raises(ValueError, match=message):
        rating.save("X5-test", "B", "it00", scores)


def test_rubric_may_change_only_during_the_calibration_round(root, tmp_path):
    changed = tmp_path / "rubric.yaml"
    changed.write_text(config.RATING_RUBRIC_FILE.read_text().replace("version: 1", "version: 2")
                       .replace("right but vague", "right but needs detail"))
    rating.start("X5-test", "A")
    rate_all(ids=["it03", "it05"])                       # calibration only
    r = rating.save("X5-test", "A", "it00", {"R1": 2}, rubric_file=changed)
    assert rating.session("X5-test", "A")["rubric"]["version"] == 2
    assert r["record"]["R1"] == 2
    with pytest.raises(rating.RatingConflict, match="outside the calibration round"):
        rating.save("X5-test", "A", "it00", {"R1": 3})   # back to version 1, after it00 was scored


def test_list_batches_shows_each_raters_progress(root):
    rating.start("X5-test", "B")
    rate_all(rater="B", ids=["it03"])
    [b] = rating.list_batches()
    assert b["id"] == "X5-test" and b["items"] == 8 and b["calibration"] == 2
    assert b["raters"]["A"] is None and b["raters"]["B"]["complete"] == 1


# ── API ──────────────────────────────────────────────────────────────────────
def test_api_rates_one_item_and_never_returns_the_key(client):
    assert [i["id"] for i in client.get("/api/rating/rubric").json()["items"]] == ["R1", "R2", "R3", "R4", "R5"]
    assert client.post("/api/rating/batches/X5-test/raters/A").status_code == 403    # guard header
    s = client.post("/api/rating/batches/X5-test/raters/A", headers=POST).json()
    item_id = s["order"][0]
    item = client.get(f"/api/rating/batches/X5-test/items/{item_id}").json()
    assert set(item) == {"item", "calibration", "alert", "body", "answer"} and item["calibration"] is True
    r = client.post(f"/api/rating/batches/X5-test/raters/A/items/{item_id}", json=FULL, headers=POST)
    assert r.status_code == 200 and r.json()["progress"]["complete"] == 1
    bodies = [client.get("/api/rating/batches").text, client.get("/api/rating/batches/X5-test/raters/A").text]
    bodies += [client.get(f"/api/rating/batches/X5-test/items/{i}").text for i in s["order"]]
    assert not any(SECRET in b for b in bodies)


def test_api_errors(client):
    assert client.get("/api/rating/batches/nope/items/it00").status_code == 404
    assert client.get("/api/rating/batches/X5-test/raters/A").status_code == 404     # not started
    assert client.post("/api/rating/batches/X5-test/raters/C", headers=POST).status_code == 422
    client.post("/api/rating/batches/X5-test/raters/A", headers=POST)
    url = "/api/rating/batches/X5-test/raters/A/items/it00"
    assert client.post(url, json={"R1": 9}, headers=POST).status_code == 400
    assert client.post(url, json={"R1": 3, "comment": "x"}, headers=POST).status_code == 422   # scores only


# ── offline pack ─────────────────────────────────────────────────────────────
def _csp_sources(html, kind):
    csp = re.search(r'http-equiv="Content-Security-Policy" content="([^"]+)"', html).group(1)
    return re.search(rf"{kind}-src ([^;]+)", csp).group(1).split(), csp


def test_pack_is_self_contained_with_hash_only_csp(root):
    html = rating.render_pack("X5-test")
    scripts = re.findall(r"<script>(.*?)</script>", html, re.S)
    styles = re.findall(r"<style>(.*?)</style>", html, re.S)
    assert len(scripts) == 1 and len(styles) == 1
    allowed, csp = _csp_sources(html, "script")
    digest = "'sha256-" + base64.b64encode(hashlib.sha256(scripts[0].encode()).digest()).decode() + "'"
    assert allowed == [digest]
    assert _csp_sources(html, "style")[0][0].startswith("'sha256-")
    assert "default-src 'none'" in csp and "connect-src 'none'" in csp and "unsafe" not in csp
    assert not re.search(r"""(?:src|href)=["'](?:https?:)?//""", html)


def test_pack_data_cannot_break_out_of_its_script_block(root):
    html = rating.render_pack("X5-test")
    block = re.search(r'<script type="application/json" id="pack-data">(.*?)</script>', html, re.S).group(1)
    assert "<" not in block and " " not in block
    data = json.loads(block)
    assert HOSTILE in data["items"]["it00"]["alert"]["full_log"]     # the text survives, escaped
    assert SECRET not in html
    assert data["orders"]["A"] == rating.Batch("X5-test").order("A")


def test_pack_script_never_writes_html():
    source = (rating.PACK_DIR / "pack.js").read_text()
    assert not re.search(r"innerHTML|outerHTML|insertAdjacentHTML|document\.write|\beval\(|new Function", source)


def test_export_pack_never_replaces_another_file(root, tmp_path):
    out = rating.export_pack("X5-test")
    assert out == root / "X5-test" / "X5-test_rating-pack.html"
    assert rating.export_pack("X5-test") == out                # same content: fine
    other = tmp_path / "pack.html"
    other.write_text("something else")
    with pytest.raises(rating.RatingConflict):
        rating.export_pack("X5-test", other)


# ── import ───────────────────────────────────────────────────────────────────
def pack_download(tmp_path, rater="B", ratings=None, **extra):
    rubric = rating.load_rubric()
    doc = {"schema_version": 1, "batch": "X5-test", "rater": rater, "via": "pack",
           "rubric": {"version": rubric["version"], "sha256": rubric["sha256"]},
           "started_at": "2026-10-12T01:00:00Z", "updated_at": "2026-10-12T02:00:00Z",
           "ratings": ratings if ratings is not None else {"it00": {**FULL, "saved_at": "2026-10-12T02:00:00Z"}},
           **extra}
    path = tmp_path / f"X5-test_rater-{rater}.json"
    path.write_text(json.dumps(doc))
    return path


def test_import_saves_a_pack_download_once(root, tmp_path):
    path = pack_download(tmp_path)
    result = rating.import_ratings(path)
    assert result["rater"] == "B" and result["progress"]["complete"] == 1 and not result["unchanged"]
    saved = json.loads((root / "X5-test" / "ratings" / "rater-B.json").read_text())
    assert saved["via"] == "pack" and saved["order"] == rating.Batch("X5-test").order("B")
    assert rating.import_ratings(path)["unchanged"]
    other = pack_download(tmp_path, ratings={"it01": {**FULL}})
    with pytest.raises(rating.RatingConflict, match="already has scores"):
        rating.import_ratings(other)


def test_import_checks_items_scores_and_rubric(root, tmp_path):
    with pytest.raises(rating.RatingNotFound):
        rating.import_ratings(pack_download(tmp_path, ratings={"it99": FULL}))
    with pytest.raises(ValueError, match="1 to 5"):
        rating.import_ratings(pack_download(tmp_path, ratings={"it00": {**FULL, "R2": 7}}))
    with pytest.raises(rating.RatingConflict, match="rubric changed"):
        rating.import_ratings(pack_download(tmp_path, rubric={"version": 0, "sha256": "old"}))
    bad = tmp_path / "x.json"
    bad.write_text("not json")
    with pytest.raises(ValueError, match="not a ratings file"):
        rating.import_ratings(bad)


def test_cli_status_export_and_import(root, tmp_path, capsys):
    assert cli.main(["rating", "status"]) == 0
    assert "X5-test: 8 items, 2 calibration · rater A: not started" in capsys.readouterr().out
    assert cli.main(["rating", "export-pack", "X5-test", "--out", str(tmp_path / "p.html")]) == 0
    assert (tmp_path / "p.html").is_file()
    assert cli.main(["rating", "import", str(pack_download(tmp_path))]) == 0
    assert "rater B, 1/8 complete" in capsys.readouterr().out
    assert cli.main(["rating", "import", str(pack_download(tmp_path, ratings={"it01": FULL}))]) == 1
    assert "already has scores" in capsys.readouterr().out
    assert cli.main(["rating", "status", "nope"]) == 1
