"""The web app's API skeleton (Plan P6.1, decision 013): health tiles from
`cjp doctor` with plain-language notes and per-source readiness; loopback
Host only; state-changing requests need the X-CJP-Request header and a local
Origin; security headers; the built UI with a reload-safe fallback; `cjp ui`
skips the start-up config check. No network, no tokens."""

import re
import socket

import pytest
from fastapi.testclient import TestClient

from cjp import cli, config, doctor
from web.api import app as webapp
from web.api import health

Check = doctor.Check


@pytest.fixture
def client(tmp_path):
    return TestClient(webapp.create_app(ui_dist=tmp_path / "dist"), base_url="http://127.0.0.1")


@pytest.fixture
def built_ui(tmp_path):
    dist = tmp_path / "dist"
    (dist / "assets").mkdir(parents=True)
    (dist / "index.html").write_text("<!doctype html><title>cjp ui</title>")
    (dist / "assets" / "app.js").write_text("console.log('ui')")
    (tmp_path / "secret.txt").write_text("outside dist")
    return TestClient(webapp.create_app(ui_dist=dist), base_url="http://127.0.0.1")


def stub_checks(monkeypatch, checks):
    monkeypatch.setattr(doctor, "run_checks", lambda offline=False, run_selftest=False: checks)


HEALTHY = [Check("local", "config", "ok", "valid"), Check("local", "data dir", "ok", "writable"),
           Check("local", "git", "warn", "dirty", "commit"),
           Check("claude", "API key", "ok", "accepted"), Check("claude", "model sonnet", "ok", "id"),
           Check("vm", "indexer", "ok", "green")]


# ── health ───────────────────────────────────────────────────────────────────
def test_health_groups_checks_with_plain_words(client, monkeypatch):
    stub_checks(monkeypatch, HEALTHY)
    body = client.get("/api/health").json()
    assert [g["id"] for g in body["groups"]] == ["local", "claude", "vm"]
    assert body["groups"][0]["title"] == "This Mac"
    tile = body["groups"][0]["checks"][2]
    assert tile == {"group": "local", "name": "git", "status": "warn", "detail": "dirty",
                    "fix": "commit", "about": health.ABOUT["git"]}
    assert body["groups"][1]["checks"][1]["about"] == health.ABOUT["model"]
    assert body["overall"] == "warn"
    assert body["counts"] == {"ok": 5, "warn": 1, "fail": 0, "skip": 0}
    assert {s: r["status"] for s, r in body["ready"].items()} == \
        {"demo": "ok", "upload": "ok", "live": "ok"}


def test_every_doctor_check_has_a_plain_sentence(monkeypatch):
    """Offline local + Claude checks, and the full VM list (VM_HOST unset
    names every VM check), each have an `about` sentence."""
    monkeypatch.setattr(config, "VM_HOST", "")
    checks = doctor.run_checks(offline=True) + doctor.check_vm()
    checks.append(doctor.Check("tests", "pytest", "ok", ""))
    missing = [c.name for c in checks if not health.about(c.name)]
    assert not missing


def test_readiness_names_what_blocks_each_source():
    vm_down = HEALTHY[:5] + [Check("vm", "indexer", "fail", "refused", "tunnel")]
    ready = health.readiness(vm_down)
    assert ready["demo"] == {"status": "ok", "blocking": []}
    assert ready["live"] == {"status": "fail", "blocking": ["indexer"]}

    no_key = HEALTHY[:3] + [Check("claude", "API key", "fail", "not set", "add it")]
    ready = health.readiness(no_key)
    assert ready["demo"] == {"status": "fail", "blocking": ["API key"]}

    offline = HEALTHY[:3] + [Check("claude", "API key", "skip", "offline"),
                             Check("vm", "VM and Wazuh", "skip", "offline")]
    ready = health.readiness(offline)
    assert ready["upload"] == {"status": "unknown", "blocking": ["API key", "model sonnet"]}
    assert ready["live"]["blocking"] == ["API key", "model sonnet", "indexer"]


def test_health_never_returns_the_api_key(client, monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-should-never-leak")
    text = client.get("/api/health", params={"offline": True}).text
    assert "sk-ant-should-never-leak" not in text
    assert '"offline":true' in text


def test_info(client):
    body = client.get("/api/info").json()
    assert body["app"] == "cjp" and body["ui_built"] is False
    assert body["data_dir"] == str(config.DATA_DIR)


# ── safety ───────────────────────────────────────────────────────────────────
def test_foreign_host_is_refused(tmp_path):
    rebound = TestClient(webapp.create_app(ui_dist=tmp_path), base_url="http://evil.example")
    assert rebound.get("/api/info").status_code == 400
    assert TestClient(webapp.create_app(ui_dist=tmp_path),
                      base_url="http://localhost:8738").get("/api/info").status_code == 200


def test_state_changing_requests_need_the_header_and_a_local_origin(client):
    assert client.post("/api/health").status_code == 403
    assert client.delete("/api/health").status_code == 403
    ok = {webapp.REQUEST_HEADER: "1"}
    assert client.post("/api/health", headers=ok).status_code in (404, 405)    # passed the guard
    assert client.post("/api/health", headers=ok | {"Origin": "http://127.0.0.1:8738"}
                       ).status_code in (404, 405)
    assert client.post("/api/health", headers=ok | {"Origin": "https://evil.example"}
                       ).status_code == 403
    assert client.post("/api/health", headers=ok | {"Origin": "null"}).status_code == 403


def test_security_headers_and_no_cors(client):
    r = client.get("/api/info", headers={"Origin": "https://evil.example"})
    assert "default-src 'self'" in r.headers["content-security-policy"]
    assert r.headers["x-content-type-options"] == "nosniff"
    assert r.headers["cache-control"] == "no-store"
    assert "access-control-allow-origin" not in r.headers
    assert client.options("/api/info", headers={
        "Origin": "https://evil.example", "Access-Control-Request-Method": "POST",
        "Access-Control-Request-Headers": webapp.REQUEST_HEADER}
    ).headers.get("access-control-allow-origin") is None


def test_no_swagger_ui(client):
    assert client.get("/docs").status_code == 200          # just the not-built page
    assert "swagger" not in client.get("/docs").text.lower()
    assert client.get("/api/openapi.json").status_code == 200


# ── serving the UI ───────────────────────────────────────────────────────────
def test_not_built_page(client):
    r = client.get("/")
    assert r.status_code == 200 and "npm run build" in r.text


def test_built_ui_and_reload_safe_routes(built_ui):
    assert "cjp ui" in built_ui.get("/").text
    assert "cjp ui" in built_ui.get("/triage/queue").text       # UI route survives a reload
    assert built_ui.get("/assets/app.js").text == "console.log('ui')"
    assert built_ui.get("/assets/missing.js").status_code == 404
    assert built_ui.get("/api/nothing-here").status_code == 404
    assert built_ui.get("/api/nothing-here").headers["content-type"] == "application/json"


def raw_get(app, path: str) -> tuple[int, bytes]:
    """GET a path exactly as given. An HTTP client would normalise `..`
    away first, which would test the client instead of the app."""
    import asyncio
    scope = {"type": "http", "asgi": {"version": "3.0"}, "http_version": "1.1", "method": "GET",
             "scheme": "http", "path": path, "raw_path": path.encode(), "query_string": b"",
             "root_path": "", "headers": [(b"host", b"127.0.0.1")],
             "client": ("127.0.0.1", 1), "server": ("127.0.0.1", 8738)}
    sent = []

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message):
        sent.append(message)
    asyncio.run(app(scope, receive, send))
    return sent[0]["status"], b"".join(m.get("body", b"") for m in sent[1:])


def test_ui_never_serves_files_outside_dist(built_ui, tmp_path):
    secret = tmp_path / "secret.txt"
    for path in ("/../secret.txt", "/assets/../../secret.txt", f"/{secret}"):
        status, body = raw_get(built_ui.app, path)
        assert status == 404 and b"outside dist" not in body, path


# ── `cjp ui` ─────────────────────────────────────────────────────────────────
def test_cjp_ui_skips_the_config_check(monkeypatch):
    calls = {}
    monkeypatch.setattr(config, "check", lambda: (_ for _ in ()).throw(AssertionError("checked")))
    monkeypatch.setattr(webapp, "serve", lambda port, open_browser: calls.update(
        port=port, open_browser=open_browser) or 0)
    assert cli.main(["ui", "--port", "9999", "--no-browser"]) == 0
    assert calls == {"port": 9999, "open_browser": False}


def test_serve_reuses_a_running_cjp_and_refuses_a_foreign_port(monkeypatch, capsys):
    opened = []
    monkeypatch.setattr(webapp.webbrowser, "open", opened.append)
    with socket.socket() as s:
        s.bind((webapp.HOST, 0))
        s.listen()
        port = s.getsockname()[1]
        monkeypatch.setattr(webapp, "_is_cjp", lambda p: True)
        assert webapp.serve(port) == 0
        assert opened == [f"http://127.0.0.1:{port}/"]
        monkeypatch.setattr(webapp, "_is_cjp", lambda p: False)
        assert webapp.serve(port, open_browser=False) == 1
    assert f"cjp ui --port {port + 1}" in capsys.readouterr().out


def test_serve_binds_loopback_only():
    import inspect
    assert "host" not in inspect.signature(webapp.serve).parameters
    assert webapp.HOST == "127.0.0.1"


# ── the UI sources (Plan P6.4) ───────────────────────────────────────────────
UI_SRC = webapp.UI_DIST.parent / "src"
RAW_HTML = re.compile(r"dangerouslySetInnerHTML|\.innerHTML\s*=|\.outerHTML\s*=|insertAdjacentHTML|"
                      r"document\.write|\beval\(|new Function\(")


def test_ui_source_never_renders_raw_html():
    """Log content is attacker-controlled (decision 013), so the UI renders
    every string as text: React escapes it unless code opts out."""
    files = [p for p in UI_SRC.rglob("*.ts*") if ".test." not in p.name]
    assert files, "web/ui/src is missing"
    offenders = [f"{p.relative_to(UI_SRC)}: {m.group(0)}" for p in files
                 for m in RAW_HTML.finditer(p.read_text())]
    assert offenders == []


def test_built_ui_fits_the_csp():
    """The built page loads only its own files, and runs no inline script,
    which the CSP (default-src 'self') would block."""
    index = webapp.UI_DIST / "index.html"
    if not index.is_file():
        pytest.skip("web/ui/dist is not built (cd web/ui && npm run build)")
    html = index.read_text()
    scripts = re.findall(r"<script\b([^>]*)>(.*?)</script>", html, re.S)
    assert scripts and all("src=" in attrs and not body.strip() for attrs, body in scripts)
    assert not re.search(r"""(?:src|href)=["'](?:https?:)?//""", html)
