"""
The web app's one process (Plan P6 "Stack"): a FastAPI app that answers
`/api/*` by calling `cjp` functions directly, and serves the built UI
(`web/ui/dist/`) from the same origin. `cjp ui` runs it with uvicorn.

Safety rules (decision 013):

- **This Mac only.** serve() binds 127.0.0.1 and has no host option. The
  Host header must be `127.0.0.1` or `localhost`, so a web page that points
  its own DNS name at 127.0.0.1 (DNS rebinding) is refused.
- **No CORS.** A page from another origin can't read any response.
  Requests that change state (POST, PUT, PATCH, DELETE) must carry the
  `X-CJP-Request: 1` header, plus a local Origin if the browser sends one.
  A cross-site form or fetch can't set that header without a CORS preflight,
  and the preflight is never granted. So a stray web page can't start a paid
  triage job.
- **The API key stays server-side.** No response carries it.
- **Log content is untrusted text.** The UI renders it escaped, and the CSP
  allows no inline script and no other origin. Even a missed escape can't
  run code or send data out.
"""

import socket
import threading
import time
import webbrowser
from pathlib import Path
from urllib.parse import urlsplit

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, Response
from starlette.middleware.trustedhost import TrustedHostMiddleware

from cjp import __version__, config
from web.api import health, rating, results, triage

HOST = "127.0.0.1"
DEFAULT_PORT = 8738
LOCAL_HOSTS = ("127.0.0.1", "localhost")
UI_DIST = Path(__file__).resolve().parent.parent / "ui" / "dist"
REQUEST_HEADER = "X-CJP-Request"
UNSAFE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}

SECURITY_HEADERS = {
    "Content-Security-Policy": "default-src 'self'; img-src 'self' data:; "
                               "style-src 'self' 'unsafe-inline'; object-src 'none'; "
                               "base-uri 'none'; form-action 'self'; frame-ancestors 'none'",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
}

NOT_BUILT = """<!doctype html><html lang="en"><head><meta charset="utf-8">
<title>cjp</title></head><body style="font-family: system-ui; max-width: 40rem; margin: 3rem auto">
<h1>cjp is running</h1>
<p>The interface has not been built yet. Install Node.js 22.12 or newer
(nodejs.org), then double-click <b>Start Triage.command</b> again: it builds the
interface and reopens this page.</p>
<p>Or, in a terminal: <code>cd web/ui &amp;&amp; npm ci &amp;&amp; npm run build</code>, then reload this page.</p>
<p>The API answers at <a href="/api/health">/api/health</a>.</p>
</body></html>"""


def _local_origin(origin: str) -> bool:
    return urlsplit(origin).hostname in LOCAL_HOSTS


def _with_headers(response: Response, path: str) -> Response:
    response.headers.update(SECURITY_HEADERS)
    if path.startswith("/api/"):
        response.headers["Cache-Control"] = "no-store"
    return response


def create_app(ui_dist: Path = UI_DIST) -> FastAPI:
    app = FastAPI(title="cjp", version=__version__, docs_url=None, redoc_url=None,
                  openapi_url="/api/openapi.json")

    @app.middleware("http")
    async def guard(request: Request, call_next):
        if request.method in UNSAFE_METHODS:
            origin = request.headers.get("origin")
            if request.headers.get(REQUEST_HEADER) != "1" or (origin and not _local_origin(origin)):
                return _with_headers(JSONResponse(
                    {"detail": f"refused: send {REQUEST_HEADER}: 1 from the cjp page"},
                    status_code=403), request.url.path)
        return _with_headers(await call_next(request), request.url.path)

    # Added last, so it runs first: a foreign Host never reaches a route.
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=list(LOCAL_HOSTS))

    @app.get("/api/health")
    def get_health(offline: bool = False) -> dict:
        """`cjp doctor`'s checks with plain-language notes, and which triage
        sources can run. Uses no API tokens and changes nothing. A sync
        endpoint, so the slow network checks run in the thread pool."""
        return health.report(offline=offline)

    @app.get("/api/info")
    def get_info() -> dict:
        from cjp.runs import git_describe
        return {"app": "cjp", "version": __version__, "git_describe": git_describe(),
                "data_dir": str(config.DATA_DIR), "ui_built": (ui_dist / "index.html").is_file()}

    app.include_router(triage.router)
    app.include_router(rating.router)
    app.include_router(results.router)

    @app.get("/{path:path}", include_in_schema=False)
    def ui(path: str) -> Response:
        """The built UI. Any path that is not a file gets index.html, so the
        UI's own routes (e.g. /triage) survive a reload. Unknown /api paths
        and missing files with an extension get a 404, not the page."""
        if path == "api" or path.startswith("api/"):
            return JSONResponse({"detail": "Not Found"}, status_code=404)
        index = ui_dist / "index.html"
        if not index.is_file():
            return HTMLResponse(NOT_BUILT)
        if path:
            file = (ui_dist / path).resolve()
            if file.is_relative_to(ui_dist.resolve()) and file.is_file():
                return FileResponse(file)
            if "." in Path(path).name:
                return JSONResponse({"detail": "Not Found"}, status_code=404)
        return FileResponse(index)

    return app


# ── `cjp ui` ─────────────────────────────────────────────────────────────────
def _port_free(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)    # as uvicorn binds
        try:
            s.bind((HOST, port))
        except OSError:
            return False
    return True


def _is_cjp(port: int) -> bool:
    import httpx
    try:
        r = httpx.get(f"http://{HOST}:{port}/api/info", timeout=2, trust_env=False)
        return r.json().get("app") == "cjp"
    except Exception:
        return False


def _open_when_started(server, url: str) -> None:
    while not server.started and not server.should_exit:
        time.sleep(0.1)
    if server.started:
        webbrowser.open(url)


def serve(port: int = DEFAULT_PORT, open_browser: bool = True) -> int:
    """Run the app on http://127.0.0.1:<port>/ until Ctrl-C. If cjp already
    runs on that port (a second double-click on the launcher), just open
    the browser. Exit code 0, or 1 when another program holds the port."""
    import uvicorn
    url = f"http://{HOST}:{port}/"
    if not _port_free(port):
        if _is_cjp(port):
            print(f"[ui] already running at {url}")
            if open_browser:
                webbrowser.open(url)
            return 0
        print(f"[ui] port {port} is used by another program; try: cjp ui --port {port + 1}")
        return 1
    server = uvicorn.Server(uvicorn.Config(create_app(), host=HOST, port=port, log_level="warning"))
    if open_browser:
        threading.Thread(target=_open_when_started, args=(server, url), daemon=True).start()
    print(f"[ui] serving {url} (this Mac only); Ctrl-C stops it", flush=True)
    server.run()
    return 0
