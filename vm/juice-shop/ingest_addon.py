"""
WP1 ingest proxy addon (mitmproxy).

Reverse-proxies Juice Shop and appends one JSON line per completed
request/response exchange to $DATA_DIR/logs/ingest_log.jsonl, keyed by the
same correlation ID (cid) attacks.sh/benign_traffic.sh already stamp on
every request via the Referer header (see fire() in both scripts).

This mirrors the existing access.log.YYYY-MM-DD convention: a flat,
continuously-written file that per-session scripts later grep by cid
prefix. The addon never looks at session IDs or session directories -
that split happens downstream, in attacks.sh/benign_traffic.sh at
session end.

Also writes a second, parallel flat log — data/logs/enriched_access.log.
YYYY-MM-DD — in Juice Shop's own apache-combined access-log format, so it
decodes through Wazuh's stock "web-accesslog" decoder and stock rules
(31101/31103/31104/31105/...) completely unchanged. The one difference
from the real access.log: the request body is percent-encoded and appended
to the URL as a "body=" query parameter, so payloads sent in a POST body
(e.g. the login-endpoint SQLi bypass) land in the same decoded `url` field
the SQLi/XSS/traversal rules already regex against — fields that are
otherwise structurally invisible to Wazuh, since the plain access log never
carries a request body at all. This is what lets a same-rules,
before/after comparison (docs/2026-08-20-closing-the-loop-plan.md) isolate
how much of "Wazuh doesn't distinguish attack types" is a logging gap
(fixed by this file) vs. a rules gap (stock signatures not matching a given
payload's literal tokens — a separate, real finding in its own right).

Also writes a third, parallel flat log — data/logs/body_field_access.log.
YYYY-MM-DD — in a bespoke, self-describing format (see
docs/2026-09-03-custom-rule-body-probe-plan.md) with the percent-encoded
request body in its own `body="..."` field, genuinely separate from the
request path. This is arm 3 of the detection comparison: unlike the
enriched log above (which rides through *stock* rules by disguising the
body as part of the URL), this arm is read by a *custom* decoder/rule
(wazuh-custom/decoders/body_field_decoders.xml,
wazuh-custom/rules/body_field_rules.xml) pointed at the body field
specifically, so it never touches `url` and stock rules 31103/31104/31105
never fire on it.

Run via start_ingest_proxy.sh, not directly.
"""

import json
import os
import time
from urllib.parse import quote

# start_ingest_proxy.sh exports CJP_DATA_DIR; the fallback is data/ next to
# this file, wherever it is deployed (~/cjp-vm since Plan P2.2).
DATA_DIR = os.environ.get("CJP_DATA_DIR") or os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "data")
LOG_PATH = os.path.join(DATA_DIR, "logs", "ingest_log.jsonl")
ENRICHED_ACCESS_LOG_DIR = os.path.join(DATA_DIR, "logs")
BODY_FIELD_ACCESS_LOG_DIR = os.path.join(DATA_DIR, "logs")

# Bodies we don't want dumped verbatim into the log (images, fonts, etc.
# served by Juice Shop's static assets, which have no cid and aren't part
# of what WP1 needs enriched).
_BINARY_CONTENT_PREFIXES = ("image/", "font/", "audio/", "video/")


def _decode_body(message) -> str | None:
    content = message.raw_content
    if not content:
        return "" if content is not None else None

    content_type = message.headers.get("Content-Type", "")
    if any(content_type.startswith(p) for p in _BINARY_CONTENT_PREFIXES):
        return f"<binary, {len(content)} bytes, {content_type}>"

    try:
        return message.get_text(strict=False)
    except ValueError:
        return f"<undecodable, {len(content)} bytes>"


def _enriched_url(path: str, request_body: str | None) -> str:
    """Juice Shop's real access.log never carries a request body — a
    body-only payload (e.g. the login-endpoint SQLi bypass, which is pure
    POST JSON with no query string) is otherwise structurally invisible to
    Wazuh's decoder. Percent-encoding it onto the URL as a query param puts
    it in the one field the stock web-attack rules (31103/31104/31105)
    already regex against, with no decoder/rule changes."""
    if not request_body:
        return path
    encoded = quote(request_body, safe="")
    sep = "&" if "?" in path else "?"
    return f"{path}{sep}body={encoded}"


def _enriched_access_line(req, res, cid, request_body, client_conn) -> str:
    srcip = client_conn.peername[0] if client_conn.peername else "127.0.0.1"
    date_str = time.strftime("%d/%b/%Y:%H:%M:%S +0000", time.gmtime(req.timestamp_start))
    url = _enriched_url(req.path, request_body)
    status = res.status_code if res else 0
    size = len(res.raw_content) if res and res.raw_content else "-"
    referrer = cid if cid else "-"
    user_agent = req.headers.get("User-Agent", "-")
    return (
        f'{srcip} - - [{date_str}] "{req.method} {url} HTTP/1.1" '
        f'{status} {size} "{referrer}" "{user_agent}"\n'
    )


def _body_field_access_line(req, res, cid, request_body, client_conn) -> str:
    """Bespoke self-describing format, decoded by
    wazuh-custom/decoders/body_field_decoders.xml into its own `http_body`
    field — genuinely separate from `url` — so
    wazuh-custom/rules/body_field_rules.xml can be pointed at body content
    specifically, unlike the url-carried trick in _enriched_access_line()."""
    srcip = client_conn.peername[0] if client_conn.peername else "127.0.0.1"
    status = res.status_code if res else 0
    body = quote(request_body, safe="") if request_body else ""
    return (
        f'body_probe cid={cid if cid else "-"} ip={srcip} method={req.method} '
        f'path={req.path} status={status} body="{body}"\n'
    )


def response(flow) -> None:
    req = flow.request
    res = flow.response

    cid = req.headers.get("Referer")
    request_body = _decode_body(req)

    record = {
        "kind": "ingest",
        "cid": cid if cid else None,
        "timestamp": time.strftime(
            "%Y-%m-%dT%H:%M:%S", time.gmtime(req.timestamp_start)
        )
        + f".{int(req.timestamp_start % 1 * 1000):03d}Z",
        "method": req.method,
        "path": req.path,
        "request_body": request_body,
        "status": res.status_code if res else None,
        "response_body": _decode_body(res) if res else None,
        "duration_ms": (
            round((res.timestamp_end - req.timestamp_start) * 1000)
            if res and res.timestamp_end
            else None
        ),
    }

    os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)
    with open(LOG_PATH, "a") as f:
        f.write(json.dumps(record) + "\n")

    date_suffix = time.strftime("%Y-%m-%d", time.gmtime(req.timestamp_start))
    enriched_log_path = os.path.join(
        ENRICHED_ACCESS_LOG_DIR, f"enriched_access.log.{date_suffix}"
    )
    with open(enriched_log_path, "a") as f:
        f.write(_enriched_access_line(req, res, cid, request_body, flow.client_conn))

    body_field_log_path = os.path.join(
        BODY_FIELD_ACCESS_LOG_DIR, f"body_field_access.log.{date_suffix}"
    )
    with open(body_field_log_path, "a") as f:
        f.write(_body_field_access_line(req, res, cid, request_body, flow.client_conn))
