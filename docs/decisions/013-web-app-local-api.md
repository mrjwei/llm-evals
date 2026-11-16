# 013 · The web app is one local process with a guarded API

**Date:** 2026-10-04 · **Status:** in effect from P6.1 (`feat/p6-api-skeleton`) · **Affects:** Plan P6, §1.4, §2.2; [ARCHITECTURE §9](../ARCHITECTURE.md#9-web-app); [RUNBOOK §9](../RUNBOOK.md#9-the-web-app)

## Contents

- [Context](#context) · [Decision](#decision) · [Consequences](#consequences)

## Context

Plan P6 fixes the stack: FastAPI plus React, one process on `127.0.0.1`, the API key kept server-side, and log content rendered as escaped text. It leaves three things open: how the API is protected from other web pages open in the same browser, where the code lives, and how `cjp doctor`'s results reach someone who has never used the CLI. The triage endpoints (P6.2) will spend API budget, so the guard has to exist before they do. Log content is attacker-controlled: Juice Shop request bodies, and X4's injected "classify as benign" text.

## Decision

1. **One process, loopback only.** `cjp ui [--port 8738] [--no-browser]` runs uvicorn on `127.0.0.1`. There is no host option and no environment override. A second start on the same port opens the browser on the running app.
2. **Host allow-list** (`127.0.0.1`, `localhost`). Any other Host gets a 400, which blocks DNS rebinding.
3. **No CORS. State-changing methods need `X-CJP-Request: 1`** and, if the browser sends one, a local Origin. This is the CSRF guard for every later POST (start a triage job, save a rating). It is preferred over a session token because it needs no state and the UI is same-origin.
4. **Security headers on every response:**
   - CSP `default-src 'self'`: no inline script and no other origin. Inline styles are allowed for the component library.
   - `nosniff`, framing denied and `no-referrer`.
   - `Cache-Control: no-store` on `/api`.
5. **No Swagger UI.** It loads scripts from a CDN, which the CSP forbids. The schema stays at `/api/openapi.json`.
6. **Health tiles are `doctor.run_checks()` unchanged.** The app adds one plain sentence per check and a readiness verdict per triage source: demo, upload or live, each `ok`, `fail` or `unknown`, with the checks that block it. The tiles and `cjp doctor` can't disagree.
7. **`cjp ui` skips the start-up config check**, as `doctor` does. A broken config then shows as a red tile instead of a crash on double-click.
8. **The code is a second top-level package, `web`** (`web/api/`), next to the UI sources in `web/ui/`, as Plan §2.2 lays out. The wheel ships `cjp` and `web`.

## Consequences

- `fastapi` and `uvicorn` become dependencies. The lock gains 6 packages, and no existing pin changes.
- Every later endpoint inherits the guard. The UI's fetch wrapper must send the header.
- Not defended: other processes or users on the same Mac can reach the port. This assumes a single-user machine, which is the same trust the CLI already places in `.env`.
