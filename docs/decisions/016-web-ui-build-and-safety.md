# 016 · Web UI: built locally, text only, nothing from another origin

**Date:** 2026-10-04 · **Status:** in effect from P6.4 (`feat/p6-ui`) · **Affects:** Plan P6, §2.2; [ARCHITECTURE §9](../ARCHITECTURE.md#9-web-app); [RUNBOOK §9](../RUNBOOK.md#9-the-web-app)

## Contents

- [Context](#context) · [Decision](#decision) · [Consequences](#consequences)

## Context

Plan P6 fixes the UI stack (React, Vite, TypeScript, Tailwind, shadcn in `web/ui/`, built into `web/ui/dist/`). [Decision 013](013-web-app-local-api.md) fixed the server side: a CSP of `default-src 'self'` with no inline script, and log content treated as attacker text. Three things were still open: whether the build is tracked, how the UI keeps to the CSP, and how "rendered as escaped text" is enforced and not just intended.

## Decision

1. **Sources are tracked, the build is not.** `web/ui/dist/` stays gitignored (the repo's `dist/` rule), like any build output, so it can never drift from the sources. `npm ci && npm run build` makes it. `package-lock.json` pins every package. Until the launcher (P6.8) builds it, `cjp ui` says how.
2. **Nothing from another origin.** System fonts, icons bundled from `lucide-react`, no CDN and no analytics. Vite emits one module script and one stylesheet, both same-origin.
3. **Every string is text.** Alerts, bodies and answers are rendered as React text children, which React escapes. No `dangerouslySetInnerHTML`, `innerHTML`, `eval` or `new Function` anywhere in `web/ui/src`. A pytest test greps for them, and another checks the built `index.html` for inline script and other origins.
4. **One fetch wrapper** (`src/lib/api.ts`) adds `X-CJP-Request: 1` to every non-GET request and turns error bodies into the server's sentence. Components never call `fetch` directly.
5. **shadcn components are copied in** (`src/components/ui/`), using the local `cn()` in `src/lib/utils.ts` (clsx + tailwind-merge).
6. **Versions:** Vite 8, React 19, TypeScript 7, Tailwind 4, vitest 5. Node ≥ 22.12, as `package.json` `engines` says.

## Consequences

- The Mac that runs `cjp ui` needs Node and one build after each UI change. The launcher (P6.8) should build when `dist/` is missing or older than `src/`.
- vitest 5 lists Node 22, 24 and 26. The Node 23 used in development works, with an engine warning on install.
- A future need for raw HTML (say, a rendered `report.md` in Results) needs a sanitiser and a new decision, not an exception to the grep test.
