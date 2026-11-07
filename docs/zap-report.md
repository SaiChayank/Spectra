# OWASP ZAP baseline (2026-11-07)

**What was run.** `zap-baseline.py` from `ghcr.io/zaproxy/zaproxy:stable` (ZAP 2.17.0, image `sha256:9624669db72f54d86c4b46a7064518bd9bf79d8c61a4c31befa9923489f328af`, 3.7 GB) against a throwaway
`spectra:1.0.0` container (read-only, capabilities dropped) on an isolated Docker network. Raw output:
`docs/evidence/2026-11-07/zap/` (`zap-baseline.html/.json/.md`, `zap-baseline-stdout.txt`).

**What it covers, and what it does not.** The baseline is a *passive* scan of the pages the spider reaches without signing in: the
dashboard HTML, its JS/CSS assets and a few 404s. It sends no attack payloads and does not log in, so it says nothing about the
authenticated REST API (that is the Schemathesis run in `docs/dast-report.md`) or the WebSocket. It is not an active scan.

**First run (before changes):** 0 FAIL, 6 WARN, 62 PASS. **After** adding `Permissions-Policy`, `Cross-Origin-Opener-Policy` and
`Cross-Origin-Resource-Policy` response headers (`backend/spectra/api/webui.py`, asserted in `tests/test_webui.py`) and rebuilding the
image: **0 FAIL, 5 WARN, 63 PASS** (the second run's output is the kept evidence).

| Remaining warning | Assessment |
|---|---|
| Storable and Cacheable Content (info) | Intended: content-hashed assets are served `immutable`; the HTML is `no-cache`. `robots.txt`/`sitemap.xml` 404s are cacheable by default. No sensitive data. |
| CSP: `style-src 'unsafe-inline'` (medium) | Known and documented in `webui.py`: the charts use inline `style` attributes. Scripts remain `script-src 'self'` with no inline code or eval. Removing it needs a front-end change (nonces or class-based styles); not done. |
| Modern Web Application (info) | Informational note that the page is a SPA. |
| Private IP Disclosure (low) | The match is the placeholder text `host:10.0.0.5` in the network-search input of the bundle, not a real address. |
| Cross-Origin-Embedder-Policy missing (low) | Not set: it only matters for cross-origin isolation, and `require-corp` risks breaking embedded resources; nothing here needs it. Left as a documented decision. |

No finding is a vulnerability in the sense of the project's gate (no Critical/High). This is one passive scan on one date, not a
sign-off.
