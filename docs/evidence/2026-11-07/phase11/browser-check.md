# Dashboard served by `spectra serve`, checked in a real browser (2026-11-07)

Throwaway instance on `127.0.0.1:8799` (own data directory, test-only admin password generated for the run and deleted
afterwards), the packaged build (`backend/spectra/webui`, from `scripts/build_release.sh`), driven through the in-app
Chromium browser.

What was observed:

* `GET /` rendered the landing page under the strict CSP (`script-src 'self'`, no inline scripts); the only console error was the
  expected `401` of the pre-login session probe (`GET /api/auth/me`).
* Sign-in through the login form (which now has the optional authenticator-code field) succeeded; the app moved to `#/overview`.
* Every REST call in the network log went to `http://127.0.0.1:8799` (the page's own origin). **Zero** requests went to the old
  hard-coded `localhost:8787` (`performance.getEntriesByType('resource')` filtered on `8787` = 0).
* The "LIVE EVENTS" pill lit up and the server log recorded `WebSocket /ws/events [accepted]`; no log line contained `token=`.
* After training on the demo baseline and processing the suspicious capture through the API, a full page reload kept the session
  (`GET /api/auth/me` -> 200), showed "MODEL READY" and the capture history (s.pcap: 13 flows, 5 detections).
* The Monitor page's charts rendered: 5 Recharts SVG surfaces with 21 paths; no CSP violation was logged.

Not covered: Firefox/Safari (the CSP's `connect-src 'self'` relies on same-origin `ws:` matching, which current browsers
implement), an HTTPS origin (`wss`), and the visual correctness of the other pages.
