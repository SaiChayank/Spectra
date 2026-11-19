# Frontend mock mode

Run the dashboard with no backend, served from the recorded contract (`frontend/contract/fixtures/`, plan §4.2):

    cd frontend
    npm run dev:mock        # http://localhost:5173

Sign in with any password as `admin`, `analyst` or `viewer` (the password `wrong` fails). The **Mock** button in the bottom-right corner
switches scenarios and can drop the WebSocket to exercise reconnects.

| Scenario | What the mock does |
|---|---|
| Demo data (normal) | recorded demo responses |
| Empty database, no model | `__empty` variants where recorded (`GET /api/model` shows an untrained model) |
| Storage unavailable | every write returns 503 with `Retry-After`; `/api/health` reports the database as busy |
| Login throttled | `POST /api/auth/login` returns 429 with `Retry-After` |
| Session expires after 60 s | every call returns 401 once the session is a minute old |

## How it works

* `src/mock/resolve.ts` (unit-tested in `resolve.test.ts`) picks a fixture per request: exact path, then a query match, then the same
  path with a different id (detail pages for unrecorded ids reuse a recorded body). A VIEWER or ANALYST gets the recorded 403 where one
  exists, otherwise a generic 403 based on an approximation of `backend/spectra/authz.py` (header `x-mock: generic 403`). Routes with
  no fixture return 404 with `x-mock: no fixture`.
* `src/mock/install.tsx` replaces `fetch` and `WebSocket` in the page; `src/mock/socket.ts` replays `ws_events.json` every 1.5 s.
* Loaded only when `import.meta.env.DEV && VITE_MOCK === "1"` (set by `vite.config.ts` in `--mode mock`), so `npm run build` contains no mock code.
* No new dependency: this was chosen instead of Mock Service Worker, which would add a dev dependency and a service-worker file in
  `public/` that a build would ship.
* The mock is stateless apart from who is signed in: actions return their recorded response, but lists do not change after them.
