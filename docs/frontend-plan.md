# Frontend plan: build the console independently, integrate later

Status: **plan, 2026-11-18.** For a frontend developer who works only in `frontend/` and never edits the backend. The backend team
(the owner and the agent) owns everything under `backend/`, the API contract export, and any new endpoint. Integration happens at fixed
checkpoints (§8) against the real backend.

## 1. Ground rules

* **Touch only `frontend/`.** No edits under `backend/`, `scripts/`, `docs/` other than `docs/frontend-*`, CI, or the Dockerfile. If the
  frontend needs something the API does not offer, write it down as a contract change request (§6), mock it, and keep going.
* **Metadata only, always.** The product never shows, stores, or asks for packet payload. The UI must not add a "show payload", "download
  raw packets" or "decrypt" feature, and must not put flow data in `localStorage`. Showing server names (SNI), addresses, ports, byte counts,
  timings, fingerprints (JA3/JA4) and scores is fine: that is the metadata.
* **Honest by design.** The evaluation results (`docs/evaluation-report.md` §14, §18-§20) say the detector is weak today. The UI must show
  that, not hide it: an untrained model, "unscored" captures, the beacon detector as a *ranking aid* (off by default), a flagged flow as
  "unusual for this network", never "malicious". No marketing words ("AI-powered", "100 % detection") anywhere.
* **Stay inside the security policy the backend serves:** `default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline';
  img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'`. So: no CDN scripts, no external fonts, no third-party analytics or
  error trackers, no iframes, no `eval`. Everything is bundled by Vite.
* **No new runtime dependency without asking.** Today the bundle has only `react`, `react-dom` and `recharts`; every addition lands in
  `THIRD_PARTY_NOTICES.md` and the licence check (`scripts/gen_third_party_notices.py --check` fails CI if it goes stale). Dev-only tools
  (mock server, test helpers, type generator) are fine.

## 2. What exists today

React 19, TypeScript 6, Vite 8, Vitest; hash routing without a router library (`src/lib/router.ts`); one typed client
(`src/lib/api.ts`, `credentials: "include"`, the session is an HttpOnly cookie); a WebSocket hook (`src/lib/useEvents.ts`, `/ws/events`);
nine sections (Overview, Monitor, Incidents, Traffic, Network, Models, Audit, Modules, System) in `src/pages/`, panels in
`src/components/`. About 5,800 lines. The built dashboard is shipped inside the Python wheel and served by the backend at `/`.

Keep the stack. Improve structure where needed, but a rewrite or a new framework is out of scope.

## 3. Users, roles and what each may see

From `backend/spectra/authz.py`. `GET /api/auth/me` returns the user, role and permission list: **drive every button from the permission
list, never from the role name.**

| Role | Permissions | UI consequence |
|---|---|---|
| VIEWER | `read` | sees everything read-only; no action buttons |
| ANALYST | `read`, `investigate`, `incidents` | can acknowledge/resolve alerts, work incidents, add notes, search |
| ADMIN | all, plus `capture:manage`, `model:manage`, `config:manage`, `users:manage` | captures, live capture, training, model registry, users, audit key rotation |

Hidden is not secure: the backend enforces every permission. Hide or disable controls only for clarity, and still handle a 403.

## 4. How to work without the backend: contract first

### 4.1 What the backend team hands over (before you start, and again at each checkpoint)

1. **`frontend/contract/openapi.json`**: the exported OpenAPI document (95 paths, 101 operations). Caveat, measured: only 30 named schemas
   exist, so many responses are untyped (`object`). Do not trust it for response shapes on its own.
2. **`frontend/contract/fixtures/`**: real responses recorded from a running backend with demo data, one JSON file per call
   (`GET_api_alerts.json`, `GET_api_incidents_1.json`, ...), including error responses (401, 403, 404, 409, 429, 503) and a recording of
   WebSocket events from `/ws/events`. These are the source of truth for shapes until response models exist.
3. **`frontend/contract/proposed/`**: shapes for endpoints that do not exist yet (§6), clearly marked PROPOSED.

The export script is backend work (`scripts/export_frontend_contract.py`, to be written by the backend team); you only consume its output.

### 4.2 Your mock mode

* Add a dev-only mock layer (Mock Service Worker is the usual choice) that serves the fixtures: `npm run dev:mock` sets
  `VITE_MOCK=1`; `npm run dev` talks to a real backend on `http://localhost:8787` as today. Mock code must be excluded from the production
  bundle (check `npm run build` output).
* Mock the WebSocket too: replay the recorded events on a timer, and simulate a disconnect so reconnect logic is exercised.
* Add scenario switches for the hard states: no model trained, empty database, 503 "storage temporarily unavailable" with `Retry-After`,
  429 login throttle with `Retry-After`, expired session (401 mid-use), a VIEWER and an ANALYST user.
* Types: generate TypeScript types from `openapi.json` (dev dependency, e.g. `openapi-typescript`) and write the rest by hand from the
  fixtures; keep hand-written types in one place so they can be replaced as the backend adds response models.

## 5. Work, in priority order

Each item lists the real endpoints. **P0** is needed for a first usable release, **P1** soon after, **P2** later.

### P0-1 Session, account and users
* Login (`POST /api/auth/login`), logout (`/api/auth/logout`), current user (`GET /api/auth/me`), TOTP setup/enable/disable
  (`/api/auth/totp/*`): already partly there; finish the TOTP flow (QR/secret shown once, code entry, recovery message).
* **Change own password**: missing today. `PATCH /api/users/{id}` works only with `users:manage` (ADMIN); a VIEWER or ANALYST gets 403
  (fixture `PATCH_api_users_{user_id}__viewer_self_403.json` or similar in `frontend/contract/fixtures/`), so non-admins cannot change
  their own password at all. This needs a new backend endpoint (proposed: `POST /api/auth/password` with the current and new password,
  §6); build the screen against that proposal. On success the session is revoked: return to login with a clear message.
* Users admin (ADMIN): list/create/edit/delete (`/api/users`, `/api/users/{id}`), reset someone's TOTP (`DELETE /api/users/{id}/totp`).
* Global handling: 401 → back to login keeping the deep link; 403 → "you do not have permission" (not a crash); 429 → show the wait from
  `Retry-After`; never log or display passwords or TOTP secrets after the first display.

### P0-2 Alerts and incidents (the analyst's daily work)
* Alerts list and detail (`GET /api/alerts`, `/api/alerts/{id}`), acknowledge/resolve (`POST .../acknowledge`, `.../resolve`).
* Incidents list, detail, create, correlate, acknowledge, investigate, notes, reopen, resolve, false-positive
  (`/api/incidents*`, `/api/investigations/{id}`), evidence timeline from the incident and its flows.
* Every alert shows *why*: the supporting signals already in the data (`threat.supporting[]`: signal, weight, plain-language detail) and
  the score with its meaning ("unusual for this network", with the threshold), never a bare number.
* Beacon alerts (`threat_type: C2_BEACONING`, only when the operator enabled it): label "ranking aid, not proven detector" with a link to
  the limitations page.

### P0-3 Captures and model state
* Upload a capture (`POST /api/captures`, multipart), list/detail/delete (`/api/captures`, `/api/captures/{id}`), process
  (`POST /api/captures/{id}/process`); show `unscored_flows` and the `warnings` entry as the existing "unscored" badge, and explain it.
* Live capture start/stop (`POST /api/capture/start|stop`, ADMIN) with interface list (`GET /api/interfaces`) and live status
  (`GET /api/status`): show `error` from the status prominently: a capture that "started" can end a second later.
* Model status (`GET /api/model`): an untrained model is a top-level banner with a "train a baseline" action
  (`POST /api/model/train`, ADMIN), not a footnote.

### P1-1 Host-centric triage (new; needs backend work, mock it)
The detection plan (`docs/35_threat_engine_plan.md` §7, P2) moves the alert unit from a flow to a **host**: "10.0.4.17 looks compromised
because A, B, C". Build the screen now against a PROPOSED contract (§6): a ranked host list with confidence, per-host evidence
timeline (which detector, when, which destination), and one-click analyst verdict *true / expected (benign but known) / false*. The
verdicts will feed per-site learning (plan E6), so they must be quick to give.

### P1-2 Traffic and network
Flows and detections (`GET /api/flows`, `/api/detections`, `/api/history/*`), search (`GET /api/search`), the graph
(`/api/graph*`). Paginate and virtualise long tables; never request unbounded data (the API caps `limit` at 1,000).

### P1-3 System, health, audit
Health (`GET /api/health`, `/api/health/system`): show `writable.data_dir` / `writable.database` and the "busy" state; a 503 anywhere
shows a non-blocking "storage temporarily unavailable, retrying in N s" banner that honours `Retry-After`. Metrics link
(`/api/metrics`). Audit: entries, verify chain, checkpoints, certificate (`/api/audit/*`); key rotation is ADMIN and needs a confirm step.

### P1-4 Model registry
Registry list/detail/compare/validate/activate/retire/rollback (`/api/model/registry*`), drift (`GET /api/model/drift`), evaluation
reports (`/api/model/eval*`). Activation and rollback change what the detector does: confirm dialogs with the consequence spelled out.

### P2 Experimental modules
PQC, TEE, bio-inspired, twin, edge (`/api/pqc|tee|bio|twin|edge/*`) are frozen by the owner's decision (docs/35 §9). Keep the existing
panels working, group them under "Experimental", do not invest further.

## 6. Contract change requests and proposed endpoints

When the UI needs something the API lacks: add a file in `frontend/contract/proposed/` (method, path, request, response example, which
screen needs it, why), mock it, and open an issue for the backend team. The backend team implements it (or proposes a different shape) and
re-exports fixtures; you then delete your proposed file.

Known proposals to start with (shapes are yours to draft; nothing here exists yet):

| Need | Proposed endpoint | Notes |
|---|---|---|
| Change own password | `POST /api/auth/password` | current + new password; any signed-in user; revokes the session; audited |
| Host triage list | `GET /api/hosts?sort=risk` | rank, host, confidence, top evidence, last seen |
| Host evidence | `GET /api/hosts/{host}/evidence` | detector, technique, time, destination, strength, flow ids |
| Analyst verdict | `POST /api/hosts/{host}/verdict` | `true` / `expected` / `false`, optional note; audited |
| Per-site allow-list view | `GET /api/allowlist` | periodic services learned or entered; read-only at first |
| Typed responses | response models on existing routes | backend work, so the generated types become trustworthy |

## 7. Quality bar (definition of done for every screen)

* Loading, empty, error, permission-denied and "no model" states all designed, not just the happy path.
* Works with keyboard only; visible focus; labels on all controls; colour is never the only signal (severity also as text); WCAG 2.1 AA
  contrast. Checked with the browser's accessibility tree and a contrast checker.
* Times in the user's local time zone with UTC on hover; byte counts and rates human-readable; scores with their threshold.
* Tests with Vitest + Testing Library for logic and for each state above (the repo already has tests under `src/**/*.test.tsx`);
  `npm run lint`, `npm run test`, `npm run build` all clean.
* Works at 1,280 px and at 390 px width; tables scroll inside their container, the page does not.
* No secrets, tokens or flow data in `localStorage`/`sessionStorage`; at most UI preferences (theme, collapsed panels).

## 8. Integration plan

| Checkpoint | When | Who | What happens |
|---|---|---|---|
| C0 Contract | before frontend work starts | backend | export `openapi.json`, fixtures (incl. errors and WebSocket), the proposed folder; agree the P0 list |
| C1 P0 against real backend | after P0 is done in mock mode | both | `npm run dev` against a local backend with demo data (`spectra demo`, then upload and train as in `docs/guide/first-run.md`); every P0 screen walked through with ADMIN, ANALYST and VIEWER; mismatches become contract issues |
| C2 Proposed endpoints | when the backend implements them | backend first, then frontend | backend ships the endpoints and new fixtures; frontend deletes the matching mocks |
| C3 Built bundle | before merge to `main` | backend | `scripts/build_release.sh` bundles the dashboard into the wheel; the served page passes the CSP (no console violations), the full backend test suite and frontend tests pass, notices file current |
| C4 Release candidate | with the first release | owner | manual walk-through on the container image; accessibility spot check |

**Drift guard (backend work):** a CI check that re-records the fixtures from a demo backend and fails when a response shape changes
without the fixtures being updated, so the frontend and backend cannot drift apart silently.

## 9. Working agreement

* Branch per feature (`frontend/<feature>`), pull requests that touch only `frontend/` (and `docs/frontend-*`); the backend team reviews
  any contract file change.
* Commit the generated types and fixtures; never hand-edit a fixture file (re-export it, or put the shape in `proposed/`).
* Report a backend bug as an issue with the request, the response and the fixture name; do not work around it in the UI silently.
* Questions about what a number means go to `docs/guide/alerts.md` and `docs/evaluation-report.md` first.
