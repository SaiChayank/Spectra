# Backend plan: the owner's generic backend brief mapped onto Spectra

Status: **rounds 1-3, 2026-11-19/20**, branch `backend/review-fixes`. The owner pasted a general backend brief (layered architecture,
auth, CRUD, files, notifications, jobs, payments, admin, integrations, security, performance, tests, observability, docs). This file
checks every part of that brief against the code as it is, says what already exists (with the file that does it), what does not apply
to a single-node, metadata-only detection tool, what needs an owner decision, and what is next. It does not replace `HANDOFF.md`,
`docs/project-rules.md` or `docs/35_threat_engine_plan.md`. Where the brief and those disagree, the project rules win (R40).

## 1. What the backend is today

| Area | Implementation |
|---|---|
| Stack | Python 3.11-3.13, FastAPI, SQLite (WAL), scikit-learn IsolationForest, own pcap reader (ADR-011 branch) / scapy |
| Layers | `api/routers/*` (HTTP only) → `services/*` (business logic) → `store.py` facade → `db/repositories.py` (SQL) → `db/connection.py` |
| Schema | 13 numbered migrations in `db/migrations.py`, forward-only, upgrade-tested (`tests/test_migrations.py`) |
| API | 106 HTTP routes + 1 WebSocket after the rebase onto `main` (101 before this review); OpenAPI exported to `frontend/contract/openapi.json` with a drift check |
| Auth | local accounts, scrypt, hashed session tokens, HttpOnly cookie or bearer, default-deny gate (`api/security.py`), RBAC ADMIN/ANALYST/VIEWER with permissions (`authz.py`), optional TOTP + recovery codes, escalating login throttle |
| Audit | hash-chained, signed audit log with key epochs (`modules/audit`), every admin action appended |
| Ops | request IDs + JSON access log (`api/middleware.py`), Prometheus `/api/metrics`, `/api/health` with a write probe, 503 + Retry-After on DB busy/disk full, backup/restore with a drill, Docker image, CI (tests, ruff, SAST, SCA, gitleaks, trivy) |
| Tests | 925 before round 1, 953 after round 2; 982 after the rebase onto `main` (948 on `main` + 34 from this branch) (count from `scripts/check_readme_counts.py`, enforced in CI) |

## 2. The brief, item by item

Legend: **Exists** (built and tested), **Partial**, **Gap** (worth doing), **N/A** (does not fit this product), **Decision** (owner).

### Project setup
| Brief item | Status | Notes |
|---|---|---|
| Env-based config, secrets outside the repo | Exists | `config.py` (`SPECTRA_*`), `.env.example`, bootstrap password via env or a 0600 file |
| dev / staging / prod profiles | Partial | `SPECTRA_PROFILE=hardened` vs local default; no separate staging profile (single node) |
| Migrations | Exists | numbered, idempotent, atomic |
| Centralised error handling | Exists | handlers for 422 (never echoes input), 413, OverflowError, StoreUnavailable/ENOSPC → 503; round 2: a JSON 500 with the request id for anything unmapped (was plain text, no id, no CORS) |
| Request IDs + logging | Exists | `X-Request-ID` honoured or generated, path-only access log |
| `GET /health`, `GET /ready` | Exists (round 2) | `/api/health` liveness + write probe; `/api/ready` readiness (storage writable, schema current). Kept under `/api/` like every other route; a root alias is a one-line change if a platform requires it |
| `/api/v1/` versioning | **Decision** | renaming 101 routes breaks the dashboard and the contract check. Option: add `/api/v1` as an alias later and freeze `/api` |
| `{success, data, message}` envelope | **Decision** | the API returns plain JSON and `{"detail": ...}` errors (FastAPI standard) across 101 routes and the frontend contract. Recommendation: keep it; if a machine-readable error code is wanted, add a `code` field next to `detail` without changing the shape |

### Database
| Brief item | Status | Notes |
|---|---|---|
| Keys, FKs, indexes, constraints | Exists | FKs on, `ON DELETE CASCADE` for sessions/TOTP, indexes per migration |
| created/updated timestamps | Exists | on users, captures, incidents, alerts, model registry |
| created_by / updated_by | Partial | the audit log records the actor of every change; columns only where the UI needs them (incident notes, registry) |
| Soft deletes | N/A mostly | flows/alerts follow retention, not soft delete; user deletion is recorded in the audit chain |
| Transactions for multi-step writes | Exists | `Database.transaction()` (BEGIN IMMEDIATE) |
| Pagination | Exists | every list route has bounded `limit`/`offset` (`le=500..2000`); `/api/users` is unpaginated (tens of rows) |
| Injection safety | Exists | parameterised SQL; Bandit B608 hits reviewed and pinned by `tests/test_sql_hostile_input.py` |

### Authentication and authorisation
| Brief item | Status | Notes |
|---|---|---|
| Login, logout, sessions, RBAC + permissions | Exists | see §1 |
| Self-registration, email verification, password reset by email | N/A | no mail server; accounts are created by an ADMIN; a forgotten password is reset by an ADMIN or `spectra auth` CLI |
| Refresh tokens | N/A | server-side sessions with a fixed TTL, revocable at once; JWT refresh tokens would add risk without benefit here |
| Self-service password change | Exists | `POST /api/auth/password` (built on `main`); race fixes here, see §6 |
| List / revoke own sessions | Gap (P2) | today only a password change revokes all sessions |
| Account deactivation (disable without delete) | Gap (P2) | needs a migration (`users.disabled_at`) |
| Brute-force protection | Exists | per ip+user and per-ip throttle, escalating blocks, no enumeration (`tests/test_login_backoff.py`) |
| Log suspicious login activity | Exists (round 2) | failed logins are deliberately not audited (unbounded writes); each throttle block now logs one `login_throttled` line (scope, length, strikes; no username or address) and counts in `spectra_login_blocks_total` |
| Object-level authorisation | Exists for this model | single-tenant: every analyst sees every incident by design; per-user objects (sessions, TOTP) are keyed to the principal |
| CSRF | **Fixed this round** | see §3, B-1 |

### Product modules
| Brief module | Status | Notes |
|---|---|---|
| Core entities + CRUD, workflows, filters | Exists | captures, flows, detections, alerts (OPEN→ACKNOWLEDGED→RESOLVED), incidents (state machine + notes), model registry (validate/activate/retire/rollback), users |
| File upload | Exists | PCAP only: basename, extension + magic, streamed size cap, uuid names, sanitised to metadata on ingest |
| Malware scanning, image optimisation, CDN, signed URLs | N/A | uploads are captures that are parsed, never served back |
| Notifications (email/push/in-app) | N/A / **Decision** | live alerts go over the WebSocket; a SIEM/webhook export is listed as "only if authorised" |
| Background jobs | Exists (in-process) | capture processing, batch writer, harden scheduler, retention; bounded queues with drop telemetry. No external queue (single node) |
| Payments, billing | N/A | |
| Admin APIs | Exists | users, TOTP reset, audit, key rotation, model registry; sensitive actions audit-chained |
| Integrations, OAuth, outbound webhooks | **Decision** | none today; every outbound call would need timeouts, retries and SSRF rules (R25) |

### Security, performance, tests, observability, docs
| Brief item | Status | Notes |
|---|---|---|
| Input validation, size limits | Exists | Pydantic bounds on every body/query, 4 MB JSON cap, capture cap |
| Security headers | Exists (round 2) | full set on the served dashboard (`api/webui.py`); every `/api/` response now has `nosniff`. `no-store` stays on `/api/auth/*` only: `tests/test_hardening.py` pins that scope, and JSON responses carry no validators, so browsers do not cache them heuristically |
| CORS | Exists | explicit origin list, credentials only for those |
| Never expose stack traces/secrets | Exists | generic bodies; 422 never echoes input; log scrubbing test |
| Dependency scanning | Exists | pip-audit, npm audit, trivy, licence policy in CI |
| Caching, compression | N/A for now | local network; measure before adding |
| Load testing | Partial | offline throughput measured (§ evaluation report); API load not measured |
| Test layers | Exists | unit, API, migration, end-to-end capture, metadata-only probe, acceptance script against a live server |
| Metrics, alerts, dashboards | Exists | Prometheus series + 8 alert rules (`docs/monitoring.md`) |
| Docs | Exists | architecture, security, runbook, retention, testing, ADRs; this file adds the brief mapping |

## 3. Bugs found and fixed in this round

### B-1 · CSRF: cookie-authenticated writes accepted from any same-site page (High)

* **Issue.** 16 state-changing POST routes take no JSON body (model registry activate/rollback/retire, audit checkpoint and
  key rotation, capture stop, alert/incident state changes, logout) and one takes multipart (capture upload). An HTML form can send
  those without a CORS preflight.
* **Why it matters.** The session cookie is `SameSite=Lax`, which stops cross-*site* requests. But another port on the same host
  (`localhost:9999`) or a sibling subdomain is the *same site*, so the browser attaches the operator's cookie. Any page there could
  roll back the model, rotate the audit key or resolve alerts as the signed-in admin. The test proved it: a forged logout ended the
  shared test session.
* **Root cause.** The WebSocket already checked `Origin` (cross-site WebSocket hijacking), but the HTTP gate relied on SameSite and
  CORS alone. CORS only protects requests that need a preflight.
* **Fix.** `api/security.py`: the default-deny gate refuses any POST/PUT/PATCH/DELETE under `/api/` whose `Origin` header is
  present and is neither a configured dashboard origin nor the API's own host (403 `cross-origin request refused`). It runs before the
  public-route branch, so login CSRF is refused too. Requests without `Origin` (curl, scripts, CLI) are unchanged: browsers always send
  `Origin` on a POST, so a forged form cannot omit it. The WebSocket and HTTP checks now share one `origin_allowed()`.
* **Tests.** `tests/test_csrf_origin.py` (11): foreign, `null` and other-host origins refused on a body-less POST, a multipart upload,
  logout and login; dashboard origins, same-origin, no-Origin requests and reads still pass. All refusal cases failed before the fix.
* **Review.** Access-control code: needs the owner's security review before merge (project rules §6).

### B-2 · Last-ADMIN guard could be raced to zero admins (Medium)

* **Issue.** `AuthService.update_user`/`delete_user` read the ADMIN count, then wrote in a separate statement.
* **Why it matters.** Two admins demoting or deleting each other at the same moment could both read "2 admins", both pass, and leave
  no ADMIN. Recovery would need shell access to the server.
* **Root cause.** Check-then-act across two statements (FastAPI runs sync routes in a thread pool, so two requests can interleave).
* **Fix.** `db/repositories.py`: the demoting `UPDATE` and the `DELETE` carry the guard in their own `WHERE` clause (the row only
  matches if it is not the last ADMIN), so the check and the write are one statement. The service keeps its early, friendly check and
  maps a refused write to the same `UserGuardError` (409).
* **Tests.** `tests/test_admin_guard_race.py` (4): replays the interleaving by pinning the count both racers read; demote/demote,
  delete/delete and demote/delete each keep one ADMIN; ordinary changes still work. The three race tests failed before the fix.

### Round 2 (foundation)

| Change | Why | Tests |
|---|---|---|
| `UnhandledErrorMiddleware` (`api/middleware.py`) | an unmapped exception answered Starlette's plain-text 500: no request id to quote, and no CORS headers, so the dashboard showed "cannot reach the server" instead of an error | `test_api_foundation.py`: JSON body, `X-Request-ID`, CORS kept, traceback logged under the id, no exception text in the body |
| `GET /api/ready` (`services/system.py::readiness`) | the brief's readiness probe; liveness alone cannot tell an orchestrator that the schema is behind | 200 when ready; 503 on unwritable storage or a schema behind; a busy database stays ready |
| `X-Content-Type-Options: nosniff` on `/api/` | API bodies must never be sniffed into HTML | four routes, metrics and a 401 |
| throttle log + `spectra_login_blocks_total` | brute force was invisible to operators | one line per block, no username/address, metric present |

All 13 tests failed on the round-1 code and pass now. The contract export gained `/api/ready` (openapi + one fixture).

Found, not changed: on this machine (WSL, Python 3.12.3, numpy 2.5.4, scikit-learn 1.9.1, the locked versions) the
contract export records `snn_score` 63.41 where the committed fixtures have 65.85 (three flow fixtures), on unmodified `main`
too, so `test_frontend_contract_is_current` fails here. The bio SNN score is not reproducible across machines; see
`HANDOFF_FINDINGS.md`.

## 4. Next tasks (proposed order, each a small reviewable change)

| # | Task | Implementation tasks | Needs |
|---|---|---|---|
| P2-2 | SNN score reproducibility | find why `snn_score` differs across machines (seeding, float order) and make it deterministic, or exclude it from the contract recording | none |
| P2-3 | Own sessions | `GET /api/auth/sessions`, `DELETE /api/auth/sessions/{id}` (own only, object-level test with two users) | review |
| P2-4 | Deactivate accounts | migration v14 `users.disabled_at`, login + validate refuse disabled users, last-ADMIN guard counts only active admins | review |
| D-1 | `/api/v1` and response envelope | see §2 | owner decision |
| D-2 | Outbound integrations (SIEM webhook) | see §2 | owner decision |

## 5. Current backend status (round 3 re-assessment, 2026-11-20)

"Complete" here means: endpoint, validation, authentication, authorisation, safe queries, error handling, edge cases and tests are
all present, with no known bug. It does not mean the owner's security review has happened (§7).

| Feature | Status | Missing before "done" |
|---|---|---|
| Login / logout / `me` | COMPLETE (round 3 fixed B-5) | owner review |
| Own password change | COMPLETE (`main`'s route; B-5/B-6 fixed here) | owner review; frontend form |
| TOTP second factor + recovery codes | COMPLETE | owner review (already open from Phase 10) |
| Login throttle | COMPLETE | |
| User management (ADMIN) | COMPLETE (B-2, B-6 fixed) | `/api/users` is unpaginated (tens of rows; fine) |
| Own sessions list / revoke | COMPLETE (round 4) | owner review |
| Account deactivation | NOT STARTED | P2-4 (migration v14) |
| Password policy | NEEDS IMPROVEMENT | length only (8-1024); no common/breached-password list. Decision D-3 |
| Captures (upload, process, delete) | COMPLETE | |
| Flows, detections, history | COMPLETE | |
| Alerts (OPEN→ACK→RESOLVED) | COMPLETE | transitions are single conditional `UPDATE`s (checked this round) |
| Incidents (state machine, notes) | COMPLETE | transitions are conditional `UPDATE`s (checked this round) |
| Investigation | COMPLETE | not re-read line by line this round |
| Model registry | COMPLETE | writes serialised by a process lock (single node) |
| Audit log (chain, checkpoints, key epochs) | COMPLETE | owner review of key epochs (open from Phase 9F) |
| Bio / SNN score | HAS BUGS | score differs across CPUs; `main` made it a constant in the contract fixtures (e586f2b), so the contract check passes, but the score itself is still not reproducible (P2-2) |
| Twin, graph, edge, TEE, PQC | maturity as reported by `GET /api/capabilities` | not re-assessed this round |
| Health, ready, metrics | COMPLETE | |
| CSRF / origin check | COMPLETE (round 1) | owner review |

## 6. Round 3: bugs found

### B-5 · A login could outrun a password reset (Medium)

* **Affected area.** `AuthService.login` → `Store.create_session`.
* **Description.** Login read the stored hash, ran scrypt (about 0.1 s), then inserted the session. An ADMIN reset that landed
  during the scrypt check revoked every existing session but could not see the one about to be created, so an attacker using the
  old (compromised) password kept a fresh 12-hour session after the reset meant to lock them out.
* **Root cause.** Check (password verify) and act (session insert) were separate, with no link between the verified hash and
  the insert.
* **Fix.** `SessionRepository.create_if_password`: `INSERT … SELECT … WHERE EXISTS (users.id = ? AND password_hash = ?)`, with the
  hash login verified. If the hash changed, no row is inserted and login answers the usual 401. The in-place rehash at login is
  now a compare-and-swap on the verified hash too (`UserRepository.rehash`), so it can never overwrite a concurrent reset.
* **Tests.** `test_login_racing_a_password_reset_opens_no_session` (failed before), `test_login_still_works_after_an_in_place_rehash`.
* **Prevention.** Writes that depend on a check carry the check in their own `WHERE` clause (same pattern as B-2).

### B-6 · Password change and session revocation were two commits (Medium)

* **Affected area.** `AuthService.update_user` (`PATCH /api/users/{id}`).
* **Description.** The new hash was committed, then sessions were deleted in a second statement. A failure in between (disk full,
  locked database, crash) left the new password in place and every old session alive, though the API promises revocation.
* **Fix.** `UserRepository.change_password` runs the `UPDATE` and the `DELETE FROM sessions` inside `Database.transaction()`.
* **Tests.** `test_admin_reset_and_revocation_are_one_transaction` and `test_own_change_and_revocation_are_one_transaction` inject a failure into the `DELETE` and checks that neither
  half landed (failed before).

### `POST /api/auth/password` (built on `main` in parallel)

While this branch was open, `main` gained its own `POST /api/auth/password` (commit b7aa6e3): a wrong current password answers
403 (so the dashboard does not read it as "signed out"), and a successful change revokes every session, the caller's included.
The rebase (2026-11-24) kept `main`'s route, contract and tests (`test_change_password.py`) unchanged and dropped this branch's
duplicate route. What this branch adds underneath it: the change is a compare-and-swap on the verified hash and runs in the same
transaction as the revocation (B-6), and login cannot outrun it (B-5).

| Tests (`tests/test_password_change.py`, 6) | what they pin |
|---|---|
| `test_login_racing_a_password_reset_opens_no_session` | B-5 |
| `test_login_still_works_after_an_in_place_rehash` | the B-5 guard does not break the login rehash |
| `test_admin_reset_and_revocation_are_one_transaction` | B-6, admin path |
| `test_own_change_and_revocation_are_one_transaction` | B-6, self-service path |
| `test_own_change_revokes_every_session` | `main`'s semantics kept |
| `test_two_racing_self_changes_cannot_both_win` | compare-and-swap |

Checked, no change needed: alert and incident state changes are single conditional `UPDATE`s; model registry writes are
serialised by a process lock; no CLI path sets a password (the only password writers are the service methods above and the
login rehash).

## 7. Next tasks and decisions

| # | Task | Needs |
|---|---|---|
| P2-4 | Account deactivation: migration v14 `users.disabled_at`; login, validate and the last-ADMIN guard ignore disabled accounts | review |
| P2-2 | SNN score reproducibility | none |
| FE-1 | Frontend: "Change password" form on the account menu using the new route | frontend branch |
| D-1 | `/api/v1` and response envelope | owner decision (recommend: keep) |
| D-2 | Outbound integrations (SIEM webhook) | owner decision |
| D-3 | Password policy: keep length-only, or add a common-password list (offline, no network) and raise the minimum | owner decision |

## 8. Running list

* **Completed:** round 1 - review, B-1 CSRF, B-2 last-ADMIN race. Round 2 - JSON 500 with request id, `/api/ready`, `nosniff`,
  throttle log + metric. Round 3 - B-5, B-6, status re-assessment (§5); rebased onto `main` 2026-11-24. Round 4 - own sessions list / end (`tests/test_own_sessions.py`, 11 tests).
* **Pending:** §7. Owner security review of B-1, B-2, B-5, B-6, and the throttle change before merge.
* **Bugs found:** 6 (B-1, B-2, plain-text 500, `snn_score`, B-5, B-6) · **fixed:** 5 · **open:** `snn_score`.
* **Tests added:** 34 (`test_csrf_origin.py` 11, `test_admin_guard_race.py` 4, `test_api_foundation.py` 13,
  `test_password_change.py` 6).
