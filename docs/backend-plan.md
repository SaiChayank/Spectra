# Backend plan: the owner's generic backend brief mapped onto Spectra

Status: **review round 1, 2026-11-19**, branch `backend/review-fixes`. The owner pasted a general backend brief (layered architecture,
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
| API | 101 HTTP routes + 1 WebSocket; OpenAPI exported to `frontend/contract/openapi.json` with a drift check |
| Auth | local accounts, scrypt, hashed session tokens, HttpOnly cookie or bearer, default-deny gate (`api/security.py`), RBAC ADMIN/ANALYST/VIEWER with permissions (`authz.py`), optional TOTP + recovery codes, escalating login throttle |
| Audit | hash-chained, signed audit log with key epochs (`modules/audit`), every admin action appended |
| Ops | request IDs + JSON access log (`api/middleware.py`), Prometheus `/api/metrics`, `/api/health` with a write probe, 503 + Retry-After on DB busy/disk full, backup/restore with a drill, Docker image, CI (tests, ruff, SAST, SCA, gitleaks, trivy) |
| Tests | 925 before this round (count from `scripts/check_readme_counts.py`, enforced in CI) |

## 2. The brief, item by item

Legend: **Exists** (built and tested), **Partial**, **Gap** (worth doing), **N/A** (does not fit this product), **Decision** (owner).

### Project setup
| Brief item | Status | Notes |
|---|---|---|
| Env-based config, secrets outside the repo | Exists | `config.py` (`SPECTRA_*`), `.env.example`, bootstrap password via env or a 0600 file |
| dev / staging / prod profiles | Partial | `SPECTRA_PROFILE=hardened` vs local default; no separate staging profile (single node) |
| Migrations | Exists | numbered, idempotent, atomic |
| Centralised error handling | Exists | handlers for 422 (never echoes input), 413, OverflowError, StoreUnavailable/ENOSPC → 503 |
| Request IDs + logging | Exists | `X-Request-ID` honoured or generated, path-only access log |
| `GET /health`, `GET /ready` | Partial | `/api/health` is liveness + write probe; no separate readiness. Only needed for an orchestrator; add when one is used |
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
| Self-service password change | **Gap (P1)** | non-admins cannot change their own password. Contract proposal exists: `frontend/contract/proposed/POST_api_auth_password.json` |
| List / revoke own sessions | Gap (P2) | today only a password change revokes all sessions |
| Account deactivation (disable without delete) | Gap (P2) | needs a migration (`users.disabled_at`) |
| Brute-force protection | Exists | per ip+user and per-ip throttle, escalating blocks, no enumeration (`tests/test_login_backoff.py`) |
| Log suspicious login activity | Partial (P2) | failed logins are deliberately not audited (unbounded writes); a throttle trip is not logged or counted either. Add a metric + one structured log line per block episode, without the attempted username |
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
| Security headers | Partial (P2) | full set on the served dashboard (`api/webui.py`); JSON API responses lack `X-Content-Type-Options: nosniff` and `Cache-Control` outside `/api/auth/*` |
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
* **Tests.** `tests/test_csrf_origin.py` (10): foreign, `null` and other-host origins refused on a body-less POST, a multipart upload,
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

## 4. Next tasks (proposed order, each a small reviewable change)

| # | Task | Implementation tasks | Needs |
|---|---|---|---|
| P1-1 | `POST /api/auth/password` (self-service change) | route + service using `_credentials` re-entry, policy check, throttle like TOTP routes, revoke the caller's *other* sessions and keep the current one, audit entry; allow/deny tests per role; export the contract fixture; README route count | owner OK to promote the proposed contract (auth code: review) |
| P2-1 | Throttle visibility | `spectra_login_throttled_total` counter, one structured warning per block episode (no username, no password), runbook line | none |
| P2-2 | JSON API headers | `X-Content-Type-Options: nosniff` on every `/api/` response, `Cache-Control: no-store` on identity and user routes; header test | none |
| P2-3 | Own sessions | `GET /api/auth/sessions`, `DELETE /api/auth/sessions/{id}` (own only, object-level test with two users) | review |
| P2-4 | Deactivate accounts | migration v14 `users.disabled_at`, login + validate refuse disabled users, last-ADMIN guard counts only active admins | review |
| D-1 | `/api/v1` and response envelope | see §2 | owner decision |
| D-2 | Outbound integrations (SIEM webhook) | see §2 | owner decision |

## 5. Running list

* **Completed this round:** backend review against the brief (this file); B-1 fixed and tested; B-2 fixed and tested.
* **Pending:** §4. Owner security review of B-1 and B-2 before merge. Nothing pushed.
* **Bugs found:** 2 · **fixed:** 2 · **open from earlier rounds:** see `HANDOFF_FINDINGS.md` (unchanged).
