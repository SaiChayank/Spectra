# Gap analysis and task board (living document, started 2026-11-25)

Owner brief of 2026-11-25: compare the current state with the final product, plan the remaining work, then execute it in order.
**Final product** (README, `docs/33_implementation_plan.md`, `HANDOFF.md`): a metadata-only encrypted-traffic threat-detection platform
that a small security team can install, sign into by role, and trust: it finds threats in real traffic at an alert volume a person can
read, explains them, and is secure, tested, documented and deployable.

Every row below was checked against code, tests or a recorded run on 2026-11-24/25. Evidence is linked, not assumed.

## 1. Where the product stands

| Area | State | Evidence |
|---|---|---|
| Detection on real traffic | **The core gap.** Isolation forest: recall about 0 at a 1 % false-alarm rate on CTU-13, HIKARI and CIC-2018. Beacon v2a1 and v3 both failed their preregistered gates | `docs/evaluation-report.md` §10-§21 |
| Capture, parsing, features, storage, audit, auth, API (105-108 routes) | Built, tested (973-991 tests per branch), CI | clean-clone runs in `HANDOFF_PROGRESS.md` |
| Frontend (Cyntra redesign) | Built on `frontend/cyntra-design` (12 pages, 88 tests) but **not merged**, and written against *proposed* contracts | this file, §2 |
| Backend fixes (CSRF, races, sessions) | On `backend/review-fixes` (pushed, not merged), awaiting the owner's security review | `docs/backend-plan.md` |
| Packaging, Docker, backups, monitoring | Built and drilled | `docs/runbook.md`, `docs/monitoring.md` |

## 2. Gaps (each: current -> expected, why, fix, priority / complexity)

| ID | Gap | Current | Expected | Why it matters | Fix | Pri | Size |
|---|---|---|---|---|---|---|---|
| G-01 | Detection accuracy | ~0 recall at 1 % FPR; v3 fused 0/33 C2 pairs | >= 30 % at <= 1 % on two datasets + an alert budget on the owner's network | it is the product | finish E22 (set C, task 14), then a design that does not need a clean learning window (supervised E3 on leave-family-out splits, peer prevalence) | Critical | XL |
| G-02 | Frontend and backend live on separate branches | three unmerged branches | one tested `main` | the shipped app is the old UI | integrate locally (`frontend/integration`), owner reviews and merges | Critical | M |
| G-03 | Password change UI uses the proposed contract | expects `sessions_revoked`, maps 401 to "wrong password", falls back to `PATCH /api/users` | real contract: `{ok, sign_in_required}`, wrong password = **403** | a typo would be shown as "signed out" / wrong message | update type, mapping, mock and tests | High | S |
| G-04 | Hosts page is a placeholder | text says the routes "do not exist" | ranked host list + evidence + verdict on `GET/POST /api/hosts*` (built on `main`) | host triage is the E4 product surface | build the page against the real contract | High | L |
| G-05 | No "my sessions" UI | backend route exists on `backend/review-fixes` only | Account page lists sessions, ends one | users cannot see or end other sign-ins | after G-02 merges that branch | Medium | M |
| G-06 | Contract types are hand-written | `types.ts` drifts from `openapi.json` | types generated or checked against the contract in CI | G-03 is this kind of drift | add a contract-vs-types check | Medium | M |
| G-07 | snn_score fix not confirmed on a second CPU | fixed on `detection/accuracy-v3` | CI on another CPU agrees, fixtures record real scores again | reproducibility | after merge, check CI | Low | S |
| G-08 | Owner security review not done | B-1, B-2, B-5, B-6, sessions, throttle | reviewed and signed off by the owner | project rule §6 | [HUMAN] | High | - |
| G-09 | Live-capture sizing, own-network baselines | not run | measured | sizing guide, alert budget | [HUMAN] tasks 13, 14 | Medium | - |
| G-10 | Password policy length-only | 8-1024 chars | owner decision D-3 | weak passwords | [DECISION] | Medium | S |
| G-11 | Phase 12 (SIEM webhook, multi-tenant, HW TEE, multi-node) | not built | only when a deployment needs it | out of scope until G-01 | deferred | Low | XL |

## 3. Prioritised order and why

1. **G-02 + G-03** (Critical/High, small, unblock everything user-facing): integrate the branches locally and fix the contract drift the
   integration exposes. Done first because every frontend test after this runs against the real API.
2. **G-04** Hosts page: the one product screen still missing, and the surface the detection work feeds.
3. **G-06** contract check: prevents the next G-03.
4. **G-05** sessions UI: depends on `backend/review-fixes` joining the integration branch (owner review, G-08).
5. **G-01** continues in parallel where it waits on data (set C running, task 14 on the owner).
6. G-07, G-10, G-11 as listed.

## 4. Task board

| Task | Status | Branch / notes |
|---|---|---|
| E22 set C (H1) | In progress | run `setc-20261124T1950Z` (first run voided: VM shut down at 0.95 h) |
| E22 own network #2 (H2) | Blocked | owner task 14 |
| G-02 integration branch | Completed (local) | `frontend/integration` = `frontend/cyntra-design` + `origin/main`; not pushed |
| G-03 password contract | Completed | `ac506db`: real contract, 403 handling, two-factor code field; 89 -> tests green |
| G-04 Hosts page | Completed (needs review) | ranked list, evidence timeline, verdict form gated by `incidents:manage`; 6 tests on the recorded fixtures; not checked in a browser (port 5173 held by another process) |
| G-06 contract-vs-types check | Completed | `src/lib/contract.typecheck.ts`: tsc compares recorded fixtures with the UI types both ways; reintroducing the G-03 bug fails the build; found and removed a phantom `ManagedUser.totp_enabled` |
| G-05 sessions UI | Blocked | needs `backend/review-fixes` merged (G-08) |
| G-08 owner security review | Needs review | owner |
| G-10 password policy | Blocked | owner decision |
| G-11 Phase 12 | Deferred | |

## 5. Decisions taken under the brief's autonomy

| Decision | Why | Alternatives | Risk |
|---|---|---|---|
| Integrate on a local branch, do not merge to `main` or push | the repo rules require the owner's word for pushes and the owner's review of auth code | merging to `main` directly | none; reversible |
| Follow the backend contract (403 on a wrong current password), not the old proposal | the backend is merged on `main` and its tests pin 403 | change the backend to 401 | none |
