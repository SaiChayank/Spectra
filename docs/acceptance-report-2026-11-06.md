# Spectra — Acceptance Report, Exit Gate 9

**Date:** 2026-11-06 · **Commit:** `a732881` (branch `phase9/exit-gate`, which contains Phases 9A–9H and the JA4 fix) · **Scope:** the Phase 9 gap-closure work (docs/33 §9A–9H) plus the whole existing acceptance surface, run against a **live server**. This report records what was run and what it returned; it makes no claim beyond that. It is not a sign-off — approvals are the owner's.

## 1. Method

* A fresh API server (`python -m spectra.cli serve --port 8787`) started on a **throwaway data directory and model path** (`SPECTRA_DATA_DIR`, `SPECTRA_MODEL_PATH` in a temp dir) with a generated admin password that is never printed, so no repo data or model file was touched.
* `python scripts/acceptance.py --skip-live` from `backend/`: signs in as the bootstrap admin and exercises every route group, the WebSocket, negative paths and the CLI sweep. The new `phase9` group (this commit) covers each Phase 9 feature through the HTTP API.
* The unit/integration suite and the other gates, run on the same commit (§4).
* The first live run (before the final commit) had the 9E drift check **vacuous** (the live window was empty, so it only warned); the check now scores a capture first. The run embedded below is the final one on the committed tree.

## 2. Result

**161 passed, 2 warnings, 0 failed of 163 checks; exit code 0.** pytest: **702 passed**. ruff, README count check, frontend lint/tsc/tests/build and `pip-audit` on the lockfile: clean (§4).

Warnings, both expected:

1. `incidents / GET /api/history/detections (anchor)` — the runner wants a persisted detection to anchor an incident test on; a brand-new instance has none flagged at that point (count=0), so it warns instead of failing. Pre-existing behaviour.
2. `live / live capture` — skipped with `--skip-live`: a live NIC capture needs Npcap/libpcap privileges and a network interface. **Not exercised in this run.**

## 3. Phase 9 coverage

| Phase | Feature | Live-API checks (`phase9` group) | Unit tests |
|---|---|---|---|
| 9A | windowed correlation (FR-2.2) | cascade echoes `window_s`; a window never widens sectors; `window_s=0` → 400; edges carry `first_ts/last_ts/flow_ids` | `test_corr.py` |
| 9B | adversarial harness (report only) | `POST /api/model/harden` returns `promoted: false`; active model unchanged; `model.harden` is audit-chained | `test_harden.py` (incl. the enabled scheduler running the real harden) |
| 9C | synthetic augmentation (opt-in) | train with `augment` is labelled `synthetic`; default training is not augmented | `test_augment.py` |
| 9D | per-host-pair beaconing | edges expose `regularity` | `test_bio.py`, `test_corr.py` |
| 9E | rolling PSI | drift reports `psi_vs_train`, `psi_vs_recent`, `alert_level` (the demo captures are too small to warm the reference, so `psi_vs_recent` correctly answers "warming up") | `test_drift.py` |
| 9F | audit key epochs | `rotate-key` returns public material only; the chain verifies across the rotation; pre- and post-rotation checkpoints verify | `test_audit_keys.py` |
| 9G | Shamir t-of-n + dropout | a round survives one dropped shareholder and one dropped party; no shares/nonces/seed in the response; too many drops → 400 | `test_federated_shamir.py` |
| 9H | twin/graph staleness | topology and graph report `hydrated_at` / `flow_lag` / `stale` | `test_twin_freshness.py` + vitest |
| fix | JA4 follows the FoxIO spec | every stored JA4 on real parsed demo flows matches the spec's shape | `test_ja4_spec.py` |

## 4. What this does NOT show

* **No accuracy claim.** Nothing here measures precision/recall on real or labelled traffic; the Phase B benchmark work in `docs/34_ship_plan.md` is still ahead. 9B/9C/9E results on synthetic data are in `HANDOFF_FINDINGS.md`, including the negative ones (augmentation does not harden the detector against evasion; the recent PSI does not catch slow drift sooner).
* **Live capture, the dashboard in a browser, long-running soak (e.g. a multi-hour scheduled harden run), and independent cryptographic review are not covered.** 9F/9G are crypto-adjacent and await human review.
* JA4S/JA4L are not built (JA4+ licensing — `HANDOFF_FINDINGS.md`, "9H findings").

## 5. Raw output — acceptance runner

```text
date: 2026-11-06T16:46:16Z
commit: a732881 (phase9/exit-gate)
python: Python 3.14.8
command: python scripts/acceptance.py --skip-live   (fresh server, throwaway data dir and model path)

== auth (local accounts, sessions, RBAC) ==
  [PASS] auth         unauthenticated request -> 401
  [PASS] auth         login failures are indistinguishable
  [PASS] auth         POST /api/auth/login
  [PASS] auth         session cookie is HttpOnly + SameSite=Lax
  [PASS] auth         login body carries no password or token material
  [PASS] auth         GET /api/auth/me (ADMIN identity)
  [PASS] auth         GET /api/users (no hash material)
  [PASS] auth         POST /api/users (create VIEWER)
  [PASS] auth         VIEWER login
  [PASS] auth         VIEWER reads the dashboard
  [PASS] auth         VIEWER denied capture/users/graph (403)
  [PASS] auth         DELETE /api/users/{id}
  [PASS] auth         deleted account's session dies with it
  [PASS] auth         POST /api/auth/logout
  [PASS] auth         logged-out token replayed -> 401
  [PASS] auth         re-login opens a fresh session
  [PASS] auth         session usable for the rest of the run
== core + capture ==
  [PASS] core         GET /api/health
  [PASS] core         GET /api/status
  [PASS] core         GET /api/stats
  [PASS] core         GET /api/flows
  [PASS] core         GET /api/detections
  [PASS] core         GET /api/interfaces
  [PASS] core         GET /api/metrics
  [PASS] core         metrics is Prometheus plaintext
  [PASS] core         GET /api/capabilities
  [PASS] core         GET /api/health/system
  [PASS] core         health reports all 14 subsystems with reasons
  [PASS] core         health overall state + counts are coherent
  [PASS] core         health metrics expose saturation, drops and latencies
  [PASS] core         responses carry X-Request-ID
  [PASS] core         POST /api/captures (import)
  [PASS] core         import stores under a generated name
  [PASS] core         duplicate import -> 409 with existing id
  [PASS] core         import rejects non-pcap extension -> 400
  [PASS] core         import rejects bad signature -> 400
  [PASS] core         traversal filename sanitized on import
  [PASS] core         GET /api/captures
  [PASS] core         GET /api/captures/{id}
  [PASS] core         POST /api/captures/{id}/process
  [PASS] core         capture completed
  [PASS] core         capture metadata persisted
  [PASS] core         no server filesystem paths exposed
  [PASS] core         status.source is the imported name
== incidents (analyst triage) ==
  [WARN] incidents    GET /api/history/detections (anchor)  — HTTP 200 count=0 keys=['count', 'offset', 'items'] items=0
== websocket ==
  [PASS] ws           anonymous WebSocket handshake refused
  [PASS] ws           flow + status events received
== model ==
  [PASS] model        POST /api/model/train
  [PASS] model        GET /api/model
  [PASS] model        GET /api/model/drift
  [PASS] model        GET /api/model/evasion
  [PASS] model        POST /api/model/robustness
== history ==
  [PASS] history      GET /api/history/flows
  [PASS] history      GET /api/history/detections
  [PASS] history      GET /api/history/captures
  [PASS] history      GET /api/history/stats
  [PASS] history      GET /api/history/model-runs
  [PASS] history      GET /api/history/events
== graph (Module 7) ==
  [PASS] graph        GET /api/graph/summary
  [PASS] graph        GET /api/graph
  [PASS] graph        GET /api/graph/node
  [PASS] graph        GET /api/graph/cascade
  [PASS] graph        GET /api/graph/path
== pqc (Module 1) ==
  [PASS] pqc          GET /api/pqc
  [PASS] pqc          GET /api/pqc/inventory
  [PASS] pqc          GET /api/pqc/scan
== audit (Module 5) ==
  [PASS] audit        GET /api/audit/head
  [PASS] audit        GET /api/audit/entries (key: items)
  [PASS] audit        GET /api/audit/verify
  [PASS] audit        POST /api/audit/checkpoint
  [PASS] audit        GET /api/audit/checkpoint/verify
  [PASS] audit        GET /api/audit/proof (capture.stop leaf 0)
  [PASS] audit        proof carries root + siblings
  [PASS] audit        POST /api/audit/certificate
  [PASS] audit        POST /api/audit/certificate/verify
== twin (Module 4) ==
  [PASS] twin         GET /api/twin/topology
  [PASS] twin         GET /api/twin/playbooks
  [PASS] twin         POST /api/twin/simulate
  [PASS] twin         POST /api/twin/playbook
  [PASS] twin         POST /api/twin/evaluate
  [PASS] twin         POST /api/twin/recommend
  [PASS] twin         POST /api/twin/shadow
== bio (Module 6) ==
  [PASS] bio          GET /api/bio/status
  [PASS] bio          POST /api/bio/assess
== tee (Module 2) ==
  [PASS] tee          POST /api/tee/attest
  [PASS] tee          POST /api/tee/verify (8 checks)
  [PASS] tee          verify rejects wrong measurement
  [PASS] tee          POST /api/tee/infer
  [PASS] tee          POST /api/tee/federate
  [PASS] tee          federate leaks no shares or seed
== edge (Module 8) ==
  [PASS] edge         GET /api/edge/report
  [PASS] edge         POST /api/edge/link (geo, scale 40)
  [PASS] edge         restore terrestrial link
  [PASS] edge         POST /api/edge/slice (urllc escalates)
  [PASS] edge         POST /api/edge/deploy
== adversarial (Module 3, via robustness probe above) ==
== phase 9 (gap closure) ==
  [PASS] phase9       9A cascade accepts window_s and echoes it
  [PASS] phase9       9A a window never widens the reachable sectors
  [PASS] phase9       9A window_s=0 is rejected (400)
  [PASS] phase9       9A edges carry first_ts/last_ts/flow_ids and 9D regularity
  [PASS] phase9       9B POST /api/model/harden reports, never promotes
  [PASS] phase9       9B the active model is unchanged by a harden run
  [PASS] phase9       9B harden runs are audit-chained
  [PASS] phase9       9C train --augment is labelled synthetic
  [PASS] phase9       9C default training is not augmented
  [PASS] phase9       9E drift reports psi_vs_train, psi_vs_recent and alert_level
  [PASS] phase9       9F POST /api/audit/rotate-key (public material only)
  [PASS] phase9       9F chain verifies across the rotation
  [PASS] phase9       9F a pre-rotation checkpoint still verifies
  [PASS] phase9       9F a post-rotation checkpoint verifies
  [PASS] phase9       9G Shamir round survives a dropped shareholder and a dropped party
  [PASS] phase9       9G federate response leaks no shares, nonces or seed
  [PASS] phase9       9G too many dropped shareholders is a 400
  [PASS] phase9       9H twin topology reports hydrated_at / flow_lag / stale
  [PASS] phase9       9H graph snapshot carries freshness
  [PASS] phase9       JA4 strings on stored flows match the FoxIO format
== negative paths ==
  [PASS] negative     train missing field -> 422
  [PASS] negative     train by pcap_path is gone -> 422
  [PASS] negative     pqc/scan unknown capture -> 404
  [PASS] negative     pqc/scan without capture_id -> 422
  [PASS] negative     graph/node unknown -> 404
  [PASS] negative     bio/assess wrong length -> 400
  [PASS] negative     tee/federate 1 party -> 400
  [PASS] negative     edge/link unknown -> 400
  [PASS] negative     capture/start bad mode -> 422
  [PASS] negative     capture/start pcap mode is gone -> 422
  [PASS] negative     capture details unknown -> 404
  [PASS] negative     capture process unknown -> 404
  [PASS] negative     audit/proof far seq -> 404
  [PASS] negative     twin/simulate rounds over cap -> 422
  [PASS] negative     DELETE /api/captures/{id}
  [PASS] negative     deleted capture is gone
  [PASS] negative     re-import after delete allowed
== CLI sweep ==
  [PASS] cli          spectra demo
  [PASS] cli          spectra train
  [PASS] cli          spectra scan
  [PASS] cli          spectra pqc
  [PASS] cli          spectra adversarial
  [PASS] cli          spectra audit entries
  [PASS] cli          spectra audit verify
  [PASS] cli          spectra audit checkpoint
  [PASS] cli          spectra audit proof
  [PASS] cli          spectra audit certify
  [PASS] cli          spectra audit verify-cert
  [PASS] cli          spectra audit profiles
  [PASS] cli          spectra twin topology
  [PASS] cli          spectra twin playbooks
  [PASS] cli          spectra twin simulate
  [PASS] cli          spectra twin playbook
  [PASS] cli          spectra twin shadow
  [PASS] cli          spectra bio status
  [PASS] cli          spectra bio assess
  [PASS] cli          spectra tee attest
  [PASS] cli          spectra tee verify
  [PASS] cli          spectra tee infer
  [PASS] cli          spectra tee federate
  [PASS] cli          spectra edge report
  [PASS] cli          spectra edge link
  [PASS] cli          spectra edge link restore
  [PASS] cli          spectra edge slice
  [PASS] cli          spectra edge deploy
  [PASS] cli          spectra status
  [PASS] cli          spectra serve  — covered by the running acceptance server
== live capture (Npcap-gated) ==
  [WARN] live         live capture  — skipped via --skip-live

161 passed, 2 warnings, 0 failed of 163 checks
exit code: 0
```

## 6. Raw output — other gates (same commit)

```text
## ruff
ruff 0.17.4
All checks passed!

## pytest
702 passed, 807 warnings in 93.20s (0:01:33)

## README counts
measured: {'tests': 702, 'api': 97, 'cli': 15}
README counts match the code

## frontend

tsc: clean
 Test Files  4 passed (4)
      Tests  11 passed (11)
✓ built in 255ms

## pip-audit (lockfile)
WARNING:pip_audit._cli:Consider using a tool like `pip-compile`: https://pip-tools.readthedocs.io/en/latest/#using-hashes
No known vulnerabilities found
```

eslint exit code: 0 (it prints nothing when clean).
