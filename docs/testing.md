# Spectra — Testing & verification

Four layers of evidence: the pytest suite, the acceptance runner against a live
server, performance measurement against a recorded baseline, and live NIC
capture validation. All were run on the committed tree before this document was
written; commands reproduce them exactly.

---

## 1. Automated tests (pytest)

```powershell
cd backend
pip install -r requirements-dev.txt     # pytest>=8
python -m pytest tests -q               # → 496 passed
```

| | |
|---|---|
| Result | **496 passed, 0 failed, 0 skipped-by-default** (~70–82 s) |
| Files | 33 test modules (+ `conftest.py`) |
| Style | hermetic: `conftest.py` points `SPECTRA_DATA_DIR` at a temp dir **before** importing `spectra`, sets a test-only admin password, runs migrations + bootstrap, and logs in once — no server, no network, no shared state |
| Policy | no test is skipped to make the suite green; the only conditional sections are capability-gated (live capture) and are reported as such |

| Area | Modules |
|---|---|
| Parsing & flows | `test_tls`, `test_quic`, `test_flow`, `test_edge` (IPv6/VLAN/ARP/mid-stream/corrupt PCAPs), `test_filters` |
| ML | `test_model` (fast path bit-identical to sklearn), `test_model_registry` (lifecycle, gates, rollback, role gates) |
| Detection semantics | `test_threats` (explainable categories), `test_alerts` (severity/evidence/grouping), `test_incidents`, `test_incident_alerts`, `test_investigation` |
| Runtime & persistence | `test_streaming` (bounded queues, overload, shutdown), `test_store`, `test_repositories`, `test_migrations` (11 migrations, idempotency, adoption) |
| Security | `test_auth` (login/session/RBAC/default-deny sweep/WS), **`test_hardening`** (28 regression tests: body limits, throttle, scrypt work factor, WS origin + revalidation, 422/500 shaping, runtime budgets, persistence caps, crafted PCAPs) |
| Modules | `test_pqc`, `test_tee`, `test_adv`, `test_twin`, `test_audit`, `test_bio`, `test_corr`, `test_edge_native` |
| Contracts & honesty | `test_module_contracts` (no false availability/scoring claims), `test_integrity` (federated privacy, metrics format, failure isolation) |
| API & end-to-end | `test_api`, `test_capture_resources`, `test_health`, `test_end_to_end` (train → detect) |

**Frontend:** no automated test runner exists (documented limitation
[limitations.md §9](./limitations.md)); it is verified by `tsc` + a production
build:

```powershell
cd frontend
npm run build          # tsc && vite build → exit 0
```

## 2. Acceptance runner (live server)

```powershell
# terminal 1
cd backend
$env:SPECTRA_ADMIN_PASSWORD='<admin password>'
python -m spectra.cli serve --port 8787

# terminal 2
cd backend
python scripts/acceptance.py           # add --skip-cli / --skip-ws / --skip-live to trim
```

**Result: 156 / 156 checks, 0 warnings.** Exit code 0 = no FAIL (1 = ≥ 1 FAIL),
so it is CI-usable as-is.

What it covers:

* **Authentication group** — login success/failure, session visibility,
  logout, RBAC for all three roles.
* **Every route group** on the live API with a real session cookie (92 HTTP
  routes across 16 routers), plus `WS /ws/events` handshake with the token.
* **Negative paths** — 400, 401, 403, 404, 409, 413, 422, 429, 4401, 4403 and
  the generic 500, plus digest refusal, artifact path escape and
  last-admin/self-lockout attempts.
* **CLI sweep** — all 12 subcommands against `backend/demo_pcaps/`.
* **Live capture section** — gated on Npcap (§4); skipped, never faked.

## 3. Performance measurement

```powershell
cd backend
python scripts/perf.py                   # full run; --quick for a smoke pass; --json out.json
```

`perf.py` is hermetic (temp data dir + temp model path) and times eight
benchmarks plus training. Reference machine: Windows, Python 3.13,
scikit-learn wheel.

| Path | Baseline (`acceptance-report.md` §5) | Current | Verdict |
|---|---|---|---|
| Edge micro-detector p50 | 0.0098 ms | 0.0081–0.0171 ms | at/below baseline |
| Edge micro p95 (10 ms budget) | 0.0189 ms | 0.0085–0.0239 ms | within budget (~400× margin) |
| Detector `score()` p50 | 0.269 ms | 0.248–0.558 ms (A/B mean 0.271) | equal |
| Detector `score()` p95 | 0.457 ms | 0.317–0.957 ms (A/B mean 0.415) | equal/better |
| `explain()` p50 | 0.040 ms | 0.034–0.065 ms | equal |
| Offline scan of `suspicious.pcap` | 0.348 s | 0.073–0.137 s | faster (method differs) |
| Detection output | 288 → 13 → 5 | 288 → 13 → 5 | identical |

New measurements (no prior baseline): flow tracking **26–35 k pkt/s**,
batched persistence **42–76 k rows/s**, queue hand-off **0.96–1.41 µs/item**,
event-bus fan-out **0.42–0.87 µs/event**, in-process API p50 **0.89–2.90 ms**,
WS first message **1.40–2.28 ms**, offline training **0.49–1.12 s**.

**Method:** sub-millisecond desktop numbers move ±30 % with background load.
Comparisons use *interleaved A/B pairs* against a clean worktree of the
previous commit, not single runs — that analysis showed −1.3 % … +2.6 %
(i.e. no regression). Full tables and caveats:
`docs/hardening-report.md` §4.

## 4. Live capture validation

* Npcap **1.88** on Windows, validated **2026-09-29**
  (`docs/acceptance-report.md` §6): a `live` capture starts, counts packets,
  and stops through the API with the session cookie.
* The acceptance runner executes this section whenever the driver is present;
  without Npcap the checks are **skipped and reported**, never counted as
  passed.
* Capture is verified to be passive (no packets transmitted) and read-only.

## 5. Documentation ↔ evidence cross-check

| Claim | Where it is proven |
|---|---|
| 496 tests pass | `python -m pytest tests -q` |
| 156/156 acceptance | `python scripts/acceptance.py` against a running server |
| Every route authorised | `test_auth.py` default-deny sweep + acceptance route groups |
| No performance regression | `docs/hardening-report.md` §4.2 (interleaved A/B) |
| Capabilities honest | `test_module_contracts.py`, `test_integrity.py`, `GET /api/capabilities` |
| Build clean | `npm run build` (type-check + bundle) |
