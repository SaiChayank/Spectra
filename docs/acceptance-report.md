# Spectra — Acceptance Report

**Version:** 1.0.0rc1 · **Date:** 2026-09-29
**Scope:** Track 4 — final acceptance & hardening for the backend described in
`Spectra documentation.docx` (Phases 0–6, all eight strategic modules).

Reproduce everything below from `backend/`:

```bash
python -m pytest tests -q                 # 230 tests
python -m spectra.cli serve --port 8787   # API (must be running for the runner)
python scripts/acceptance.py              # 95 checks: API + WS + negative paths + CLI
```

---

## 1. Method

Three independent layers of evidence:

1. **Unit/integration tests (pytest)** — 230 checks of behaviour, including
   malformed-input (400) paths across five module test files.
2. **Acceptance runner (`scripts/acceptance.py`)** — exercises every one of the
   52 HTTP routes plus the WebSocket against a *running* server, performs nine
   deliberate negative-path probes, and sweeps all 12 CLI commands.
3. **Manual dashboard walkthrough** — every Phase-6 panel driven in the browser.

## 2. Documentation claim → coverage matrix

| Doc claim area | Implementation | Surface exercised | Tests |
|---|---|---|---|
| Live/PCAP capture, privacy (payload never touched) | `capture/`, `parse/` | `POST /api/capture/{start,stop}`, `spectra scan` | `test_flow`, `test_tls`, `test_quic`, `test_end_to_end` |
| Flow tracker + TLS/QUIC metadata (SNI, ALPN, JA3/JA4, ciphers) | `parse/` | `/api/flows`, WS `flow` events | `test_flow`, `test_tls`, `test_quic` |
| 39-feature vector, IsolationForest 0–100 scoring, σ-explanations | `features/`, `ml/` | `GET /api/model`, `/api/model/{drift,evasion,robustness}` | `test_model`, `test_adv`, `test_end_to_end` |
| M1 PQC readiness | `modules/pqc/` | `/api/pqc*`, `spectra pqc` | `test_pqc` |
| M2 Confidential computing (TEE) | `modules/tee/` | `/api/tee*`, `spectra tee` | `test_tee` |
| M3 Adversarial resilience | `modules/adv/` | `/api/model/{drift,evasion,robustness}`, `spectra adversarial` | `test_adv` |
| M4 Digital twin | `modules/twin/` | `/api/twin*`, `spectra twin` | `test_twin` |
| M5 ZK-proof audit | `modules/audit/` | `/api/audit*`, `spectra audit` | `test_audit` |
| M6 Bio-inspired immunity | `modules/bio/` | `/api/bio*`, `spectra bio` | `test_bio` |
| M7 Cross-domain correlation | `modules/corr/` | `/api/graph*` | `test_corr` |
| M8 Edge-native (5G/6G) | `modules/edge/` | `/api/edge*`, `spectra edge` | `test_edge`, `test_edge_native` |
| History / persistence | `store.py` | `/api/history/*` | `test_store` |
| Filter language | `filters.py` | `?filter=` query params | `test_filters` |
| Dashboard (React) | `frontend/` | WS `flow`/`detection`/`status`/`model` | browser walkthrough + `npm run build` |

## 3. Test suite

```
230 passed in 31.90s
```

Includes six fast-path equivalence tests (`tests/test_model.py`) that pin the
single-row scoring fast path (§5) bit-for-bit against sklearn, plus malformed
input coverage in `test_edge.py`, `test_quic.py`, `test_tls.py`, `test_tee.py`,
`test_audit.py` (unknown fields, wrong types, out-of-range values → HTTP 400).

## 4. Acceptance runner — 95/95 PASS

Thirteen groups covering every route/CLI surface:

| Group | Coverage |
|---|---|
| `core` | health, status, stats, flows, detections, interfaces, metrics, capture start/stop |
| `ws` | WebSocket connect + `flow`, `detection`, `status` event types |
| `model` | model info, train from `demo_pcaps/baseline.pcap`, drift, evasion, robustness |
| `history` | flows, detections, captures, stats, model-runs |
| `graph` | graph, summary, node, cascade, path (M7) |
| `pqc` | pqc, inventory, scan (M1) |
| `audit` | entries, head, verify, checkpoint, proof, certificate (M5) |
| `twin` | topology, playbooks, simulate, playbook, evaluate, recommend, shadow (M4) |
| `bio` | status, assess (M6) |
| `tee` | attest, verify, infer, federate (M2) |
| `edge` | report, link, deploy, slice (M8) |
| `negative` | 9 malformed-input probes must return 4xx, never 5xx |
| `cli` | all 12 `python -m spectra.cli …` commands incl. one-shot twin/audit/twin hydrate paths |

**Result: 95/95 PASS, exit code 0.** (Runner exits 1 on any FAIL; WARN allowed.)

## 5. Performance

Measured on this machine (Windows, Python 3.13, scikit-learn installed wheel):

| Path | Budget / baseline | Measured |
|---|---|---|
| Edge MEC micro-detector (12-feature) | 10 ms | p50 **0.0098 ms**, p95 **0.0189 ms** |
| Main detector `score()` per flow | was ~10.4 ms | p50 **0.269 ms**, p95 0.457 ms (**~39× faster**, §5 note) |
| `explain()` (σ-attribution) | — | p50 **0.040 ms** |
| End-to-end scan of `suspicious.pcap` (288 pkts, 13 flows, 5 detections) | was 0.448 s | **0.348 s** (≈827 pkt/s) |

Detection output is unchanged by the optimisation: same 288 packets → 13 flows
→ 5 detections (QUIC 100.0, beacon 96.8 ×4).

### Main-detector fast path (why it was needed and how it's safe)

sklearn's `IsolationForest.decision_function` pays ~300 per-tree task
dispatches (joblib + validation + sparse allocation) per call — ~10 ms for the
one-row inputs the ingest path produces. The computation is equivalent to
summing per-tree `decision_path_lengths[leaf] + avg_path_lengths[leaf] − 1`
over cached fit-time arrays, so `SpectraDetector` pre-converts each tree's node
arrays to Python lists once and walks them directly (`_build_fast` /
`_raw_fast`).

Safety properties, enforced by tests:

- **Bit-identical** to `-decision_function` on 302 varied probe vectors and in
  `tests/test_model.py` (exact `==`, not tolerance).
- Single-row inputs use the fast path; batches still take the sklearn path.
- Any missing prerequisite (feature subsampling, older sklearn pickle, import
  failure) falls back to sklearn's `decision_function` — correctness first.
- `fit()` invalidates the caches; `save()` excludes them from artifacts and
  `load()` rebuilds lazily.

## 6. Security & privacy posture

- API binds `127.0.0.1` by default; CORS allow-list is
  `http://localhost:5173,http://127.0.0.1:5173` (no wildcard).
- **No secrets in git:** `.gitignore` excludes `backend/models/` and
  `backend/data/` (TEE attestation key, audit signing key, model artifacts are
  auto-minted when missing). `git check-ignore` verified; zero
  `.key/.db/.joblib` files tracked.
- Negative-path checks confirm malformed JSON/params produce 4xx, not 5xx or a
  crash.
- Privacy invariant holds by construction: only flow statistics and
  TLS/QUIC handshake fields reach the model; payload bytes are consumed only to
  advance framing and are never stored, logged, or scored (covered by
  `test_flow`/`test_tls`).

## 7. Fixes made during acceptance

1. **Proof targeting** — `/api/audit/proof` and `spectra audit proof` must
   target a `capture.stop` entry: session flow records are the Merkle leaves,
   while `checkpoint` entries carry none. The runner now walks
   `/api/audit/entries?kind=capture.stop` to select the sequence and feeds the
   same sequence to the CLI check.
2. **One-shot twin CLI hydration** — `spectra twin simulate/playbook` (and
   friends) call `engine.hydrate_graph()` first, mirroring API startup, so they
   work against persisted flows without a running server.
3. **Detector fast path** — §5 (including the "### Main-detector fast path"
   note and six equivalence tests).
4. *Note (environment, not code):* PowerShell corrupts `$LASTEXITCODE` when
   native commands use `2>&1`/`2>$null`; redirect to files (or use
   `$LASTEXITCODE` before the redirect chain) when asserting exit codes.

## 8. Known gaps → 1.0.0

- **Live NIC capture on Windows** awaits [Npcap](https://nmap.org/npcap/)
  (with "WinPcap API-compatible mode") and an Administrator shell — Track 3.
  All other paths (PCAP file capture, full API, CLI, dashboard) are accepted.
- On successful live-capture validation, version flips `1.0.0rc1` → `1.0.0`
  and the tag moves to `v1.0.0`.
