# Spectra — Acceptance Report

**Version:** 1.0.0 · **Date:** 2026-09-29
**Scope:** Tracks 3 + 4 — live NIC capture acceptance and final acceptance &
hardening for the backend described in `Spectra documentation.docx`
(Phases 0–6, all eight strategic modules).

Reproduce everything below from `backend/`:

```bash
python -m pytest tests -q                 # 230 tests
python -m spectra.cli serve --port 8787   # API (must be running for the runner)
python scripts/acceptance.py              # 102 checks: API + WS + negative + CLI + live
```

---

## 1. Method

Three independent layers of evidence:

1. **Unit/integration tests (pytest)** — 230 checks of behaviour, including
   malformed-input (400) paths across five module test files.
2. **Acceptance runner (`scripts/acceptance.py`)** — exercises every one of the
   52 HTTP routes plus the WebSocket against a *running* server, performs nine
   deliberate negative-path probes, sweeps all 12 CLI commands, and (when Npcap
   is present) runs an 8-second live NIC capture.
3. **Manual dashboard walkthrough** — every Phase-6 panel driven in the browser,
   plus a live-capture session from the UI (§6).

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
230 passed in 26.32s
```

Includes six fast-path equivalence tests (`tests/test_model.py`) that pin the
single-row scoring fast path (§5) bit-for-bit against sklearn, plus malformed
input coverage in `test_edge.py`, `test_quic.py`, `test_tls.py`, `test_tee.py`,
`test_audit.py` (unknown fields, wrong types, out-of-range values → HTTP 400).

## 4. Acceptance runner — 102/102 PASS

Fourteen groups covering every route/CLI surface:

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
| `live` | Npcap-gated: interfaces listed, 8-second live capture on the active NIC, packets > 0, flows ≥ 1 (skips to WARN without Npcap) |

**Result: 102/102 PASS, exit code 0.** (Runner exits 1 on any FAIL; WARN allowed.)

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

## 6. Live NIC capture (Track 3)

**Environment:** Npcap 1.88 (WinPcap API-compatible mode) on Windows 11;
active adapter **Wi-Fi (192.168.1.8)** — Realtek RTL8852BE. Capture works
**without elevation** on this install (verified directly: a 4-second non-elevated
`sniff()` returned real packets), so the API server does not need to run as
Administrator here; `live.py` still surfaces a clear permission error if a
machine requires it.

**Acceptance (`live` group, 7 checks, all PASS):**

- `GET /api/interfaces` lists 8 NPF devices with friendly metadata
- 8-second live capture on the active NIC started/stopped via API
- packets > 0, flows ≥ 1, no capture errors

**Dashboard walkthrough (browser-driven):**

| Window | Result |
|---|---|
| 1 — model trained on *synthetic* demo baseline | 28,593 packets → 472 flows; real SNIs (`chatgpt.com`, `consent.config.office.com`), TLS 1.2/1.3, ALPN `h2` parsed correctly; **all flows scored ~97.6** — synthetic baseline is out-of-distribution for real traffic (expected; not a pipeline fault) |
| baseline | 70 s of real benign traffic captured to `backend/data/live-baseline.pcap` (4.9 MB, gitignored) and trained: **185 real flows**, bio + edge sidecars fitted |
| 2 — model trained on *real* baseline | 10,536 packets → **112 flows → 4 detections (3.6%)**; graded scores min **3.26**, p50 **33.15**, p90 **91.85**; DNS to the router scored **10.87** (normal); flagged: `models.opencode.ai` 96.74 and two IPv6-heavy flows 95.65 |

Window 2 is the product's intended behaviour: **train on your own benign
baseline → normal traffic scores low, genuine outliers land above the
contamination threshold.** Guidance recorded in the README quickstart: use a
real baseline capture when scoring real networks; the synthetic demo baseline
is for the demo PCAPs only.

**Privacy note:** scoring consumes only flow/handshake metadata; payload bytes
are never extracted. The raw baseline PCAP used for training stays in
gitignored `backend/data/` and is never committed.

## 7. Security & privacy posture

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

## 8. Fixes made during acceptance

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
4. **Interface discovery UX** — `/api/interfaces` now returns friendly
   metadata (`name`, `description`, `ip`, `mac`) with the active adapter
   sorted first; the dashboard dropdown shows `Wi-Fi (192.168.1.8) — Realtek
   RTL8852BE …` instead of raw NPF GUIDs, and the runner auto-selects the
   adapter carrying a real IP.
5. **Gated live group in the runner** — `scripts/acceptance.py` gained
   `run_live()` (and `--skip-live`): full live checks when Npcap is present,
   a WARN (exit 0) when it isn't, so the same script gates every machine.
6. *Note (environment, not code):* PowerShell corrupts `$LASTEXITCODE` when
   native commands use `2>&1`/`2>$null`; redirect to files (or use
   `$LASTEXITCODE` before the redirect chain) when asserting exit codes.

## 9. Release status

- **Version 1.0.0** — all tracks accepted: Tracks 1 (hygiene), 2 (Phase-6
  panels), 3 (live capture) and 4 (acceptance/hardening).
- Tags: `v1.0.0rc1` on the Track-4 commit; `v1.0.0` on the release commit.
- Operational requirements on target machines: [Npcap](https://nmap.org/npcap/)
  (WinPcap-compat mode) for live capture, Python 3.11+, `npm install` for the
  dashboard. No Administrator shell was needed on the validated install.
