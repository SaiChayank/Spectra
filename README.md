# Spectra

**Next-Generation Encrypted Traffic Threat Detection** — detects threats hidden in
encrypted traffic *without decrypting it*. Only flow and TLS/QUIC handshake metadata are
processed; **payload contents are never decrypted, stored, or displayed**.

Three target verticals: **Fintech · Healthcare · Smart City Infrastructure**.

> Product strategy and the eight strategic modules are documented in
> [`Spectra documentation (extracted).md`](./Spectra%20documentation%20(extracted).md).

---

## Status

Backend **complete** (Phases 0–6): detection core, all 8 strategic modules, REST API,
CLI, and the React dashboard — with **224 passing tests**.

| Layer | State |
|---|---|
| Packet capture (PCAP file / live NIC) | ✅ pluggable sources |
| Flow tracking + TLS/QUIC metadata (SNI, ALPN, JA3/JA4, versions, ciphers) | ✅ streaming parser |
| Feature extraction (39-feature vector per flow) | ✅ |
| ML anomaly detector (IsolationForest + scaler, 0–100 scoring, σ-explanations) | ✅ trained from a benign baseline |
| 8 strategic modules (see matrix below) | ✅ |
| API (52 HTTP routes + WebSocket) + CLI (12 commands) | ✅ |
| React dashboard | ✅ live |
| Automated tests (pytest) | ✅ 224 passing |
| Live capture on Windows | ⏳ requires [Npcap](https://nmap.org/npcap/) installed |

## The eight modules

| # | Module (doc) | Implementation | Key routes / CLI |
|---|---|---|---|
| 1 | PQC readiness | `modules/pqc/` — quantum-readiness scoring per handshake (classical vs hybrid vs PQ groups, TLS 1.2/RSA critical), cipher-suite registry, HNDL bulk-transfer screening, migration roadmap | `/api/pqc*` · `spectra pqc` |
| 2 | Confidential computing (TEE) | `modules/tee/` — nonce-bound Schnorr attestation quotes, sealed inference receipts, k-of-k federated secret sharing | `/api/tee*` · `spectra tee` |
| 3 | Adversarial resilience | `modules/adv/` — score-boundary probing, evasion watch, robustness evaluation | `/api/model/{drift,evasion,robustness}` · `spectra adversarial` |
| 4 | Digital twin | `modules/twin/` — traffic replica, deterministic attack simulation, IR playbooks, legacy z-score shadow mode | `/api/twin*` · `spectra twin` |
| 5 | ZK-proof audit | `modules/audit/` — hash-chained log, Merkle checkpoints + inclusion proofs, Schnorr ZKP statements, signed compliance certificates | `/api/audit*` · `spectra audit` |
| 6 | Bio-inspired immunity | `modules/bio/` — self-model affinity + 6 danger signals, spiking NN timing detector, 5-agent swarm voting, memory cells | `/api/bio*` · `spectra bio` |
| 7 | Cross-domain correlation | `modules/corr/` — host/IP/SNI correlation graph, blast-radius cascade analysis, attack paths | `/api/graph*` |
| 8 | Edge-native (5G/6G) | `modules/edge/` — network slices (URLLC/eMBB/mMTC), MEC micro-detector (12 features, 10 ms budget), NTN link profiles (LEO/GEO) | `/api/edge*` · `spectra edge` |

## Architecture

```
┌──────────────┐   ┌────────────────┐   ┌──────────────────┐   ┌─────────────────┐
│ Capture      │ → │ Flow tracker   │ → │ Feature          │ → │ IsolationForest │
│ live / pcap  │   │ + TLS metadata │   │ extractor (39d)  │   │ score 0-100     │
└──────────────┘   └────────────────┘   └──────────────────┘   └┬────────────────┘
                                                                │
   bio immunity · edge slices · correlation graph · audit chain │
                                                                ▼
        React dashboard  ←  WebSocket / REST  ←  FastAPI  ←  detections + explanations
```

Key idea: the model learns the *shape* of normal traffic from a baseline PCAP and flags
flows that deviate — with the top contributing features (σ-deviations) attached to every
alert. The bio layer, edge policies, and correlation graph annotate results; **the
bio layer never creates detections on its own**.

## Quickstart

```bash
cd backend
python -m venv .venv && .venv\Scripts\activate     # optional
pip install -r requirements.txt

# 1. generate demo traffic (benign baseline + suspicious mix) and train
python -m spectra.cli demo --out data/demo --train

# 2. scan the suspicious capture
python -m spectra.cli scan data/demo/suspicious.pcap

# 3. run the API for the dashboard
python -m spectra.cli serve --port 8787
```

Then in another terminal:

```bash
cd frontend
npm install
npm run dev          # http://localhost:5173
```

Use your own traffic instead of the demo:

```bash
python -m spectra.cli train  /path/to/benign-baseline.pcap   # learn "normal"
python -m spectra.cli scan   /path/to/capture.pcap           # find deviations
```

### Live capture (Windows)

Live sniffing needs Npcap: install from <https://nmap.org/npcap/> with
**"WinPcap API-compatible mode"** enabled, then restart the API and start a
`live` capture from the dashboard (run the backend **as Administrator**).

## API

52 HTTP routes + 1 WebSocket, grouped by module:

| Group | Routes |
|---|---|
| Core | `GET /api/health`, `/api/status`, `/api/stats`, `/api/flows`, `/api/detections`, `/api/interfaces`, `/api/metrics` |
| Capture | `POST /api/capture/start`, `POST /api/capture/stop` |
| Model | `GET /api/model`, `POST /api/model/train`, `GET /api/model/drift`, `/api/model/evasion`, `POST /api/model/robustness` |
| History | `GET /api/history/{flows,detections,captures,stats,model-runs}` |
| Correlation (M7) | `GET /api/graph`, `/api/graph/summary`, `/api/graph/node`, `/api/graph/cascade`, `/api/graph/path` |
| PQC (M1) | `GET /api/pqc`, `/api/pqc/inventory`, `/api/pqc/scan` |
| Audit (M5) | `GET/POST /api/audit/{entries,head,verify,checkpoint,proof,certificate}` |
| Twin (M4) | `GET /api/twin/{topology,playbooks}`, `POST /api/twin/{simulate,playbook,evaluate,recommend,shadow}` |
| Bio (M6) | `GET /api/bio/status`, `POST /api/bio/assess` |
| TEE (M2) | `POST /api/tee/{attest,verify,infer,federate}` |
| Edge (M8) | `GET /api/edge/report`, `POST /api/edge/{link,deploy,slice}` |
| Events | `WS /ws/events` — `flow` / `detection` / `status` / `model` events |

## CLI

| Command | Purpose |
|---|---|
| `spectra demo` | generate demo PCAPs (benign baseline + suspicious mix) |
| `spectra train <pcap>` | train the detector (+ bio/edge sidecars) from a benign baseline |
| `spectra scan <pcap>` | run detection over a PCAP, print scores + explanations |
| `spectra status` | engine snapshot (model info, buffers) |
| `spectra serve` | run the API + dashboard backend |
| `spectra pqc` | Module 1: post-quantum readiness report for a PCAP |
| `spectra adversarial` | Module 3: evasion / robustness probes |
| `spectra audit` | Module 5: entries · verify · checkpoint · proof · certify · profiles |
| `spectra twin` | Module 4: topology · playbooks · simulate · playbook · shadow |
| `spectra bio` | Module 6: status · assess (self model, SNN, swarm, memory) |
| `spectra tee` | Module 2: attest · verify · infer · federate |
| `spectra edge` | Module 8: report · link · slice · deploy |

## Tests

```bash
cd backend
python -m pytest tests -q      # 224 tests
```

The suite covers TLS/QUIC parsing, flow tracking, feature extraction, filters, the
detector, PQC, correlation, adversarial, twin, audit, bio, TEE, edge, the store, the
API (including 400-paths), and end-to-end capture runs. Synthetic PCAPs are built with
hand-crafted TLS ClientHello/ServerHello messages; a model is trained on a benign
baseline and beacon flows must be flagged.

## Project layout

```
backend/
  spectra/
    capture/        # pluggable sources: PCAP file, live NIC (scapy)
    parse/          # flow tracker + streaming TLS & QUIC metadata parser
    features/       # 39-feature vector per flow
    ml/             # IsolationForest detector: train / score / explain / persist
    modules/        # eight strategic modules (pqc, tee, adv, twin, audit, bio, corr, edge)
    api/            # FastAPI: 52 HTTP routes + WebSocket event stream
    filters.py      # pure-Python BPF-style filters (no libpcap needed)
    pipeline.py     # engine wiring capture → detection → annotation → events
    cli.py          # 12 CLI commands
    demo.py         # synthetic PCAP generators (tests + demos)
  tests/            # 224 unit/integration tests
  demo_pcaps/       # committed fixture captures
frontend/           # React + TypeScript dashboard (Vite)
```

## Privacy invariants

- Only flow statistics, TLS/QUIC handshake fields, and timing are extracted.
- Payload bytes are read by the parser only to advance framing — never stored,
  logged, or sent to the model.
- Anomaly scores are computed from the 39-feature metadata vector alone.

## Version

`1.0.0rc1` — final acceptance pass (live-capture validation + module acceptance
matrix) pending; see repository history for phase-by-phase development.
