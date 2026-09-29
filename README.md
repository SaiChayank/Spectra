# Spectra

**Next-Generation Encrypted Traffic Threat Detection** — detects threats hidden in
encrypted traffic *without decrypting it*. Only flow and TLS handshake metadata are
processed; payload contents are never inspected or stored.

Three target verticals: **Fintech · Healthcare · Smart City Infrastructure**.

> 📄 Product strategy and the eight strategic modules are documented in
> [`Spectra documentation (extracted).md`](./Spectra%20documentation%20(extracted).md).

---

## Status

Building the **detection ML core** first (per project plan), then the dashboard,
then the strategic modules (PQC readiness, cross-domain correlation, ...).

| Layer | State |
|---|---|
| Packet capture (PCAP file / live NIC) | ✅ pluggable sources |
| Flow tracking + TLS metadata (SNI, ALPN, JA3/JA4, versions, ciphers) | ✅ streaming parser |
| Feature extraction (38 statistical/handshake features) | ✅ |
| ML anomaly detector (IsolationForest + scaler, 0–100 scoring, explanations) | ✅ trained from a benign baseline |
| CLI (`demo`, `train`, `scan`, `status`, `serve`) | ✅ |
| REST API + WebSocket event stream | ✅ |
| React dashboard | 🚧 in progress |
| Live capture on Windows | ⏳ requires [Npcap](https://nmap.org/npcap/) installed |

## Architecture

```
┌──────────────┐   ┌────────────────┐   ┌──────────────────┐   ┌─────────────────┐
│ Capture      │ → │ Flow tracker   │ → │ Feature          │ → │ IsolationForest │
│ live / pcap  │   │ + TLS metadata │   │ extractor (38d)  │   │ score 0-100     │
└──────────────┘   └────────────────┘   └──────────────────┘   └────────┬────────┘
                                                                        │
        React dashboard  ←  WebSocket / REST  ←  FastAPI  ←  detections + explanations
```

Key idea: the model learns the *shape* of normal traffic from a baseline PCAP and
flags flows that deviate — with the top contributing features attached to every alert.

## Quickstart

```bash
cd backend
python -m venv .venv && .venv\Scripts\activate     # optional
pip install -r requirements.txt

# 1. generate demo traffic (40 benign TLS flows + 4 C2-style beacon flows)
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

| Method | Route | Purpose |
|---|---|---|
| GET | `/api/health` | liveness |
| GET | `/api/status` | capture state, counters |
| GET | `/api/stats` | totals, protocol/TLS breakdown, 5s timeline |
| GET | `/api/flows` | recent flows (metadata + JA3/JA4) |
| GET | `/api/detections` | scored anomalies with explanations |
| POST | `/api/capture/start` | `{mode: "pcap"\|"live", path?, iface?, bpf_filter?}` |
| POST | `/api/capture/stop` | stop the active capture |
| POST | `/api/model/train` | `{pcap_path, contamination}` → trains + persists |
| GET | `/api/model` | model info (features, threshold, training time) |
| WS | `/ws/events` | live `flow` / `detection` / `status` / `model` events |

## Tests

```bash
cd backend
python -m pytest tests -q      # 15 tests: TLS parsing, flows, features, end-to-end, API
```

The suite builds synthetic PCAPs with hand-crafted TLS ClientHello/ServerHello
messages, trains a model on a benign baseline, and asserts that beacon flows are flagged.

## Project layout

```
backend/
  spectra/
    capture/        # pluggable sources: PCAP file, live NIC (scapy)
    parse/          # flow tracker + streaming TLS handshake metadata parser
    features/       # 38-feature vector per flow
    ml/             # IsolationForest detector: train / score / explain / persist
    api/            # FastAPI + WebSocket
    pipeline.py     # engine wiring capture → detection → events
    cli.py          # spectra demo|train|scan|status|serve
    demo.py         # synthetic PCAP generators (tests + demos)
  tests/            # 15 unit/integration tests
frontend/           # React + TypeScript dashboard (Vite)
```

## Roadmap (from the product doc)

1. **Phase 1 (0–6 mo):** PQC readiness scanner · cross-domain correlation
2. **Phase 2 (6–18 mo):** TEE integration · 5G/edge-native detectors
3. **Phase 3 (18–36 mo):** ZK-proof audits · digital twin simulation
