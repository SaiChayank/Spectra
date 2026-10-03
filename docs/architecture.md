# Spectra — Architecture

How a packet becomes an alert in the locally hosted Spectra application. Every
stage below names the file that implements it, so this document can be checked
against the code.

Related documents: [local setup](./local-setup.md) ·
[capabilities](./capabilities.md) · [ML](./ml.md) ·
[security](./security.md) · [testing](./testing.md) ·
[limitations](./limitations.md)

---

## 1. Shape of the system

Spectra is a **local modular monolith**: one Python process (FastAPI + a staged
capture pipeline) plus one React SPA served by a dev server. No message broker,
no external database, no containers.

```
                              ┌──────────────────────────────────────────────┐
   .pcap/.pcapng import       │  backend/spectra (single Python process)     │
   ──────────────────────►    │                                              │
                              │  capture ─► flow table ─► TLS/QUIC parse     │
   live NIC (Npcap/libpcap)   │     │            │                           │
   ──────────────────────►    │  packet_queue   39-feature vector            │
                              │  (4096)              │                       │
                              │                 IsolationForest score        │
                              │                 + 8 module annotations       │
                              │                      │                       │
                              │                 rule classification          │
                              │                      │                       │
                              │        alerts ─► incidents ─► correlation    │
                              │              │                                │
                              │   SQLite (WAL) ◄── audit hash chain          │
                              │              │                                │
                              │      REST (92 routes) + WS /ws/events        │
                              └──────────────┬───────────────────────────────┘
                                             │  HttpOnly session cookie
                                             ▼
                        frontend/ React 19 + Vite (9-section console, :5173)
```

**Composition root:** `backend/spectra/pipeline.py` → `SpectraEngine` wires the
services (event bus, audit, alerts, model, correlation, detection, capture,
training, auth, incidents, investigation). `backend/spectra/api/runtime.py`
builds one engine for the API process; `backend/spectra/cli.py` builds one per
command.

## 2. Runtime shape: threads and queues

Capture runs in bounded, non-blocking stages so packet acquisition is never
back-pressured by slow consumers (`backend/spectra/streaming.py`):

| Thread | Stage | Hand-off | Queue (size / policy) |
|---|---|---|---|
| `spectra-sniff` | live source (`capture/live.py`) | packets → pipeline | internal 10 000, `put_nowait` + counted drops |
| `spectra-capture` | `_capture_stage` | source → flow tracker | `packet_queue` 4096 · **drop_newest** |
| `spectra-flow` | `_flow_stage` | `FlowTracker` → inference | `flow_queue` 1024 · **drop_oldest** |
| `spectra-infer` | `_inference_stage` | scoring + annotations | → `publish_queue` 1024 · **drop_oldest** |
| `spectra-publish` | `_publish_stage` | classify/alert/persist/events | → buffers, SQLite, WS |
| `spectra-engine` | supervisor (`services/capture.py`) | start / drain / finalise | — |

Shedding is explicit and counted: overload appears as
`status["pipeline"]` drops on `GET /api/status` and `GET /api/metrics`
instead of unbounded memory growth. Flow-table bounds live in
`backend/spectra/config.py` (`max_active_flows=5000` with LRU force-completion,
`flow_max_packets=512`, `flow_max_lifetime=900 s`, `idle_timeout=30 s`).

## 3. The stages

### 3.1 Capture — `backend/spectra/capture/`

Two interchangeable sources behind `CaptureSource` (`capture/base.py`,
`open_source(mode, path, iface, filter)`):

* **Managed PCAP import** — the only file route is `POST /api/captures`
  (multipart). `capture/storage.py` sanitises the filename (basename only),
  enforces the `.pcap`/`.pcapng` extension, checks the magic bytes, streams the
  body under a 256 MiB cap, hashes it (sha256, duplicate → `409`), and stores it
  under a **generated** name `cap_<uuid>` — a client filename never becomes a
  path. `services/captures.py` owns the lifecycle
  `UPLOADED → PROCESSING → COMPLETED | FAILED | STOPPED`.
* **Live NIC capture** — `capture/live.py` sniffs an interface (Npcap on
  Windows, libpcap elsewhere) with a pure-Python BPF-style filter
  (`filters.py`), read-only, never injecting or modifying traffic.
  `POST /api/capture/start|stop`, ADMIN only.

Every read is clamped to the file's own size (`_SizeBoundedFile`), so a crafted
record length cannot make the parser allocate more than the upload contained.

### 3.2 Flow tracking — `backend/spectra/parse/flow.py`

`FlowTracker.process(pkt, ts)` keys packets by the 5-tuple (forward and reverse
direction), maintains the active table, and finalises a flow on TCP RST, both
FINs, idleness, lifetime, or table pressure. Each `Flow` keeps per-direction
packet statistics (counts, bytes, flags, timestamps) and at most
`flow_max_packets` packet records.

### 3.3 Encrypted metadata parsing — `backend/spectra/parse/tls.py`, `quic.py`

Only handshake structure is parsed; application payload is never decrypted,
stored, or logged.

* **TLS (TCP):** a streaming reassembler feeds ClientHello/ServerHello parsing
  → `TlsMetadata`: legacy/negotiated version, cipher suites, extensions,
  supported groups, signature algorithms, **SNI** (IDNA-decoded), **ALPN**,
  key-share group, JA3 (MD5, GREASE stripped) and **JA4** (SHA-256).
* **QUIC:** the *Initial* packet is opened with HKDF-derived secrets (RFC 9001 —
  this is standard Initial-header handling, not a privacy boundary crossing),
  the CRYPTO frames are reassembled, and the same `TlsMetadata` is produced.
  0-RTT/Handshake packets are counted, never opened.

### 3.4 Feature extraction — `backend/spectra/features/extractor.py`

`extract_features(flow) → float32[39]` — one vector per completed flow from
packet statistics, inter-arrival timing, TCP flags, endpoint context and the
TLS metadata above. `FEATURE_SCHEMA_VERSION = 1`; `feature_schema_digest()`
(SHA-256 over the ordered names) is the compatibility key checked when a model
artifact is loaded. Full list and semantics: [ml.md](./ml.md §1).

### 3.5 Anomaly inference — `backend/spectra/ml/model.py`

`SpectraDetector` = `StandardScaler` + `IsolationForest(300 trees)`.
`score_and_predict()` (single pass, with a bit-identical fast tree walk) returns
a **0–100 percentile score** — how far the flow sits from the training
distribution — plus an anomaly flag against the training-derived threshold.
An untrained model yields `score=None`, never a fabricated number.
Explainers return the top |z|-scored features attached to the detection.

### 3.6 Behavioural classification — `backend/spectra/threats.py`

Only flows the detector already flagged reach `classify_threat()`. Rule
categories (`C2_BEACONING`, `RECONNAISSANCE`, `DATA_EXFILTRATION_SUSPECTED`,
`TLS_ANOMALY`, `QUIC_ANOMALY`, `VOLUMETRIC_ANOMALY`,
`UNUSUAL_ENDPOINT_BEHAVIOR`, `UNKNOWN_ANOMALY`) are scored from weighted
signals over a bounded context window (the current flow is excluded from its
own window); a verdict needs ≥ 2 distinct signals and
confidence ∈ [0.30, 0.95], otherwise it degrades to `UNKNOWN_ANOMALY`.

### 3.7 Alert generation — `backend/spectra/services/threat_alerts.py`

`observe()` groups sightings of the same behaviour
(`threat_type|proto|src_host|dst_host`) within `alert_group_seconds` (600 s)
into one alert with `occurrences`, keeping the anomaly-score high-water mark.
`backend/spectra/severity.py::calculate_severity` derives severity in five
documented steps (category base → confidence → score ≥ 99 → asset criticality →
repeat sightings) and returns **every** input as `factors`. Evidence is built by
`evidence.py`; the flow row stores the reverse `alert_id` link before it is
written. Lifecycle: `OPEN → ACKNOWLEDGED → RESOLVED`.

### 3.8 Incident correlation — `backend/spectra/incident_correlation.py`

Pure functions `related(a, b, window)` / `cluster(alerts)` score shared anchors
(src/dst host, SNI, graph edge), shared threat type, time proximity, /24
overlap and repeated beacons; `MIN_SCORE = 4.0` keeps grouping conservative.
`services/incidents.py` owns the state machine
(`open → investigating → resolved / reopened / false-positive`), auto-attaches
alerts from the event bus, and caps every collection
(200 alerts/incident, 50 active incidents). Incidents are **never invented**:
nothing creates one without an alert to attach.

### 3.9 Persistence — `backend/spectra/db/`, `store.py`

SQLite in WAL mode behind a repository layer:

* **Schema:** 11 ordered migrations (`db/migrations.py`), applied at import,
  upgrade existing databases in place; `schema_version()` is the contract.
* **Writes:** flows and events are batched (`WriteBuffer`, 256 rows / 1.0 s)
  and flushed before every read, so readers always see their own writes.
  Captures, users, sessions, alerts, incidents, model registry rows and audit
  entries are written immediately.
* **Bounds:** row caps (flows 200 000, events 50 000, alerts 50 000) with
  newest-kept pruning; age-based retention policies exist but default to **off**
  (`0`); `audit_log` is exempt by design — its chain needs the full sequence.
  See [limitations.md](./limitations.md §7).

### 3.10 Audit — `backend/spectra/modules/audit/`, `services/audit.py`

Append-only hash chain: `entry_hash = sha256(canonical(seq, ts, kind, actor,
payload, leaves, prev_hash))` over a genesis of 64 zeros. Capture sessions add
`capture.start` / `capture.stop` entries; processed flows are recorded as
Merkle leaves (≤ 5000/entry); checkpoints Merkle-root the entries since the
previous one and Schnorr-sign them. `verify()` checks sequence continuity,
previous-hash links and hash recomputation; `inclusion_proof()` proves a leaf.
Appends are **guarded**: an audit failure is counted, never allowed to break
capture. Details: [security.md](./security.md §6).

### 3.11 API and WebSocket — `backend/spectra/api/`

* **Middleware order:** request-id + structured access log (query strings are
  **never** logged) → CORS (explicit allowlist, credentials on) → body limit
  (4 MiB JSON; `capture_max_bytes + 1 MiB` for the upload route → `413`) →
  `auth_gate`.
* **Default-deny:** only `GET /api/health` and `POST /api/auth/login` are
  public; every other request must resolve to a live session and then pass the
  route's `require(permission)` check from `authz.py`.
* **Surface:** 16 routers → **92 HTTP routes** (plus FastAPI's own
  `/docs`/`/redoc`/`/openapi.json`) and one `WS /ws/events`.
* **WebSocket:** handshake authenticated by cookie or `?token=`, Origin must be
  in the CORS allowlist (else `4403`), unauthenticated handshakes close `4401`
  before accept, a per-client queue of 500 drops oldest with a counter, and the
  session is **revalidated every 30 s** so logout/expiry closes the stream.
* **Shutdown:** FastAPI `lifespan` stops capture and flushes the write buffer.

### 3.12 Frontend — `frontend/src/`

React 19 + Vite + TypeScript, hash router with nine sections
(`overview, monitor, incidents, traffic, network, models, audit, modules,
system`). `lib/api.ts` calls the API with `credentials: "include"` — the session
lives in an HttpOnly cookie, no token is ever held in JavaScript. `lib/useEvents.ts`
keeps `/ws/events` open (1.5 s reconnect while signed in) and merges events into
3-second polls; a `spectra:unauthorized` event on any 401 returns the user to
the landing page. Controls are gated by the permissions returned from
`/api/auth/me` (the server enforces them regardless).

## 4. Where the eight strategic modules attach

Invariant (`capabilities.py::SCORING_POLICY`): **no module changes the anomaly
score, the alert confidence, or the severity** — every module contributes
evidence or context only.

| # | Module | Attaches at | Guard |
|---|---|---|---|
| 1 | PQC readiness | inference — `assess_handshake()` annotates each scored flow | `pqc` |
| 2 | TEE attestation (**simulated**) | off the hot path — its own `/api/tee*` routes | route-level 400 |
| 3 | Adversarial resilience | inference — score window, drift refresh every 200 flows | `adversarial_watch` |
| 4 | Digital twin (**simulated**) | read side — replays the correlation graph topology | `twin` |
| 5 | ZKP audit chain | publication (Merkle leaves) + capture session edges | `audit` |
| 6 | Bio-inspired (**experimental**) | inference — annotations only, never a verdict | `bio` |
| 7 | Correlation graph | publication — `observe()` per published record | `correlation` |
| 8 | Edge / 5G slicing | inference — slice tags + micro-detector; fit at training | `edge_slice` |

Each module runs inside a `FailureTracker` guard: a failure increments a
counter, is reported by `GET /api/capabilities`, and degrades that module only.
Maturity labels per module: [capabilities.md](./capabilities.md).

## 5. End-to-end trace (one packet)

1. `open_source()` (upload or NIC) → thread `spectra-capture`.
2. `packet_queue` → thread `spectra-flow` → `FlowTracker` attaches TLS/QUIC
   metadata → completed `flow_queue`.
3. Thread `spectra-infer`: `extract_features` (39) → `score_and_predict` →
   PQC / edge / bio / adversarial annotations.
4. `publish_queue` → thread `spectra-publish`: audit leaf → `classify_threat`
   (only if flagged) → `ThreatAlertService.observe` → `CorrelationService.observe`
   → event bus → `Store.save_flow` (batched) → incident auto-attach.
5. Event bus fans out to `WS /ws/events` and the REST routers; the React
   console renders it in the matching section.

## 6. Invariants worth stating once

* **Metadata only** — payload bytes are consumed solely to advance framing.
* **Read-only capture** — Spectra never sends packets.
* **Local by default** — binds `127.0.0.1`, no cloud/broker/cluster.
* **Bounded everything** — queues, buffers, tables, requests, and pages all
  have explicit caps; overload is counted, not absorbed.
* **Evidence, not verdicts** — modules annotate; only the detector + rule
  classifier produce scores/categories, and severity is derived with reasons.
