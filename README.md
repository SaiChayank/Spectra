# Spectra

**Next-Generation Encrypted Traffic Threat Detection** — detects threats hidden in
encrypted traffic *without decrypting it*. Only flow and TLS/QUIC handshake metadata are
processed; **payload contents are never decrypted, stored, or displayed**.

Three target verticals: **Fintech · Healthcare · Smart City Infrastructure**.

> Product strategy and the eight strategic modules are documented in
> [`Spectra documentation (extracted).md`](./Spectra%20documentation%20(extracted).md).

## Documentation

| Document | Contents |
|---|---|
| [`docs/architecture.md`](./docs/architecture.md) | capture → flows → parsing → features → inference → classification → alerts → incidents → persistence → audit → API/WS → frontend |
| [`docs/local-setup.md`](./docs/local-setup.md) | toolchain, dependencies, environment variables, backend/frontend startup, first admin, Npcap |
| [`docs/capabilities.md`](./docs/capabilities.md) | every capability classified REAL / LOCAL / SIMULATED / EXPERIMENTAL / FUTURE |
| [`docs/ml.md`](./docs/ml.md) | the 39-feature schema, baseline, training, model lifecycle, score/confidence/severity interpretation |
| [`docs/security.md`](./docs/security.md) | auth, RBAC, managed captures, artifact integrity, audit chain, local-only assumptions |
| [`docs/testing.md`](./docs/testing.md) | 496 tests · 156 acceptance checks · performance · live-capture validation |
| [`docs/limitations.md`](./docs/limitations.md) | detection, classification, TEE/twin/edge, metadata-only analysis, operational caveats |
| [`docs/readiness-report.md`](./docs/readiness-report.md) | final readiness report (completed / partial / future / known limitations) |
| [`docs/hardening-report.md`](./docs/hardening-report.md) · [`docs/acceptance-report.md`](./docs/acceptance-report.md) | engineering evidence: fixes, performance baselines, live capture |

---

## Status

Backend **complete** (Phases 0–6): detection core, all 8 strategic modules, REST API,
CLI, and the React dashboard — with **496 passing tests**. Local authentication
(login, sessions, RBAC) gates the API, WebSocket, and dashboard.

| Layer | State |
|---|---|
| Capture (managed PCAP import / live NIC) | ✅ validated upload store, pluggable sources |
| Flow tracking + TLS/QUIC metadata (SNI, ALPN, JA3/JA4, versions, ciphers) | ✅ streaming parser |
| Feature extraction (39-feature vector per flow) | ✅ |
| ML anomaly detector (IsolationForest + scaler, 0–100 scoring, σ-explanations) | ✅ trained from a benign baseline |
| 8 strategic modules (see matrix below) | ✅ |
| API (92 HTTP routes + WebSocket, default-deny auth) + CLI (12 commands) | ✅ |
| Persistence (SQLite: migration-driven schema, batched writes, bounded retention) | ✅ |
| React dashboard | ✅ live (local login, role-aware UI) |
| Automated tests (pytest) | ✅ 496 passing |
| Authentication & RBAC (ADMIN / ANALYST / VIEWER) | ✅ scrypt + sessions |
| Live capture on Windows | ✅ validated with [Npcap](https://nmap.org/npcap/) (driver required) |

### Persistence

SQLite (WAL) behind a repository layer (`backend/spectra/db/`): schema changes are
**migration-driven** — existing databases upgrade in place with data preserved — and
flow/event writes are batched instead of committed per row (`SPECTRA_DB_BATCH_SIZE`,
`SPECTRA_DB_FLUSH_INTERVAL`). Retention is configurable per table
(`SPECTRA_FLOW_RETENTION_DAYS`, `SPECTRA_DETECTION_RETENTION_DAYS`,
`SPECTRA_CAPTURE_RETENTION_DAYS`, `SPECTRA_EVENT_RETENTION_DAYS`,
`SPECTRA_STALE_SESSION_HOURS`); age policies default to **off** so history is kept,
while row caps keep tables bounded. The audit log is never pruned — its hash chain
requires the full sequence.

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

Full instructions (toolchain versions, environment variables, first admin,
Npcap, troubleshooting): [`docs/local-setup.md`](./docs/local-setup.md).

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

Or run both with the convenience script: `.\start.ps1` (PowerShell, optional —
it prints what it does and stops the backend on `Ctrl+C`).

### First sign-in

The API bootstraps a local `admin` account on first start: the password comes from
`SPECTRA_ADMIN_PASSWORD` if set, otherwise a random one is written to
`backend/data/admin_bootstrap.txt` (mode 600). Sign in on the dashboard, change
the password, then delete that file. Use `http://localhost:5173` (not
`127.0.0.1`) — the session cookie is `SameSite=Lax` and cross-port on `localhost`.

The dashboard's **Capture** panel imports a `.pcap`/`.pcapng` from your machine
(multipart upload — a server filesystem path is never typed or accepted), processes
it through detection, and lists every import with its lifecycle status so captures
can be re-run or deleted. The **Model** panel trains from an imported baseline file.

Use your own traffic instead of the demo:

```bash
python -m spectra.cli train  /path/to/benign-baseline.pcap   # learn "normal"
python -m spectra.cli scan   /path/to/capture.pcap           # find deviations
```

### Live capture (Windows)

Live sniffing needs Npcap: install from <https://nmap.org/npcap/> with
**"WinPcap API-compatible mode"** enabled, then restart the API and start a
`live` capture from the dashboard (run the backend **as Administrator** if your
machine requires it — the validated install did not).

When scoring real networks, train on a benign baseline captured from *that*
network (`spectra train your-baseline.pcap`): the bundled synthetic demo
baseline is tuned for the demo PCAPs and will flag ordinary real traffic as
out-of-distribution (validated in
[`docs/acceptance-report.md`](./docs/acceptance-report.md) §6).

## API

92 HTTP routes + 1 WebSocket, grouped by module:

| Group | Routes |
|---|---|
| Core | `GET /api/health`, `/api/status`, `/api/stats`, `/api/flows`, `/api/detections`, `/api/interfaces`, `/api/metrics`, `/api/capabilities` |
| Auth (local) | `POST /api/auth/login`, `POST /api/auth/logout`, `GET /api/auth/me` |
| Users (ADMIN) | `GET/POST /api/users`, `GET/PATCH/DELETE /api/users/{id}` |
| Incidents | `GET/POST /api/incidents`, `GET /api/incidents/{id}`, `POST /api/incidents/{id}/{acknowledge,resolve,notes}` |
| Live capture | `POST /api/capture/start` (live mode only), `POST /api/capture/stop` |
| Captures (managed) | `POST /api/captures` (multipart import), `GET /api/captures`, `GET /api/captures/{id}`, `POST /api/captures/{id}/process`, `DELETE /api/captures/{id}` |
| Model | `GET /api/model`, `POST /api/model/train`, `GET /api/model/drift`, `/api/model/evasion`, `POST /api/model/robustness` |
| History | `GET /api/history/{flows,detections,captures,stats,model-runs,events}` |
| Correlation (M7) | `GET /api/graph`, `/api/graph/summary`, `/api/graph/node`, `/api/graph/cascade`, `/api/graph/path` |
| PQC (M1) | `GET /api/pqc`, `/api/pqc/inventory`, `/api/pqc/scan` |
| Audit (M5) | `GET/POST /api/audit/{entries,head,verify,checkpoint,proof,certificate}` |
| Twin (M4) | `GET /api/twin/{topology,playbooks}`, `POST /api/twin/{simulate,playbook,evaluate,recommend,shadow}` |
| Bio (M6) | `GET /api/bio/status`, `POST /api/bio/assess` |
| TEE (M2) | `POST /api/tee/{attest,verify,infer,federate}` |
| Edge (M8) | `GET /api/edge/report`, `POST /api/edge/{link,deploy,slice}` |
| Events | `WS /ws/events` — `flow` / `detection` / `status` / `model` / `capture` / `alert` / `drift` events |

No route accepts a server filesystem path. Files enter through `POST /api/captures`,
which validates the filename (basename only), extension (`.pcap`/`.pcapng`), magic
signature and size, then stores the bytes under a **generated** name and records the
capture (`UPLOADED → PROCESSING → COMPLETED / FAILED / STOPPED`, persisted across
restarts). Identical content returns `409` with the existing id; `DELETE` removes the
row and stored file (refused while running). Training, robustness, PQC scan and twin
shadow all address captures by this generated id.

## Authentication & access control

Local accounts only — no external OAuth/identity provider. A middleware makes
`/api/*` **default-deny** (public: `GET /api/health`, `POST /api/auth/login`,
`/docs`); every other request must resolve to a live session, and each protected
route checks a permission from `spectra/authz.py`.

| Role | Permissions |
|---|---|
| `ADMIN` | everything: user management, capture start/stop, PCAP import, model train/activate/rollback, advanced configuration |
| `ANALYST` | investigate detections/incidents, acknowledge/resolve incidents, add analyst notes, inspect network/correlation/audit data |
| `VIEWER` | read-only dashboard and reports |

- **Hashing** — `hashlib.scrypt` (n=65536, r=8, p=1, per-user salt, parameters
  upgraded in place on the next successful login). Hashes are never returned by
  any endpoint or log. The password policy (≥ 8 chars) is
  enforced only when a password is *set*, never at login, so a failed login is
  indistinguishable (`401 invalid username or password` for unknown user and
  wrong password alike — no user enumeration).
- **Sessions** — a 256-bit random token kept server-side only as a SHA-256 hash,
  delivered as an HttpOnly `SameSite=Lax` cookie (`spectra_session`) and also
  accepted as a `Bearer` header or WebSocket `?token=` query parameter. Absolute
  lifetime `SPECTRA_SESSION_TTL_MINUTES` (default 720). Logout deletes the row;
  a password change revokes *all* of that user's sessions; deleting a user
  cascades their sessions. Unauthorized WebSocket handshakes close with `4401`.
- **Bootstrap** — the first start creates `admin` from `SPECTRA_ADMIN_PASSWORD`
  (or a generated password written to `data/admin_bootstrap.txt`, mode 600);
  later starts are idempotent. `SPECTRA_ADMIN_USERNAME` overrides the name.
- **Audit** — login, logout, and user-management actions are recorded in the
  hash-chained audit log with the acting user.

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
python -m pytest tests -q      # 496 tests
```

Full verification workflow (pytest + acceptance runner + performance + build):
[`docs/testing.md`](./docs/testing.md).

The suite covers TLS/QUIC parsing, flow tracking, feature extraction, filters, the
detector, PQC, correlation, adversarial, twin, audit, bio, TEE, edge, the persistence
layer (11 migrations, repositories, batched writes, retention), managed capture
resources (import validation, lifecycle, path-traversal rejection, delete safety),
local authentication and RBAC (login success/failure, session expiry and revocation,
role matrices, default-deny route sweep, WebSocket authorization, incidents
lifecycle), the API (including 400-paths), a dedicated hardening regression suite
(`test_hardening.py`, 28 tests), and end-to-end capture runs. Synthetic PCAPs are
built with hand-crafted TLS ClientHello/ServerHello messages; a model is trained on
a benign baseline and beacon flows must be flagged.

Against a running server, `python scripts/acceptance.py` replays the whole surface
as **156 checks** (every route group, WebSocket, negative paths, CLI sweep, live
capture when Npcap is present); `python scripts/perf.py` records the performance
numbers in [`docs/testing.md`](./docs/testing.md §3).

## Project layout

```
backend/
  spectra/
    capture/        # pluggable sources: PCAP file, live NIC (scapy)
    parse/          # flow tracker + streaming TLS & QUIC metadata parser
    features/       # 39-feature vector per flow
    ml/             # IsolationForest detector: train / score / explain / persist
    modules/        # eight strategic modules (pqc, tee, adv, twin, audit, bio, corr, edge)
    auth/           # password policy + scrypt hashing
    authz.py        # RBAC matrix (ADMIN / ANALYST / VIEWER → permissions)
    api/            # FastAPI: 92 HTTP routes + WebSocket event stream (auth gate)
    db/             # SQLite layer: 11 migrations, repositories, batched writes, retention
    filters.py      # pure-Python BPF-style filters (no libpcap needed)
    streaming.py    # bounded staged capture runtime (queues, overload policy, telemetry)
    pipeline.py     # engine wiring capture → detection → annotation → events
    cli.py          # 12 CLI commands
    demo.py         # synthetic PCAP generators (tests + demos)
  tests/            # 496 unit/integration tests
  demo_pcaps/       # committed fixture captures
frontend/           # React + TypeScript dashboard (Vite)
docs/               # as-built documentation + evidence reports
start.ps1           # optional convenience launcher (backend + frontend)
```

## Privacy invariants

- Only flow statistics, TLS/QUIC handshake fields, and timing are extracted.
- Payload bytes are read by the parser only to advance framing — never stored,
  logged, or sent to the model.
- Anomaly scores are computed from the 39-feature metadata vector alone.

## Version

`1.0.0` — PCAP + **live NIC capture** (Npcap 1.88, validated 2026-09-29),
92-route API + WebSocket, CLI, React console, model registry with integrity
checks: **496 tests**, **156/156 acceptance checks**, performance at or better
than the recorded baseline. Evidence:
[`docs/acceptance-report.md`](./docs/acceptance-report.md),
[`docs/hardening-report.md`](./docs/hardening-report.md),
[`docs/readiness-report.md`](./docs/readiness-report.md).
