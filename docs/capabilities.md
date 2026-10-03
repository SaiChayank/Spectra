# Spectra — Capabilities

What each capability actually is in this build, classified honestly. The
advanced-module rows are not prose: they come from
`backend/spectra/capabilities.py`, which the API serves verbatim at
`GET /api/capabilities` and the dashboard renders.

---

## 1. Classification ladder

| Label | Meaning |
|---|---|
| **REAL** | Real functionality operating on real inputs — no simulated components. |
| **LOCAL IMPLEMENTATION** | Real computation, but local single-process scope: it stands in for a distributed/hardware-scoped integration that does not exist here (code label `LOCAL`). |
| **SIMULATED** | Modelled or emulated behaviour — the underlying integration does not exist in this build (code label `SIMULATED`). |
| **EXPERIMENTAL** | Research prototype: real mathematics, not hardened for production (code label `EXPERIMENTAL`). |
| **FUTURE** | Not present in this build at all. |

Two extra code labels exist for completeness: `HARDWARE_BACKED` (SGX/SEV
enclave, vendor MEC/5G control plane) is **reserved and claimed by nothing** —
`GET /api/capabilities` reports `hardware_backed_count: 0`; `UNAVAILABLE` maps
to FUTURE below.

**Scoring invariant (applies to every row):** no module changes the anomaly
score, the alert confidence, or the severity. Modules contribute evidence and
context only (`SCORING_POLICY`).

## 2. Detection pipeline

| Capability | Class | What it really is |
|---|---|---|
| Managed PCAP import (`.pcap`/`.pcapng`) | **REAL** | Streaming upload, magic/extension/size validation, sha256 dedupe, generated storage names, id-addressed lifecycle |
| Live NIC capture | **REAL** | scapy/libpcap sniff thread, read-only, BPF-style filter; requires Npcap on Windows ([setup §6](./local-setup.md)) |
| Flow tracking | **REAL** | 5-tuple table with idle/lifetime/LRU bounds, TCP completion, packet-stat accounting |
| TLS/QUIC metadata parsing | **REAL** | Handshake-only parsing (SNI, ALPN, versions, ciphers, extensions, JA3/JA4); QUIC Initial opened per RFC 9001. **No payload decryption, ever** |
| Feature extraction | **REAL** | 39 metadata features per flow, schema-versioned with a digest checked at model load ([ml.md §1](./ml.md)) |
| Anomaly inference | **REAL** | `StandardScaler` + `IsolationForest` trained locally on a benign baseline; 0–100 percentile score + σ-explanations |
| Behavioural classification | **REAL** | Rule categories over weighted signals; ≥ 2 signals and confidence ∈ [0.30, 0.95] or it degrades to `UNKNOWN_ANOMALY` |
| Alert generation | **REAL** | Grouped sightings (600 s window), evidence, severity derived in five audited steps |
| Incident correlation | **REAL** | Anchor/threat/proximity scoring with a minimum score, auto-attachment, explicit state machine |
| Persistence | **REAL** | SQLite (WAL), 11 migrations, batched writes, row caps, read-your-writes flush |
| Audit trail | **EXPERIMENTAL** | Real hash chain + Merkle/Schnorr, but pure-Python research-grade crypto; see module row below |
| REST API + WebSocket | **REAL** | 92 routes + `WS /ws/events`, default-deny auth, body limits, structured logs with credential redaction |
| Authentication & RBAC | **REAL** | scrypt, server-side sessions, three roles, login throttling, default-deny middleware ([security.md](./security.md)) |
| Model registry lifecycle | **REAL** | CANDIDATE→VALIDATED→ACTIVE→RETIRED, sha256 integrity, single-ACTIVE index, validate/rollback |
| React console | **REAL** | 9 sections, role-aware UI, live WS, no token in JS |
| Health & observability | **REAL** | Per-subsystem states, runtime metrics, failure counters, request ids |

## 3. Advanced modules (served by `/api/capabilities`)

| # | Module | Class | Honest note (from the code) |
|---|---|---|---|
| 1 | PQC crypto-readiness | **REAL** | Heuristic quantum-risk scoring over real parsed TLS/QUIC handshakes |
| 2 | TEE attestation | **SIMULATED** | In-process enclave; quotes carry `environment: "SIMULATED"`. Real deployment needs SGX/SEV — never hardware-backed here |
| 3 | Adversarial resilience | **REAL** | White-box evasion, drift (PSI) and robustness analysis against the fitted model |
| 4 | Digital twin | **SIMULATED** | Deterministic local simulator over the observed flow topology; no live-network coupling |
| 5 | Audit chain / ZKP | **EXPERIMENTAL** | Research-grade hash chain, Merkle, Schnorr, ZK statements — tamper-evidence of *this* log, not regulatory compliance |
| 6 | Bio-inspired detection | **EXPERIMENTAL** | Danger theory / SNN / swarm heuristics; annotations only, never an independent verdict |
| 7 | Correlation graph | **REAL** | Attack-graph correlation over observed flow records, hydrated from history at startup |
| 8a | Edge slicing + MEC micro-detector | **LOCAL IMPLEMENTATION** | Real micro-detector scoring and slice classification, single-process scope |
| 8b | Edge deployment / NTN registry | **SIMULATED** | In-process registry explicitly marked `capability: SIMULATED` — no MEC or 5G control plane |
| — | Federated aggregation (TEE sub-feature) | **SIMULATED** | Real additive secret-sharing math over *locally simulated* parties |

Per-module integration contract (what it consumes/produces, whether it may touch
scoring, how it degrades on failure) is machine-readable in
`GET /api/capabilities` and in `capabilities.py::_MODULE_CAPABILITIES`.

## 4. FUTURE — not in this build

| Item | Why it is future/absent |
|---|---|
| Hardware-backed TEE (SGX / SEV / TrustZone), remote attestation | No enclave hardware in scope; label reserved, count 0 |
| Real 5G/MEC control plane, NTN (satellite/UAV) links | Simulated registry only |
| Cross-organisation federated training | Secret-sharing math exists; parties are simulated |
| Multi-node deployment, HA database, container/K8s, Kafka/Redis | Local modular monolith by standing rule |
| External identity (OIDC/LDAP/SSO), MFA | Local accounts only |
| Payload decryption / DPI content inspection | **Excluded by design** — privacy boundary, not a backlog item ([limitations.md §1](./limitations.md)) |
| SIEM / SOAR / webhook / ticketing integration | Out of scope for a local build |
| Age-based retention enabled by default, idle-session timeout | Implemented but off by default ([limitations.md §5–§7](./limitations.md)) |
| Automated frontend tests (unit/e2e) | Backend suites only; frontend verified by `tsc` + build ([testing.md](./testing.md)) |
| Prompt 15 | Deferred by standing rules |

## 5. How to verify at runtime

```powershell
# after signing in
GET http://localhost:8787/api/capabilities
```

Returns `statuses`, `definitions`, `scoring_policy`, `hardware_backed_count`
(0) and one entry per module with `status`, `hardware_backed`, `note`,
`available` (probed live), `failures` (guarded-failure counter) and the
consume/produce/failure contract. `test_module_contracts.py` and
`test_integrity.py` fail if a module ever claims hardware backing, invents an
availability claim, or declares that it moves scoring.
