# Low-Level Architecture
## FinShield AI

**Version:** 0.1 (Draft) | **Classification:** Confidential

---

## 1. Purpose
Implementation-level detail for engineering: service boundaries, internal APIs, storage design, and technology choices. Complements High-Level Architecture.

## 2. Service Breakdown

| Service | Responsibility | Module |
|---------|-----------------|--------|
| `metadata-extractor` | Parses TLS handshake, JA3/JA4, no payload access | PQC Readiness |
| `crypto-agility-tracker` | Maintains per-endpoint PQC posture history | PQC Readiness |
| `stream-router` | Event bus consumption/routing (Kafka/Pulsar) | Core |
| `behavioral-analytics` | Anomaly scoring, baseline modeling | Core |
| `detection-inference` | ML inference, runs inside TEE | TEE Integration |
| `attestation-service` | Issues/verifies TEE attestation reports | TEE Integration |
| `adversarial-sandbox` | Generates adversarial samples, drives retraining | Adversarial Resilience |
| `correlation-graph-service` | Cross-sector graph queries/writes | Cross-Domain Correlation |
| `twin-orchestrator` | Provisions isolated replica environments | Digital Twin |
| `zk-proof-generator` | Produces compliance tokens | ZK-Proof Audit Trail |
| `snn-timing-detector` | Spiking neural net timing-anomaly path | Bio-Inspired Detection |
| `mec-micro-detector` | Lightweight edge inference | 5G/6G Edge |
| `alerting-service` | Routes/dedupes detections to dashboard/SIEM | Core |

## 3. Inter-Service Communication
- Internal: gRPC for low-latency service-to-service calls (detection pipeline).
- External: REST/JSON per Machine-Readable API Specs.
- Event bus: Kafka/Pulsar topics per data type (`metadata.raw`, `alerts.detected`, `graph.edges`).
- All internal calls mutually authenticated (mTLS service mesh).

## 4. Storage Layer Detail
See Database Schemas & Data Dictionary and Data Architecture for full schema. Summary:

| Store | Technology | Used By |
|-------|------------|---------|
| Time-series DB | ClickHouse/TimescaleDB | `behavioral-analytics`, `alerting-service` |
| Graph DB | Neo4j/Neptune | `correlation-graph-service` |
| Object store | S3-compatible | `detection-inference` (model artifacts), `zk-proof-generator` (tokens) |
| Relational | PostgreSQL | Tenant config, RBAC, model registry |

## 5. TEE Boundary Detail
- `detection-inference` loads signed model artifacts only after `attestation-service` confirms enclave identity.
- Fallback mode (TEE unavailable): inference runs in standard isolated container, output flagged `trust_level: reduced` — never silently treated as equivalent.

## 6. Scaling Strategy
- `stream-router` and `behavioral-analytics` scale horizontally, partitioned by `tenant_id`.
- `correlation-graph-service` scaling requires load-testing plan (see Performance Test Report) given graph traversal cost profile.
- `mec-micro-detector` scales per edge node, independent of core platform.

## 7. Failure Modes & Handling

| Failure | Handling |
|---------|----------|
| TEE attestation failure | Block inference, alert Security Lead, fallback per §5 |
| Graph DB unavailable | Correlation alerts suppressed, core per-session alerts continue |
| Edge node connectivity loss | Local buffering, sync on reconnect within data-retention window |

## 8. Technology Stack Detail

| Layer | Technology |
|-------|------------|
| Service runtime | Go/Rust (ingestion), Python (ML serving) |
| Orchestration | Kubernetes (core), K3s (edge) |
| TEE runtime | Gramine/Occlum on SGX; SEV-SNP guest tooling |
| Service mesh | Istio/Linkerd (mTLS enforcement) |

*Draft — finalize service boundaries and tech stack during detailed engineering design.*
