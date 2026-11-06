# Documentation Reconciliation Note
## Spectra

**Status:** Living document · **Last updated:** 2026-09-30
**Read this first:** it explains how the rest of `docs/` maps onto the code that actually exists.

---

## 1. Why this note exists

The `docs/` directory contains two generations of documentation written at different
project stages:

| Generation | Files | Written | Nature |
|---|---|---|---|
| Planning era | `01_…` – `30_…` (45 files) | 2026-08-11, pre-development | Governance/architecture **drafts & templates** for a distributed cloud platform provisionally named "FinShield AI" |
| Acceptance era | `acceptance-report.md` | 2026-09-29 | **Real, evidence-backed** acceptance record of the implemented system |
| Reconciliation era | `00_reconciliation_note.md`, `31_requirements_traceability_matrix.md` | 2026-09-30 | This note, plus the requirement-by-requirement mapping to code and tests |

The planning docs describe a multi-service cloud deployment (Kafka, Neo4j,
ClickHouse, SGX/SEV-SNP TEEs, Kubernetes). What was built — **Spectra v1.0.0** — is
a deliberately single-node, embeddable platform: Python/FastAPI, one SQLite
database, in-process streaming stages, and software-cryptography analogs of the
hardware-trust ideas. That design divergence was never written back into the
planning docs; this note is that record. The planning docs remain valuable as the
requirements baseline and the roadmap for the distributed/hardened future — treat
them as *targets*, not current-state description.

## 2. Naming

"FinShield AI" (planning docs) and "Spectra" (code, README, acceptance report) are
the same product. All planning documents have been renamed to **Spectra** (2026-09-30);
historical references to the old name survive only in this note and in git history.

## 3. Decision ledger

Status legend: **KEPT** = implemented as planned · **ANALOG** = core idea delivered
with different technology · **REPLACED** = different mechanism chosen ·
**DEFERRED** = not built, still on the roadmap · **DIVERGED** = partially built,
differently shaped.

| Planning decision (doc §) | Status | What actually exists | Where |
|---|---|---|---|
| Metadata-only, no decryption capability anywhere (ADR-001, Guardrails §2, Project Rules §2) | **KEPT** | Core invariant: payload bytes only advance framing, never stored/logged/scored; 39-feature vector is the sole model input; enforced by tests | `spectra/parse/`, `spectra/features/`, `spectra/ml/`; `tests/test_flow`, `test_tls` |
| All 8 strategic modules (BRD FR-1…FR-8) | **KEPT** | Every module implemented in-process (the 3-phase schedule was collapsed into one release) | `spectra/modules/{pqc,tee,adv,twin,audit,bio,corr,edge}` |
| Rust/Go edge-node ingestion (Architecture Plan §5.1) | **REPLACED** | Python + scapy capture (PCAP file, live NIC via Npcap) | `spectra/capture/` |
| Kafka/Pulsar event bus (LLA §3) | **REPLACED** | In-process bounded queues with explicit overload policies and counted drops | `spectra/streaming.py` |
| ClickHouse / Neo4j / PostgreSQL / S3 storage (DB Schemas, Data Architecture) | **REPLACED** | Single SQLite (WAL) with 6 migrations + repositories + batched writes; joblib model artifacts; in-memory correlation graph hydrated from flow rows | `spectra/db/`, `spectra/store.py`, `modules/corr/graph.py` |
| Hardware TEE inference: SGX/SEV-SNP/TrustZone + vendor-rooted attestation (ADR-002, FR-3.1) | **ANALOG** | Software enclave: nonce-bound Schnorr attestation quotes, sealed inference receipts, Shamir k-of-k federated secret sharing | `modules/tee/{enclave,federated}.py` |
| ZK-proof audit trail (FR-6.1) | **ANALOG** | Hash-chained append-only log, Merkle checkpoints + inclusion proofs, Schnorr proof statements, signed compliance certificates — verifiable, but not zk-SNARKs | `modules/audit/` |
| OAuth2/OIDC + MFA + mTLS service mesh (Security Architecture §2) | **DIVERGED** | Local scrypt accounts, HttpOnly session cookies, RBAC (ADMIN/ANALYST/VIEWER), default-deny auth gate | `services/auth.py`, `api/security.py`, `authz.py` |
| Multi-tenancy as a hard constraint (SRS §6, Threat Model TB-4) | **DEFERRED** | Single-tenant; API binds 127.0.0.1 | `config.py` |
| SIEM webhook delivery + signed payloads (Security Payload, SRS §5) | **DEFERRED** | WebSocket event stream + REST only | `api/app.py` |
| 30-day/13-month/7-year retention schedule (Data Governance §5) | **DIVERGED** | Age-based retention implemented but **default off**; growth bounded by row caps; audit log never pruned | `config.py`, `db/retention.py` |
| Sector model: fintech / healthcare / smart_city (terminology, PRD) | **KEPT** | `SectorClassifier` with per-sector domains and sensitivity weights (healthcare 1.0/HIPAA, fintech 0.9/PCI-DSS, smart city 0.7); sector-specific PQC roadmaps | `sectors.py`, `modules/pqc/roadmap.py` |
| PQC readiness: scanner, crypto-agility tracking, HNDL screening, roadmap generator (FR-1) | **KEPT** | Handshake scanner + registry, per-endpoint inventory (`PQCInventory.observe`), bulk-transfer HNDL screening, `generate_roadmap` | `modules/pqc/` |
| Cross-domain correlation graph + kill-chain visualization (FR-2) | **KEPT (partial)** | Host/IP/SNI graph, blast-radius cascade, attack paths, `/api/graph/*` — no time-window correlation parameter (FR-2.2 gap) | `modules/corr/` |
| Adversarial red team + drift-vs-attack correlation (FR-4) | **KEPT** | Score-boundary attack generators, evasion watch (meta-anomaly on probing), PSI drift baseline; on-demand rather than continuously scheduled | `modules/adv/`, `ml/model.py` |
| Digital twin: replica, simulation, playbooks, shadow mode (FR-5) | **KEPT** | Topology builder from live graph, deterministic attack simulation, playbook validation library, z-score shadow comparison | `modules/twin/` |
| Bio-inspired: danger theory, SNN timing path, swarm (FR-7) | **KEPT** | Self-model + 6 danger signals, spiking-NN timing detector, 5-agent swarm voting, memory cells; annotates only, never creates detections | `modules/bio/` |
| Edge MEC micro-detector, sub-10 ms (FR-8.1) + slice policy (FR-8.2) | **KEPT** | 12-feature robust-z micro-detector (measured p50 0.0098 ms), URLLC/eMBB/mMTC slice policies, LEO/GEO link compensation | `modules/edge/` |
| Managed file intake without filesystem paths (DAST §5 philosophy) | **KEPT** | Multipart upload: basename/extension/magic/size validation, generated stored names, traversal-proof path re-derivation | `capture/storage.py` |
| CI/CD gates: SAST, SCA, DAST per PR (CI/CD Doc) | **DEFERRED** | No CI config in repo; the 106-check acceptance runner + pytest suite are the manual gate | `backend/scripts/acceptance.py` |
| VAPT / SAST / DAST / SCA / model-validation / sign-off records | **STILL TEMPLATES** | Deliberately unpopulated (anti-fabrication rule, Project Rules §4); must be completed with real, dated events before any external claim | docs 09/10/11/15/19/20 |
| Graph DB for correlation (ADR-004) | **DIVERGED** | In-memory adjacency graph rebuilt from persisted flows on startup (`hydrate`) | `modules/corr/graph.py` |
| Hashed/tokenized identifiers for cross-sector sharing (ADR-003) | **DEFERRED** | No cross-tenant sharing exists (single tenant) | — |

## 4. ADR status update

| ADR | Was | Now |
|---|---|---|
| ADR-001 Metadata-only | Proposed | **Accepted by implementation** — enforced architecturally and by tests |
| ADR-002 TEE inference | Proposed | **Analog delivered** (software enclave); hardware TEE remains Phase-2+ roadmap |
| ADR-003 Hashed cross-sector identifiers | Proposed | **Deferred** with the multi-tenant roadmap |
| ADR-004 Graph database | Proposed | **Superseded in practice** by in-memory graph + SQLite persistence; revisit if cross-sector scale arrives |

## 5. What remains on the roadmap

Multi-tenancy and regional deployment · real hardware TEE execution · SIEM/webhook
delivery · time-windowed cross-sector correlation (FR-2.2) · automated CI security
gates · external VAPT · age-based retention defaults aligned to the Data Governance
schedule (currently opt-in via `SPECTRA_*_RETENTION_DAYS`).

## 6. Convention going forward

When the implementation diverges from a planning document, either update that
document or add a row here — do not let a planning doc silently become a false
description of current state. Evidence documents (VAPT, SAST, sign-offs) may only
be populated with real, dated, attributable events per `16_project_rules_file.md` §4.
