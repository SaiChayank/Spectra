# Database Schemas & Data Dictionary
## FinShield AI

**Version:** 0.1 (Draft) | **Classification:** Confidential

**Note:** This complements doc 07 (feature-level dictionary) with storage-layer schema design. No database is provisioned yet.

---

## 1. Storage Layer Overview

| Store | Technology (proposed) | Purpose |
|-------|--------------------------|---------|
| Time-series DB | ClickHouse / TimescaleDB | Session metadata, anomaly scores |
| Graph DB | Neo4j / Neptune | Cross-domain correlation |
| Object store | S3-compatible | Model artifacts, compliance tokens |
| Relational (control plane) | PostgreSQL | Tenant config, RBAC, audit log |

## 2. Table: `sessions` (Time-series DB)

| Column | Type | Notes |
|--------|------|-------|
| session_id | string (PK) | Hashed |
| tenant_id | string (FK) | Tenant partition key |
| ts_start | timestamp | |
| ts_end | timestamp | |
| src_ip_hash | string | |
| dst_ip_hash | string | |
| sni | string | nullable |
| cipher_suite | string | |
| tls_version | string | |
| ja3_fingerprint | string | |
| pqc_classification | enum | quantum_safe / quantum_vulnerable / unknown |
| sector_tag | enum | fintech / healthcare / smart_city |

Partitioned by `tenant_id` + date. No cross-tenant query allowed without explicit correlation-service path (see Threat Model TB-4).

## 3. Table: `alerts` (Time-series DB)

| Column | Type | Notes |
|--------|------|-------|
| alert_id | string (PK) | |
| session_id | string (FK) | |
| tenant_id | string (FK) | |
| detection_type | enum | see API Specs `Alert.detection_type` |
| confidence | float | |
| model_version | string | FK to model registry |
| status | enum | open / dismissed / escalated |
| created_at | timestamp | |

## 4. Graph DB: Node & Edge Types

| Node type | Properties |
|-----------|------------|
| `Endpoint` | endpoint_id, sector_tag, pqc_classification |
| `Infrastructure` | infra_id, provider, region |
| `Tenant` | tenant_id (hashed reference only, no PII) |

| Edge type | Meaning |
|-----------|---------|
| `SHARES_INFRA` | Two endpoints share cloud/network infrastructure |
| `COMMUNICATED_WITH` | Observed session between endpoints (hashed) |
| `FLAGGED_TOGETHER` | Correlated alert pattern across sectors |

## 5. Table: `model_registry` (PostgreSQL control plane)

| Column | Type | Notes |
|--------|------|-------|
| model_version | string (PK) | |
| module | string | e.g., pqc_scanner, adversarial_detector |
| training_data_hash | string | Links to Experiment Tracking Log |
| status | enum | staging / canary / production / retired |
| tee_compatible | boolean | |
| deployed_at | timestamp | |

## 6. Table: `compliance_tokens` (Object store index in PostgreSQL)

| Column | Type | Notes |
|--------|------|-------|
| token_id | string (PK) | |
| tenant_id | string (FK) | |
| window_start | timestamp | |
| window_end | timestamp | |
| proof_location | string | Pointer to object store artifact |
| issued_at | timestamp | |

## 7. Access Control Notes
- `sessions` and `alerts` tables enforce row-level security by `tenant_id`.
- Cross-tenant graph queries logged separately (see Threat Model, Data Governance §8) and require the dual-sign-off de-anonymization path if resolving hashed identifiers.

## 8. Retention Enforcement
- Automated TTL/purge jobs aligned with Data Governance Plan §5 retention schedule, implemented at the database layer (e.g., ClickHouse TTL clauses), not just application logic.

*Draft schema — subject to revision during database engineering design review.*
