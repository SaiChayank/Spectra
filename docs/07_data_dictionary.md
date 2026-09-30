# Data Dictionary
## FinShield AI

**Version:** 0.1 (Draft) | **Classification:** Confidential

**Note:** Covers raw/stored field definitions. See Feature Engineering Specification for derived ML features.

---

## 1. Raw Metadata Fields

| Field Name | Type | Source | Description | Sensitivity |
|------------|------|--------|--------------|-------------|
| `session_id` | string (hashed) | TLS Metadata Extractor | Unique session identifier, salted hash | Internal |
| `ts_start` | timestamp | Extractor | Session start time | Sensitive |
| `ts_end` | timestamp | Extractor | Session end time | Sensitive |
| `src_ip_hash` | string (hashed) | Extractor | Hashed source IP | Sensitive |
| `dst_ip_hash` | string (hashed) | Extractor | Hashed destination IP | Sensitive |
| `sni` | string | TLS ClientHello | Server Name Indication (if present) | Sensitive |
| `cipher_suite` | string | TLS handshake | Negotiated cipher suite | Internal |
| `tls_version` | string | TLS handshake | e.g., TLS 1.2, TLS 1.3 | Internal |
| `ja3_fingerprint` | string | Extractor | Client TLS fingerprint | Internal |
| `ja3s_fingerprint` | string | Extractor | Server TLS fingerprint | Internal |
| `byte_count_up` | integer | Extractor | Bytes sent client→server | Internal |
| `byte_count_down` | integer | Extractor | Bytes sent server→client | Internal |
| `packet_timing_vector` | array[float] | Extractor | Inter-packet timing | Internal |
| `network_slice_id` | string | 5G edge node | Slice identifier (Phase 2) | Internal |
| `sector_tag` | enum | Ingestion config | fintech / healthcare / smart_city | Internal |
| `pqc_classification` | enum | PQC Scanner | quantum_safe / quantum_vulnerable / unknown | Internal |
| `tenant_id` | string (hashed) | Ingestion config | Tenant partition key | Sensitive |

## 2. Stored/Derived Reference Fields (Non-ML)

| Field Name | Type | Description |
|------------|------|--------------|
| `alert_id` | string | Unique alert identifier |
| `detection_type` | enum | pqc_vulnerable / hndl_pattern / adversarial_probe / cross_sector_correlation / timing_anomaly |
| `confidence` | float | Model confidence score 0.0–1.0 |
| `model_version` | string | Model registry reference |
| `compliance_token_id` | string | ZK-proof token reference |

## 3. Naming Conventions
- `snake_case` for all field names.
- Hashed/PII-adjacent fields suffixed `_hash`.
- Boolean fields prefixed `is_`/`has_`.
- Time-windowed aggregates suffixed with window, e.g., `_30d`.

## 4. Sensitivity Classes
Aligned with Data Governance Plan §2: Restricted (never collected) / Sensitive / Internal / Public.

## 5. Governance
Any new field touching Sensitive-classified data requires Data Governance Officer review before ingestion (Data Governance Plan §6).

*Draft — populate/extend as real ingestion schema is implemented. See Database Schemas for storage-layer table definitions.*
