# Data Dictionary
## Spectra

**Version:** 0.2 (Consolidated draft) | **Classification:** Confidential

**Note (2026-09-30):** This document absorbs and replaces
`07_data_dictionary_feature_engineering_log.md` (deleted to remove
duplication). It now carries the raw/stored field definitions **and** the
feature-engineering log format. The derived ML feature specification lives in
`08_feature_engineering_specification.md`.

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

---

## 6. Derived / Engineered Features (Template)

| Feature Name | Definition | Source Field(s) | Transformation | Owner |
|--------------|------------|-------------------|-----------------|-------|
| `session_duration_s` | Session length in seconds | `ts_start`, `ts_end` | `ts_end - ts_start` | TBD |
| `bytes_ratio` | Upload/download ratio | `byte_count_up`, `byte_count_down` | `up / (down + 1)` | TBD |
| `cipher_risk_score` | Quantum vulnerability weight | `cipher_suite` | Lookup against NIST reference table | TBD |
| `endpoint_crypto_agility_trend` | 30-day trend of PQC posture | `pqc_classification` (time series) | Rolling window aggregation | TBD |
| `timing_entropy` | Entropy of inter-packet timing | `packet_timing_vector` | Shannon entropy calculation | TBD |
| `cross_sector_edge_weight` | Strength of inferred infra link | Graph DB edges | Graph algorithm (TBD) | TBD |

## 7. Feature Engineering Log Format

Each entry logs a change to feature definitions or engineering logic:

```
Date:
Author:
Feature(s) affected:
Change description:
Rationale:
Validation performed (before/after distribution comparison):
Model(s) impacted:
Approved by:
```

### Example (illustrative placeholder — not a real entry)

```
Date: TBD
Author: TBD
Feature(s) affected: cipher_risk_score
Change description: Added weighting for hybrid PQC handshakes
Rationale: TLS 1.3 hybrid key exchange was misclassified as fully vulnerable
Validation performed: TBD
Model(s) impacted: PQC Risk Scanner
Approved by: TBD
```

## 8. Feature Governance

- Any new field touching Sensitive-classified data requires Data Governance Officer review before ingestion.
- Feature changes affecting a production model require Model Evaluation & Validation re-run before deployment.
- Feature drift monitored continuously; significant drift triggers review per ML Architecture §6.

*Draft — populate/extend as the real ingestion schema and feature pipeline are implemented.*
