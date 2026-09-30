# Data Dictionary & Feature Engineering Log
## FinShield AI

**Version:** 0.1 (Draft Template) | **Classification:** Confidential

**Note:** No production data exists yet. This document defines the schema/naming conventions and log format to be populated as ingestion and feature engineering are built.

---

## 1. Data Dictionary — Raw Metadata Fields

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
| `packet_timing_vector` | array[float] | Extractor | Inter-packet timing (for SNN path) | Internal |
| `network_slice_id` | string | 5G edge node | Slice identifier (Phase 2) | Internal |
| `sector_tag` | enum | Ingestion config | fintech / healthcare / smart_city | Internal |
| `pqc_classification` | enum | PQC Scanner | quantum_safe / quantum_vulnerable / unknown | Internal |

## 2. Data Dictionary — Derived / Engineered Features (Template)

| Feature Name | Definition | Source Field(s) | Transformation | Owner |
|--------------|------------|-------------------|-----------------|-------|
| `session_duration_s` | Session length in seconds | `ts_start`, `ts_end` | `ts_end - ts_start` | TBD |
| `bytes_ratio` | Upload/download ratio | `byte_count_up`, `byte_count_down` | `up / (down + 1)` | TBD |
| `cipher_risk_score` | Quantum vulnerability weight | `cipher_suite` | Lookup against NIST reference table | TBD |
| `endpoint_crypto_agility_trend` | 30-day trend of PQC posture | `pqc_classification` (time series) | Rolling window aggregation | TBD |
| `timing_entropy` | Entropy of inter-packet timing | `packet_timing_vector` | Shannon entropy calculation | TBD |
| `cross_sector_edge_weight` | Strength of inferred infra link | Graph DB edges | Graph algorithm (TBD) | TBD |

## 3. Feature Engineering Log Format

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

## 4. Naming Conventions
- `snake_case` for all field and feature names.
- Hashed/PII-adjacent fields suffixed with `_hash`.
- Boolean features prefixed with `is_` or `has_`.
- Time-windowed aggregates suffixed with window, e.g., `_30d`.

## 5. Governance
- Any new field touching Sensitive-classified data requires Data Governance Officer review before ingestion.
- Feature changes affecting a production model require Model Evaluation & Validation re-run before deployment.

*Template — populate as real ingestion pipeline and feature store are implemented.*
