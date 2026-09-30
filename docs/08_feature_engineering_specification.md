# Feature Engineering Specification
## FinShield AI

**Version:** 0.1 (Draft Template) | **Classification:** Confidential

**Note:** No production data exists yet. Defines feature definitions/logging format to be populated as feature engineering work begins.

---

## 1. Derived Feature Definitions (Template)

| Feature Name | Definition | Source Field(s) | Transformation | Owner |
|--------------|------------|-------------------|-----------------|-------|
| `session_duration_s` | Session length in seconds | `ts_start`, `ts_end` | `ts_end - ts_start` | TBD |
| `bytes_ratio` | Upload/download ratio | `byte_count_up`, `byte_count_down` | `up / (down + 1)` | TBD |
| `cipher_risk_score` | Quantum vulnerability weight | `cipher_suite` | Lookup against NIST reference table | TBD |
| `endpoint_crypto_agility_trend` | 30-day trend of PQC posture | `pqc_classification` (time series) | Rolling window aggregation | TBD |
| `timing_entropy` | Entropy of inter-packet timing | `packet_timing_vector` | Shannon entropy calculation | TBD |
| `cross_sector_edge_weight` | Strength of inferred infra link | Graph DB edges | Graph algorithm (TBD) | TBD |
| `bulk_transfer_score` | HNDL-pattern likelihood | `byte_count_up/down`, `session_duration_s`, historical baseline | Statistical deviation from baseline | TBD |

## 2. Feature Store Architecture
- Online store: low-latency serving for real-time inference.
- Offline store: training/backtesting, versioned snapshots (linked to Experiment Tracking Log `data_snapshot_hash`).
- Every feature versioned; breaking changes to a feature definition create a new feature version, not an in-place mutation.

## 3. Feature Engineering Log Format

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

### Example (illustrative placeholder only)
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

## 4. Feature Governance
- New features touching Sensitive-classified source fields require Data Governance Officer review.
- Any feature change affecting a production model requires re-run of Model Evaluation & Validation before redeployment.
- Feature drift monitored continuously; significant drift triggers review per ML Architecture §6.

*Template — populate as real feature store and pipelines are implemented.*
