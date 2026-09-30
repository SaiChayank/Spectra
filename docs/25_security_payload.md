# Security Payload (Event/Alert Payload Schema)
## FinShield AI

**Version:** 0.1 (Draft) | **Classification:** Confidential

**Scope note:** This defines the structured payload FinShield sends *about* a detection (to SIEM/webhook/SOC integrations) — it never contains raw network payload content, consistent with the platform's metadata-only architecture.

---

## 1. Purpose
Standardize the JSON payload FinShield emits for security events so customer SIEMs (Splunk, Sentinel, QRadar, etc.) can ingest it consistently.

## 2. Event Payload Schema

```json
{
  "event_id": "string (uuid)",
  "event_type": "pqc_vulnerable | hndl_pattern | adversarial_probe | cross_sector_correlation | timing_anomaly",
  "severity": "informational | low | medium | high | critical",
  "confidence": "float 0.0-1.0",
  "tenant_id": "string (hashed)",
  "sector": "fintech | healthcare | smart_city",
  "session_ref": {
    "session_id": "string (hashed)",
    "src_ref": "string (hashed)",
    "dst_ref": "string (hashed)",
    "ts_start": "ISO 8601",
    "ts_end": "ISO 8601"
  },
  "detection_context": {
    "model_version": "string",
    "detection_module": "string",
    "cipher_suite": "string (if relevant)",
    "correlation_graph_ref": "string (if cross-domain event)"
  },
  "recommended_action": "monitor | investigate | escalate",
  "compliance_ref": {
    "zk_proof_token_id": "string (nullable)"
  },
  "created_at": "ISO 8601"
}
```

## 3. Field Rules
- No field in this payload may ever contain raw payload bytes, decrypted content, or unhashed PII — enforced by schema validation before emission (payload structurally cannot carry it).
- `confidence` below the tenant's configured threshold is suppressed from external emission (see Guardrails Context §3) but retained internally for tuning.
- `severity` mapping to `confidence`/`event_type` combinations defined per Evaluation Rubrics §4 (alert quality).

## 4. Delivery
- Delivered via signed webhook (HMAC signature header) or pull via `/v1/alerts` (see API Specs).
- Retry policy: exponential backoff, max 24 hours, then logged as delivery failure for manual review.

## 5. Integrity & Non-Repudiation
- Each payload optionally references a `zk_proof_token_id` so the receiving SIEM can independently verify the processing claim via the Compliance API — ties the security payload directly to the ZK-Proof Audit Trail module.

## 6. Versioning
- Payload schema versioned alongside the API (`/v1`); additive-only changes within a version, per Routing Conventions §3.

*Draft — finalize field list with SIEM integration partners during Phase 1.*
