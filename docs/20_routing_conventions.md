# Routing Conventions
## FinShield AI

**Version:** 0.1 (Draft) | **Classification:** Internal

---

## 1. Purpose
Consistent routing/URI conventions across all FinShield services so new endpoints (as modules mature through Phase 1–3) stay predictable.

## 2. URI Structure
```
/{version}/{resource}/{resource_id?}/{sub-resource?}
```
Example: `/v1/alerts/{alert_id}/status`

## 3. Versioning
- Path-based major versioning: `/v1`, `/v2`.
- No breaking changes within a version — additive fields only.
- Deprecated versions supported minimum 12 months post-successor release.

## 4. Resource Naming
- Plural nouns for collections: `/alerts`, `/endpoints`, `/tenants`.
- No verbs in paths — actions expressed via HTTP method or a clear sub-resource (`POST /correlation/query`, not `/getCorrelation`).

## 5. Module-to-Route Mapping

| Module | Route Prefix |
|--------|----------------|
| PQC Readiness | `/v1/pqc/*` |
| Cross-Domain Correlation | `/v1/correlation/*` |
| TEE Integration / Attestation | `/v1/attestation/*` |
| Adversarial Resilience | `/v1/adversarial/*` (internal-only, not customer-facing) |
| Digital Twin | `/v1/twin/*` |
| ZK-Proof Audit Trail | `/v1/compliance/*` |
| Bio-Inspired Detection | Internal service, not directly routed (feeds `/v1/alerts`) |
| 5G/6G Edge | `/v1/edge/*` (edge-node-local API, separate from core) |

## 6. Internal vs. External Routing
- Customer-facing routes served through API gateway with OAuth2/mTLS.
- Internal-only routes (e.g., adversarial sandbox controls, model registry writes) never exposed through the public gateway — separate internal service mesh.

## 7. Multi-Tenancy in Routing
- Tenant context derived from authenticated token, never from a client-supplied path/query parameter alone (prevents tenant-ID spoofing — ties to Threat Model §4.1).

## 8. Rate Limiting Convention
- Per-tenant rate limits applied at gateway level; correlation and compliance-proof endpoints have stricter limits given higher compute cost.

## 9. Edge Routing (5G/6G MEC)
- Edge nodes route detection locally first (sub-10ms budget); only aggregated/summary events forwarded to core platform to preserve latency SLA.

*Draft — finalize alongside API Specs during Phase 1 engineering design.*
