# Security Architecture
## FinShield AI

**Version:** 0.1 (Draft) | **Classification:** Confidential

**Note:** This is the technical security-controls design. See Compliance Strategy for regulatory mapping, and Threat Model for the threat/risk analysis these controls address.

---

## 1. Security Architecture Principles
1. Metadata-only by design (no decryption capability exists).
2. Zero-trust internal networking — every service call authenticated, nothing trusted by network location alone.
3. Hardware-enforced isolation (TEE) for the most sensitive workload: model inference.
4. Defense in depth — no single control is the only thing standing between an attacker and sensitive data.

## 2. Identity & Access Management
- Internal services: mTLS via service mesh, short-lived certificates.
- Human users (dashboard): OAuth2/OIDC, MFA required, role-based access (Analyst / ML Engineer / Compliance / Admin).
- Customer API access: OAuth2 client-credentials or mTLS, scoped per tenant.
- Privileged actions (e.g., cross-tenant de-anonymization) require dual-control approval, not single-admin capability.

## 3. Network Security
- Edge nodes: outbound-only connections to core platform where possible, minimizing inbound attack surface.
- Core platform: segmented by function (ingestion / analytics / trust layer), east-west traffic restricted by service mesh policy.
- Public-facing surface limited to API gateway and dashboard; internal services never directly internet-reachable.

## 4. Encryption Architecture
| Data State | Control |
|------------|---------|
| In transit (customer → edge) | TLS 1.3 minimum |
| In transit (internal) | mTLS via service mesh |
| At rest (all stores) | AES-256 or provider-managed equivalent |
| Key management | Cloud KMS / HSM, rotation policy enforced in IaC |

## 5. TEE & Attestation Architecture
- Model inference isolated in TEE (SGX/SEV-SNP/TrustZone abstraction).
- Attestation Service validates enclave identity before releasing model weights or accepting inference requests.
- Attestation chain rooted in hardware vendor certificate — no software-only attestation accepted in production.

## 6. Secrets Management
- No secrets in code or config files — injected via KMS-integrated secret store at deploy time (see IaC Documentation §5).
- Secrets scanning enforced in CI (see SAST Report §2, CI/CD Documentation).

## 7. Application Security Controls
- Input validation on all ingestion endpoints (malformed TLS handshakes quarantined, not silently processed).
- Output encoding on all dashboard-rendered data to prevent injection.
- Rate limiting per tenant on all public API endpoints.

## 8. Security Monitoring
- Centralized logging (no Sensitive-classified fields in plaintext logs — see Guardrails Context §2).
- Anomaly detection on internal access patterns (e.g., unusual cross-tenant query attempts) feeds into Monitoring & Observability and Incident Response.

## 9. Security Architecture Review Cadence
- Reviewed at every Phase gate and after any change to trust boundaries defined in the Threat Model.

*Draft — control implementations to be validated via SAST/DAST/VAPT before production reliance.*
