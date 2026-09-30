# Static Application Security Testing (SAST) — Strategy & Report Template
## FinShield AI

**Version:** 0.1 (Draft) | **Classification:** Confidential

**Note:** No codebase exists yet. This document defines the SAST program; the report section is a template to be populated once scans run against real code.

---

## 1. Purpose
Catch insecure coding patterns before code reaches production, especially critical given FinShield handles security-sensitive metadata and cryptographic logic.

## 2. Tooling (Proposed)
| Language/Stack | Tool Candidates |
|-----------------|------------------|
| General/multi-language | Semgrep, SonarQube |
| Python (ML pipeline) | Bandit, Semgrep |
| Go/Rust (ingestion layer) | gosec, cargo-audit / clippy |
| Infrastructure as Code | Checkov, tfsec |
| Container images | Trivy, Grype |
| Secrets detection | Gitleaks, TruffleHog |

## 3. Scan Scope & Cadence
- Every pull request: lightweight SAST + secrets scan (CI gate, blocking on High/Critical).
- Nightly: full-repo deep scan.
- Pre-release: full SAST + dependency (SCA) scan, results attached to release record.

## 4. Custom Rule Priorities (FinShield-Specific)
Given the architecture's "no payload decryption" and "metadata-only" guarantees, custom rules should specifically flag:
- Any code path that accesses or logs raw packet payload.
- Any hardcoded cryptographic key or TEE attestation secret.
- Any use of a non-approved (quantum-vulnerable-only, no fallback) cipher in internal service-to-service TLS.
- Any disabled certificate validation in HTTP/TLS client code.
- Logging statements that could leak Sensitive-classified fields (see Data Dictionary).

## 5. Severity & Gating Policy
| Severity | Action |
|----------|--------|
| Critical | Blocks merge; requires Security Lead sign-off to override |
| High | Blocks merge; fix or documented exception required |
| Medium | Tracked in backlog, SLA 30 days |
| Low | Tracked, best-effort |

## 6. Report Template (populate per scan)

```
Scan Date:
Scanner(s) used:
Codebase / commit hash scanned:
Total findings: Critical __ / High __ / Medium __ / Low __
Critical/High findings detail:
  - Finding:
    File/Location:
    Description:
    Remediation status:
False positives excluded (with justification):
Overall pass/fail against gating policy:
Reviewed by:
```

## 7. Exception Process
- Any unresolved Critical/High finding requires a written exception with compensating control, approved by Security Lead, with a remediation deadline.
- Exceptions logged and reviewed monthly by the Governance Committee (see Data Governance Plan §10).

*Draft — activate once repository and CI pipeline exist. No scan has been performed; do not present this as evidence of a completed assessment.*
