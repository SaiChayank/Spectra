# Software Composition Analysis (SCA) — Strategy & Report Template
## FinShield AI

**Version:** 0.1 (Draft Template) | **Classification:** Confidential

**Note:** No dependency tree exists yet. This defines the SCA program; the report section is a template.

---

## 1. Purpose
Identify known vulnerabilities and license risks in third-party/open-source dependencies — especially important given FinShield's ML and cryptographic libraries are prime attack targets.

## 2. Tooling (Proposed)
| Ecosystem | Tool |
|-----------|------|
| Python (ML pipeline) | pip-audit, Safety |
| Go/Rust (ingestion) | govulncheck, cargo-audit |
| Container images | Trivy, Grype |
| General/multi-ecosystem | Snyk, Dependabot |

## 3. Scan Scope & Cadence
- Every pull request: dependency vulnerability check (CI gate).
- Nightly: full dependency tree scan across all services.
- Pre-release: full SCA scan attached to release record, alongside SAST/DAST.

## 4. FinShield-Specific Priorities
- Cryptographic libraries (TLS parsing, PQC algorithm implementations) reviewed with extra scrutiny — a vulnerability here undermines the product's core value proposition.
- TEE SDK dependencies (Intel SGX SDK, AMD SEV-SNP tooling) tracked against vendor security advisories specifically, not just generic CVE feeds.
- ML framework dependencies (training/serving libraries) checked for known adversarial-ML-relevant CVEs.

## 5. License Compliance
- Flag copyleft licenses (e.g., GPL) in any dependency bundled into customer-facing/proprietary components — requires legal review before inclusion.
- Maintain an approved-license allowlist.

## 6. Severity & Gating Policy
| Severity | Action |
|----------|--------|
| Critical (known exploited CVE) | Blocks merge/release immediately |
| High | Blocks merge; remediation SLA 14 days |
| Medium | SLA 30 days |
| Low | Best effort |

## 7. Report Template

```
Scan Date:
Scanner(s) used:
Total dependencies scanned:
Vulnerable dependencies: Critical __ / High __ / Medium __ / Low __
Critical/High findings detail:
  - Package/Version:
    CVE(s):
    Affected component:
    Remediation (upgrade/patch/replace):
    Status:
License issues found:
Overall pass/fail against gating policy:
Reviewed by:
```

*Template only — no scan has been performed against a real dependency tree yet.*
