# Dynamic Application Security Testing (DAST) — Strategy & Report Template
## FinShield AI

**Version:** 0.1 (Draft Template) | **Classification:** Confidential

**Note:** No running application exists yet to scan. This defines the DAST program; the report section is a template.

---

## 1. Purpose
Find runtime vulnerabilities (auth bypass, injection, misconfigured TLS, SSRF, etc.) that static analysis can't catch, by testing the running application.

## 2. Tooling (Proposed)
| Target | Tool Candidates |
|--------|------------------|
| Web dashboard / APIs | OWASP ZAP, Burp Suite |
| TLS/endpoint configuration | testssl.sh, sslyze |
| API fuzzing | Schemathesis (against OpenAPI spec) |

## 3. Scan Scope
- Customer dashboard (authenticated and unauthenticated surfaces).
- All public API endpoints per Machine-Readable API Specs.
- API gateway TLS configuration (must itself use quantum-safe-forward-looking cipher suites where possible — dogfooding the product's own PQC principle).

## 4. Cadence
- Full DAST scan: staging environment, before every production release.
- Scheduled scan: production (safe, non-destructive checks only), weekly.

## 5. FinShield-Specific Test Focus
- Attempt to retrieve payload content via any endpoint (should be structurally impossible — confirms the metadata-only architectural guarantee at runtime, not just in code review).
- Attempt cross-tenant data access via API parameter manipulation (tenant ID spoofing per Threat Model §4.1).
- Attempt to bypass attestation check on inference endpoints.

## 6. Severity & Gating Policy
| Severity | Action |
|----------|--------|
| Critical | Blocks release |
| High | Blocks release; documented exception possible with Security Lead sign-off |
| Medium | Tracked, SLA 30 days |
| Low | Tracked, best effort |

## 7. Report Template

```
Scan Date:
Environment tested:
Scanner(s) used:
Total findings: Critical __ / High __ / Medium __ / Low __
Critical/High findings detail:
  - Finding:
    Endpoint/Component:
    Description:
    Reproduction steps:
    Remediation status:
Overall pass/fail against gating policy:
Reviewed by:
```

*Template only — no scan has been performed. Do not present as evidence of a completed assessment.*
