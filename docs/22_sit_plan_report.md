# System Integration Testing (SIT) — Plan & Report Template
## FinShield AI

**Version:** 0.1 (Draft Template) | **Classification:** Confidential

**Note:** No integrated system exists yet. This defines the SIT plan; the report section is a template.

---

## 1. Purpose
Validate that individually-built services (per Low-Level Architecture) work correctly together end-to-end, before release.

## 2. Integration Points to Test

| Integration | What Could Go Wrong |
|--------------|----------------------|
| Edge Extractor → Stream Router | Metadata schema mismatch, dropped events under load |
| Stream Router → Behavioral Analytics / PQC Scanner / Correlation Engine | Fan-out consistency, ordering guarantees |
| Detection Inference ↔ Attestation Service | Attestation failure not correctly blocking inference |
| Alerting Layer → SIEM webhook | Payload schema drift, delivery retry logic |
| ZK-Proof Generator ↔ Compliance API | Token generation matches actual processing window |
| Correlation Graph ↔ dual-sign-off de-anonymization flow | Approval gate correctly enforced, not bypassable |

## 3. Test Case Categories
- **Happy path:** normal traffic flows end-to-end, correct alert produced.
- **Boundary/edge cases:** malformed TLS handshake, TEE attestation expiry mid-session, network partition between edge and core.
- **Cross-module:** an event that should trigger both PQC and Cross-Domain Correlation simultaneously — verify no duplicate/conflicting alerts.
- **Failure injection:** simulate graph DB outage, verify graceful degradation per Low-Level Architecture §7.

## 4. Environments
- SIT runs in staging, ideally against a Digital Twin replica for realistic traffic patterns without production risk.

## 5. Entry/Exit Criteria
- **Entry:** all unit tests passing, SAST/SCA gates clear for included services.
- **Exit:** 100% of Critical/High-priority integration test cases passing; no open Critical defects.

## 6. Report Template

```
Test cycle date:
Environment:
Services under test (versions):
Total test cases: __ / Passed: __ / Failed: __ / Blocked: __
Critical/High defects found:
  - Defect:
    Integration point affected:
    Description:
    Status:
Exit criteria met: Yes/No
Reviewed by:
```

## 7. Traceability
Each SIT test case should trace back to an SRS requirement (System Requirements Specification §3) and forward to release sign-off (Security Sign-Off / Deployment gate).

*Template only — no integration testing has occurred yet.*
