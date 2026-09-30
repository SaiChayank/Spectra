# Data Privacy Impact Assessment (DPIA)
## FinShield AI

**Version:** 0.1 (Draft) | **Framework:** GDPR Art. 35-aligned | **Classification:** Confidential

---

## 1. Description of Processing

**Nature:** Automated analysis of encrypted network traffic metadata (TLS handshake fields, timing, byte counts, fingerprints) to detect security threats. No payload content is decrypted or accessed.

**Scope:** Traffic metadata from customer networks in fintech, healthcare, and smart city sectors, potentially spanning multiple jurisdictions.

**Context:** Processing occurs as a security service on behalf of customers (FinShield acts as processor; customer is controller for their end-user data).

**Purpose:** Threat detection, quantum-vulnerability assessment, cross-sector attack correlation.

## 2. Necessity & Proportionality
- Metadata-only analysis is the minimum data required to achieve detection — payload access is explicitly excluded by architecture, not just policy.
- Cross-domain correlation uses hashed/tokenized identifiers by default, reducing identifiability while preserving detection utility.
- Retention windows (see Data Governance Plan) are the minimum needed for trend analysis and incident investigation.

## 3. Data Subjects & Categories of Data

| Data Subject | Data Involved | Special Category? |
|---------------|----------------|--------------------|
| End users of customer networks | Device IP/fingerprint, connection metadata | No (but healthcare context may make device identity sensitive by association) |
| Healthcare patients (indirect) | IoT medical device traffic metadata | Indirectly sensitive — device identity could reveal treatment context |
| Financial customers (indirect) | Payment API traffic metadata | Indirectly sensitive — financial behavior inference risk |

## 4. Risks to Data Subjects

| Risk | Likelihood | Severity | Mitigation |
|------|:---:|:---:|:---:|
| Re-identification via metadata pattern analysis | Medium | Medium | Field generalization, aggregation where detection doesn't require full granularity |
| Cross-sector correlation reveals sensitive association (e.g., device linked to hospital) | Low | High | Hashed identifiers, dual sign-off for de-anonymization |
| Data breach of metadata store | Low | High | Encryption at rest, TEE isolation, access logging |
| Function creep — metadata repurposed beyond security detection | Low | Medium | Purpose limitation enforced in Data Governance Plan; contractual restriction with customers |
| Over-retention beyond stated schedule | Low | Medium | Automated purge jobs, audited |

## 5. Mitigation Measures Summary
- No payload decryption capability exists (architectural, not procedural, control).
- Encryption in transit/at rest; TEE-based inference isolation.
- Retention limits enforced automatically (30-day rolling for raw metadata).
- Access control and audit logging on all Sensitive-classified data.
- ZK-Proof audit trail gives data subjects' organizations (controllers) verifiable evidence of minimal processing.

## 6. Legal Basis (to confirm per customer contract)
- Typically "legitimate interest" (security) or contractual necessity, established at the controller (customer) level; FinShield operates as processor under a Data Processing Agreement.

## 7. International Transfers
- Default: no cross-region metadata transfer without an active agreement (see Data Governance Plan §8).
- Where transfer occurs, standard contractual clauses (SCCs) or equivalent mechanism required.

## 8. Consultation
- Data Protection Officer (customer-side) to be consulted before onboarding any healthcare or EU-based customer.
- Internal Compliance Lead reviews this DPIA before each new sector entry.

## 9. Outcome & Residual Risk
Residual risk assessed as **Low-Medium**, contingent on:
- Cross-tenant isolation controls being implemented as designed (see Threat Model §4.4).
- Retention automation being verified operational before first customer onboarding.

## 10. Sign-Off

| Name | Role | Date |
|------|------|------|
| | Data Protection Officer / Compliance Lead | |
| | Security Architecture Lead | |

*Draft — this DPIA must be revisited before processing any real customer data, and prior to each new sector or jurisdiction entry.*
