# Architecture Decision Logs (ADRs)
## FinShield AI

**Version:** 0.1 (Draft Template) | **Classification:** Internal

---

## 1. ADR Format

```
ADR ID:
Title:
Date:
Status: [Proposed / Accepted / Superseded / Deprecated]
Context:
Decision:
Consequences (positive and negative):
Alternatives considered:
Related requirements (BRD FR-#):
```

## 2. Seed ADRs (Derived from Concept Documentation — require formal ratification)

### ADR-001: Metadata-Only Processing (No Payload Decryption)
```
Date: 2026-08-11
Status: Proposed
Context: Core value proposition is threat detection without decrypting or
exposing sensitive payloads.
Decision: The architecture will not include any payload decryption
capability at any layer — this is an architectural exclusion, not a
configurable policy.
Consequences:
  + Strong default privacy/compliance posture (PCI-DSS, HIPAA alignment)
  + Reduces attack surface (nothing to steal that constitutes payload access)
  - Limits detection to metadata/behavioral signals only; some threats
    detectable only via content inspection are out of reach
Alternatives considered: Optional decryption with strict access controls —
rejected due to compliance risk and trust-model complexity.
Related requirements: BRD NFR-1
```

### ADR-002: TEE-Based Model Inference
```
Date: 2026-08-11
Status: Proposed
Context: Privacy-preserving ML alone doesn't protect against a compromised
cloud provider or side-channel attack at inference time.
Decision: Detection model inference for Phase 2+ will run inside a Trusted
Execution Environment with attestation support.
Consequences:
  + Hardware-enforced isolation, strong audit story for regulated customers
  - Performance overhead; vendor lock-in risk (SGX/SEV-SNP/TrustZone differences)
  - Requires fallback strategy when TEE unavailable (graceful degradation, flagged output)
Alternatives considered: Software-only confidential computing (homomorphic
encryption) — rejected for Phase 2 due to current performance cost at
required latency budgets; may revisit for specific sub-workloads later.
Related requirements: BRD FR-3
```

### ADR-003: Hashed/Tokenized Identifiers for Cross-Sector Correlation
```
Date: 2026-08-11
Status: Proposed
Context: Cross-domain correlation needs to link entities across
organizational and sector boundaries without creating a de-anonymization
shortcut.
Decision: Cross-sector graph edges use hashed/tokenized identifiers by
default; resolving to real identity requires dual sign-off.
Consequences:
  + Reduces risk of cross-tenant privacy violation
  - Adds friction/latency to legitimate investigation workflows requiring
    identity resolution
Alternatives considered: Full identity visibility with strict RBAC only —
rejected as insufficient given DPIA risk rating on this data flow.
Related requirements: BRD FR-2, DPIA §4
```

### ADR-004: Graph Database for Cross-Domain Correlation
```
Date: 2026-08-11
Status: Proposed
Context: Need efficient traversal of shared-infrastructure relationships
across large numbers of endpoints.
Decision: Use a property graph database (Neo4j/Neptune candidate) rather
than modeling relationships in the relational or time-series store.
Consequences:
  + Native support for multi-hop traversal queries central to correlation
  - New operational skillset/tooling required; scale-testing needed before
    Phase 1 commitment
Alternatives considered: Relational adjacency-list model — rejected as
unlikely to scale for multi-hop cross-sector queries.
Related requirements: Architecture Plan §5.2
```

## 3. Governance
- New ADRs required for any decision that is expensive to reverse (data model, crypto approach, TEE vendor commitment, storage technology).
- Superseding an ADR requires linking the new ADR ID and marking the old one `Superseded`, never deleting history.

*Seed ADRs are drafts reflecting the initial concept doc — require Architecture Review Board ratification before `Accepted` status.*
