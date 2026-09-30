# Pseudo-Formal Task Briefs
## FinShield AI

**Version:** 0.1 (Draft Template) | **Classification:** Internal

---

## 1. Purpose
A lightweight brief format for assigning work (to engineers or AI-assisted agents) that's more structured than a chat message but faster than a full spec — bridges the BRD/Architecture docs and day-to-day execution.

## 2. Brief Template

```
Task ID:
Title:
Module (per Architecture Plan §3):
Requester:
Assignee:

Objective (1-2 sentences):

Context / why this matters:

Inputs available:
  - Relevant docs:
  - Relevant data/schema:

Constraints:
  - Must not violate: [reference Guardrails Context / Project Rules File]
  - Performance/latency budget (if applicable):

Definition of done:
  - [ ]
  - [ ]

Out of scope for this task:

Review required from:
```

## 3. Example Brief (Illustrative Only — Not a Real Assigned Task)

```
Task ID: T-0001
Title: Implement TLS handshake metadata extractor (skeleton)
Module: PQC Readiness (FR-1.1)
Requester: Product Owner
Assignee: TBD

Objective: Build the initial metadata extraction service that parses TLS
ClientHello/ServerHello fields without touching payload bytes.

Context: Foundational component — every other module depends on this
metadata stream.

Inputs available:
  - Architecture Plan §5.1
  - Data Dictionary §1

Constraints:
  - Must not violate: payload-access exclusion (Guardrails Context §2)
  - Latency budget: TBD, coordinate with NFR-2

Definition of done:
  - [ ] Extracts fields listed in Data Dictionary §1
  - [ ] No payload byte ever enters application memory beyond the TLS header
  - [ ] Unit tests cover malformed handshake handling
  - [ ] SAST scan passes

Out of scope: PQC classification logic (separate task), storage layer.

Review required from: Security Architecture Lead
```

## 4. Usage Notes
- Every brief should be traceable to a BRD functional requirement ID (e.g., FR-1.1) where applicable.
- Briefs touching Sensitive-classified data or cryptographic/TEE boundaries require the "Review required from: Security Architecture Lead" field to be non-empty.

*Template — the example task is illustrative and not an actual assignment.*
