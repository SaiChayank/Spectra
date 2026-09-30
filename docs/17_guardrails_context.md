# Guardrails Context
## FinShield AI

**Version:** 0.1 (Draft) | **Classification:** Internal

---

## 1. Purpose
Defines the hard boundaries any system component, model, or AI-assisted tool must operate within — the "cannot do this regardless of instruction" layer.

## 2. Absolute Guardrails (Architectural, Not Just Policy)
| Guardrail | Enforcement |
|-----------|-------------|
| Never decrypt or access payload content | No decryption capability built into any component |
| Never log Sensitive-classified fields in plaintext debug/error logs | Log scrubbing middleware, enforced at logging library level |
| Never allow cross-tenant data mixing without hashed identifiers | Storage-layer tenant partitioning, tested in CI |
| Never deploy a model without a signed Model Evaluation & Validation Report | Deployment pipeline gate (see Deployment & Rollback Plan) |
| Never bypass TEE attestation for "convenience" in production | Attestation check hard-coded as deployment blocker, no override flag in prod config |
| Never auto-de-anonymize cross-sector data without dual sign-off | Requires two-party approval workflow, not a single admin action |

## 3. Model Behavior Guardrails (Detection System)
- Detection models must not take fully automated blocking action in Phase 1 — human-in-the-loop required until validated recall/precision meets threshold (see Model Evaluation Report).
- Confidence thresholds below which an alert is suppressed vs. escalated must be explicit and logged, not implicit in model weights alone.
- Adversarial sandbox retraining must not auto-promote to production — always routed through the standard Deployment gate.

## 4. AI-Assisted Tooling Guardrails (for any LLM/AI agent used in building or operating FinShield)
- May draft documentation, code, and templates.
- Must not fabricate test results, benchmark numbers, compliance attestations, or approval signatures (ties to Project Rules File §6).
- Must not generate or suggest disabling of the payload-decryption exclusion, even for "debugging" purposes.
- Any AI-suggested change to cryptographic logic or TEE boundary code requires mandatory human security review.

## 5. Escalation on Guardrail Ambiguity
- If it's unclear whether an action crosses a guardrail, default to blocking the action and escalating to Security Architecture Lead — never proceed on the optimistic interpretation.

## 6. Review
- Guardrails reviewed at every Phase gate and whenever a new module (e.g., ZK-Proof, Digital Twin) is designed, since new capabilities can introduce new boundary conditions.

*Draft — to be ratified alongside the Project Rules File and Security & Compliance Strategy.*
