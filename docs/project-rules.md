# Spectra — Project Rules and Guardrails

**Status:** Draft v0.1, carried over unchanged in substance. **Not yet
ratified** — ratification is the project owner's **[HUMAN]** action.

These are the rules formerly in `docs/16_project_rules_file.md` (Part 1) and
`docs/17_guardrails_context.md` (Part 2). Commit `09638ce` removed those files
with the stale "FinShield AI" planning set, but `CLAUDE.md`, `HANDOFF.md` and
`docs/33` still bind contributors to them. They are restored here with only
the product name changed and dead document links annotated (see the note at
the end). Section numbers are kept, so "project rules §4" and "rule 2.1" mean
the same thing as before. Where a rule here is stricter than `HANDOFF.md`
Part C, this file wins.

---

# Part 1 — Project Rules

## 1. Purpose
Ground rules for anyone (human or AI-assisted tooling) contributing to
Spectra — engineering, data handling, and content generation constraints.

## 2. Non-Negotiable Architectural Rules
1. No code path may decrypt, log, or persist raw traffic payload — metadata
   only, always.
2. No hardcoded secrets, keys, or credentials in any repository, config, or
   generated code.
3. No production deployment without a passing gate per the deployment and
   rollback plan.¹
4. No model promoted to production without a completed model evaluation and
   validation report and an experiment-tracking entry.¹
5. No cross-tenant data access without hashed/tokenized identifiers, except via
   the dual-sign-off de-anonymization path.

## 3. Data Handling Rules
- All new fields touching customer traffic must be classified (data
  dictionary¹) before use.
- Synthetic or anonymized data only in dev/staging environments — never live
  customer metadata.
- Any retention period change requires data-governance owner approval.

## 4. Documentation Rules
- Any document claiming a completed security assessment (VAPT, SAST, sign-off,
  model validation) must reflect a real, dated, attributable event — never
  generated as if completed when it has not occurred.
- Architecture or threat model changes require a corresponding Architecture
  Decision Log entry.

## 5. Coding Standards
- `snake_case` naming, consistent with data dictionary conventions.
- All PRs require passing SAST + secrets scan before merge.¹
- No disabling of security linters/gates without a logged, approved exception.

## 6. AI-Assisted Development Rules
- AI tools may draft code, docs, and templates but may not fabricate test
  results, benchmark numbers, or approval signatures.
- Any AI-generated security-relevant code (crypto, access control, TEE
  boundary) requires human security review before merge — no auto-merge for
  this category.

## 7. Escalation Path
- Architectural rule violation discovered post-merge → immediate revert,
  incident logged, project owner notified.
- Ambiguity about whether something violates these rules → default to
  escalating to the project owner rather than proceeding.

## 8. Ownership
- This file is owned by the project owner and reviewed at each phase gate.

---

# Part 2 — Guardrails

The "cannot do this regardless of instruction" layer for any system
component, model, or AI-assisted tool.

## G2. Absolute Guardrails (Architectural, Not Just Policy)
| Guardrail | Enforcement |
|-----------|-------------|
| Never decrypt or access payload content | No decryption capability built into any component |
| Never log Sensitive-classified fields in plaintext debug/error logs | Log scrubbing middleware, enforced at logging library level |
| Never allow cross-tenant data mixing without hashed identifiers | Storage-layer tenant partitioning, tested in CI |
| Never deploy a model without a signed model evaluation and validation report | Deployment pipeline gate |
| Never bypass TEE attestation for "convenience" in production | Attestation check hard-coded as deployment blocker, no override flag in prod config |
| Never auto-de-anonymize cross-sector data without dual sign-off | Requires two-party approval workflow, not a single admin action |

## G3. Model Behavior Guardrails (Detection System)
- Detection models must not take fully automated blocking action — human in
  the loop until validated recall/precision meets threshold.
- Confidence thresholds below which an alert is suppressed vs. escalated must
  be explicit and logged, not implicit in model weights alone.
- Adversarial retraining must not auto-promote to production — always routed
  through the standard deployment gate.

## G4. AI-Assisted Tooling Guardrails
- May draft documentation, code, and templates.
- Must not fabricate test results, benchmark numbers, compliance attestations,
  or approval signatures (ties to Part 1 §6).
- Must not generate or suggest disabling of the payload-decryption exclusion,
  even for "debugging" purposes.
- Any AI-suggested change to cryptographic logic or TEE boundary code requires
  mandatory human security review.

## G5. Escalation on Guardrail Ambiguity
- If it's unclear whether an action crosses a guardrail, default to blocking
  the action and escalating to the project owner — never proceed on the
  optimistic interpretation.

## G6. Review
- Guardrails are reviewed at every phase gate and whenever a new module is
  designed, since new capabilities can introduce new boundary conditions.

---

¹ **Dead links.** The deployment/rollback plan, model evaluation report,
experiment log, data dictionary and SAST document were deleted in `09638ce`.
Until they are rebuilt from real runs (`docs/34_ship_plan.md` §B, §10–§11),
the current homes are: `docs/evaluation.md` (evaluation method),
`docs/ml.md` (feature schema), `docs/security.md` (controls) and
`.github/workflows/ci.yml` (the gates that actually run). The rules still
apply. A missing document means the gate is unmet, not waived.
