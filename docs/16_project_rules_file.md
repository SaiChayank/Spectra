# Project Rules File
## FinShield AI

**Version:** 0.1 (Draft) | **Classification:** Internal

---

## 1. Purpose
Ground rules for anyone (human or AI-assisted tooling) contributing to FinShield AI — engineering, data handling, and content generation constraints.

## 2. Non-Negotiable Architectural Rules
1. No code path may decrypt, log, or persist raw traffic payload — metadata only, always.
2. No hardcoded secrets, keys, or credentials in any repository, config, or generated code.
3. No production deployment without a passing gate per the Deployment & Rollback Plan.
4. No model promoted to production without a completed Model Evaluation & Validation Report and Experiment Tracking Log entry.
5. No cross-tenant data access without hashed/tokenized identifiers, except via the dual-sign-off de-anonymization path.

## 3. Data Handling Rules
- All new fields touching customer traffic must be classified (Data Dictionary) before use.
- Synthetic or anonymized data only in dev/staging environments — never live customer metadata.
- Any retention period change requires Data Governance Officer approval.

## 4. Documentation Rules
- Any document claiming a completed security assessment (VAPT, SAST, sign-off, model validation) must reflect a real, dated, attributable event — never generated as if completed when it has not occurred.
- Architecture or threat model changes require a corresponding Architecture Decision Log entry.

## 5. Coding Standards (Proposed — align with engineering)
- `snake_case` naming, consistent with Data Dictionary conventions.
- All PRs require passing SAST + secrets scan before merge (see SAST doc §5).
- No disabling of security linters/gates without a logged, approved exception.

## 6. AI-Assisted Development Rules
- AI tools may draft code, docs, and templates but may not fabricate test results, benchmark numbers, or approval signatures.
- Any AI-generated security-relevant code (crypto, access control, TEE boundary) requires human security review before merge — no auto-merge for this category.

## 7. Escalation Path
- Architectural rule violation discovered post-merge → immediate revert, incident logged, Security Lead notified.
- Ambiguity about whether something violates these rules → default to escalating to Security Architecture Lead rather than proceeding.

## 8. Ownership
- This file is owned by the Security Architecture Lead and reviewed at each Phase gate.

*Draft — ratify with full engineering team before treating as binding.*
