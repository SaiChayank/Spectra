# Evaluation Rubrics
## FinShield AI

**Version:** 0.1 (Draft Template) | **Classification:** Internal

---

## 1. Purpose
Standardized scoring rubrics so model, module, and release readiness are judged consistently rather than ad hoc — feeds into Model Evaluation & Validation Report and Deployment gate decisions.

## 2. Detection Model Readiness Rubric (0–4 scale per criterion)

| Criterion | 0 (Not Started) | 1 (Poor) | 2 (Fair) | 3 (Good) | 4 (Excellent) |
|-----------|------------------|----------|----------|----------|----------------|
| Precision/Recall vs. target | No data | Below target by >20% | Below target by 5-20% | Meets target | Exceeds target with margin |
| Adversarial robustness | Not tested | Evasion success >50% | 20-50% | 5-20% | <5% evasion success |
| Cross-sector consistency | Not tested | >20% recall variance | 10-20% | 5-10% | <5% variance |
| Latency vs. SLA | Not measured | Fails SLA | Meets SLA marginally | Meets SLA comfortably | Well under SLA budget |
| Explainability/traceability | None | Model is a black box | Partial feature attribution | Full attribution available | Attribution + audit trail (ZK-Proof compatible) |

**Promotion threshold (proposed):** Average score ≥3 across all criteria, with no individual criterion below 2, required for production promotion.

## 3. Module Readiness Rubric (for Phase-gate decisions)

| Criterion | Weight | Scoring Guidance |
|-----------|:---:|-------------------|
| Functional requirements met (per BRD) | 30% | % of module's FRs implemented and tested |
| Security review complete | 25% | Threat model updated + SAST clean + (if applicable) VAPT scoped |
| Compliance mapping validated | 20% | Relevant regulation(s) reviewed by Compliance Lead |
| Documentation complete | 15% | Model Card / API Spec / Architecture doc updated |
| Operational readiness | 10% | Monitoring, rollback plan, on-call ownership defined |

**Phase-gate pass threshold (proposed):** ≥80% weighted score, with Security review criterion never below 70% individually (non-negotiable given product category).

## 4. Alert Quality Rubric (for SOC analyst / dashboard review)

| Criterion | Description |
|-----------|--------------|
| Actionability | Can an analyst act on this alert without needing raw payload? |
| Context sufficiency | Does the alert include enough correlation/graph context to triage quickly? |
| Noise level | Is the false-positive rate low enough not to erode analyst trust? |

## 5. Documentation Quality Rubric (for this document set itself)

| Criterion | Check |
|-----------|-------|
| Traceable | Does every claim link back to a BRD requirement, ADR, or real data source (not invented)? |
| No fabricated evidence | Are template sections clearly marked as unpopulated rather than filled with invented numbers? |
| Current | Has the document been reviewed since the last material architecture/threat model change? |

## 6. Usage
- Rubrics applied at: model promotion decisions, Phase-gate reviews, quarterly documentation audits.
- Scores logged alongside the relevant Experiment Tracking Log entry or Security Sign-Off record for auditability.

*Draft — thresholds are proposed starting points; ratify with engineering and security leadership.*
