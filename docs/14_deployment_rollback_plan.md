# Deployment & Rollback Plan
## FinShield AI

**Version:** 0.1 (Draft) | **Classification:** Confidential

---

## 1. Deployment Strategy
- Blue/green or canary deployment for core platform services.
- Model deployments (detection models) always go through: Digital Twin/shadow mode → canary (small traffic %) → full rollout.
- TEE-hosted services require re-attestation as part of the deployment pipeline — a deployment without a fresh, valid attestation report is automatically blocked.

## 2. Pre-Deployment Gate Checklist
- [ ] SAST scan passed (see SAST doc §5 gating policy)
- [ ] Model Evaluation & Validation Report signed off (for model deployments)
- [ ] Experiment Tracking Log entry complete for deployed model version
- [ ] IaC change reviewed and approved (2 approvals for production)
- [ ] Security Sign-Off obtained for any change touching Sensitive-classified data paths

## 3. Deployment Sequence (Core Platform)
1. Deploy to staging, run against Digital Twin replica traffic.
2. Shadow mode in production: new version runs in parallel, output compared but not acted upon.
3. Canary: route small % of live traffic decisions through new version.
4. Full rollout, with automated monitoring against defined SLOs.

## 4. Deployment Sequence (Model Updates)
1. Validate via Model Evaluation & Validation Report.
2. Adversarial robustness regression check against previous production model (must not regress — see Model Card §4).
3. Shadow mode minimum duration: [TBD by team, e.g., 48–72 hours].
4. Canary rollout with cross-sector recall monitoring (flag if any sector regresses).
5. Full rollout.

## 5. Rollback Triggers
| Trigger | Action |
|---------|--------|
| False positive rate exceeds threshold post-deploy | Automatic rollback to previous version |
| Detection latency SLA breach | Automatic rollback |
| Adversarial robustness regression detected | Manual review, rollback recommended |
| Security incident traced to new deployment | Immediate rollback, incident response engaged |
| Attestation failure on TEE-hosted service | Deployment blocked pre-rollout; if post-rollout, immediate rollback |

## 6. Rollback Procedure
1. Trigger detected (automated monitor or manual report).
2. Traffic routed back to last-known-good version (infra supports instant version switch via blue/green).
3. Incident logged with timestamp, trigger, affected components.
4. Root cause analysis before re-attempting deployment.
5. Post-incident review within 5 business days.

## 7. Communication Plan
- Internal: Security Lead + Product Owner notified immediately on any rollback.
- Customer-facing: notify affected customers per SLA if detection availability was impacted (align with Security Sign-Off / incident disclosure obligations under HIPAA/PCI-DSS/GDPR as applicable).

## 8. Post-Deployment Validation
- Monitor cross-sector recall, latency, and false-positive rate for [TBD stabilization window] post-full-rollout.
- Attach validation results to the Deployment record for audit trail.

*Draft — thresholds and durations marked TBD require engineering/security sign-off before this becomes operational policy.*
