# Operations Runbook
## FinShield AI

**Version:** 0.1 (Draft Template) | **Classification:** Internal

**Note:** Procedures below are structural placeholders reflecting the architecture defined elsewhere in this document set. Exact commands/scripts to be filled in once the real system is built.

---

## 1. Purpose
Step-by-step operational procedures for common tasks and failure scenarios — what an on-call engineer actually does at 3am.

## 2. On-Call Structure
- Primary/secondary on-call rotation, engineering + security-relevant escalation path (per Incident Response Plan §4).
- Escalation: Primary → Secondary → Engineering Lead → Security Architecture Lead (for SEV-1/2).

## 3. Runbook: Detection Latency SLA Breach
```
1. Check platform health dashboard (Monitoring & Observability §5) for affected component.
2. Identify: ingestion bottleneck, stream lag, or inference latency spike?
3. If inference latency: check TEE node health, attestation status.
4. If stream lag: check consumer group status, scale stream processing if needed.
5. If unresolved in [TBD] minutes: escalate per on-call chain.
6. If customer-impacting beyond [TBD] minutes: notify per Incident Response communication plan.
```

## 4. Runbook: Attestation Failure
```
1. Confirm scope: single node or platform-wide?
2. Single node: cordon node, route traffic to healthy TEE nodes, investigate offline.
3. Platform-wide: this is SEV-1 — invoke Incident Response Plan immediately.
4. Do NOT disable attestation checking to "restore service" — fallback mode (reduced trust,
   flagged) is the only acceptable degradation path (Security Architecture §5, Guardrails §2).
```

## 5. Runbook: Suspected Cross-Tenant Data Exposure
```
1. This is SEV-1 by definition — invoke Incident Response Plan immediately.
2. Do not attempt silent remediation; containment and evidence preservation take priority.
3. Isolate affected query path / service.
4. Compliance Lead engaged immediately for notification-obligation assessment.
```

## 6. Runbook: Model Rollback
```
1. Confirm rollback trigger per Deployment & Rollback Plan §5.
2. Execute traffic switch to last-known-good model version (blue/green).
3. Verify cross-sector recall and latency normalize post-rollback.
4. Log incident, schedule root cause analysis.
```

## 7. Runbook: Edge Node Offline
```
1. Confirm via Monitoring & Observability heartbeat alert.
2. Check customer-side connectivity vs. FinShield-side issue.
3. Confirm local buffering is active (no detection gap once reconnected, within retention window).
4. If extended outage: notify customer per SLA.
```

## 8. Routine Operational Tasks

| Task | Frequency | Owner |
|------|-----------|-------|
| Backup restoration test | Quarterly | Engineering Lead |
| DR tabletop exercise | Quarterly | Engineering + Security Lead |
| Incident response tabletop | Quarterly | Security Lead |
| Key/certificate rotation verification | Per IaC-defined rotation policy | Security Lead |
| Compliance token retention audit | Annually | Compliance Lead |

## 9. Escalation Contacts (Template)
```
Primary on-call:
Secondary on-call:
Engineering Lead:
Security Architecture Lead:
Compliance Lead:
```

*Template — populate with real contacts, commands, and thresholds once the system is operational.*
