# Monitoring & Observability
## FinShield AI

**Version:** 0.1 (Draft) | **Classification:** Internal

---

## 1. Purpose
Defines what FinShield monitors about itself — the observability layer that feeds Incident Response, Disaster Recovery triggers, and day-to-day operations.

## 2. Observability Pillars
- **Metrics:** system health, latency, throughput, model performance proxies.
- **Logs:** structured, Sensitive-field-scrubbed (per Guardrails Context §2).
- **Traces:** distributed tracing across service boundaries (ingestion → detection → alerting).

## 3. Key Metrics by Layer

| Layer | Metrics |
|-------|---------|
| Ingestion | Events/sec, malformed-record rate, edge node connectivity status |
| Stream processing | Consumer lag, partition health |
| Detection models | Inference latency (p50/p95/p99), confidence score distribution, drift score |
| TEE/Attestation | Attestation success/failure rate, attestation staleness |
| Cross-Domain Correlation | Graph query latency, edge-write rate |
| Alerting | Alert volume, false-positive feedback rate (from analyst dismissals), delivery success to SIEM |
| Compliance | ZK-proof generation time, token issuance rate |

## 4. Alerting Rules (Examples — thresholds TBD with engineering)

| Alert | Condition | Severity |
|-------|-----------|----------|
| Detection latency SLA breach | p99 > SLA threshold for 5 min | High |
| Attestation failure spike | Failure rate > [TBD]% | Critical → Incident Response |
| Consumer lag growing | Sustained lag increase over [TBD] min | Medium |
| Drift score exceeds threshold | Per ML Architecture §8 | Medium → triggers Adversarial Sandbox review |
| Cross-tenant access anomaly | Any unexpected cross-tenant query pattern | Critical → Incident Response |
| Edge node offline | No heartbeat for [TBD] min | Medium |

## 5. Dashboards
- **Platform health dashboard:** ops-facing, all layers above.
- **Model performance dashboard:** ML Eng-facing, per-model metrics and drift.
- **Security dashboard:** Security Lead-facing, attestation status, anomalous access, incident status.
- **Customer-facing status page:** availability, no internal metric detail exposed.

## 6. Tooling (Proposed)
| Function | Tool Candidates |
|----------|-------------------|
| Metrics | Prometheus + Grafana |
| Logs | ELK/OpenSearch or cloud-native equivalent |
| Tracing | OpenTelemetry + Jaeger/Tempo |
| Alerting/on-call | PagerDuty or Opsgenie |

## 7. Log Handling Constraints
- No Sensitive-classified field ever appears in plaintext in logs — enforced by log-scrubbing middleware, tested as part of SAST custom rules (SAST Report §4).
- Log retention aligned with Data Governance Plan schedule, not indefinite by default.

## 8. Ownership
- Platform/infra metrics: Engineering Lead.
- Model metrics: ML Engineering Lead.
- Security/access metrics: Security Architecture Lead.

*Draft — thresholds and tool selection to be finalized during Phase 1 implementation.*
