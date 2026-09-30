# Model Card (Fact Sheet) — Template
## FinShield AI

**Version:** 0.1 (Draft Template) | **Classification:** Confidential / Customer-shareable summary version recommended

---

## 1. Model Overview
```
Model name:
Version:
Module:
Date released:
Model type (e.g., gradient-boosted classifier, spiking neural net, transformer-based sequence model):
```

## 2. Intended Use
- **Primary use case:** [e.g., classify TLS sessions as quantum-vulnerable vs. quantum-safe]
- **Intended users:** SOC analysts, automated alerting pipeline
- **Out-of-scope uses:** Not intended for payload content classification (architecturally impossible); not intended as sole basis for automated blocking without human review during Phase 1

## 3. Training Data
```
Data sources (categories, not raw data):
Data snapshot hash / version (link to Feature Engineering Log):
Sector representation (fintech/healthcare/smart city split):
Known limitations of training data:
```

## 4. Evaluation Results
Summary pulled from Model Evaluation & Validation Report — link full report internally.

| Metric | Result |
|--------|--------|
| Precision | [ ] |
| Recall | [ ] |
| Adversarial robustness (evasion success rate) | [ ] |
| Cross-sector recall variance | [ ] |

## 5. Ethical & Fairness Considerations
- Risk: uneven detection performance across sectors could leave one vertical under-protected — mitigated via cross-sector consistency check (Model Evaluation Report §6).
- Risk: false positives disproportionately impacting specific traffic patterns (e.g., legitimate backup jobs flagged as HNDL) — monitored via analyst feedback loop.

## 6. Privacy Considerations
- Model trained and inferring exclusively on metadata; no payload content in training data (see Data Governance Plan).
- If TEE-deployed: inference isolated from host OS/cloud provider access (see Architecture Plan §5.3).

## 7. Known Limitations
```
[To be completed based on actual evaluation — e.g., degraded performance on TLS 1.2-only networks, latency under high load, etc.]
```

## 8. Maintenance & Monitoring
- Retraining trigger: [performance degradation threshold TBD] or scheduled cadence.
- Drift monitoring: tied to Module 3 (Drift vs. Attack Correlation).
- Owner: ML Engineering Lead.

## 9. Version History

| Version | Date | Change | Approved By |
|---------|------|--------|--------------|
| | | Initial release | |

*Template — populate once a model is trained and evaluated. Do not publish externally until Section 4 reflects real, signed-off evaluation results.*
