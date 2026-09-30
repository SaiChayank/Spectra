# Model Evaluation & Validation Report — Template
## FinShield AI

**Version:** 0.1 (Draft Template) | **Classification:** Confidential

**Note:** No models have been trained yet. This defines the required evaluation structure. All bracketed values are placeholders — do not fill with invented numbers.

---

## 1. Model Identification
```
Model name/version:
Module (e.g., PQC Risk Scanner, Adversarial Detector):
Training data snapshot hash (link to Experiment Tracking Log run_id):
Intended use:
Out-of-scope uses:
```

## 2. Evaluation Methodology
- Held-out test set, stratified by sector (fintech/healthcare/smart city).
- Adversarial robustness evaluation using Self-Attacking Module outputs (see Module 3 spec).
- Fairness/consistency check across sectors — a model shouldn't systematically under-detect in one vertical.

## 3. Core Detection Performance (fill in with real results)

| Metric | Target | Result | Pass/Fail |
|--------|--------|--------|-----------|
| Precision | [TBD by team] | [ ] | [ ] |
| Recall | [TBD by team] | [ ] | [ ] |
| F1 | [TBD by team] | [ ] | [ ] |
| False positive rate | [TBD by team] | [ ] | [ ] |
| Inference latency (p99) | Per NFR-2 in BRD | [ ] | [ ] |

## 4. Adversarial Robustness

| Attack Type | Evasion Success Rate (lower is better) | Notes |
|-------------|------------------------------------------|-------|
| Traffic pattern perturbation | [ ] | |
| Timing manipulation | [ ] | |
| Poisoning (federated scenario) | [ ] | |

## 5. Drift Sensitivity
- Comparison against Model Drift vs. Attack Correlation module: does the model distinguish benign drift from adversarial manipulation? [Results TBD]

## 6. Cross-Sector Consistency Check
| Sector | Recall | Notes |
|--------|--------|-------|
| Fintech | [ ] | |
| Healthcare | [ ] | |
| Smart City | [ ] | |

*Significant recall gaps across sectors must be investigated before promotion — a security product that underperforms for one vertical creates uneven protection.*

## 7. TEE Compatibility Check (if applicable)
- Model successfully executes inside target TEE: [Yes/No]
- Inference latency overhead introduced by enclave: [ ]

## 8. Validation Decision

| Decision | Rationale |
|----------|-----------|
| [ ] Approved for staging | |
| [ ] Rejected — needs iteration | |
| [ ] Approved with documented limitations | |

## 9. Sign-Off
```
ML Engineering Lead:
Security Architecture Lead:
Date:
```

*Template — no evaluation has occurred. This must not be circulated as a completed validation until real results are entered and signed off.*
