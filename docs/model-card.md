# Spectra detector — model card

**Model:** `SpectraDetector` (`backend/spectra/ml/model.py`) · **Card version:** 1.0 · **Date:** 2026-11-06 · **Code version:** artifact format `MODEL_VERSION = 1`, feature schema `FEATURE_SCHEMA_VERSION = 1` · **Evidence:** `docs/evaluation-report.md` (all synthetic). Not a sign-off.

Spectra does **not** ship a trained model. Each deployment trains its own on its own benign traffic (`spectra train` / `POST /api/model/train`), so this card describes the model *family and training procedure*; the registry (`GET /api/model/registry`) and each artifact's `info()` record the per-model facts (training size, threshold, hashes, contamination, any synthetic augmentation).

## Intended use
Passive, metadata-only anomaly detection on encrypted-traffic flows for an operator monitoring a network they own or are authorised to monitor: surface flows that behave unlike that network's own benign baseline, with an explanation and a threat-type hypothesis, for a human analyst. **Decision support, not a verdict**: nothing blocks traffic, and detections never auto-promote a model.

## Not for
Automated blocking or enforcement; judging people; payload or content inspection (impossible by design — no payload is decrypted, logged or used); use as a general "is this malware" classifier; use on a network without a baseline from that network; any security claim based on the synthetic results alone.

## Model
* **Algorithm:** scikit-learn `IsolationForest`, 300 trees, `random_state=42`, behind a `StandardScaler`; unsupervised, trained on benign flows only. Anomaly = raw score above a threshold set from the training set at the configured **contamination** (default 0.02 → about 2 % of training flows would be flagged).
* **Input:** 39 numeric features per completed flow (counts, sizes, inter-arrival statistics, TCP flag counts, TLS/QUIC handshake structure, SNI presence/length, handshake timing) — `FEATURE_NAMES` in `features/extractor.py`. Derived from headers, timing and handshake structure only.
* **Output:** a 0–100 score (percentile rank against the training set, clipped at 100), a boolean flag, and the top contributing features by z-score. Downstream, a rule layer proposes a threat type (`threats.py`), and the bio/pair-cadence signals add context. Those layers are heuristics, not learned models.
* **Optional training aids (off by default):** synthetic benign augmentation (`--augment N`, always labelled synthetic in the run record, audit entry and UI).

## Training data
Operator-supplied benign PCAP of their own network. The repository's demo generators (`spectra.demo`) produce synthetic baselines for tests and demonstrations only. One public capture (CTU-13 scenario 1, botnet-host traffic) has been *scored* but not used for validation: with no labels and a TLS-only synthetic baseline it flagged everything, benign control included, so it says nothing about detection (evaluation report §9).

## Performance (synthetic only — read the caveats there)
* Trained on a single-profile demo baseline, the model **flagged 58.2 % [53.5, 63.0] of held-out diverse benign traffic** (1.5 % on traffic like its own training data). Baseline-matching is the dominant failure mode.
* Trained on the 7-profile synthetic library: 2.2 % [1.0, 3.8] false flags on held-out traffic from the same generators (in-distribution, a best case); all four synthetic attack families detected (hardest: slow TLS beacon, AUC 0.997, 94 % recall at 0.1 % FPR on validation).
* At 1 % attack prevalence the computed precision is about 31 % even for the better model.
* Cross-sector false-flag spread: ≤ 1 pp (within noise); no sector-specific behaviour.
* **Adversarial robustness: poor.** The greedy feature-perturbation attack evaded 100 % of sampled flagged flows on three of four families against the better model. Retraining on evaded vectors did not help (`HANDOFF_FINDINGS.md`, 9B).

## Limitations and known failure modes
* Baseline-matching: behaviour outside the training distribution — including legitimate new applications — is flagged. Drift is reported (PSI vs training and vs recent history); retraining is the operator's decision.
* Metadata-only: content-level threats are invisible by design.
* Not evasion-robust (above); a patient adversary who shapes timing and sizes can hide.
* Periodic benign traffic (NTP, updates, health checks) looks like beaconing; the pair-cadence signal is unvalidated on real traffic.
* Class imbalance: precision falls sharply at realistic attack prevalence.
* Unvalidated on real labelled data. On the one real capture tried, synthetic-trained baselines flagged 100 % of flows including a benign plaintext control (evaluation report §9): train on your own network's baseline, never on synthetic data alone. The synthetic attack families were written by the detector's authors.
* The 0–100 score saturates at 100; use the raw score for ranking analyses.

## Ethical and privacy considerations
Operates on traffic metadata about people's connections (addresses, SNI, timing) even without payload. Deploy only where monitoring is authorised and disclosed; apply retention (`SPECTRA_*_RETENTION_DAYS`); uploaded capture files are stored verbatim and may contain payload (`docs/security.md` §4.9); access is role-gated and audit-chained.

## Versioning and change control
Artifacts are sha256-recorded in the registry with CANDIDATE → VALIDATED → ACTIVE → RETIRED states; promotion is explicit and audit-chained. A change to `MODEL_VERSION`, the feature schema, the algorithm or the default contamination requires a new card version and a re-run of `scripts/eval_synthetic.py`. This card is versioned with the repository (git history); approval is the owner's.
