# Spectra — Machine learning

What the model is, what it needs, how it is trained and versioned, and — most
importantly — **what its numbers mean and what they do not mean.**

Code: `backend/spectra/features/extractor.py`, `backend/spectra/ml/model.py`,
`backend/spectra/services/training.py`, `backend/spectra/services/model_registry.py`.

---

## 1. The 39-feature schema

One `float32` vector per **completed flow** (`extract_features(flow)`),
`FEATURE_SCHEMA_VERSION = 1`, `N_FEATURES = 39`. Features come from packet
statistics, inter-arrival timing, TCP flags, endpoint context and handshake
metadata — **never from payload contents.**

| # | Feature | Group | Meaning |
|---|---|---|---|
| 1 | `duration_s` | timing/volume | flow lifetime in seconds |
| 2–4 | `packets_total/fwd/bwd` | timing/volume | packet counts, both directions |
| 5–7 | `bytes_total/fwd/bwd` | timing/volume | byte counts, both directions |
| 8–11 | `bytes_mean/std/min/max` | timing/volume | per-packet size statistics |
| 12–13 | `fwd_bwd_pkt_ratio`, `fwd_bwd_byte_ratio` | timing/volume | order-independent `min/max ∈ [0,1]` |
| 14–17 | `iat_mean/std/min/max_s` | timing/volume | inter-arrival time statistics |
| 18–20 | `iat_fwd_mean/std/mad_s` | timing/volume | forward IATs; `mad` = median absolute deviation (beacons collapse it) |
| 21–22 | `packets_per_s`, `bytes_per_s` | timing/volume | rates over the flow duration |
| 23–26 | `syn_count/fin_count/rst_count/psh_count` | flags | TCP flag totals |
| 27 | `payload_ratio` | flags | Σ payload ÷ (fwd+bwd bytes) |
| 28 | `size_entropy` | flags | Shannon entropy of packet sizes over 16 normalised buckets |
| 29 | `is_tcp` | context | 0/1 |
| 30 | `dst_port_norm` | context | destination port ÷ 65535 |
| 31 | `tls_present` | TLS metadata | handshake observed |
| 32 | `tls_version_norm` | TLS metadata | negotiated version ÷ 0x0304 |
| 33–34 | `tls_cipher_count`, `tls_extension_count` | TLS metadata | ServerHello cipher count, ClientHello extension count |
| 35–36 | `sni_present`, `sni_length` | TLS metadata | SNI presence and length |
| 37 | `alpn_count` | TLS metadata | offered/selected ALPN protocols |
| 38–39 | `handshake_ms`, `server_hello_ms` | TLS metadata | flow start → ClientHello / ServerHello |

Diagnostics are sanitised (`nan/inf → 0`) and length-guarded; the ordered name
list is hashed (`feature_schema_digest()`), and **any artifact whose digest
differs is refused at load** — a detector trained against another layout can
never be scored silently.

## 2. Baseline requirements

The detector is trained on **known-benign** traffic only:

* A PCAP of ordinary, expected traffic for **the network you will monitor**.
  The synthetic demo baseline (`spectra demo`) is tuned for the demo captures;
  real traffic scored against it is out-of-distribution
  ([limitations.md §5](./limitations.md)).
* **≥ 10 completed flows** — both `collect_flows()` and `SpectraDetector.fit`
  refuse below that floor.
* A capture must not be running while training (409 `AnalysisBusy`, single
  flight), and training requires `model:manage` (ADMIN).
* `contamination` = expected anomaly fraction in the baseline
  (default `0.02`, `0 < c < 1`). It sets the *threshold*, not the fit.

Input addressing is id-only: `POST /api/model/train` takes `capture_id`
(a managed import), never a filesystem path.

## 3. Training process

```
PCAP → collect_flows(idle_timeout 30 s, bucket 5 s) → flows_to_matrix
     → StandardScaler.fit_transform → IsolationForest(n_estimators=300,
       random_state=42, n_jobs=-1).fit
     → raw = -decision_function
     → threshold = percentile(raw, 100·(1−contamination))     # 98th pct at 0.02
     → sorted training raws (the percentile scale for scoring)
     → 40-bin per-feature PSI baseline (drift reference)
```

* **Output:** a `SpectraDetector` joblib bundle `{version: 1, detector}` at
  `SPECTRA_MODEL_PATH` (`backend/models/spectra_model.joblib`), plus:
  * bio layer and edge micro-detector **sidecars** fitted on the same matrix;
  * TEE re-measurement of the artifact (simulated enclave measurement);
  * a `model_runs` row and an audit entry `model.train` carrying `model_sha256`.
* **Registry registration (default):** the artifact is copied to an immutable
  `<data_dir>/model_artifacts/mdl_<id>.joblib` as a `CANDIDATE`, then validated
  and activated.
* **Sidecar digests:** bio/edge artifacts get a `<file>.sha256` sidecar; a
  mismatch means "do not load" (the subsystem is skipped, detection continues).
* Measured cost on the reference machine: **0.49–1.12 s** for the 42-flow
  demo baseline (496-test suite exercises this path repeatedly).

## 4. Model lifecycle

```
CANDIDATE ──validate──► VALIDATED ──activate──► ACTIVE ──supersede──► RETIRED
    │                                                                  │
    └── any failed check ──► FAILED                          rollback ─┘
```

* **Validation gate — 8 checks**, any failure ⇒ `FAILED` with an error:
  `artifact_contained`, `artifact_exists`, `artifact_sha256`,
  `artifact_loads` (version/class/schema), `trained`, `threshold_set`,
  `min_training_rows (≥ 10)`, `feature_schema`.
* **Integrity:** every load re-runs path containment + sha256 against the
  registry row + `SpectraDetector.load` (rejects version or schema mismatch).
  See [security.md §5](./security.md).
* **Single ACTIVE:** a partial unique index (`status='ACTIVE'`) plus one
  `BEGIN IMMEDIATE` transaction makes retire-then-promote atomic.
* **Startup:** if the registry has rows, **only** its ACTIVE artifact is
  loaded — an untrusted/missing ACTIVE yields an untrained session (no legacy
  fallback). An empty registry adopts an existing deployed model once,
  marked `adopted: true` in the audit entry.
* **Activation side effects** (one hook): swap the live detector → copy the
  artifact to the deployed path → set `model_trained` → refresh alert
  contamination → re-measure TEE → repoint the evasion watch → emit the `model`
  event → audit `model.activate`.
* **Rollback:** `POST /api/model/registry/rollback` re-activates the most
  recently superseded (RETIRED) row, audited as `model.rollback`.
* Transitions are serialised under a re-entrant lock; with `persist=false` the
  registry reports `enabled: false` and writes return 409.

## 5. Interpreting the numbers

Four different quantities ride on every detection. They are **not**
interchangeable:

| Quantity | Range | Produced by | Meaning |
|---|---|---|---|
| **Anomaly score** | 0–100 | `SpectraDetector.score` | *Percentile rank of the flow against the training distribution* — how far from "normal" it sits. **Not a probability, not a confidence.** |
| **Anomaly flag** | bool | `raw > threshold` | Above the `100·(1−contamination)` percentile of the training set (≈ top 2 % at 0.02) |
| **Confidence** | 0.30–0.95 | `threats.classify_threat` | Support ÷ (support+oppose) over rule signals, clamped; unknown verdicts capped at 0.45 |
| **Severity** | LOW < MEDIUM < HIGH < CRITICAL | `severity.calculate_severity` | Ordinal urgency: category base → ±confidence → score ≥ 99 → critical asset → repeat sightings; every input is returned in `factors` |

Reading a detection in the console:

* **Score 95+ with `reasons`** — the top |z|-scored features that pulled the
  flow away from the baseline (e.g. `iat_fwd_mad_s: 4.1σ`).
* **Score high, category `UNKNOWN_ANOMALY`** — deviant but the rules lack the
  ≥ 2 independent signals a named category needs. Treat as "look at it", not as
  a named attack.
* **Confidence** rises only when independent signals agree; it can never reach
  1.00 by design.
* **Severity** may differ from the score on purpose: a 99-score anomaly of a
  routine kind on an internal host can be LOW, while a 90-score beacon against
  a critical asset repeated three times is HIGH.
* **PSI drift** (`/api/model/drift`): `< 0.10` stable, `0.10–0.25` moderate,
  `> 0.25` significant — above that, scores are no longer calibrated and the
  recommendation is retrain.

## 6. Limitations (short form — full list in [limitations.md](./limitations.md))

1. **Unsupervised.** Trained on benign data only; there is no labelled
   precision/recall, no calibrated false-positive rate.
2. **Baseline-dependent.** A baseline from another network flags ordinary
   traffic (measured: 472 real flows ≈ 97.6 on the synthetic baseline vs
   3.6 % flagged on a matching 70 s baseline).
3. **Metadata-only by design** — payload-level threats (malware content, DNS
   names inside encrypted tunnels) are architecturally invisible.
4. **Small baselines give a coarse percentile scale** (42 demo flows).
5. **Detector and classifier are not independent evidence** — rules run only on
   flows the detector already flagged, and one rule reads the score itself.
6. **Adversarial robustness is measured, not guaranteed**
   (`spectra adversarial` / `/api/model/robustness`).
7. **Threshold ≠ calibration:** `contamination` states how much of the
   *baseline* you consider abnormal; it does not control production precision.
