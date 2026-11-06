# Related Research & How It Maps to Spectra
## Spectra

**Created:** 2026-09-30 · **Purpose:** a working bibliography of the research
Spectra builds on or should build on, with, for every entry: the idea, how it
contributes (already-used vs. backlog), and the module(s) affected. Entries are
grouped by Spectra's architecture, not by venue. Status legend:
**[USED]** the paper's idea is already implemented · **[PARTIAL]** partially
implemented · **[BACKLOG]** concrete improvement opportunity.

> Sourcing note: entries were gathered via web search (2026-09-30); verify
> citation details against the publisher page before quoting them externally.
> The classic papers (iForest, CONIKS, Bonawitz, STRIDE-adjacent) are stable;
> the 2025–2026 items are newer and less canonical.

---

## 1. Detection core (capture → features → IsolationForest)

### 1.1 Liu, Ting, Zhou — "Isolation Forest" (ICDM 2008; extended TKDD 2012)
- **Idea:** anomalies are few and different → they isolate faster in random
  recursive partitions than normal points; path length is the score. No distance
  or density needed; O(n log n) with small subsamples (ψ=256).
- **Contributes [USED]:** the entire detection core. `ml/model.py` is a 300-tree
  IsolationForest over 39 features with contamination=0.02 and a percentile
  threshold — a direct implementation.
- **Backlog insight [BACKLOG]:** the paper's subsampling (ψ=256) exists for
  speed; the current implementation trains on all flows. Also, the original
  score is a path-length average — Spectra's 0–100 percentile rescaling is a
  sensible extension, but the training threshold distribution is kept only as a
  sorted array; the paper's expected-path-length normalization
  c(n) = 2H(n−1) − 2(n−1)/n is what makes scores comparable across tree sizes.

### 1.2 Hariri, Kind, Brunet — "Extended Isolation Forest" (arXiv:1811.02141, IEEE TKDE 2019)
- **Idea:** axis-parallel splits leak anomaly scores along gridlines and produce
  score-band artifacts; using random slopes (hyperplanes) removes the bias and
  makes maps consistent.
- **Contributes [BACKLOG]:** the fast path pre-walks axis-parallel trees, so
  upgrading to EIF means a new fast-path derivation. Worth prototyping as an
  alternate detector side-by-side in the digital-twin shadow mode
  (`modules/twin/shadow.py` is exactly the harness for this comparison).

### 1.3 Arcudi et al. — "ExIFFI: Extended Isolation Forest Feature Importance" (arXiv:2310.05468, 2023)
- **Idea:** global + local feature-importance scores derived from Extended
  Isolation Forest partition statistics — model-internal explanations.
- **Contributes [PARTIAL → BACKLOG]:** Spectra already explains detections via
  robust z-deviations per feature (`Detection.reasons`, σ-explanations) — an
  external, model-agnostic attribution. ExIFFI would provide model-internal
  attribution that could validate/refute the z-based story per detection.
  A cheap first step: aggregate the fast path's per-tree split features at
  scoring time into a frequency-weighted attribution.

### 1.4 Anderson, McGrew — "Machine Learning for Encrypted Malware Traffic Classification (without decryption)" (ACSAC 2017) + follow-up (KDD 2017)
- **Idea:** TLS/SNI/session metadata alone (no payload) can classify malware;
  the two failure modes are **noisy labels** and **non-stationarity** — the
  papers propose handling both explicitly rather than ignoring them.
- **Contributes [USED]:** validates Spectra's founding premise and its
  metadata-only feature set (SNI, versions, cipher/extension counts, JA3/JA4,
  timing) — the 39-feature vector is this lineage.
- **Backlog insight [BACKLOG]:** the non-stationarity treatment argues for
  scheduled retraining and time-decayed baselines — currently the model drifts
  silently until someone retrains (see 1.6 and the PSI drift work in 1.7).

### 1.5 Apruzzese, et al. — "Identifying malicious hosts involved in periodic beaconing" (2018–2022 line) and Hu et al. — "BAYWATCH: Robust Beaconing Detection" (DSN 2016)
- **Idea:** beaconing detection is more robust when done per *host pair* over
  sliding windows with periodicity + regularity statistics (BAYWATCH models
  benign periodicity explicitly so backups/updates don't fire), rather than per
  flow in isolation.
- **Contributes [PARTIAL]:** the bio layer's danger signals already use
  IAT mean/std (metronomic cadence), but evaluation is **per flow**. C2 beacons
  that jitter their period or split across flows evade a per-flow view.
- **Backlog insight [BACKLOG]:** aggregate IAT regularity per (src, SNI/IP)
  pair over a window in `CorrelationService`; a per-pair periodicity score
  would feed both the bio danger signals and the correlation graph as a new
  edge weight. The acceptance report's beacon fixture (4 flows) is a good unit
  test for a jitter-tolerant version.

### 1.6 Previous-work drift/PSI baseline (population-stability index; training-set drift literature)
- **Contributes [USED]:** `SpectraDetector._make_baseline` stores per-feature
  histograms (40 bins) at train time; drift is PSI over those bins
  (`GET /api/model/drift`), and evasion watch correlates drift with
  near-miss probing (`modules/adv/watch.py`) — matching the KDD-2017 argument
  that drift-vs-attack separation needs explicit baselines.
- **Backlog insight [BACKLOG]:** PSI currently compares against the *training*
  snapshot only; a rolling-window baseline (compare recent hour vs previous
  day) would catch slow drift the fixed baseline underestimates.

### 1.7 "TLS fingerprinting" — Althouse et al. — JA3/JA3S (Salesforce 2017) and JA4/JA4+ (FoxIO 2023)
- **Idea:** hash ClientHello fields into compact, comparable client
  fingerprints; JA4 sorts extensions and hashes in a structured format to stay
  stable across cipher-order randomization (TLS 1.3, Chrome GREASE).
- **Contributes [USED]:** both `ja3` and `ja4` are computed in `parse/tls.py`
  and stored on every flow row, queryable via `/api/flows` and the graph.
- **Backlog insight [BACKLOG]:** JA4+'s sibling specs (JA4S, JA4H, JA4L, JA4T)
  fingerprint server responses, HTTP behavior, and latency — natural feature
  extensions that keep the metadata-only invariant (all from handshake/framing,
  no payload). Also worth exposing a JA4→reputation sidecar (the specs ship
  community lists) as a bio danger signal.

### 1.8 Xue et al. — "Fingerprinting Obfuscated Proxy Traffic with Encapsulated TLS Handshakes" (USENIX Security 2024) + the TLS-fingerprint-evasion literature
- **Idea:** attackers randomize/tamper TLS fingerprints to blend in; detection
  must rely on *consistency* across layers (handshake vs. timing vs. behavior)
  rather than any single fingerprint.
- **Contributes [BACKLOG]:** motivates cross-checking `ja3`/`ja4` stability per
  host over time (a host whose fingerprint churns across "browsers" is itself a
  signal). The correlation graph already tracks per-host SNI sets — add
  fingerprint-set churn as a node attribute and a bio danger signal.

## 2. PQC module (M1)

### 2.1 NIST FIPS 203/204/205 (ML-KEM, ML-DSA, SLH-DSA), 2024 + NIST IR 8547 (transition guidance)
- **Contributes [USED]:** the cipher registry (`modules/pqc/registry.py`)
  classifies classical vs hybrid vs PQ exactly along these lines and flags
  TLS 1.2/RSA-static as critical; the roadmap generator prioritizes migration
  per sector.
- **Backlog insight [BACKLOG]:** NIST IR 8547's deprecation timelines (RSA/ECC
  112-bit security by 2030, disallowed by 2035) should be a registry data
  field, so readiness scores can state *how* urgent each finding is, not just
  that it is vulnerable.

### 2.2 "Harvest Now, Decrypt Later" threat-model literature (CSA 2026 report; time-dependent HNDL models)
- **Idea:** HNDL risk is a function of data sensitivity × lifetime × adversary
  capability timeline — not a binary flag.
- **Contributes [PARTIAL]:** `modules/pqc/hndl.py` screens bulk transfers with
  sector-sensitivity weighting (healthcare 1.0 > fintech 0.9 > smart city 0.7)
  but applies a static threshold, not a time-dependent exposure model.
- **Backlog insight [BACKLOG]:** add a data-lifetime parameter per sector
  (e.g., medical records decades, payment data years) and express HNDL findings
  as "decrypt-by dates" — the roadmap generator can then order migrations by
  expected exposure window.

## 3. TEE module (M2)

### 3.1 Costan, Devadas — "Intel SGX Explained" (eprint 2016/086) and the SEV-SNP/TrustZone attestation literature
- **Idea:** hardware enclaves isolate computation; remote attestation proves
  the exact code/data measurement to a verifier.
- **Contributes [PARTIAL]:** `modules/tee/enclave.py` mirrors the *protocol
  shape*: model file measurement (SHA-256), feature digest, nonce-bound quotes,
  Schnorr signatures — an honest software stand-in for the attestation flow
  (documented as an analog in `00_reconciliation_note.md`).
- **Backlog insight [BACKLOG]:** when hardware TEE lands (roadmap), the quote
  format should keep the same (measurement ‖ digest ‖ nonce) binding so the
  API contract survives the swap.

### 3.2 Bonawitz et al. — "Practical Secure Aggregation for Privacy-Preserving Machine Learning" (CCS 2017 / arXiv:1611.04482)
- **Idea:** federated participants' updates are masked with pairwise PRG
  secrets and Shamir-shared so the server only ever sees the sum; dropout-
  robust, communication-efficient.
- **Contributes [PARTIAL]:** `modules/tee/federated.py` implements Shamir
  k-of-k secret sharing of model updates with recombination — the same trust
  goal (server learns only the aggregate), a simpler mechanism.
- **Backlog insight [BACKLOG]:** Bonawitz's dropout handling is the practical
  gap: current k-of-k recombination requires all shares. Adding threshold
  reconstruction (k-of-n) + share verification would make federated sessions
  survive a dropped participant.

### 3.3 Side-channel literature on ML inference (timing/cache attacks on SGD, e.g., Batina et al. CCS 2019)
- **Contributes [BACKLOG]:** any real enclave deployment needs constant-time
  scoring. The detector fast path (tree-walk) has data-dependent branches —
  document it as a known side-channel surface for the Phase-2 TEE threat model.

## 4. Adversarial module (M3)

### 4.1 Biggio & Roli — "Wild Patterns: 10 Years of Adversarial ML" (ACM TOPS 2018) and Demetrio et al. — "Adversarial EXEmples" (ACM TOPS 2020)
- **Idea:** taxonomy of evasion (exploratory vs. poisoning) with empirical
  evidence that <1% feature perturbations can evade ML malware detectors;
  defense requires measuring *evasion cost*, not just accuracy.
- **Contributes [USED]:** `modules/adv/evasion.py` implements score-boundary
  search (gradient-free, feature-bounded perturbations to push benign vectors
  across the threshold), `attack_batch`, and robustness reporting — the
  exploratory-attack half.
- **Backlog insight [BACKLOG]:** the literature's strongest recommendation —
  **adversarial retraining** with generated evasions — is absent. The twin
  shadow harness can host it: train candidate on benign + attacked vectors,
  compare via `run_shadow` before promotion (also closes FR-4.1's
  "continuous" gap by scheduling it).

### 4.2 Anderson, Pardo, et al. — "Bot vs. Bot: Evading ML Malware Detection" (Black Hat / arXiv 2017) + Apruzzese's evaluation-rigor papers
- **Idea:** reinforcement agents learn evasions against a *frozen* detector;
  evaluation must assume the attacker knows the model (white-box-ish).
- **Contributes [BACKLOG]:** current `attack()` assumes bounded feature
  knowledge. A harder evaluation mode that assumes knowledge of the threshold
  and feature normalization (which the API's σ-explanations effectively leak
  to analysts/attackers) would produce more honest robustness scores.

## 5. Digital twin module (M4)

### 5.1 Digital-twin-for-security survey line (Qureshi et al. 2025, Computer Communications; Erceylan et al. 2025, IJIS; Alcaraz 2022)
- **Idea:** twins enable safe rehearsal: simulate attacks against a replica,
  validate playbooks, compare candidate detectors in shadow before promotion.
- **Contributes [USED]:** `modules/twin/` implements exactly this loop:
  `build_topology` from the live correlation graph → deterministic seeded
  `simulate` → playbook validation/evaluation → `run_shadow` z-score vs.
  candidate comparison.
- **Backlog insight [BACKLOG]:** the surveys' key caution — twins drift from
  reality — applies: topology is rebuilt only at hydrate time. A staleness
  indicator on `/api/twin/topology` (age of last hydration vs. newest flow)
  would make twin results honestly interpretable.

## 6. Audit module (M5)

### 6.1 Schneier & Kelsey — "Secure Audit Logs to Support Computer Forensics" (ACM TISSEC 1999); Bellare & Yee — "Forward Integrity for Secure Audit Logs" (1997); Crosby & Wallach — "Efficient Data Structures for Tamper-Evident Logging" (USENIX ATC 2009)
- **Idea:** hash-chained entries give tamper evidence; forward integrity means
  a compromised logger can't rewrite the past; Merkle trees give O(log n)
  inclusion proofs with a signed root.
- **Contributes [USED]:** `modules/audit/log.py` is the direct descendant:
  `entry_hash = sha256(canonical(entry) ‖ prev_hash)` (Schneier-Kelsey chain),
  per-entry Merkle leaves with inclusion proofs and Schnorr-signed checkpoints
  (Crosby-Wallach), retention that never prunes the chain (forward-integrity
  spirit). `tests/test_integrity.py` verifies tamper detection.
- **Backlog insight [BACKLOG]:** Bellare-Yee's *forward integrity* proper uses
  evolving/erased keys so an attacker holding the current key still can't
  forge old entries; the current single signing key (flat file next to the
  DB) does not. Key evolution or an external KMS is the literature-backed fix
  to the key-management risk flagged in the earlier code review.

### 6.2 Melara et al. — "CONIKS: Bringing Key Transparency to End Users" (USENIX Security 2015) + Certificate Transparency (RFC 6962)
- **Idea:** publicly verifiable append-only logs with consistent checkpoints —
  auditors verify inclusion without trusting the operator.
- **Contributes [PARTIAL]:** the checkpoint/certificate flow gives auditors
  signed roots + proofs; there is no *cross-party* checkpoint publication or
  mirror, so verification still trusts the operator's key.
- **Backlog insight [BACKLOG]:** even a simple "publish checkpoint hash to a
  second location" (a file the operator can't retroactively change, or an
  append-only external sink) would upgrade the trust model from operator-
  attested to witness-cosigned — CONIKS/CT's core lesson.

## 7. Bio-inspired module (M6)

### 7.1 Aickelin & Cayzer — "The Danger Theory and Its Application to AIS" (ICARIS 2002); Greensmith et al. — "Dendritic Cells for Anomaly Detection" (2006)
- **Idea:** react to *danger* (context signals) rather than *non-self*
  (novelty); combine a stimulus's self-similarity with contextual danger
  signals and map to escalating responses.
- **Contributes [USED]:** `modules/bio/danger.py` is a faithful adaptation:
  self-model (median/MAD robust-z affinity) + 6 danger signals (detector score,
  drift, evasion watch, cadence, rate spike, memory hit) → band-mapped
  ignore/monitor/alert/isolate, with memory cells accelerating repeat
  offenders. The docstring cites Cohen/Aickelin directly.
- **Backlog insight [BACKLOG]:** the dendritic-cell literature's main design
  rule is that signal *combination weights* are safety-critical (CSM weights);
  the current bands are hand-tuned constants. Logging bio verdicts with their
  contributing signals (already partly in `immune` annotations) enables the
  weight-tuning loop the papers recommend.

### 7.2 SNN/neuromorphic timing detection literature (spiking encoding of IATs; e.g., the neuromorphic-IDS line)
- **Contributes [PARTIAL]:** `modules/bio/snn.py` spike-encodes inter-arrival
  patterns into a percentile timing score — a lightweight analog of the
  neuromorphic proposals.
- **Backlog insight [BACKLOG]:** per the MEC literature (8.1), the SNN path is
  the natural candidate to move to the edge module's micro-detector set if a
  second latency-class detector is ever needed.

### 7.3 Swarm/agent-based detection literature (ACO/PSO-inspired multi-agent IDS)
- **Contributes [USED, scoped]:** `modules/bio/swarm.py` runs 5 voting agents
  over feature slices; quorum flags annotate flows (never create detections).
- **Backlog insight [BACKLOG]:** the literature's value is *diversity of
  agents*; adding one agent keyed on the JA4 fingerprint-stability signal
  (1.8) would be a cheap diversity win.

## 8. Correlation module (M7)

### 8.1 Graph-based attack attribution / blast-radius literature (attack-graph & provenance-graph lines, e.g., King & Chen's alert-correlation lineage)
- **Contributes [PARTIAL]:** `modules/corr/` builds the host/IP/SNI graph,
  computes cascade/blast-radius and kill-chain paths, and exposes shortest-path
  queries — the structural half of attack-graph analysis.
- **Backlog insight [BACKLOG]:** the literature's time-windowed correlation
  (also FR-2.2's open gap) is the missing half: edges carry no temporal
  scoping, so `cascade` can connect flows days apart. Time-bounding edges
  (or window-scoped subgraphs) is the highest-value research-aligned fix in
  this module and directly closes a traced requirement gap
  (`31_requirements_traceability_matrix.md`, FR-2.2).

## 9. Edge module (M8)

### 9.1 ETSI MEC white papers + the MEC-IDS literature (e.g., "Real-Time Anomaly Detection in 5G Networks Through Edge Computing", 2018; Domeke et al. 2022)
- **Idea:** push detection onto MEC nodes for latency-budget compliance; only
  aggregated/summary events leave the edge; slice-aware policies.
- **Contributes [USED]:** `modules/edge/mec.py` `MicroDetector` (12 features,
  measured p50 0.0098 ms vs the 10 ms budget), `EdgeSystem` deployment
  simulation, `slices.py` URLLC/eMBB/mMTC policy temperament, and NTN link
  profiles (LEO/GEO RTT) that descale timing so satellite backhaul doesn't
  false-positive — matching the latency-aware slice policy pattern in that
  literature.
- **Backlog insight [BACKLOG]:** the literature's *edge–cloud model drift*
  problem (edge models diverge from central retraining) maps to a concrete
  feature: version-pair the micro-detector with the central model at deploy
  time and warn when baselines diverge (`GET /api/edge/report` already has a
  natural place for it).

## 10. Cross-cutting: evaluation and false positives

### 10.1 McCall, Chorley, et al. — "Omniscient Data-Augmentation: Demographic False Positives" (CCS 2018, Demographic FP line)
- **Idea:** intrusion-detection false positives are dominated by *novel benign
  behavior*; augmenting training data with plausible synthetic benign traffic
  reduces demographic FPs far more than threshold tuning.
- **Contributes [BACKLOG, high-value]:** `demo.py` already generates synthetic
  benign PCAPs — but only for demos/tests. The papers' program is to put
  synthetic benign diversity *into the training set*: a `spectra train
  --augment` mode that mixes the generator's benign variants into the baseline
  would directly attack the false-positive problem the acceptance report
  observed (synthetic-baseline OOD on real traffic).

### 10.2 Apruzzese et al. — evaluation-rigor line ("Role of ML in cybersecurity", real-world evaluation critiques)
- **Contributes [BACKLOG]:** the acceptance report's honest synthetic-vs-real
  finding is exactly the rigor this line demands. Institutionalizing it: the
  model card (`12_model_card.md`) and evaluation report (`10_...`) templates
  should require the two-baseline evaluation (synthetic + real) that
  acceptance §6 performed.

---

## 11. Priority backlog derived from this survey

Ordered by (research support × implementation cost):

1. **Time-window correlation edges** (8.1) — closes FR-2.2; well-supported by
   attack-graph literature; medium cost in `modules/corr/`.
2. **Adversarial retraining via twin shadow** (4.1) — strongest-consensus
   defense in the adversarial-ML literature; harness already exists; medium.
3. **Synthetic-benign augmentation in `spectra train`** (10.1) — directly
   targets the documented FP/OOD failure; generator exists; low–medium.
4. **Per-host-pair beaconing aggregation** (1.5) — cheap; feeds bio + graph;
   improves jitter tolerance over the per-flow rule.
5. **Rolling-window PSI drift baseline** (1.6) — cheap; catches slow drift.
6. **JA4+ family features + fingerprint-churn signal** (1.7/1.8) — low cost,
   metadata-only invariant preserved.
7. **Audit key evolution / KMS** (6.1) — fixes the flagged key-management risk
   with literature-grade design.
8. **k-of-n federated recombination with dropout handling** (3.2) — cheap,
   aligns with Bonawitz.
9. **Twin topology staleness indicator** (5.1) — trivial cost, honesty win.
10. **EIF detector prototype behind shadow mode** (1.2) — research-grade
    experiment, non-urgent.

*No entry above changes the privacy invariant: every addition consumes only
flow/handshake metadata.*
