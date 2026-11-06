# Requirements Traceability Matrix
## Spectra

**Created:** 2026-09-30 · **Method:** every BRD functional requirement (docs
`01_business_requirements_document.md` FR-1…FR-8, plus NFRs) traced downward to
implementing code, API/CLI surfaces, and tests. Upward trace lives in
`docs/03_system_requirements_specification.md`; acceptance evidence for most rows
in `docs/acceptance-report.md` §2.

Status legend: ✅ implemented · 🟡 partial · ⏳ deferred (see `00_reconciliation_note.md`).

---

## FR-1: PQC Readiness — ✅

| Req | Text (abridged) | Implementation | Surface | Tests | Status |
|---|---|---|---|---|---|
| FR-1.1 | Parse TLS handshake metadata to identify cipher suites in use | Streaming TLS parser: ClientHello/ServerHello, cipher list, extensions; QUIC CRYPTO frames feed the same pipeline | `parse/tls.py` `parse_handshake`, `TlsMetadata`; `parse/quic.py`; flows expose `cipher_count`, `tls_version` | `test_tls.py` (hand-crafted handshakes), `test_quic.py` | ✅ |
| FR-1.2 | Classify connections quantum-vulnerable vs quantum-resistant against a maintained reference list | Cipher-suite registry (classical / hybrid / PQ groups, TLS 1.2 + RSA-static flagged critical); scan produces per-handshake readiness scores | `modules/pqc/registry.py`, `modules/pqc/scanner.py`, `modules/pqc/scan.py` | `test_pqc.py` | ✅ |
| FR-1.3 | Track per-endpoint crypto-agility status over time | `PQCInventory.observe()` records per-endpoint posture; summary + endpoint listing with sector filter | `modules/pqc/inventory.py`; `GET /api/pqc/inventory`, `GET /api/pqc` | `test_pqc.py` | ✅ |
| FR-1.4 | Flag traffic patterns consistent with Harvest-Now-Decrypt-Later behavior | `assess_hndl` scores bulk transfers (volume/duration asymmetry vs sector sensitivity), `screen_flows` batch screen | `modules/pqc/hndl.py`; surfaced in PQC scan report; `spectra pqc` | `test_pqc.py` | ✅ |
| FR-1.5 | Generate sector-specific PQC migration roadmap on demand | `generate_roadmap` builds prioritized items (priority × sector sensitivity weight: healthcare 1.0/HIPAA, fintech 0.9/PCI-DSS, smart city 0.7) from inventory findings | `modules/pqc/roadmap.py`, `sectors.py`; PQC scan response | `test_pqc.py` | ✅ |

## FR-2: Cross-Domain Correlation — ✅

| Req | Text (abridged) | Implementation | Surface | Tests | Status |
|---|---|---|---|---|---|
| FR-2.1 | Maintain a graph model of shared infrastructure across monitored sectors | In-memory `CorrelationGraph`: host/IP/SNI nodes typed with sector (`fintech`/`healthcare`/`smart_city`/`general`), weighted edges; hydrated from persisted flow rows at startup | `modules/corr/graph.py` (`observe`, `hydrate`, `SectorClassifier` from `sectors.py`); `GET /api/graph`, `/api/graph/summary`, `/api/graph/node` | `test_corr.py` | ✅ |
| FR-2.2 | Detect anomalies correlated across ≥2 sectors within a configurable time window | Graph edges carry first/last contact times and sampled flow ids; `cascade`, `shortest_path` and `reachable` take `window_s` (anchored to the newest contact in the graph, so replays window like live data); `window_s` ≤ 0 or NaN is a 400; kill-chain scoring respects the window (Phase 9A) | `modules/corr/graph.py`, `modules/corr/cascade.py`; `GET /api/graph/cascade?window_s=`, `/api/graph/path?window_s=`; Network page window selector | `test_corr.py` (5 windowed tests), acceptance `phase9` group | ✅ |
| FR-2.3 | Visualize a cross-sector kill chain when a correlated threat is detected | Cascade result carries kill-chain stage paths; correlation panel consumes `/api/graph*` | `modules/corr/cascade.py`; dashboard correlation views | `test_corr.py` | ✅ |

## FR-3: Confidential Computing / TEE — 🟡 (analog delivered)

| Req | Text (abridged) | Implementation | Surface | Tests | Status |
|---|---|---|---|---|---|
| FR-3.1 | Detection inference executes inside a supported TEE (SGX/SEV-SNP/TrustZone) | Software enclave analog: `TeeEnclave` measures model file digest, holds signing keypair, seals inference; **no hardware enclave** (roadmap, ADR-002) | `modules/tee/enclave.py`; `POST /api/tee/infer` | `test_tee.py` | 🟡 analog only |
| FR-3.2 | Produce an attestation report proving model integrity on request | Nonce-bound Schnorr attestation quotes over (model digest ‖ feature digest ‖ nonce); verify endpoint recomputes and checks freshness | `modules/tee/enclave.py` (`attest`, `verify`); `POST /api/tee/{attest,verify}`; `spectra tee attest/verify` | `test_tee.py` (incl. malformed-input 400s) | ✅ (software attestation) |
| FR-3.3 | Federated training across ≥2 participants without raw data leaving their enclave | Secret sharing: model updates split additively k-of-k (default) or Shamir t-of-n with dropout (opt-in, Phase 9G); the aggregate is reconstructed, never a party update — participants exchange shares, not raw updates | `modules/tee/federated.py`; `POST /api/tee/federate` | `test_tee.py`, `test_federated_shamir.py` | ✅ (mechanism) |

## FR-4: Adversarial Resilience — ✅ (continuous mode is opt-in, default off)

| Req | Text (abridged) | Implementation | Surface | Tests | Status |
|---|---|---|---|---|---|
| FR-4.1 | Continuously generate adversarial traffic samples against own models | Score-boundary attack: feature-perturbation search that pushes benign vectors across the decision boundary; `attack_batch`. **Opt-in scheduled mode (Phase 9B):** with `SPECTRA_HARDEN_INTERVAL_H` > 0 the report-only harness attacks the incumbent's flagged flows on the live window every N hours and audit-chains `model.harden`/`model.shadow`; default 0 = off. Adversarial *feature vectors* are generated, not packets. **Retraining on them does NOT reduce evasion** (HANDOFF_FINDINGS.md 9B), so the harness never promotes a model | `modules/adv/evasion.py`; `services/harden.py`; `POST /api/model/robustness`, `POST /api/model/harden`; `spectra adversarial` | `test_adv.py`, `test_harden.py` (incl. the enabled scheduler running the real harden), acceptance `phase9` group | ✅ (generation; no robustness gain shown) |
| FR-4.2 | Detect when the system is being actively probed (meta-anomaly) | Evasion watch: `ScoreWindow` near-miss-rate detection + `watch()` meta-anomaly on score distribution shapes; drift events and evasion alerts are audit-chained | `modules/adv/watch.py`; `GET /api/model/evasion`, `/api/model/drift` | `test_adv.py` | ✅ |
| FR-4.3 | Distinguish natural concept drift from adversarial manipulation | PSI baseline per feature (40 bins) captured at training; drift endpoint reports per-feature PSI so benign drift vs boundary-probing signatures are separable | `ml/model.py` (`_make_baseline`, drift info); `modules/adv/watch.py` | `test_model.py`, `test_adv.py` | ✅ |

## FR-5: Digital Twin — ✅

| Req | Text (abridged) | Implementation | Surface | Tests | Status |
|---|---|---|---|---|---|
| FR-5.1 | Support creation of an isolated replica environment per customer network | Topology builder constructs a replica graph (hosts, services, trust levels) from the live correlation graph | `modules/twin/topology.py` (`build_topology`); `GET /api/twin/topology` | `test_twin.py` | ✅ |
| FR-5.2 | Support shadow-mode deployment alongside existing tooling | `ZScoreDetector` legacy detector + `run_shadow` scores candidate vs incumbent on identical flows, reports binary metrics (agreement, precision/recall delta) | `modules/twin/shadow.py`; `POST /api/twin/shadow` | `test_twin.py` | ✅ |
| — (beyond BRD) | Attack simulation + IR playbook validation | Deterministic seeded propagation simulation, playbook library (`LIBRARY`) with validation, evaluation, recommendation | `modules/twin/{simulate,playbook}.py`; `POST /api/twin/{simulate,playbook,evaluate,recommend}`; `spectra twin` | `test_twin.py` | ✅ |

## FR-6: ZK-Proof Audit Trail — 🟡 (verifiable audit ✅, true ZKP 🟡)

| Req | Text (abridged) | Implementation | Surface | Tests | Status |
|---|---|---|---|---|---|
| FR-6.1 | Generate a zero-knowledge proof that only metadata was processed for a window | Analog: hash-chained append-only log (`entry_hash` commits to `prev_hash`); Merkle checkpoints over session flow-record leaves; Schnorr proof statements; inclusion proofs per entry. **Not a zk-SNARK** — verifier needs the checkpoint, not just a statement | `modules/audit/{log,merkle,zkp,certify}.py`; `POST /api/audit/{checkpoint,proof}`, `GET /api/audit/verify`; `spectra audit {verify,checkpoint,proof}` | `test_audit.py`, `test_integrity.py` (tamper detection) | 🟡 |
| FR-6.2 | Issue a compliance token consumable by third-party auditors | Schnorr-signed compliance certificates bound to checkpoint root; independent verification path (key + root + proof) requires no database access | `modules/audit/certify.py`; `POST /api/audit/certificate`; `spectra audit certify` | `test_audit.py` | ✅ (signed certificate) |

## FR-7: Bio-Inspired Detection — ✅

| Req | Text (abridged) | Implementation | Surface | Tests | Status |
|---|---|---|---|---|---|
| FR-7.1 | Support a spiking neural network detection path for timing-based anomalies | `TimingSNN` spike-encoding of inter-arrival patterns → percentile timing score; plus danger-theory layer (self-model robust-z affinity + 6 danger signals → ignore/monitor/alert/isolate), 5-agent swarm voting, memory cells. **Annotates flows only — never creates detections** (architecture rule) | `modules/bio/{snn,danger,swarm,system}.py`; `GET /api/bio/status`, `POST /api/bio/assess`; `spectra bio`; per-flow `snn_score`, `swarm_flag`, `immune` fields | `test_bio.py` | ✅ |

## FR-8: 5G/6G Edge — ✅

| Req | Text (abridged) | Implementation | Surface | Tests | Status |
|---|---|---|---|---|---|
| FR-8.1 | Deploy lightweight models on MEC nodes with sub-10 ms inference | `MicroDetector`: 12-feature robust-z ensemble, trains from same baseline, speaks the same 0–100 score; **measured p50 0.0098 ms / p95 0.0189 ms** (acceptance §5) | `modules/edge/mec.py`; `POST /api/edge/deploy`, `GET /api/edge/report`; `spectra edge deploy/report` | `test_edge.py`, `test_edge_native.py` | ✅ |
| FR-8.2 | Apply differentiated policy per 5G network slice | Slice classifier (URLLC / eMBB / mMTC from flow shape + port), `apply_slice_policy` adjusts response level per slice temperament (URLLC escalates, eMBB suppresses); NTN link profiles (LEO/GEO RTT) descale timing so satellite latency doesn't false-positive | `modules/edge/slices.py`, `mec.py` (`LINK_PROFILES`); `POST /api/edge/{slice,link}`; per-flow `slice` field | `test_edge.py`, `test_edge_native.py` | ✅ |

## Non-functional requirements

| NFR (BRD §6) | Text (abridged) | Evidence | Status |
|---|---|---|---|
| NFR-1 | No plaintext payload ever persisted or logged | Parser reads payload only to advance framing; feature vector is the sole model input; 0–100 scoring from metadata alone; asserted by `test_flow`/`test_tls` | ✅ |
| NFR-2 | Latency SLAs (fintech sub-second; healthcare edge sub-10 ms) | Measured: edge micro-detector p50 0.0098 ms; main detector per-flow p50 0.269 ms (fast path, bit-identical, ~39× vs sklearn); full 288-pkt scan 0.348 s | ✅ |
| NFR-3 | Every detection traceable to model version + input metadata hash | `ModelVersion` identity (path, trained_at, n_train, contamination, schema); feature-schema SHA-256 digest rejects mismatched artifacts at load; audit chain binds capture session leaves to checkpoints | ✅ |
| NFR-4 | Graceful degradation if a module is unavailable | `FailureTracker` counts per-component failures into `status["failures"]`; optional modules annotate but never gate detection; persistence loss never blocks detection (engine falls back to memory-only) | ✅ |

## SRS placeholder resolution (docs 03 §3)

The SRS left engineering values as `[X]`. Measured/implemented values:

| SRS | Placeholder | Resolved value |
|---|---|---|
| SRS-1.1 | Extract fields within `[X]` ms | Handshake metadata parsed in the streaming path; per-flow overhead dominated by scoring at p50 0.269 ms |
| SRS-3.1 | Reject inference if attestation stale > `[X]` h | Nonce-bound quotes: freshness enforced per-request by nonce, not by TTL |
| SRS-4.1 | ≥ `[X]` adversarial samples per cycle | `attack_batch` generates on demand; robustness report scores the batch |
| SRS-6.1 | ZK-proof for a window within `[X]` min | Checkpoint + proof generation is sub-second in acceptance run (vs BRD §8 5-minute budget) |
| SRS-8.1 | Edge inference ≤ 10 ms p99 | p50 0.0098 ms, p95 0.0189 ms — **met with ~500× margin** |

## Gaps and known deltas (summary)

Re-run at Exit Gate 9 (2026-11-06; evidence in `docs/acceptance-report-2026-11-06.md`):

1. ~~**FR-2.2** — no configurable time window.~~ **Closed in Phase 9A** (`window_s`).
2. **FR-3.1** — hardware TEE replaced by software enclave analog.
3. **FR-6.1** — audit proofs are hash-chain/Merkle/Schnorr, not zero-knowledge. Signing keys now have epochs and a provider seam (9F, awaiting human security review); the Schnorr/secp256k1 code is Spectra's own and has had no independent review.
4. ~~**FR-4.1** — adversarial generation is on-demand, not continuous.~~ **Scheduled mode added (9B), opt-in and default off.** Residual: retraining on the generated vectors does not make the detector harder to evade; the harness reports and never promotes.
5. Multi-tenancy, SIEM delivery, MFA/OIDC: deferred (see `00_reconciliation_note.md` §5).
6. **New in Phase 9, recorded honestly:** 9C synthetic augmentation is opt-in and only validated on synthetic data (no real-traffic comparison run); 9E's rolling PSI re-baselines after legitimate shifts but does **not** detect slow drift sooner than the training PSI; 9H shipped the twin staleness badge but **not** JA4S/JA4L, because JA4+ is licensed non-commercially (FoxIO License 1.1) and cannot sit in an Apache-2.0 release without an owner decision.
