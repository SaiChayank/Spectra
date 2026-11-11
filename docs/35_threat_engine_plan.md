# Threat engine first: plan to a best-in-class product

Status: **proposal, 2026-11-08.** Nothing in this plan is built. Numbers marked *target* are goals to measure against, not results.
Owner decisions this plan needs are collected in §11.

## 0. The honest starting point

"No competition from anyone" is not a reachable goal: Darktrace, Vectra AI, ExtraHop RevealX, Cisco Secure Network Analytics (Encrypted
Traffic Analytics), Corelight and Stamus are funded, deployed and have years of labelled customer data. The reachable goal is narrower and
stronger: **be the measurably best option in one clearly defined place, and prove it in public.**

Where Spectra stands today (`docs/evaluation-report.md` §10-§14):

* The platform around detection is solid: metadata-only by construction and tested, audit chain, RBAC, backup/restore, hardened container.
* The detector is not: one unsupervised isolation forest over 39 per-flow features flags almost no attacks at the default threshold (CTU
  2.9 %, HIKARI 0.4 %, CIC-2018 Ares C2 0 of 98,700) and ranks regular C2 *below* benign (ROC-AUC 0.19).
* Two signals that work are unused: a supervised model on the same features separates classes in-distribution (CTU 0.91-0.98), and
  host-pair gap regularity points at the C2 pairs (pair-level AUC 0.71). The features carry signal; the engine design throws it away.

The lesson: **a single anomaly score over single flows is the wrong shape for this problem.** Attacks in encrypted traffic show up as
*behaviour of a host over time* (calling home on a schedule, talking to a destination nobody else talks to, sending more than it receives),
not as one odd flow.

## 1. Positioning: where Spectra can be the best

| Wedge | Why incumbents don't own it | What Spectra must prove |
|---|---|---|
| **Metadata-only by construction** | Commercial NDRs keep payload or offer decryption; regulated buyers (healthcare, fintech, public infrastructure) must argue it away | already true; keep a test for every code path (non-negotiable) |
| **Open, self-hosted, reproducible** | Competitors publish no reproducible detection numbers | a public benchmark anyone can rerun, with Spectra *and* baselines on it (§3) |
| **Runs on sensors people already have** | Each NDR wants its own sensor | ingest Zeek logs, Suricata EVE and pcap with the same engine (P1) |
| **Explains every alert in plain metadata terms** | ML-NDR verdicts are often opaque | every alert carries the evidence chain: which detectors, which flows, which baseline |
| **Encrypted C2 and exfiltration, specifically** | Signature IDS can't see it (Suricata ET found 0 % on our runs); open-source RITA covers beaconing only | beat Zeek+RITA and Suricata on encrypted C2/exfil at a fixed alert budget |

Everything in this plan serves the last row first.

## 2. Engine architecture (target)

```
 pcap / live / Zeek / EVE ──► L0 metadata fidelity ──► L1 specialist detectors ──► L2 entity evidence fusion ──► L3 triage + feedback
                              (flows, packet-length     (beacon, exfil, rarity,     (host risk over 24 h / 7 d,   (explanations, dedupe,
                               sequences, TLS/QUIC,      DNS, fan-out, TLS-anomaly,   peer groups, ATT&CK tactic   per-site suppression,
                               JA4, DNS, long-lived      supervised malware model,    progression, confidence)     calibration, drift)
                               connections)              intel, isolation forest)
```

Rules for the engine:

1. **Many narrow detectors, each tied to one ATT&CK technique,** each with its own evaluation and its own gate, instead of one general score.
   The isolation forest stays as one weak "unusual flow" signal.
2. **The alert unit is a host (or host pair), not a flow.** One alert says "10.0.4.17 looks compromised: beacon to X every 300 s ± 4 %,
   destination seen by 1 of 2,400 hosts, outbound 40× inbound since Tuesday".
3. **Precision is budgeted.** Every detector and the fused score are judged at a fixed alert budget (alerts per 1,000 hosts per day), never
   at an arbitrary threshold. This is the number buyers feel.
4. **No learned weights from evaluation data.** Thresholds and fusion weights are fixed on a development set and reported on held-out sets
   (same rule as `docs/plan-beaconing-detector.md`).
5. **Metadata only.** Packet *lengths, directions and times* are metadata; packet *bytes* never leave the parser.

## 3. Phase E0: the benchmark is the product's backbone (2-3 weeks)

Without this, every later phase is opinion. Builds on `spectra eval`, `bench_*.py`, the dataset registry and the nightly job.

* **Spectra-Bench**: one command runs every detector and every baseline on every dataset and writes one hashed JSON per run.
* **Metric set, fixed now:** recall of attack *hosts/pairs* at 1 and 10 alerts per 1,000 hosts per day; time-to-detect; ROC-AUC/PR-AUC
  with bootstrap CIs as secondary; false alerts per day on the owner's own network (task 12) as the precision anchor.
* **Splits:** time split (train early, test late), **leave-attack-family-out** (the generalisation test the supervised model failed on
  HIKARI), cross-dataset.
* **Data sources** (licences checked and recorded in `docs/datasets.md` before use): the three already run; Stratosphere CTU malware
  captures (many families, long captures); CIC-IDS2017; and a **lab corpus we generate ourselves**: open-source C2 frameworks run in an
  isolated lab against our own VMs, with beacon interval, jitter, sleep and transport recorded per run, which gives exact labels and the
  jitter sweep no public dataset has. Benign: own-network capture plus long public benign captures.
* **Baselines, as specified:** Suricata + ET Open (rules only and tuned), **Zeek + RITA** (the open-source beaconing reference and the
  real competitor for E2.1), stock Zeek notices, the current isolation forest.
* **Preregistration:** each run reads a committed `prereg/*.json` (dataset hashes, split, thresholds, metric) before it sees results.

**Exit E0:** current numbers reproduce from one command; RITA and Suricata baselines in the same JSON; lab corpus of at least 3 C2
frameworks × 4 jitter settings, labelled.

## 4. Phase E1: see more without seeing payload (3-4 weeks)

Today's features are flow summaries. The research (`docs/32` §1.4, Anderson & McGrew) shows most of the signal is in the *sequence*.

* **Packet-length/direction/time sequence** for the first N (≈20) packets per flow, and a byte-distribution-free summary of the rest.
* **TLS:** make the existing `ja4()` match the published spec (today it does not, so JA4 intel lists cannot match - `HANDOFF_FINDINGS.md`
  "9H findings"; base JA4 only, JA4+ stays excluded per `docs/release-policy.md`), JA3S, certificate metadata where visible (TLS 1.2:
  issuer, validity length, self-signed, SAN count), resumption, ECH presence.
* **DNS metadata** (query name, type, response code, TTL, answer count), the biggest gap: most C2 and every DGA touches DNS first.
* **Long-lived connections** tracked across flow timeouts (C2 over one held-open TLS session evades per-flow cadence).
* **Entity model:** internal vs external from configured CIDRs, stable host identity, destination = IP + SNI/domain.

Every parser change gets the metadata-only probe test and fuzzing (existing pattern). Feature schema version bumps; old models refuse to load.

**Exit E1:** schema v2 extracted on all E0 datasets; parser fuzz clean; throughput loss ≤ 30 % vs today on `bench_throughput.py` (*target*).

## 5. Phase E2: specialist detectors (6-8 weeks, one at a time, each with its own gate)

Order is by expected value on the evidence we have. Each ships behind a flag, off until its gate passes.

| # | Detector | ATT&CK | Signal | Main false-positive source |
|---|---|---|---|---|
| E2.1 | **Beaconing** (in progress in its own session) | T1071, T1573 | gap regularity, periodogram/autocorrelation robust to jitter (BAYWATCH-style), size consistency, long-lived sessions | update checks, telemetry, NTP, monitoring, so ship an allow-list and per-site learning |
| E2.2 | **Rare destination / first seen** | T1071, T1583 | destination prevalence across the network's hosts, domain age where locally known, first-seen-for-network | new SaaS rollouts |
| E2.3 | **Exfiltration** | T1041, T1048 | per-host outbound/inbound ratio vs its own and its peers' baseline, sustained upload to rare destination | backups, cloud sync, so peer groups matter |
| E2.4 | **DNS abuse** | T1071.004, T1568.002 | DGA-likeness of names (character model, NXDOMAIN rate), tunnelling (long/high-entropy labels, TXT volume) | CDNs, anti-virus lookups |
| E2.5 | **Scanning and lateral fan-out** | T1046, T1021 | new internal pairs per host, port fan-out, failed-connection ratio | IT inventory scanners, allow-listed |
| E2.6 | **TLS anomalies** | T1573, T1587 | self-signed / very short-lived certs to external hosts, JA4 rare for this network, JA3/JA4 intel matches (existing intel lists) | internal PKI, dev tooling |

**Gate per detector (fixed before first run):** beats the best baseline on recall at 10 alerts/1,000 hosts/day on at least two datasets
it was not tuned on, with non-overlapping 95 % CIs, or the report says it is "a ranking aid, not a detector" and it stays off by default.

## 6. Phase E3: supervised encrypted-malware model (4-6 weeks)

The supervised RandomForest already shows the features separate classes in-distribution. Make that useful without overclaiming:

* Gradient-boosted model on E1 sequence + handshake features, trained on labelled malware vs benign from E0 sources.
* **Judged only on leave-family-out and time splits.** In-distribution scores are not reported as headline numbers.
* Calibrated probabilities; output is **one evidence signal** into E4, never an alert alone.
* Model card per release (existing pattern), training data hashes, and a refusal to score on schema mismatch.

**Exit E3:** leave-family-out recall at the alert budget beats the isolation forest on ≥ 2 held-out families (*target*), reported with CIs
whether it passes or fails.

## 7. Phase E4: evidence fusion and host risk (4 weeks), where Spectra becomes a product

* Each detector emits *evidence* (host, time, technique, strength, flows). Fusion combines evidence per host over 24 h and 7 d windows with a
  documented, fixed combination (noisy-OR / log-odds with priors per detector, set on the dev set).
* **Kill-chain progression boosts confidence:** rare destination → beacon → upload on the same host scores far above three unrelated hits.
* Peer groups (hosts with similar destination mix) for exfil/rarity baselines.
* Output: one ranked list of hosts with a confidence, the evidence chain in plain words, and links to the flows. This replaces per-flow alerts
  in the UI and API (flow alerts remain queryable).
* Reuses `incident_correlation.py`, `modules/corr/graph.py`, severity rules, audit chain.

**Exit E4 (the engine gate):** on the lab corpus plus held-out public data, at ≤ 1 alert per 1,000 hosts per day on the owner's network
(*target*), Spectra finds more compromised hosts than Zeek+RITA and Suricata combined, with the comparison in one Spectra-Bench JSON.

## 8. Phases E5-E7: robustness, adaptation, real-world proof

* **E5 Adversarial robustness (3 weeks, then continuous).** Extend `modules/adv/evasion.py` to the lab corpus: jitter sweep 0-90 %,
  random sleep, padding, traffic shaping, domain fronting, long-poll C2. Publish the degradation curve per detector. Fuse detectors so
  evading one (e.g. beacon jitter) still leaves rarity and exfil evidence.
* **E6 Feedback and per-site adaptation (3-4 weeks).** Analyst verdicts (true / benign-expected / false) feed per-site suppressions,
  per-site threshold calibration against the alert budget, and an active-learning queue; PSI drift (existing 9E) triggers recalibration.
  Every suppression is audited and reversible.
* **E7 Real-world validation (owner-led, 8-12 weeks, overlaps P-phases).** 3-5 design partners in the target verticals run Spectra in
  shadow mode beside their current tools. Measured: alerts/day, analyst-confirmed true positives, misses found by other tools. This is
  the only evidence that would justify a "better than X" claim, and it needs written agreements and data-handling terms.

## 9. Around the engine (after E4 passes)

| Phase | What | Why now |
|---|---|---|
| **P1 Ingest** | Zeek `conn/ssl/dns/x509` logs, Suricata EVE, NetFlow/IPFIX (reduced feature set, stated) as inputs to the same engine | widest adoption lever: no new sensor |
| **P2 Triage UI** | host-centric queue, evidence timeline, one-click verdict (feeds E6), ATT&CK view | the analyst's daily surface |
| **P3 Integrations** | SIEM export (12A, if authorised), webhooks, STIX/TAXII intel in, Sigma-style rule export | fits existing SOC workflow |
| **P4 Scale and deploy** | Kubernetes manifest, ARM sensor image, multi-site (12E), model registry with staged rollout (12B) | partner deployments |
| **P5 Release** | open-source release, docs site, signed releases, published Spectra-Bench leaderboard | the public proof is the marketing |

**Stop or freeze until E4 passes (owner decision):** the PQC, TEE, bio-inspired, digital twin, edge and ZKP modules. They don't improve
detection and each one is maintenance and attack surface. Keep `corr` (graph, beacon), `adv` (evasion) and `audit`.

## 10. Order, size, gates

| Phase | Size | Depends on | Gate |
|---|---|---|---|
| E0 benchmark | 2-3 wk | - | reproducible baselines + lab corpus |
| E1 fidelity | 3-4 wk | E0 | schema v2, fuzz clean, throughput |
| E2 detectors | 6-8 wk | E1 (E2.1 can start now) | per-detector gate |
| E3 supervised | 4-6 wk | E1 | leave-family-out result reported |
| E4 fusion | 4 wk | E2, E3 | **engine gate** |
| E5 robustness | 3 wk + ongoing | E4 | degradation curves published |
| E6 adaptation | 3-4 wk | E4 | alert budget held on own network |
| E7 partners | 8-12 wk | E4, owner | partner results |
| P1-P5 | parallel after E4 | E4 | per phase |

Roughly 6-8 months of focused engineering to the engine gate. Phases E2 and E3 can run in parallel sessions once E1 lands.

## 11. Decisions needed from the owner

1. Approve the positioning in §1 (encrypted C2/exfil, metadata-only, open, reproducible) as the product's claim.
2. Approve building a **lab C2 corpus** with open-source C2 frameworks in an isolated network you control (hardware/VMs, no internet egress
   from victims except to the lab C2).
3. Approve freezing the non-detection modules (§9).
4. Run task 12 (own-network capture) early: it is the precision anchor for every gate from E2 on.
5. Start design-partner outreach (E7) in parallel; it has the longest lead time.
6. Licence check sign-off for each new dataset before it is used.

## 12. Risks

* **Visibility shrinks:** TLS 1.3 hides certificates, ECH hides SNI, DoH hides DNS. Mitigation: lean on timing, sizes, rarity and fusion,
  which survive; measure per-detector loss when those fields are absent.
* **Labels are weak and positives few** (10 C2 pairs on CIC-2018). The lab corpus is the fix; small-sample results stay labelled as such.
* **Base rates:** even 0.1 % false positives per flow is thousands of alerts per day. Host-level fusion and the alert budget exist because of this.
* **Benchmark overfitting:** fixed preregistration, held-out families, and partner data guard against tuning to our own test sets.
* **Incumbents can copy features, not evidence:** the moat is the public, reproducible benchmark, the labelled corpus and partner results.
