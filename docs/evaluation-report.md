# Spectra — Model evaluation and validation report

**Date:** 2026-11-06 · **Commit:** `a0ef02a` (branch `phase10/gate-10`) · **Status:** engineering evidence, **not a sign-off**; sections 2-8 synthetic data only, sections 9-12 real public captures (read their caveats).

This is the document `docs/datasets.md` and `docs/34_ship_plan.md` call `evaluation-report.md`, and the "model evaluation and validation report" of the project rules (the numbered `docs/10_…` template was removed in `09638ce`). It follows the honesty rules in `docs/evaluation.md` §2.

## 1. Read this first

* **Everything below is SYNTHETIC.** Benign traffic comes from `spectra.demo` (the 7-profile library and the demo baseline); attack traffic from four families written for this report (`scripts/eval_synthetic.py`). Nothing was captured from a network. The families were written by the people who wrote the detector, so the recall figures say how the detector behaves on *these* generators, **not** how well it detects real attacks.
* **Partly run (see §9): one public capture, CTU-13 scenario 1, scored for flag rate only and found uninformative.** **NOT RUN: the real-capture *baseline*** the plan calls for ("two baselines: synthetic + real capture, mirroring acceptance §6"). That capture is not on this machine. **NOT RUN: any labelled evaluation** (no per-flow ground truth was fetched; CICIDS2017/2018 and others untouched). No claim is made about detection on real traffic anywhere in this report.
* "Two baselines" here are two **synthetic** training sets (A: the single-profile demo baseline; B: the 7-profile benign-diversity library). They are a stability comparison, not the requested real/synthetic pair.
* Intervals are 95 % percentile bootstraps over flows (1000 resamples; AUC 300). Flows from one generator are not independent draws from a real population, so the intervals are optimistic.

## 2. Setup (reproducible)

`cd backend && python scripts/eval_synthetic.py --out ../docs/evidence/2026-11-06/eval-synthetic.json --n-attack 120 --n-benign 400 --evasion-sample 60` (seed `20261106`; two runs on the same commit produced identical metrics). Python 3.14.8. The JSON carries the SHA-256 and size of every generated capture and the full numbers; the transcript is `eval-synthetic.stdout.txt`.

Detector: `SpectraDetector` (IsolationForest, 300 trees, contamination 0.02, `random_state=42`) on the 39-feature schema v1, fitted on benign flows only. Training sets: **A** `make_baseline_pcap(300 flows, seed 7)` → 302 flows; **B** `make_benign_diversity_pcap(420, seed 21)` → 420 flows. Held-out benign: `test_benign_diverse` (400 flows, seed 1000, 7 profiles) and `test_benign_demo` (402 flows, demo generator, seed 99). Operating points for "recall at FPR" come from a separate validation benign set (400 flows, seed 501), never from the test sets. Ranking metrics use the raw isolation-forest score: the production 0–100 score is a percentile against the training set, clipped at 100, so it ties (found while building this — AUC computed on it was identical for every family).

## 3. False flags on held-out benign traffic

| Baseline | `test_benign_demo` | `test_benign_diverse` |
|---|---|---|
| A — demo baseline | 1.5% [0.5%, 2.7%] | **58.2% [53.5%, 63.0%]** |
| B — benign-diversity | 0.2% [0.0%, 0.8%] | 2.2% [1.0%, 3.8%] |

Baseline A flags more than half of benign traffic that does not look like its single training profile — the "baseline-matching" limitation (`docs/limitations.md` §2), measured. Baseline B's low rate is **in-distribution by construction** (train and test come from the same seven generators with different seeds), so it is a best case, not a forecast.

## 4. Detection of the synthetic attack families

Recall at the production threshold; ROC-AUC vs the diverse benign set; recall at the validation-set FPR points.

| Family | What it is | n | A recall | A AUC | A recall @1 % FPR | B recall | B AUC | B recall @1 % / 0.1 % FPR |
|---|---|---|---|---|---|---|---|---|
| `beacon_plain` | no-TLS tiny periodic records, RST end (period 1-30 s, jitter 0-30 %) | 123 | 100.0% [100.0%, 100.0%] | 0.858 [0.823, 0.890] | 0.0% | 100.0% [100.0%, 100.0%] | 1.000 [1.000, 1.000] | 100.0% / 100.0% |
| `beacon_tls` | normal-looking TLS session carrying tiny slow records (hard) | 120 | 100.0% [100.0%, 100.0%] | 0.672 [0.630, 0.710] | 0.0% | 100.0% [100.0%, 100.0%] | 0.997 [0.993, 1.000] | 96.7% / 94.2% |
| `exfil_bulk` | TLS session moving 60-140 large records (hard) | 120 | 100.0% [100.0%, 100.0%] | 0.857 [0.827, 0.888] | 0.0% | 100.0% [100.0%, 100.0%] | 1.000 [1.000, 1.000] | 100.0% / 100.0% |
| `scan` | single-SYN probes answered by RST (easy) | 120 | 100.0% [100.0%, 100.0%] | 0.958 [0.936, 0.978] | 0.0% | 100.0% [100.0%, 100.0%] | 1.000 [1.000, 1.000] | 100.0% / 100.0% |

* Both models flag **every** synthetic attack flow at the default threshold. For A that is cheap: it also flags 58 % of benign traffic, so its useful ranking quality is the AUC column (0.67–0.96), and no attack family scores above the 99th percentile of the diverse benign set (recall @1 % FPR = 0 %).
* B separates all families (AUC ≥ 0.997). The synthetic families are far from the benign library, so this is an easy test; the hardest one (`beacon_tls`) is still caught at 94 % even at 0.1 % FPR on this data.
* **Precision depends on prevalence and is computed, not measured**, from the pooled attack TPR and the diverse-benign FPR: A — 1.7% at 1 % attacks, 16.0% at 10 %; B — 31.0% at 1 %, 83.2% at 10 %, 97.8% at 50 %. At the 1 % prevalence typical of real networks, even B's precision is about a third.

## 5. Adversarial robustness (the 9B evasion attack)

Share of *flagged* attack flows (up to 60 sampled per family) that the greedy feature-perturbation attack (`modules/adv/evasion.attack`, 12 features × 6 rounds, the default budget) turns into unflagged vectors. These are perturbed **feature vectors**, not packets: a real adversary also has to realise them in traffic.

| Family | A: flows attacked | A evaded | B: flows attacked | B evaded |
|---|---|---|---|---|
| `beacon_plain` | 60 | 0.0% [0.0%, 0.0%] | 60 | 1.7% [0.0%, 5.0%] |
| `beacon_tls` | 60 | 3.3% [0.0%, 8.3%] | 60 | 100.0% [100.0%, 100.0%] |
| `exfil_bulk` | 60 | 0.0% [0.0%, 0.0%] | 60 | 100.0% [100.0%, 100.0%] |
| `scan` | 60 | 0.0% [0.0%, 0.0%] | 60 | 100.0% [100.0%, 100.0%] |

B is evaded on three of four families in 100 % of sampled flows. A's evasion rate is near zero; its attack flows start far from its narrow baseline and the default budget does not bring them back (the reason was not investigated further), and A flags most diverse benign traffic anyway, so this is not robustness in any useful sense. This agrees with the recorded 9B experiment (`HANDOFF_FINDINGS.md`): the detector is not robust to a feature-space adversary, and retraining on evaded vectors does not fix that. **No robustness claim is made.**

## 6. Cross-sector consistency

Identical benign flow shapes with the SNI swapped for one classified into each sector by `sectors.py` (400 flows per sector; the classifier's label for each SNI is asserted in the script). The only feature that can differ is `sni_length`/`sni_present`.

| Sector | SNI | A false flags | B false flags |
|---|---|---|---|
| fintech | `pay.bank.test` | 1.5% [0.5%, 2.8%] | 0.0% [0.0%, 0.0%] |
| healthcare | `portal.health.test` | 2.5% [1.0%, 4.2%] | 0.0% [0.0%, 0.0%] |
| smart_city | `cdn.city.test` | 1.8% [0.5%, 3.0%] | 0.0% [0.0%, 0.0%] |
| general | `static.assets.io` | 1.5% [0.5%, 2.8%] | 0.0% [0.0%, 0.0%] |

The spread across sectors is 1.0% for A and 0.0% for B, inside the bootstrap intervals: the detector has no sector-specific behaviour, as designed (sectors only drive scoring weights and reports). That is consistency on *synthetic* sector mixes; per-sector real traffic is untested.

## 7. What would make this a real validation

1. Approved public datasets hashed into a fresh directory with per-flow labels (`scripts/make_labels.py`), evaluated with `spectra eval run` under the honesty rules — the one capture fetched so far (§9) has no labels and is botnet-only.
2. A real benign capture from a network the operator owns, as the second baseline, held out in time from training.
3. Attack traffic not written by the detector's authors, and the 9B harness's evasion rate re-measured on it.
4. Re-run this script's tables on each.

## 8. Findings recorded while building this

* The 0–100 production score saturates at 100 and ties; any ranking metric must use the raw score.
* The single-profile demo baseline is a poor operating point on varied traffic (58 % false flags): train on what the network actually carries (`docs/ml.md`).
* The model is not evasion-robust (§5).

## 9. Real capture: CTU-13 scenario 1 (flag rate only — and confounded)

**What was run (approved by the owner on 2026-11-07).** `botnet-capture-20110810-neris.pcap` from the CTU-13 dataset (Stratosphere/CTU Prague; SHA-256 `b89cd5931f62d87ceff266568c97c6e36e56dd0330813cacadbc14a6c5576a36`, 58,266,506 bytes), fetched with `scripts/fetch_datasets.py --only ctu13-s1-pcap` into a fresh directory and verified with `spectra dataset verify`. Scored by `scripts/eval_real_pcap.py` (raw output `docs/evidence/2026-11-07/ctu13-s1-flagrate.json`) with the same two synthetic-trained baselines as §2, plus a control of 300 synthetic, plainly benign plaintext-HTTP flows. Terms: free to use with attribution (see `docs/datasets.md` for the required citation). The per-flow label file (696 MB) was not fetched, so there is **no ground truth here and nothing below is recall, precision or an FPR**.

**What the capture is.** Botnet-host traffic from 2011: 21,254 flows (13,175 TCP, 8,079 UDP), 26 source and 4,193 destination addresses; only **124 flows (0.6%) carry a TLS handshake**. Destination ports: 25 (8,392), 53 (7,698), 80 (1,315), 6667 (974), 4506 (867), 65500 (278) — mostly SMTP spam, DNS, HTTP and IRC, i.e. not encrypted C2.

| Scored by | Capture flag rate | TLS flows in capture | non-TLS flows in capture | **Benign plaintext-HTTP control** |
|---|---|---|---|---|
| A — demo baseline | 100.0% [100.0%, 100.0%] | 100.0% [100.0%, 100.0%] | 100.0% [100.0%, 100.0%] | **100.0% [100.0%, 100.0%]** |
| B — benign-diversity | 100.0% [100.0%, 100.0%] | 99.2% [97.6%, 100.0%] | 100.0% [100.0%, 100.0%] | **100.0% [100.0%, 100.0%]** |

**Reading.** Every flow is flagged, **including the benign control**, on every port. A flag rate that is the same for malicious and benign plaintext flows is not detection; it is the baseline-matching limitation in its extreme form: a detector fitted to synthetic TLS/QUIC traffic treats anything else, and even real TLS flows (flagged 99.2% by B), as anomalous. This run therefore shows two things and no more: **(1)** the parser and feature extractor process a real 58 MB, 21,254-flow capture end to end without failure (about 50 s to parse); **(2)** synthetic-trained models do not transfer to real traffic. It does **not** show that Spectra detects botnets. A meaningful test needs a *real benign baseline from the network under test* plus per-flow labels (`docs/evaluation.md` §3–§4), and for modern encrypted C2 a capture with TLS C2 rather than this 2011 plaintext botnet.

## 10. Real captures, benign-trained: CTU-Normal vs CTU botnet (pcap-level labels)

**Run.** `backend/scripts/bench_ctu.py` (raw: `docs/evidence/2026-11-07/bench/ctu-bench.json`; file SHA-256s in `docs/datasets.md` §5c; commit of the run `0342337` plus the then-uncommitted script, now `e06860a`). Model: the shipped isolation-forest detector, contamination 0.02, trained on **63,567 flows of CTU-Normal captures dated 2017-04-18…30** (scripted HTTPS browsing of Alexa top-1000 sites; 12–17% of flows carry a parsed TLS handshake). Test, later in time: benign = CTU-Normal 2017-05-01 and 05-02 (23,378 flows); positives = five botnet captures (101,976 flows: CTU-13 s1 and s2, rbot, fast-flux, botnet2.infected.1). Scores are the raw isolation-forest scores (the 0-100 score saturates). `CTU-Malware-Capture-Botnet-100/…win5.pcap` was **excluded**: Spectra's reader and Zeek both report it ends inside a record. Positives are **pcap-level**: every flow of a botnet capture counts as malicious, so botnet captures that contain benign background understate recall.

| Measure | Value | 95% CI (1000 bootstrap, seed 1337) |
|---|---|---|
| Benign flag rate at the default threshold | 4.2% | [3.9%, 4.4%] |
| Botnet flow flag rate at the default threshold | 2.9% | [2.8%, 3.0%] |
| ROC-AUC, pooled | 0.746 | [0.742, 0.750] |
| PR-AUC, pooled (**81% of test flows are positive**, so this is inflated; do not compare across datasets) | 0.897 | n/a |
| Recall at benign FPR 1% / 0.1% | 0.1% / 0.0% | n/a |
| Null control: benign vs benign halves, ROC-AUC | 0.494 | [0.487, 0.502] |
| TLS-handshake flows only (316 botnet vs 5,819 benign flows), ROC-AUC | 0.855 | [0.837, 0.873] |

Per botnet capture ROC-AUC vs the benign test: s1 0.635, s2 0.826, rbot 0.767, fast-flux 0.744, botnet2 0.742. **Reading:** the detector ranks botnet flows above benign ones only modestly, and at any operating point an operator would use (≤1% false flags) it detects essentially none of them. The default threshold flags *fewer* botnet flows (2.9%) than benign ones (4.2%). The botnet captures are 2011/2015 plaintext-heavy host traces (0–12% TLS), while the benign side is lab HTTPS; AUC here partly measures "unlike CTU-Normal HTTPS", so even the modest 0.75 is not evidence of malice detection.

**Baselines on the same pcaps** (`ctu-baselines.json`; Suricata 7.0.8 with ET Open fetched 2026-11-07, 69,342 rules / 53,373 enabled; Zeek 7.0.5 stock scripts, no packages). A flow counts as alerted if its 4-tuple appears in a Suricata alert.

| | Benign test flows alerted | Botnet flows alerted |
|---|---|---|
| Suricata + ET Open, **all alerts** | 1.3% [1.15%, 1.47%] (263 of 20,204) | 3.3% [3.16%, 3.40%] (2,945 of 89,872) |
| Suricata + ET Open, **ET rules only** (no `SURICATA …` engine/decoder events, no `ET INFO`) | 0.10% [0.06%, 0.15%] (20) | 0.17% [0.14%, 0.20%] (152) |
| Stock Zeek notices | 0 | 0 |

The "all alerts" row includes Suricata engine events (for example "invalid checksum", a capture artefact) and informational rules, which say nothing about threats; the "ET rules only" row is the fair signature-IDS reference. **Suricata detects essentially none of these botnet flows** (0.17%), and stock Zeek is not an IDS (zero notices is expected, not a tuned-Zeek result). The Zeek JA3 reference was not run as written (installing the third-party Zeek JA3 package was blocked); the fingerprint-list reference was measured with Spectra's own JA3 instead, see §13.

**Supervised upper bound** (RandomForest on the same 39 features, trained **with** labels on the benign train slice vs the other four botnet captures, tested on the held-out one): ROC-AUC 0.91 (s1), 0.94 (s2), 0.97 (rbot), 0.98 (fast-flux), 0.93 (botnet2); recall at 1% FPR 0.58 / 0.68 / 0.81 / 0.79 / 0.07. Because positives are pcap-level and the environments differ, this number mostly shows how separable the capture environments are; it is an upper bound on the headroom of these features, not a competitor.

**Not done here:** cross-dataset (train CTU-Normal / test HIKARI and the reverse), the 9C/9D/9H ablations, the 9B evasion run on real data, performance replay (`bench_perf`, needs `CAP_NET_RAW`/sudo from the human), and the labelled-real-benign baseline from the owner's own network.

## 11. Real captures with per-flow labels: HIKARI-2021/2022 (attacks inside TLS)

**Run.** `backend/scripts/bench_hikari.py` (raw: `docs/evidence/2026-11-07/bench/hikari-bench.json`). Labels come from the dataset's `ALLFLOWMETER_HIKARI2021.csv` and `ALLFLOWMETER_HIKARI2022.csv` (SHA-256 in the JSON), joined to Spectra's flows **by the 4-tuple only** (the CSVs carry no timestamps); 23,856 tuples with conflicting labels were dropped and unlabelled flows excluded. Detector trained on the **benign + background flows of the 2021-04-11/12 captures only** (32,929 flows) and tested on later captures: 2021-04-17 (benign/background only), 2022-04-10 (HTTPS brute force + XMRig miner) and 2022-04-11 (XML brute force + miner): 75,044 benign/background and 10,664 attack flows (2,048 Bruteforce, 3,641 Bruteforce-XML, 4,975 XMRig crypto-miner).

| Measure (Spectra, unsupervised) | Value |
|---|---|
| Benign flag rate at the default threshold (0.140) | 1.9% [1.8%, 2.0%] |
| Attack flag rate at the default threshold | 0.4% [0.3%, 0.5%] |
| ROC-AUC, all attacks | 0.617 [0.609, 0.625] |
| PR-AUC, all attacks (prevalence 12.4%) | 0.334 [0.327, 0.342] |
| Recall at benign FPR 1% / 0.1% | 0.2% / 0.0% |

Per category (ROC-AUC vs all benign): Bruteforce 0.963, Bruteforce-XML 0.966, **XMRig miner 0.219 (scores *lower* than benign)**. For both brute-force categories ~100% of attack flows score above the benign 90th percentile, but only 0.0–0.05% exceed the 99th percentile or the default threshold. **Reading:** the brute-force flows are a distinct, consistent cluster that the model ranks high, yet well inside the benign tail, so the shipped contamination-based threshold (and a 1% FPR budget) misses them; a 10% false-flag budget would catch them, which is not an acceptable operating point. The miner flows look *more* ordinary than the benign mix and are not detected at all. In this lab the attacks are few, regular and synthetic; this is not a general encrypted-traffic claim.

**Baselines on the same 85,708 labelled test flows.** Suricata + ET Open, **ET rules only** (no engine events, no `ET INFO`): **0 of 10,664 attack flows alerted (recall 0%)** and 6 benign flows alerted (0.01%). Counting *all* alerts, including engine/decoder events and informational rules, 19.7% of benign flows alerted (14,758) and still 0 attack flows; that figure measures capture artefacts, not detection quality. TLS brute-force and miner traffic carries no ET signature. Supervised RandomForest (trained with labels on only 247 attack flows available in the training captures, all HTTPS brute force): ROC-AUC 0.594, recall at 1% FPR 19.5%, at 0.1% FPR 13.1% — it does not generalise to the other attack types. Against Suricata's 0 detections, Spectra's ranking of brute force (AUC 0.96) is better, but neither is operationally useful at a low-FPR operating point.

**Caveats specific to this run.** Same lab, same servers for train and test (in-distribution for the network); 4-tuple joining can mislabel reused tuples; the 2021 captures contain almost no attack flows, so most evidence comes from two 2022 captures of about 150 s each; the attacks are lab-generated.

## 12. Real captures, Bot day: CSE-CIC-IDS2018 (labels from the published attack schedule)

**Run.** `backend/scripts/bench_cic2018.py` (raw: `docs/evidence/2026-11-07/bench/cic2018-bench.json`; file hashes in `docs/datasets.md` §5c). The per-host captures are cut off mid-record (8 of 24 here), so the script reads the packets before the cut; the product's strict reader would refuse them. Positives: flows of the ten documented Bot-victim hosts (`172.31.69.{6,8,10,12,14,17,23,26,29,30}`) that have the documented C2 address `18.219.211.138` as an endpoint, inside the documented windows (10:11-11:34 and 14:24-15:55 local, ±120 s): **98,700 flows**. Negatives: all flows of the day's non-victim hosts: **30,107 flows**. 57,434 other victim flows and 44,311 C2 flows outside the windows are excluded and not scored. The time-zone offset is not documented, so it was chosen from the data: UTC−4 puts 98,700 of 143,011 C2 flows inside the windows (UTC−5, which I expected, puts 76,030). Training: two benign client hosts of Wednesday 2018-02-14 (an earlier day).

| Measure (Spectra, unsupervised) | Value |
|---|---|
| ROC-AUC (Bot vs benign) | **0.190** [0.186, 0.194] (below 0.5: Bot flows score *lower* than benign) |
| PR-AUC (prevalence 77%, inflated) | 0.653 |
| Recall at benign FPR 1% / 0.1% | 0% / 0% |
| Benign flag rate at the default threshold | 1.15% [1.02%, 1.26%] |
| Bot flag rate at the default threshold | 0.0% (0 of 98,700) |
| Supervised RandomForest (random 50/50 split of the same flows; optimistic by construction) | ROC-AUC 1.0 |
| Suricata + ET Open, all alerts | Bot 0.96% (946), benign 49.5% (14,911) |
| Suricata + ET Open, ET rules only | **Bot 0.0% (0 of 98,700)**, benign 1.56% (471) |

**Reading.** The Ares C2 traffic is invisible to the unsupervised scorer: it scores the Bot flows as *more* ordinary than the benign mix, and flags none. The RandomForest separating them perfectly shows the 39 features do carry the signal; the isolation forest ranks the dense, repetitive beacon flows as typical, because a dense cluster is not isolated. This is the mechanism Spectra's separate beaconing module (9D, flow-start cadence per host pair) is meant to address, and **it has not been measured on this data**. Suricata with ET Open also detects none of it. **Benign half is dominated by capture artefacts for Suricata:** 49.5% of benign flows triggered an alert, almost all "SURICATA … invalid checksum" engine events and `ET INFO RDP` rules (checked in the Suricata output), not threat rules.

**Caveats.** Positives are only the documented C2-address flows; other Bot-related flows are not labelled and not scored. Negatives are all flows of non-victim hosts, assumed benign because the schedule lists no attack on them, which is not an audit of their traffic. Same AWS lab for train and test; one botnet on ten hosts.

## 13. Gate B remainder: cross-dataset, ablations, adversarial run, throughput, fingerprint list

Raw: `docs/evidence/2026-11-07/bench/gateb.json`, `throughput.json`; script `backend/scripts/bench_gateb.py`. To keep the run tractable the score metrics here use at most 20,000 flows per class (fixed-seed subsample) and 300 bootstrap resamples, unlike §10-§12 (full sets, 1000 resamples); the ROC-AUC values are therefore within sampling noise of the earlier ones, not identical.

**Cross-dataset generalisation** (train on the row's benign slice; each cell = benign flag rate at that model's default threshold / ROC-AUC of the target's attacks vs the target's benign flows):

| trained on ↓ / tested on → | CTU | HIKARI | CIC-2018 |
|---|---|---|---|
| CTU-Normal | 4.1% / 0.75 | 1.8% / 0.54 | 4.0% / 0.59 |
| HIKARI | 15.4% / 0.61 | 1.9% / 0.62 | 15.8% / 0.25 |
| CIC-2018 | 2.3% / 0.67 | 0.8% / 0.48 | 1.0% / 0.19 |

This is the README's "baseline matching" warning, measured. Moving a HIKARI-trained model to CTU or CIC-2018 traffic raises benign false flags from about 2% to about 15-16%, roughly eight-fold; CTU-trained and CIC-trained models stay at 1-4% on the other networks but then detect little anywhere (the CTU-trained model flags 16% of HIKARI attack flows but only 0% of CIC-2018 Bot flows). The in-network cells repeat the §10-§12 results (CTU 0.75, HIKARI 0.62, CIC-2018 0.19).

**Ablations** (with / without 1000 synthetic benign flows at train time, as `spectra train --augment 1000`):

| dataset | ROC-AUC | benign flag rate | attack flag rate |
|---|---|---|---|
| CTU | 0.746 → 0.761 | 4.1% → 3.8% | 2.8% → 2.7% |
| HIKARI | 0.617 → 0.616 | 1.9% → 2.0% | 0.4% → 0.4% |
| CIC-2018 | 0.191 → 0.195 | 1.0% → 1.0% | 0.0% → 0.0% |

9C (augmentation) changes nothing measurable on real data (all differences are small compared with the intervals in §10-§12). **9D (beaconing):** per host-pair gap regularity (`modules.corr.graph.cadence_stats`) on the CIC-2018 Bot victims: the ten C2 pairs have median regularity 0.3468 against 0.0 for the other 1572 pairs; ROC-AUC 0.71 [0.56, 0.82] at pair level. That is the one signal in this report that points towards the Bot traffic, but with 10 positive pairs and a lower bound barely above chance it is weak evidence, and it is a cadence statistic, not a detector verdict. **9H (JA4+): not applicable**: JA4 values are not among the model's 39 features (they feed `spectra intel` matching only), so there is no scoring effect to ablate.

**9B adversarial robustness on real flows** (greedy feature-perturbation attack on flows the detector flags, up to 300 sampled): CTU 555 of the sampled positives flagged, evasion rate **100%** (300 of 300), HIKARI 43 flagged, evasion rate **100%**; CIC-2018: nothing flagged, so nothing to evade (the detector already misses every Bot flow). The median relative change needed to evade was tiny (0.0% and 2.5% of the feature vector). This repeats the synthetic result (§5): evasion is easy.

**Fingerprint-list reference ("Zeek + JA3" substitute).** Spectra's own JA3 of every TLS-handshake flow in the CTU, HIKARI and CIC captures against the abuse.ch SSLBL JA3 blacklist (97 entries parsed; fetched 2026-11-07, the first download attempt returned an HTTP 503 page and was redone): **0 matches** among 14,153 flows with a JA3 (of 229,181 flows in the files processed). The list has been frozen since 2021, and most botnet flows here are not TLS, so this reference neither detects nor falsifies anything. It is Spectra's JA3, not Zeek's.

**Offline throughput** (`backend/scripts/bench_throughput.py`; single process, no NIC; Intel i5-12450HX, 12 threads, Python 3.14; each file read twice): parse-only 6,905 and 6,532 packets/s (ctu_normal--2017-05-01_normal.pcap, Monday_2022-04-11_0622_BRUTEFORCE_XML_150s.pcap); parse + features + per-flow scoring 5,605 and 4,381 packets/s (256 and 427 flows/s); peak RSS about 215 MB. "Packets" counts packets assigned to flows. **One core digests roughly 4-7 thousand packets per second from disk; a 50 kpps link would not fit one core.** This is not the live-capture sizing (veth + tcpreplay, drop counters, p99 latency, an ARM box): `backend/scripts/bench_perf.sh` is written for that and **has not been run**; it needs `sudo`, which only the owner can supply.

**Nightly regression job.** `.github/workflows/nightly-bench.yml` + `backend/scripts/bench_nightly.py` + `ci/nightly_thresholds.json`: trains on CTU-Normal-26, tests CTU-Normal-28 vs the CTU-13 s2 botnet capture (SHA-256 pinned, about 290 MB, cached), and fails on moved flow counts or wrong-direction metric changes. Run locally twice (passes), and with a threshold set to 0.99 it fails with exit 1. **It has not run in GitHub Actions yet**; thresholds are generous (another CPU and Python) and should be tightened after a few CI runs. Note what the baseline run shows: trained on a single 2017-04-28 capture the detector flags 64% of the botnet flows (benign 8.5%), against 2.9% when trained on four captures. The result is very sensitive to the training slice.

## 14. Summary of what Phase B shows so far

Three real public datasets were evaluated with a benign-only training slice from an earlier time and the same signature-IDS baseline (Suricata 7.0.8, ET Open, ET rules only): CTU-Normal vs CTU botnet captures (§10), HIKARI-2021/2022 (§11) and CSE-CIC-IDS2018 Bot day (§12). Across them:

* The unsupervised detector behaves correctly on its null control (benign vs benign AUC 0.49) and keeps benign false flags low (1-4% at the default threshold).
* **It detects almost none of the attacks at the default threshold or at a 1% false-flag budget** (CTU 2.9% of botnet flows flagged, recall 0.1% at 1% FPR; HIKARI 0.4%; CIC-2018 Bot 0 of 98,700).
* Ranking differs by attack type: HIKARI brute force ranks well above benign (AUC 0.96), CTU botnets modestly (0.75), the HIKARI miner (0.22) and CIC-2018 Ares C2 beaconing (0.19) rank *below* benign. Dense, regular flows look ordinary to an isolation forest. The beaconing module (9D) that targets exactly this was not measured here.
* Suricata with ET Open (ET rules only) detects essentially nothing either: 0.17% of CTU botnet flows, 0 of 10,664 HIKARI attack flows, 0 of 98,700 CIC-2018 Bot flows. This comparison is weak (rule/era mismatch, lab-generated attacks, stock Zeek only), so it does not show that Spectra is better than a tuned IDS.
* A supervised RandomForest on the same features separates the classes well on in-distribution splits (CIC-2018 1.0, CTU 0.91-0.98), so the features hold signal that the unsupervised scoring does not use. On unseen attack types (HIKARI) it did not generalise.

**Gate B status.** Done: three Tier-1 datasets with a signature-IDS baseline (Suricata, ET rules only) and a supervised upper bound; bootstrap intervals, recall at 1% and 0.1% FPR, PR-AUC; cross-dataset generalisation; ablations (9C measured, 9D measured at pair level, 9H not applicable); the 9B evasion run on real flows; offline throughput; a nightly regression job (written, verified locally, not yet run in CI). **Not done, and why:** live-capture sizing (needs `sudo`; script written, not run); the Zeek + JA3 reference as specified (third-party package install blocked; a Spectra-JA3 substitute was run); the owner's own-network benign capture (human task); an ARM sizing box; Suricata/Zeek *tuned* baselines. Labels are weak in all three datasets (pcap-level, 4-tuple join, schedule windows). **No claim of detection performance on real networks follows from these runs, and the numbers argue against shipping the default threshold as a detector for these attack types.** Gate B as written ("every published number traceable to a JSON file and a hash") holds for the numbers in §10-§13, with the open items above.

## 15. Phase E0: pair-level beaconing sweep (2026-11-08, synthetic positives)

`backend/scripts/bench_beacon_sweep.py` -> `docs/evidence/2026-11-08/bench/beacon-sweep.json` (inputs hashed, commit recorded, 500-sample bootstrap).
Scorers: Spectra's current gap regularity (`1 - cv`), a **RITA-style re-implementation** (skew/MAD of gaps and sizes; *not RITA*, which has not been run), and a gap-histogram mode share.
Positives are **synthetic** beacons (30 flows, 200 per cell, intervals 30 s / 300 s / 1 h, uniform jitter 0-90 %): idealised, so hits are an upper bound, not a measurement of any real C2 framework. Negatives: (a) 177 real benign pairs (>=10 flows) from CTU-Normal 2017-04-28 and 05-01; (b) *hard negatives*, synthetic steady non-beacon services with gamma-renewal gaps (cv 0.5) and the beacon's size spread (0.05) or a wide one (0.5).

| Finding (300 s interval; other intervals alike unless noted) | Evidence |
|---|---|
| Against real benign pairs, gap regularity separates beacons up to ~50 % jitter (recall 1.0 at 0.6 % pair FPR) and **collapses at 75 % (recall 0.09) and 90 % (0.01)** | the cells, `recall_at_fpr_1pct` |
| The ROC-AUC of 0.98 at 90 % jitter against real pairs is misleading: real benign pairs here are bursty (cv > 1), so *any* steady series ranks above them. Against steady non-beacon services with the same gap spread, AUC is **0.77 at 75 % and 0.36 (below chance) at 90 %** | `hard_negatives` |
| Timing alone cannot separate a heavily jittered beacon from a steady service; size consistency can, **if** services vary in size (RITA-style AUC 1.0 vs wide-size services) and **cannot if** they do not (0.29-0.48 vs identical-size services) | `steady_size_cv_*` |
| The gap-mode-share scorer degrades faster than regularity (AUC 0.69 at 50 % jitter) | cells |
| The RITA-style scorer loses accuracy at long intervals (AUC 0.70 at 1 h with >=10 % jitter) because the absolute MAD scale (30 s, 128 B) penalises long gaps; this may be an artefact of this re-implementation | cells, interval 3600 |

**What this means for the engine (docs/35 E2.1):** gap regularity is a useful but narrow signal. Jitter above ~50 % defeats it, and periodic benign services look the same, so a beacon detector needs destination rarity, size and long-session features and allow-lists on top, which is why docs/35 fuses evidence per host. **Limits:** the real benign set has only 177 pairs (confidence intervals at the 1 % operating point are wide, e.g. [0.0, 1.0]); it has no periodic benign services, so false alerts from NTP/telemetry are not measured here; the real C2 pairs of CIC-2018 (pair-level AUC 0.71 earlier) remain the only real positives. Run RITA on Zeek logs of the same data before any statement about RITA.
