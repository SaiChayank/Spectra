# Spectra — Model evaluation and validation report

**Date:** 2026-11-06 · **Commit:** `a0ef02a` (branch `phase10/gate-10`) · **Status:** engineering evidence, **not a sign-off**; synthetic data only.

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
| Suricata + ET Open | 1.3% [1.15%, 1.47%] (263 of 20,204) | 3.3% [3.16%, 3.40%] (2,945 of 89,872) |
| Stock Zeek notices | 0 | 0 |

Suricata also finds little (3.3%): ET Open fires on a small share of these old botnet flows, and stock Zeek is not an IDS (zero notices is expected, not a tuned-Zeek result). The JA3-list reference ("Zeek + JA3") was **not run**: installing the third-party Zeek JA3 package was blocked, and the abuse.ch SSLBL list fetched (16 entries, frozen since 2021) is tiny.

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

**Baselines on the same 85,708 labelled test flows.** Suricata + ET Open: **0 of 10,664 attack flows alerted (recall 0%)**, and **19.7% of benign/background flows alerted** (14,758) — HIKARI's benign side contains traffic ET Open rules fire on, and TLS brute-force/miner traffic carries no signature. Supervised RandomForest (trained with labels on only 247 attack flows available in the training captures, all HTTPS brute force): ROC-AUC 0.594, recall at 1% FPR 19.5%, at 0.1% FPR 13.1% — it does not generalise to the other attack types either. If Suricata is judged on this dataset, Spectra's ranking (AUC 0.96 on brute force) beats Suricata's 0 detections, but neither is operationally useful at a low-FPR operating point.

**Caveats specific to this run.** Same lab, same servers for train and test (in-distribution for the network); 4-tuple joining can mislabel reused tuples; the 2021 captures contain almost no attack flows, so most evidence comes from two 2022 captures of about 150 s each; the attacks are lab-generated.

## 12. Summary of what Phase B shows so far

On two real datasets with a benign-only training slice from an earlier time, the unsupervised detector (a) behaves correctly on its null control (AUC 0.49 benign vs benign), (b) ranks some attack types well above benign (HIKARI brute force 0.96) and others at or below benign (miner 0.22), (c) detects almost nothing at the default threshold or at a 1% false-flag budget, and (d) was not better than a labelled RandomForest or competitive with a tuned IDS — but the Suricata/Zeek comparison here is weak (rule/era mismatch, stock Zeek). Not reached: CIC-2018 (skipped on size), cross-dataset generalisation, ablations, real-data adversarial run, performance sizing, the owner's own-network baseline. **No claim of detection performance on real networks follows from these runs.**
