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
