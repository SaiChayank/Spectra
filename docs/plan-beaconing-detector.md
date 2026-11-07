# Plan: make host-pair beaconing a first-class detector (owner decision 9, 2026-11-07)

**Decision recorded:** ship the isolation-forest detector with honest limits and a "calibrate on your own network" guide, and make beaconing a
detector in its own right next. Nothing in this plan is built yet.

## Why
`docs/evaluation-report.md` §10-§13: the flow-level isolation forest ranks dense, regular flows as ordinary (CIC-2018 Ares C2: ROC-AUC 0.19,
0 of 98,700 flows flagged; Suricata also 0). The one signal that pointed towards that traffic is the per-host-pair gap regularity already
computed by `modules.corr.graph.cadence_stats`: the ten C2 pairs had median regularity 0.35 against 0.0 for 1,572 other pairs, pair-level
ROC-AUC 0.71 [0.56, 0.82]. Today that value only feeds a bio "danger signal" and a graph-edge attribute; it never raises an alert.

## What to build
1. A **pair scorer** (new module, not a change to the forest): for each (source host, destination IP-or-SNI) pair with at least `N` flows in a
   window, compute regularity (`1 - cv` of start-time gaps), gap median, jitter ratio, flow-size consistency and duration; score = a fixed,
   documented combination; **no learned weights from the evaluation data**.
2. An alert type `C2_BEACONING` from the pair scorer with the pair, the cadence and the evidence in the alert body, behind a config flag (off
   until validated), reusing the existing alert/incident path and severity rules. Metadata only.
3. Allow-list support (known periodic services: NTP, update checks, monitoring probes), because periodic benign traffic is the main false-positive source.

## How to judge it (fixed before the first run)
* Pair-level metrics with 95% bootstrap intervals, recall at a fixed pair-level false-alert rate, on: CIC-2018 Bot day (10 C2 pairs; add the
  other victims' pairs as negatives), CTU botnet captures (infected-host pairs), HIKARI (miner traffic), and the owner's own-network baseline
  (`docs/human-benchmark-tasks.md` task 12) for false alerts per day.
* Thresholds chosen on one dataset, reported on the others; never tuned on the test split. Report where it fails (periodic benign pairs).
* Add to the nightly job only if it is stable on CPU-dependent float summation.

## Risks
Ten positive pairs is a tiny sample; jittered beacons (the technique designed to defeat this) will evade it; CDN and telemetry traffic is
periodic. The result may be "useful as a ranking aid, not as a detector", and the report must say so if so.

## Protocol as run (written 2026-11-07 BEFORE the first evaluation run; code: `backend/scripts/bench_beacon.py`)
* **Detector, fixed before any result:** pair = (initiating host, destination IP); scored with at least 8 flows in the trailing 64-flow
  window and a median start gap of at least 1 s; score = mean of (1 - cv of gaps, 1 - min(1, MAD/median of gaps), 1 - min(1, cv of flow
  bytes)). Equal weights, nothing fitted. A pair "alerts" the first time any trailing window scores >= the threshold (same code as the
  product's streaming tracker; the script cross-checks this).
* **Threshold:** the 0.99 quantile of the scorable *benign* pair scores of the CIC-2018 calibration captures (every even-indexed
  non-victim capture of the Bot day, sorted by file name). **No positive label of any dataset is used to choose it.** The odd-indexed
  non-victim captures are the CIC-2018 test negatives; the ten victim-to-C2 pairs are the CIC-2018 positives.
* **Other datasets use that threshold unchanged:** CTU (all pairs of the five botnet captures vs all pairs of the six CTU-Normal captures;
  pcap-level labels) and HIKARI (pair label = majority of its 4-tuple-labelled flows, benign needs zero attack flows; mixed pairs dropped
  and counted).
* **Reported:** ROC-AUC / PR-AUC / recall at 1 % and 0.1 % false-alert rate on scorable pairs with 95 % bootstrap intervals (1000 resamples,
  seed 1337); recall and false-alert rate at the fixed threshold, both over scorable pairs and over all pairs (a positive pair with too
  few flows to score counts as missed in the "all pairs" view); per-component AUC (reporting only); the benign pairs that alert; a
  synthetic jitter sweep (labelled synthetic).
* **Not run here:** the owner's own-network baseline (task 12 is a human task); the nightly job (not added - see the report).
