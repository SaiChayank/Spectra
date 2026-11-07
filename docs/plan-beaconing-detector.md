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
