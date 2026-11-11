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

## v2 (preregistered 2026-11-11, before any v2 scoring code is run on data; machine-readable copy: `ci/prereg/e21.json`)
v1 (above) was a ranking aid on one dataset. v2 follows RITA's published method plus `docs/evaluation-report.md` §15. **Nothing is fitted to
data; the numbers below are decided and are not tuned after seeing results.**
* **Pair** = (source host, SNI if the flow has one, else destination IP); the verdict carries the SNI and the set of destination IPs seen.
* **State per pair:** newest 512 flows as (start_ts, forward bytes, duration_s), first_seen, hourly flow counts; the pair cap stays; all state
  is bounded. "Now" = the largest flow timestamp seen (capture clock, never wall clock). A flow longer than 1 h counts in every hour bin it spans.
* **Components, each in [0, 1], robust statistics only:** **G** gaps = mean of (1 - |bowley|) and (1 - min(1, MAD/median)) of start-to-start
  gaps (bowley = (Q3 + Q1 - 2*Q2)/(Q3 - Q1), 0 when Q3 == Q1); **S** sizes = the same two formulas on forward bytes (0 if the median is 0);
  **D** persistence = active hour bins / total hour bins from first_seen to now inclusive, newest 24 bins; **H** histogram flatness =
  1 - min(1, MAD/median) of the hourly counts over those bins including empty ones (0 if the median count is 0).
* **Minimum evidence:** G and S need >= 12 flows and a median gap >= 1 s. D and H need a span (now - first_seen) >= 3 h. A score exists only
  when D is available and at least one of G or H is; otherwise no verdict.
* **Score** = unweighted mean of the available components; **alert at score >= 0.8**. Allow-list semantics unchanged; the allow-list is EMPTY
  for every gate run.
* **Known consequences:** nothing can alert in the first 3 h of a pair; a 1 h beacon needs about 12 h; captures shorter than 3 h give no verdict.
* **Evaluation:** CIC-2018 Bot day has been seen: dev/smoke only, its own row, never in the gate. Held-out set A = CTU-13 botnet C2 pairs vs
  CTU-Normal 2017 benign pairs; held-out set B = a lab C2 corpus generated after this file is committed (dataset hashes added by amendment).
  Pairs with >= 20 flows. **Gate (needs A and B):** recall >= 0.8 at <= 1 false pair per 1,000 benign pairs (zero false pairs when fewer than
  1,000), bootstrap 95 % lower bound >= 0.6, and recall not more than 0.05 below real RITA v5.1.2 on the same pairs; B is gated at jitter
  <= 50 %, 75 % is a reported curve only. **On failure:** report "ranking aid, not a detector", the flag stays off, numbers are published, no
  retuning in the same session. Any change after a held-out run needs a committed amendment with its reason.

### Amendment 1 (2026-11-12; before any held-out run; weights and the 0.8 threshold unchanged)
Decided from the CIC-2018 dev smoke (seen data): all ten C2 pairs had no G/S (sub-second cadence) and 50 of the 51 benign pairs scoring >= 0.8
were inbound (external source). Three structural changes, which supersede the matching v2 bullets above:
1. **G on unique whole seconds.** G uses the gaps between the sorted unique `floor(start_ts)` values (RITA analyses unique one-second
   timestamps); the "median gap >= 1 s" rule is removed; G needs >= 12 unique timestamps. S still uses every flow's forward bytes (>= 12 flows).
2. **Direction.** Only pairs with an internal source and an external destination are tracked and scored. Inside = `beaconing_internal_nets`
   (default RFC1918 + fc00::/7). Set A (CTU-13) uses 147.32.0.0/16, the capture network documented by the dataset; fixed before set A was
   scored. Internal-to-internal pairs are out of scope for this detector.
3. **G required.** A verdict exists only when G and D are both available (S and H join the mean when available). Persistence without timing
   evidence is not a beacon; long-lived single sessions will be a separate signal (docs/35 E1). "Now" is the largest flow end time.
