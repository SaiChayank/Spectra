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

### Amendment 2 (2026-11-12; clarification and data only; written after the CIC smoke and before set A was scored)
* **Gate metric** (as originally worded): recall at the best operating point with <= 1 false pair per 1,000 benign pairs (zero false pairs when
  fewer than 1,000), `spectra.eval.metrics.recall_at_fpr(pos, neg, 0.001)`, bootstrap 95 % lower bound >= 0.6, and not more than 0.05 below real RITA
  v5.1.2 scored by the same rule on the same pairs. Recall and false pairs **at the fixed 0.8 threshold** are reported for every set; they are not
  part of the gate, but the detector may not be switched on by default unless fixed-threshold recall is also >= 0.8 with zero false pairs on
  both held-out sets. This was written after the CIC smoke, where C2 pairs scored 0.75-0.78, and before set A.
* **Set A:** the four CTU-13 captures (scenarios 1, 2, 3, 5: Botnet-42, 43, 44, 46) vs the six CTU-Normal 2017 captures; hashes in `ci/prereg/e21.json`.
  Positives = pairs (infected host -> destination, >= 20 flows) whose flows the dataset's own labels mark C2 (Stratosphere `capture*.binetflow.2format`,
  label contains "CC"; oriented as inside host -> other end); labels downloaded 2026-11-12 into `~/Projects/Spectra_bench_data/datasets/labels/`
  (URLs, sizes, SHA-256 in the prereg and `docs/datasets.md`), parsed as text only. Negatives = every scored CTU-Normal pair. Botnet non-C2 pairs are
  reported outside the gate. Botnet-91 and Botnet-100 are not CTU-13 and are not part of set A. Inside networks: 147.32.0.0/16 for the botnet
  captures; for CTU-Normal the capturing hosts are 10.0.2.15 / 192.168.1.191 (from the Zeek conn.log), covered by the defaults. A pair with no verdict
  scores 0. RITA: beacon_score from the same captures' Zeek logs; its default alert level is `base` 50 (0.5).
* **Known limits, up front:** 2011 botnets vs 2017 benign traffic (pcap-era mismatch); captures of about 3-6 h, so slow beacons cannot be scored;
  few positive pairs (the public CTU-13 pcaps hold botnet-host traffic only).

### Amendment 3 (2026-11-12; set B redefined; written BEFORE any simulator traffic is generated; scorer and gate wording unchanged; machine-readable copy in `ci/prereg/e21.json`)
Reason: the agent could not fetch C2 frameworks; the owner approved (2026-11-12) a harmless simulator instead (plain Python clients and servers, ordinary
HTTPS, isolated Docker network). Set B is **simulated**: idealised beacons with real TCP/TLS 1.3 on a real network stack. Results bound what the
detector can do and say nothing about any specific C2 framework. Real-framework captures remain an optional owner-run addition.
* **Network:** one Docker network, `internal: true`, subnet 203.0.113.0/24 (TEST-NET-3), no published ports. Clients: static addresses in
  203.0.113.128/25; servers in 203.0.113.0/25. Scoring set B: `beaconing_internal_nets` = ["203.0.113.128/25"]; RITA's internal subnet the same. Allow-list empty.
* **Duration:** 10 h wall clock, real time. 12 client hosts, each capturing its own traffic to its own pcap.
* **Beacons (positives):** 16 cells = interval {10, 60, 300, 1800 s} x jitter {0, 25, 50, 75 %}; next delay = interval * (1 + U(-j, +j)). Each cell runs on 3
  different hosts (48 pairs); each host runs 4 beacons, one per interval, jitters by a fixed seeded rotation so every cell appears 3 times. One server per cell
  (own IP, SNI `c-<interval>-<jitter>.lab.example`). Every check-in is a NEW TCP + TLS 1.3 connection: POST 300 B +-5 %, response 200 B +-5 %, with
  probability 0.05 a "tasking" response of 2-20 kB. Start at a random offset in the first interval, run the whole 10 h.
* **Gate negatives (every host):** B1 browsing: Poisson sessions (mean 20 min apart), 5-40 requests per session, lognormal gaps (median 2 s, sigma 1.0), 6 shared
  SNIs, request 200-2,000 B, response 1-200 kB heavy-tailed. B2 chat long-poll: active (60-120 min) / idle (30-90 min) periods; while active reconnect after
  U(30, 90) s, 100-5,000 B. B3 app polling: two active windows of about 2 h at seeded random times; while active a request every 15 s +-10 %, request 150-400 B,
  response 0.2-50 kB.
* **Periodic benign, reported as its own class OUTSIDE the gate (stated now: the detector is not expected to separate these from beacons; their alert count is the
  number of allow-list entries a site would need):** B4 telemetry every 300 s +-10 %, 0.5-20 kB; B5 time-sync-like every 64 s fixed, about 100 B each way; B6 update
  check every 3600 s +-300 s, about 1 kB.
* Benign destinations are shared by all hosts (own server IP and SNI each). All randomness: seed 1337 plus host index; exact schedule parameters go to a manifest.
* **Gate (unchanged wording):** pairs with >= 20 flows; positives at jitter <= 50 % gated (36 pairs), 75 % (12 pairs) a curve only; negatives = B1-B3 pairs; a pair
  without a verdict scores 0. **Known consequences:** the 1800 s beacon gives about 20 check-ins in 10 h (at the edge of the >= 20 flow rule); the 3600 s update check
  about 10 (not scored). Pcap SHA-256 hashes are added by a later data-only amendment when the run finishes.

### Amendment 4 (2026-11-12; clarification made while the set B capture was still running and unread; no design, scorer, threshold or weight change)
Stricter reading: a slow beacon that cannot reach 20 flows in 10 h is a miss, not an exclusion. All 36 gated beacons (jitter <= 50 %) and all 12 at 75 % always
count; a labelled beacon pair with fewer than 20 flows, or absent from the pcap, is included with score 0 for both Spectra and RITA and flagged `below_min_flows` /
`absent` in the per-pair table (the manifest must list exactly 36 gated beacons). B1-B3 negatives and the periodic-benign class keep the >= 20 flows rule; their
below-20 counts are reported. Machine-readable copy in `ci/prereg/e21.json`.
