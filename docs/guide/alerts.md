# Reading alerts

An alert means: **this flow looked different from your baseline.** It does not mean an attack happened. Treat each
alert as "look at this", and use the evidence attached to decide.

## The numbers on an alert

| Field | Range | What it is | What it is not |
|---|---|---|---|
| Anomaly score | 0-100 | Percentile rank of the flow against the training flows. 99 means "more unusual than 99 % of the baseline". | Not a probability of being malicious. |
| Confidence | 0.30-0.95 | How strongly independent rule signals agree on a named category. Capped at 0.45 when no category is reached. | Not the same as the score; it can never be 1.00. |
| Severity | LOW, MEDIUM, HIGH, CRITICAL | Ordinal urgency from the category, confidence, score and repeat sightings. The alert lists the factors it used (`severity_factors`). | Not a risk rating with asset inventory or threat intelligence behind it. |
| Category | e.g. `C2_BEACONING`, `UNKNOWN_ANOMALY` | A rule verdict that needs at least two independent signals. | Not proof. Real attacks can land in `UNKNOWN_ANOMALY`. |

A high score with `UNKNOWN_ANOMALY`, confidence 0.45 and LOW severity (as in the [first run](./first-run.md)) is
normal: unusual, but the rules could not name why. The detector and the classifier are not independent evidence,
because classification only runs on flows the detector already flagged, so do not count score plus category as two
proofs. Details: [ml.md](../ml.md), [limitations](../limitations.md) section 3.

## "Unscored"

If no model is trained, Spectra still parses and stores the flows but cannot score them. The capture then shows an
**unscored** badge, `unscored_flows` greater than zero and a warning such as "model not trained: N of M flows were
parsed and stored but not scored, so this capture can show no detections". **Zero detections on an unscored capture
means nothing.** Train a model ([first run](./first-run.md), step 6) and process the capture again. The same happens
if the model file is damaged: the server starts but loads no model, and the metric `spectra_model_trained` is 0
([runbook](../runbook.md), "Model artifact corrupt").

## The beaconing detector is off, and only a ranking aid

Beaconing (regular call-backs to one destination, typical of some command-and-control software) has its own pair
detector. It is **off by default** (`beaconing_enabled` is `False` in the configuration) and should stay a ranking
aid, not an alarm:

* It was tested against a pre-registered gate and **failed it twice**
  ([evaluation report](../evaluation-report.md) sections 18 and 19). On real botnet captures (set A) it caught 3 of 8
  command-and-control pairs without any false pair; on 10 hours of simulated beacons (set B) it caught about 3 % of
  beacons without any false pair.
* At its 0.8 threshold it caught 33 of 36 simulated beacons, but also raised 15 false pairs out of 96, all periodic
  but harmless services (app polling, chat long-poll). Telemetry and time-sync services also scored at or above 0.8.
  Timing alone cannot tell a beacon from a periodic service; expect to need an allow-list entry for each such service.
* It needs about 12 distinct seconds and a 3 hour span before it gives a verdict, so short captures give none.
* Those results used synthetic or old public data. Nobody has yet measured it on a real network of your kind;
  the plan is documented in [plan-beaconing-detector.md](../plan-beaconing-detector.md).
* There is no environment variable for it in `config.py`; it is a code-level setting.

## How well does the detector find attacks?

Honestly: not reliably yet. On three real public datasets, with a benign-only baseline from earlier traffic
([evaluation report](../evaluation-report.md) section 14):

* False flags on benign traffic were low (1-4 % at the default threshold).
* It flagged almost none of the attacks: 2.9 % of botnet flows in one set, 0.4 % in another, 0 of 98,700 command and
  control flows in a third. Regular, dense flows (miners, command-and-control beacons) can score as *more normal*
  than benign traffic.
* Brute-force traffic ranked well above benign (AUC 0.96). The numbers argue against relying on the default threshold
  as a detector for these attack types, and "no claim of detection performance on real networks follows".
* An equivalent signature IDS run (Suricata, ET Open rules only) caught essentially nothing either, but that
  comparison is weak and does not show Spectra is better than a tuned IDS.
* Scores drift as your network changes. Drift above 0.25 PSI (`GET /api/model/drift`) means scores are no longer
  calibrated: retrain ([calibrate](./calibrate.md)).

## What Spectra cannot see

* **Content.** Payloads are never decrypted, stored or displayed. Malware signatures, file contents, DNS names inside
  a tunnel and request bodies are invisible. Uploaded captures are rewritten on import so only headers, payload
  lengths, TLS handshake records and QUIC Initial packets remain (unless `SPECTRA_STORE_RAW_CAPTURES=1`).
* **Anything off the capture point.** It sees only the traffic on the interface or in the file you give it.
* **Slow, spread-out activity.** A patient beacon across many endpoint pairs produces several alerts, not one.
* **Response.** There is no blocking, quarantine or automated action.
* **Hardware-backed claims.** The TEE module is simulated, and the digital twin, bio and audit modules are
  simulated or experimental annotations. They never create detections ([limitations](../limitations.md) section 6).
