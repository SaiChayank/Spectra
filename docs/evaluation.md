# Spectra — Ground-truth evaluation

How Spectra is measured against **labeled real-world traffic** — the label
schema, the dataset-to-category mapping, the flow-to-label join rules, the
metric definitions, and the honesty rules that keep the numbers honest.

Code: `backend/spectra/eval/` (labels, join, metrics, report),
`backend/spectra/datasets.py` (artifact registry),
CLI: `spectra dataset …`, `spectra eval run|compare`.

---

## 1. Why this exists

Spectra's detector is **unsupervised** (`IsolationForest` over a benign
baseline). Before this module the honest statement was *"we cannot claim
precision or recall"*. This module replaces that with *"we measured precision,
recall and FPR on these labeled datasets — and here is what we could **not**
measure because the attack is invisible without payload"*.

It does **not** change the detector: evaluation runs the *real* pipeline
(parse → 39 features → model → classifier) offline over a PCAP and joins its
output to ground truth. Nothing about the live serving path changes.

## 2. Honesty rules (binding)

1. **`METADATA_INVISIBLE` attacks are never counted as failures.** Attacks
   whose evidence lives in payload content (e.g. CIC's *Web Attack*,
   *Heartbleed*) are architecturally invisible to metadata-only detection.
   They are counted in a separate bucket and reported as *"out of scope by
   design"* — never silently dropped, never scored as misses.
2. **Unlabeled time is not benign time.** Datasets label *attacks*; the
   absence of a label does not prove benign traffic. False-positive rate is
   computed only over windows explicitly labeled benign (when the dataset
   provides benign labels); otherwise FPR is reported as `null` with the
   reason.
3. **Every report carries its caveats.** A report names its dataset, dataset
   checksum, model id, feature schema version and join tolerance. A number
   without those is not a Spectra evaluation.
4. **The baseline-matching limitation stands.** The unsupervised detector is
   trained on *some* benign baseline; its behaviour on a different network's
   traffic is the baseline-matching limitation (`limitations.md` §2), and a
   good score on CICIDS2017 does not license claiming general accuracy.

## 3. Label schema

Ground truth is a CSV file, one row per labeled interval:

```csv
t_start,t_end,src_ip,src_port,dst_ip,dst_port,proto,dataset_label,mapped_category
```

| Column | Type | Meaning |
|---|---|---|
| `t_start`, `t_end` | epoch seconds (float) | labeled interval; a flow matches when its start falls within `[t_start - W, t_end + W]` with tolerance `W` (default 10 s) |
| `src_ip`, `dst_ip` | string | either direction matches (labels are endpoint-pair based, see §5) |
| `src_port`, `dst_port` | int, `*` = any | `*` matches any port (many datasets label at host level) |
| `proto` | `TCP` / `UDP` / `*` | transport; `*` matches either |
| `dataset_label` | string | the dataset's own label, verbatim (e.g. `PortScan`, `Bot`, `DoS slowloris`) |
| `mapped_category` | one of `THREAT_TYPES` ∪ `METADATA_INVISIBLE` | see §4 |

Label files are generated per dataset from the dataset's own ground-truth
artifacts (see `backend/scripts/` per-dataset adapters) and stored next to
the dataset under `backend/data/datasets/` — never in git.

## 4. Dataset → `THREAT_TYPES` mapping

Mapping is **fixed at evaluation time** and written into every report. A
mapping may be changed only by editing this table, regenerating labels and
re-running; each mapping revision is stamped in the report.

### CICIDS2017

| Dataset label | Mapped category | Rationale |
|---|---|---|
| `PortScan` | `RECONNAISSANCE` | SYN-scan pattern is visible in flags/ports/IAT |
| `FTP-BruteForce` / `SSH-Bruteforce` | `RECONNAISSANCE` | auth-abuse shows as repeated short flows to one port |
| `DoS slowloris`, `DoS GoldenEye`, `DoS Hulk`, `DoS slowhttptest`, `DoS SYN` | `VOLUMETRIC_ANOMALY` | rate/size/IAT signatures |
| `Bot` | `C2_BEACONING` | periodic low-rate C2-ish conversations |
| `Infiltration` | `DATA_EXFILTRATION_SUSPECTED` | *weak* — mostly internal-lateral, timing-only evidence |
| `Web Attack …` | `METADATA_INVISIBLE` | payload-level (HTTP request content) |
| `Heartbleed` | `METADATA_INVISIBLE` | payload-level exploit evidence |
| `FTPS Patator` | `METADATA_INVISIBLE` | encrypted content; only the TLS handshake is visible |
| `Email Bounce` / Benign | (benign) | FPR reference when labeled benign |

### CTU-13 (botnet scenarios)

| Dataset label | Mapped category | Rationale |
|---|---|---|
| botnet / cyclic / narad / infected host flows | `C2_BEACONING` | the dataset *is* a C2-beaconing benchmark |
| normal | (benign) | FPR reference |
| background | *excluded* | unlabeled background — never counted benign or attack |

### ISCX VPN-nonVPN 2016

| Dataset label | Mapped category | Rationale |
|---|---|---|
| `VPN` traffic types | `UNUSUAL_ENDPOINT_BEHAVIOR` | *operational* — only when the monitored baseline excludes the VPN endpoints; the app label itself is not an attack |
| non-VPN app traffic | (benign) | FPR reference for encrypted-app behaviour |

### MAWI

| Dataset label | Mapped category | Rationale |
|---|---|---|
| (no attack labels) | (benign) | FPR reference only — backbone traffic, not a monitored endpoint network |

## 5. Join rules (flow ↔ label)

1. **Endpoint-pair match, both directions.** A flow's `(src_ip, dst_ip)`
   matches a label row when it equals `(src_ip, dst_ip)` or `(dst_ip, src_ip)`.
   Port constraints apply per column; `*` matches anything.
2. **Time-window match.** The flow's `start_ts` must fall in
   `[t_start − W, t_end + W]` (default `W = 10 s`).
3. **Detection = anomaly flow.** A *hit* is an anomalous flow (the model's
   verdict) that joins to a label row of its mapped category. Recall counts
   label rows (or benign windows) that received at least one hit; precision
   counts anomalous flows that joined *some* attack label.
4. **`METADATA_INVISIBLE` joins are counted and reported, never scored.**
   They appear as `invisible_joined` in the report.
5. **Multiple labels, one flow:** the flow is assigned the label with the
   smallest time distance; ties break on mapped-category order
   (`THREAT_TYPES` order, then `METADATA_INVISIBLE`).

## 6. Metrics

Computed per mapped category (`per_category`) and overall (`overall`):

| Metric | Definition |
|---|---|
| `precision` | TP / (TP + FP) — anomalous flows joined to an attack label of that category ÷ all anomalous flows |
| `recall` | TP / (TP + FN) — label rows of that category with ≥1 anomalous-flow hit ÷ all label rows of that category |
| `f1` | harmonic mean of precision and recall |
| `anomaly_auc` | ROC-AUC of the *continuous* anomaly score against the category-vs-benign binary label (null when one class is absent) |
| `benign_fpr` | anomalous flows joined to a benign window ÷ flows in benign windows (null when no benign labels, per honesty rule 2) |
| `support` | label rows of that category |
| `hits` / `misses` | label rows with / without a hit |

Plus run-level figures:

- **Parser coverage** — fraction of flows in the PCAP that yielded usable
  metadata (TLS/QUIC handshake parsed, or valid TCP/UDP flow record). Truncated
  captures (MAWI truncates payloads) can drop this; the report must show it so
  metrics computed over a parseable subset are not mistaken for full-traffic
  results.
- **Flow counts** — total flows, anomalous flows, flows joined to labels,
  flows joined to nothing (unlabeled).
- **`invisible_joined`** — anomalous flows joined only to
  `METADATA_INVISIBLE` labels (counted, never scored).

## 7. Report schema (`eval_report.json`, version 1)

```json
{
  "report_version": 1,
  "created_at": "...",
  "dataset": {"name": "...", "artifact": "...", "sha256": "..."},
  "model": {"path": "...", "sha256": "...", "trained_flows": 0,
             "feature_schema_version": 1},
  "params": {"idle_timeout": 30.0, "join_tolerance_s": 10.0,
              "contamination": 0.02},
  "flows": {"total": 0, "anomalous": 0, "joined": 0, "unlabeled": 0},
  "parser_coverage": {"parseable": 0, "total": 0, "ratio": 0.0},
  "per_category": {"RECONNAISSANCE": {"tp": 0, "fp": 0, "fn": 0,
                    "precision": 0.0, "recall": 0.0, "f1": 0.0,
                    "anomaly_auc": 0.0, "benign_fpr": null,
                    "support": 0, "hits": 0, "misses": 0}},
  "overall": {"precision": 0.0, "recall": 0.0, "f1": 0.0,
               "anomaly_auc": 0.0, "benign_fpr": null},
  "invisible_joined": 0,
  "caveats": ["..."]
}
```

`spectra eval compare a.json b.json` diffs two reports (per-category deltas)
— used for model-candidate comparisons via the registry.

## 8. Datasets

See `docs/datasets.md` for the artifact registry, checksums and fetch
instructions. Quick map of what this phase evaluates:

| Dataset | Purpose |
|---|---|
| CICIDS2017 (Mon benign + Fri attacks) | primary precision/recall benchmark |
| CTU-13 (2 botnet scenarios) | `C2_BEACONING` recall on a purpose-built benchmark |
| ISCX VPN-nonVPN 2016 (subset) | encrypted-app / VPN behaviour (FPR + `UNUSUAL_ENDPOINT_BEHAVIOR`) |
| MAWI (one daily trace) | real-world benign FPR + parser coverage under truncation |
| synthetic (`spectra demo`) | CI-safe harness self-test, no external data |

## 9. Limitations of this evaluation

- The label join is **endpoint-pair + time-window** — it cannot distinguish
  two concurrent flows between the same hosts beyond the time tie-break.
- Datasets label at their own granularity (host-level, day-level); Spectra's
  idle-timeout flow segmentation will not reproduce dataset flow definitions,
  so recall is measured at *label-row* level, not at per-flow identity.
- One run per report: no repeated-trial confidence intervals (the model is
  deterministic given artifact + inputs).
- CICIDS2017's synthetic benign background (B-Profile) is unlike production
  traffic; FPR on it does not transfer — MAWI is included precisely to give a
  second, real-traffic FPR reference.
