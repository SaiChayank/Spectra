# Spectra — Limitations

Explicit, verified, and deliberate. Nothing here is hidden behind a green
checkmark: each item states what is limited, why, and what the operational
consequence is. Items marked **by design** are privacy/scope boundaries, not
defects.

---

## 1. No payload decryption — metadata-only analysis (by design)

Spectra parses **flow statistics and TLS/QUIC handshake structure only**
(SNI, ALPN, versions, cipher suites, extensions, JA3/JA4, timing). Payload
bytes are consumed solely to advance framing, then discarded; QUIC 0-RTT and
Handshake packets are counted, never opened; no application key material is
ever derived.

*Consequence:* content-level threats (malware signatures, DNS names inside a
tunnel, file contents, body keywords) are **architecturally invisible**.
Detection rests on *how* traffic behaves, not *what* it says. Capture is also
strictly passive/read-only — Spectra never transmits packets.

## 2. Anomaly detection limitations

* **Unsupervised.** IsolationForest is fitted on benign data only. There are no
  labels, therefore **no precision/recall, no ROC, no calibrated false-positive
  rate**. "0.2 % of baseline flows are anomalous" is what `contamination`
  asserts, not a measured production FPR.
* **The score is a percentile, not a probability.** Score 99 means "more
  deviant than 99 % of training flows", not "99 % likely malicious".
* **Threshold ≠ calibration.** `SPECTRA_CONTAMINATION` moves the decision
  boundary; it does not control alert precision in production.
* **Drift degrades scores silently until measured.** PSI monitoring
  (`GET /api/model/drift`) flags `<0.10` stable /
  `0.10–0.25` moderate / `>0.25` significant — above that, scores are no
  longer calibrated and the answer is retrain.
* **Minimum data:** < 10 completed flows cannot train at all; tiny baselines
  (the 42-flow demo) give a coarse percentile scale.
* **Adversarial robustness is measured, not guaranteed** — evasion succeeds to
  a degree (`spectra adversarial`, `/api/model/robustness`). Module 3 watches
  and reports; it does not eliminate evasion.
* **One model per deployment.** There is no cross-tenant or per-sector model
  zoo; a single ACTIVE artifact serves the whole process.

## 3. Classification & alerting limitations

* **Rules are heuristics over metadata.** A category
  (`C2_BEACONING`, `DATA_EXFILTRATION_SUSPECTED`, …) is a weighted-signal
  verdict needing ≥ 2 independent signals; insufficient evidence yields
  `UNKNOWN_ANOMALY` with confidence capped at 0.45 — deliberate, but it means
  real attacks can land in "unknown".
* **Classifier and detector are not independent evidence.** Classification
  runs only on flows the detector already flagged, and one rule
  (`extreme_score`) reads the detector score itself — score and category must
  not be double-counted as two proofs.
* **Confidence is clamped** to [0.30, 0.95]; nothing can ever be "certain".
* **Severity is ordinal and local.** It has no threat-intel enrichment, no
  asset inventory beyond port/sensitivity heuristics, no CVE correlation.
* **Alert grouping is time+key based** (same threat/endpoint pair within
  600 s); a slow, patient beacon spread across many endpoint pairs produces
  several alerts rather than one.
* **Incidents never auto-create.** Correlation only attaches existing alerts —
  an analyst must create or correlate an incident (conservative by design).
* **No automated response.** There is no blocking, quarantine, or SOAR action;
  triage ends with acknowledge/resolve/notes.

## 4. Simulated TEE and federated aggregation

The confidential-computing module is **SIMULATED**: an in-process enclave with
local key material, quotes that carry `environment: "SIMULATED"`, and
verification that *reports* that fact. There is no SGX/SEV/TrustZone hardware,
no remote attestation service, and no hardware-backed claim anywhere
(`hardware_backed_count: 0`).

Federated aggregation performs **real** additive secret-sharing math over
**locally simulated parties** — it demonstrates the protocol, not a
cross-organisation deployment. Consequence: attestation receipts are useful as
an integrity *mechanism* demonstration, not as evidence to an auditor that code
ran inside an enclave.

## 5. Baseline and data assumptions

* **The baseline must match the network being monitored.** Trained on the
  bundled synthetic demo baseline, ordinary real traffic scores ≈ 97.6
  (measured: 472 real flows flagged); a matching 70 s real baseline flagged
  4/112 (3.6 %). Always retrain on a benign capture of *your* network.
* Baselines are assumed **benign**; poisoning the baseline is not defended
  against (training is ADMIN-only and audited, but there is no robust training).
* History is bounded by **row caps** (flows 200 k, events 50 k, alerts 50 k),
  so what exists is *newest-kept* — old rows are pruned, not archived.
* Legacy capture rows created before the managed-resource model (and finished
  live sessions) have no stored file: they report `source_type: "path"` and are
  refused for re-processing instead of being re-imported.
* **Age-based retention is off by default** (`0` = keep), including for
  detections; only row caps bound growth. `audit_log` is never pruned — its
  chain requires the full sequence, so audit growth depends on
  archive/checkpoint practice.

## 6. Edge, digital twin, bio and audit modules

| Module | Class | Limitation |
|---|---|---|
| Edge slicing / MEC micro-detector | LOCAL | Real scoring, but single-process: no real gNB, no MEC host, no QoS control plane. The 10 ms budget is a measured compute budget, not a network guarantee. |
| Edge deployment / NTN registry | SIMULATED | In-process records marked `capability: SIMULATED`; no remote agent, no satellite/UAV link. |
| Digital twin | SIMULATED | Deterministic replay over the **observed flow topology only** — no invented infrastructure, no live-network coupling, no traffic replay. Blast-radius numbers are scenario arithmetic, not forecasts. |
| Bio-inspired detection | EXPERIMENTAL | Danger/SNN/swarm heuristics produce annotations only; an untrained bio system is skipped entirely. Never a verdict, never a score change. |
| Audit chain / ZKP | EXPERIMENTAL | Pure-Python research-grade cryptography. Proves tamper-evidence of *this* log; it is **not** a compliance certification, and the proof system is not constant-time or peer-reviewed. |

## 7. Operational limitations

1. **Login throttling is per-process and in-memory** (10/60 s per
   *(ip, username)*, 40/60 s per ip): it resets on restart, is not shared
   across processes, and covers **login only**. Other endpoints rely on RBAC,
   bounded pagination and the 4 MiB body limit.
2. **No idle-session timeout.** Sessions expire after an absolute 12 h; a
   revoked session's open WebSocket keeps streaming for up to the 30 s
   revalidation interval before it is closed with `4401`.
3. **`serve` ignores `SPECTRA_API_HOST`/`SPECTRA_API_PORT`** — only the
   `--host`/`--port` flags take effect.
4. **Text/JSON search predicates are not index-covered** (`LIKE` over stored
   JSON); cost is bounded by anchors, page limits and row caps rather than by
   an index.
5. **Live capture needs Npcap on Windows.** Without the driver those
   acceptance checks are skipped, not passed; live capture is unavailable.
6. **Single process, no HA.** Killing the process stops capture (bounded drain
   via `shutdown_timeout`); SQLite is one writer; there is no failover,
   replication, or horizontal scale — intentionally (local modular monolith).
7. **No TLS in-process.** Loopback binding is the transport security; front it
   with a TLS proxy and set `SPECTRA_SESSION_COOKIE_SECURE=true` before any
   non-local exposure.
8. **Prompt 15 remains deferred** by the standing rules of this phase.

## 8. Measurement caveats

Desktop performance figures move **±30 %** on sub-millisecond rows depending on
background load; API timings are in-process (route + auth + store, no network);
the scan baseline in the acceptance report includes CLI startup. Absolute
numbers will differ on other hardware — causal comparisons use interleaved A/B
pairs ([testing.md §3](./testing.md)).

## 9. Frontend

* **No automated frontend tests** (no unit runner, no e2e); verification is
  `tsc` + `vite build` + the acceptance runner against the live API.
* `vite build` warns that the single JS chunk exceeds 500 kB (744 kB /
  211 kB gzip, recharts included) — a build warning, not a functional defect.
* Served by the Vite dev server on `:5173`; the backend does not host
  `frontend/dist` (no deployment infrastructure in scope).
* Live updates combine 3-second polling with the WebSocket stream; a section
  therefore shows data at most a few seconds stale if the socket drops.
