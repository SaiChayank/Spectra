# Spectra — Threat model (refreshed 2026-11-06)

Replaces the planning-era model that was removed with the old `docs/NN_*` set. Scope: the as-built service at commit `6508658` including the Phase 9 surfaces. Written from the code and the recorded test/scan evidence; it is an engineering document, not an assessment sign-off.

## 1. What is being protected

| Asset | Where | Why it matters |
|---|---|---|
| Uploaded capture files | `SPECTRA_DATA_DIR/captures/cap_*.pcap` (verbatim) | may contain payload bytes (ciphertext, or plaintext protocols) |
| Derived flow metadata, alerts, incidents | SQLite | behavioural record of a network |
| Audit chain + signing key | `audit_log`, `audit_key_epochs`, `audit_signing.key` | tamper evidence for what Spectra did |
| Model artifacts | `models/`, registry rows | what decides "anomalous" |
| Accounts, sessions | `users`, `sessions` (scrypt hashes, hashed session tokens) | access to all of the above |

## 2. Trust boundaries

* **TB-1 network → sensor.** Hostile packets are parsed (live or from files). The parser only reads framing and handshake structure, drops resync bytes, bounds record sizes and per-flow memory (flow table cap, packet metadata cap, lifetime cap). Payload is consumed to advance framing and discarded.
* **TB-2 client → API.** Local accounts, session cookies, RBAC (`READ`, `INVESTIGATE`, `INCIDENTS`, `CAPTURE_MANAGE`, `MODEL_MANAGE`, `CONFIG_MANAGE`, `USERS_MANAGE`); JSON bodies capped at 4 MiB; every list paginated; bound loopback by default. No TLS in-process: terminate TLS in front of it when exposed.
* **TB-3 upload → managed store.** Name/extension/magic/size validation, generated storage names, realpath containment; stored verbatim (see residual risk 1).
* **TB-4 operator host → data directory.** Key files are mode 0600; whoever can read the directory can read captures and the database.
* **TB-5 intel files → service.** Operator-maintained lists, validated and counted; a hit is evidence, never a verdict.
* **TB-6 federation participants → aggregator.** Simulated in-process (`SIMULATED`); the protocol shape (Shamir shares, commitments) is real, the isolation is not.

## 3. Phase 9 surfaces and their controls

| Surface | Threat | Control | Evidence |
|---|---|---|---|
| `window_s` on graph cascade/path (9A) | NaN/zero/huge values, expensive queries | 400 on ≤0/NaN; bounded depth; in-memory graph | `test_corr.py`, DAST run |
| `POST /api/model/harden` (9B) | CPU exhaustion; silent model swap | ADMIN only; single-flight (`409` when busy); report-only, never promotes; audit-chained `model.harden`/`model.shadow` | `test_harden.py`, acceptance `phase9` |
| `augment` on train (9C) | huge synthetic sets | `0..5000`; labelled synthetic in response, run history, audit | `test_augment.py` |
| pair-cadence state (9D) | unbounded memory from many host pairs | `PAIR_CAP` 10 000 pairs, newest `pair_window_flows` starts each; timestamps only | `test_corr.py` (cap, metadata-only) |
| rolling PSI reference (9E) | unbounded memory | sampled deque, `REF_MAX` 4 000 float vectors, cleared per session | `test_drift.py` |
| `POST /api/audit/rotate-key` (9F) | key theft → forged checkpoints; secret exposure | ADMIN (`config:manage`); secret never in responses/audit; epoch window binds a key to a seq range; old secret overwritten; chain-backed epochs | `test_audit_keys.py` (incl. forgery cases, mutation-checked) |
| `POST /api/auth/totp/*`, `totp_code` on login (Phase 10) | authenticator brute force; session-theft enrolment; secret theft; replay | password re-entry; throttle on wrong codes; atomic single-use counter; AES-GCM at rest with an off-database key; generic failures | `test_totp.py` (mutation-checked) |
| Shamir `threshold`/dropout on `POST /api/tee/federate` (9G) | tampered/misattributed shares; leaking shares | per-share SHA-256 commitments with secret nonces, consistency check, explicit errors below threshold/survivors; no shares, nonces or seed in responses | `test_federated_shamir.py` (independent vectors) |
| graph/twin `freshness` (9H) | stale topology trusted as current | `hydrated_at`/`flow_lag`/`stale` + UI badge | `test_twin_freshness.py` |
| JA4 parsing (fix) | fingerprint spoofing/evasion | evidence only, never a verdict | `test_ja4_spec.py` |

## 4. Assurance added in Phase 10

Custom Semgrep rule bars packet-payload reads outside `parse/` (gate in CI); a runtime probe asserts a marker in payload appears in no API response, memory buffer or database file; Schemathesis fuzzing produced no server error; dependency, licence and SQL-string reviews are in `docs/sast-report.md`, `docs/sca-report.md`, `docs/dast-report.md`.

## 5. Residual risks and open items

1. **Payload at rest in uploaded captures** (verbatim store). Owner decision: accept/document (done), sanitise on ingest, or make it opt-in.
2. **The hash chain is unkeyed.** Anyone able to rewrite the database *and* recompute every hash can rewrite history; only checkpoints exported off-host close this. Key epochs limit what a stolen key can forge, they do not prevent rewriting.
3. **Own-implemented cryptography** (secp256k1 Schnorr, Pedersen/ZK primitives, Shamir field arithmetic) has had no independent review. 9F awaits the owner's security review.
4. **Login hardening is new and unreviewed:** escalating throttle (per source, non-enumerating, 15-minute cap) and an optional TOTP second factor (`docs/security.md` §2). Residual: behind a reverse proxy all clients share one throttle key; TOTP is opt-in, has no enrolment screen, and its secrets are only as safe as the host protecting `totp.key`; both are awaiting the owner's review.
5. **GPL-2.0-only scapy** under an Apache-2.0 licence (owner decision pending).
6. **No in-process TLS**; deploy behind a TLS terminator and set `SPECTRA_SESSION_COOKIE_SECURE=true`.
7. **Federation randomness is seeded** (reproducible, not a CSPRNG) — acceptable only while the capability is `SIMULATED`.
8. Not yet tested: OWASP ZAP and real-traffic accuracy (Phase B). gitleaks over full history: 0 findings (2026-11-07, `docs/evidence/2026-11-07/`).
