# Spectra — Static Application Security Testing (SAST) report

**Date:** 2026-11-06 · **Commit:** `24221c9` · **Evidence:** `docs/evidence/2026-11-06/` (raw tool output, never edited). Every number below comes from those files. This is engineering evidence, not a sign-off — approvals are the owner's.

## 1. What was run

| Tool | Version | Command | Result |
|---|---|---|---|
| Semgrep (custom rule) | 1.184.0 | `semgrep --metrics=off --test security/semgrep` | rule tests pass (8 must-flag fixtures incl. a payload passed as an argument, 5 must-not-flag fixtures) — `semgrep-custom-rule.txt` |
| Semgrep (custom rule, real tree) | 1.184.0 | `semgrep --metrics=off --config security/semgrep/spectra-payload.yml --error --exclude backend/spectra/parse --exclude backend/spectra/demo.py backend/spectra` | **0 findings**, 124 files |
| Semgrep (rule *blocks* a violation) | 1.184.0 | same command after appending `bytes(pkt["TCP"].payload)` to `features/extractor.py`, then reverted | **1 finding, exit 1**; tree clean after revert — `semgrep-violating-patch-blocked.txt` |
| Semgrep registry packs | 1.184.0 | `--config p/python --config p/owasp-top-ten` over `backend/spectra backend/scripts` | **4 findings** (all triaged false positives, §3) — `semgrep-registry.json` |
| Bandit | 1.9.4 | `bandit -r backend/spectra backend/scripts -f json` (26 943 LOC, 134 files) | **0 High, 34 Medium, 23 Low** (all triaged, §4) — `bandit.json` |
| gitleaks | — | — | **NOT RUN locally**: no binary on this machine; running it needs a download that has not been approved. CI already runs `gitleaks/gitleaks-action` on every push/PR (full history) — its result is the evidence, and has not been collected here. |
| pip-audit | 2.10.1 | see `docs/sca-report.md` | |

## 2. The custom rule (project rule: payload only in `parse/`)

`security/semgrep/spectra-payload.yml` (`spectra-payload-access-outside-parser`) flags scapy payload access — `pkt[TCP|UDP|IP|IPv6].payload`, the `Raw` layer (`pkt[Raw]`, `getlayer/haslayer(Raw)`), `raw(pkt)` and the bare `.load` attribute — anywhere under `backend/spectra` except `parse/` (the only module allowed to read above the transport header) and `demo.py` (it *builds* synthetic packets). It is deliberately scapy-specific: `p.payload` on Spectra's own packet record is an integer length and must not trip it, and `joblib.load(...)` is a method call, not an attribute read; both are pinned as must-not-flag fixtures.

It is a gate in CI (`sast` job), tested by `semgrep --test` on annotated fixtures, and the "deliberately payload-touching patch" requirement was demonstrated on a real module and reverted (above). **Limit:** it is syntactic. It does not follow payload bytes once copied into another variable, and it cannot see code that reads payload through a different library. The runtime counterpart is `tests/test_metadata_only_probe.py` (see `docs/dast-report.md`).

## 3. Semgrep registry findings — 4, all false positives, no code change

`python-logger-credential-disclosure` at `services/auth.py` lines 267, 322, 325, 457. Each logger call contains the *word* "password" in its message text; the logged arguments are only a username, a file path or a count (checked by reading the calls and `_write_bootstrap_file`). No credential value reaches a log. Not suppressed with `nosemgrep` — project rule §5 says disabling a gate needs a logged, approved exception — so the registry packs run as a **reported, non-gating** CI step and these four stay visible here. One earlier finding was fixed in code instead of waived: `insecure-hash-algorithm-md5` at `parse/tls.py` (JA3 *is* MD5 by definition; the call now says `usedforsecurity=False`).

## 4. Bandit — 57 findings, 0 High

* **B608 SQL string building — 27 Medium.** Reviewed one by one: every interpolated fragment is a literal clause, a whitelisted column tuple (`TRANSITION_EXTRA`, `AGGREGATE_COLUMNS`, the fixed `model_registry` column list) or a placeholder list; all values are bound parameters; `_endpoint_where(column, …)` takes only literal column names. Pinned by `tests/test_sql_hostile_input.py` (injection strings through every string filter; tables, audit chain and credentials untouched). **Accepted as false positives.**
* **B310 `urlopen` — 6 Medium**, all in operator scripts (`acceptance.py` → loopback constant, `fetch_datasets.py` → fixed catalogue URLs). Not part of the service. **Accepted.**
* **B305 weak cipher mode — 1 Medium**, `parse/quic.py::_ecb_encrypt`: AES-ECB over exactly one 16-byte block is how RFC 9001 §5.4.3 derives the QUIC header-protection mask. **Accepted (spec-mandated).**
* **Low (23):** B110/B112 `except … pass/continue` ×9 — deliberate best-effort paths (telemetry, caches), each commented; B311 `random` ×6 — synthetic demo traffic and the *simulated* federated sharing (seeded, reproducible; documented as not a CSPRNG in `modules/tee/federated.py` and `docs/limitations.md` — this must change if federation ever leaves SIMULATED); B105 ×4 — dictionary keys such as `"pass"` and an empty string; B404/B603 ×4 — subprocess with fixed argv in two scripts. Two `assert` uses (B101) in `db/repositories.py` were converted to explicit `StoreError`s.

## 5. What changed because of this work

`parse/tls.py` JA3 `usedforsecurity=False`; two `assert` → explicit errors; new CI `sast` job (custom rule gating, Bandit High gating, registry packs and Bandit report as artifacts); tests `test_sql_hostile_input.py`, `test_metadata_only_probe.py`. CI gating thresholds: Bandit blocks on High only (the 34 triaged Mediums would otherwise block every PR); that is a **proposal** for the owner to accept.

## 6. Not covered

gitleaks run (see above); CodeQL (needs the repository to be public or Advanced Security); taint analysis; the frontend source (only `eslint`/`tsc`). Findings in third-party dependencies are in `docs/sca-report.md`.
