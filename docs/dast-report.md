# Spectra — Dynamic testing (DAST) report

**Date:** 2026-11-06 · **Commit:** `24221c9` · **Evidence:** `docs/evidence/2026-11-06/schemathesis.txt`, `schemathesis-junit.xml`; `backend/tests/test_metadata_only_probe.py`. Engineering evidence, not a sign-off. All traffic went to a **throwaway instance on loopback that I started myself** (own data directory, own model path, generated admin password never printed) — nothing else was scanned.

## 1. Schemathesis (property-based API fuzzing)

`schemathesis 4.33.1 run http://127.0.0.1:8788/openapi.json -c all -n 25 --seed 1337 --workers 1` with the admin session; `POST /api/auth/logout` and `PATCH/DELETE /api/users/{id}` were excluded because they would end the run's own session or demote the admin. **93 of 97 operations tested, 3 432 generated cases, 35 s.**

* **Server errors (5xx): 0.** No crash, traceback or internal error was provoked by any generated input.
* 122 unique findings, none a vulnerability, in five contract-conformance classes:
  * ST103 *undocumented status code* (60) — handlers return 401/403/404/409 that the OpenAPI document does not list.
  * ST202 *schema-valid request rejected* (32) — business rules (unknown ids, "run a capture first") that the schema cannot express.
  * ST108 *response violates schema* (21) — several routes return free-form dicts that do not match their declared model.
  * ST205 *Allow header mismatch* (6).
  * ST201 *schema-violating request accepted* (3): `POST /api/edge/slice` (`level: false`), `POST /api/twin/evaluate` and `/recommend` (`monitoring: false`) accept a JSON boolean where a number/object is declared (Pydantic's lax coercion). Low severity, no security impact seen; fix by strict field types.
* One warning: `POST /api/auth/login` returned only 401 (the fuzzer sends random credentials — expected).

Triage verdict: **no Critical/High**. The contract findings are API-documentation and strictness work (tracked, not blocking). Schemathesis is not in CI (35 s here but it mutates state); it is a manual / nightly job for Phase 11.

## 2. Metadata-only runtime probe (docs/33 Phase 10 §2)

`tests/test_metadata_only_probe.py` builds a capture whose payload carries the marker `SPECTRA-PROBE-9d41c7e2b0a8` three ways (inside a TLS application-data record, in a plaintext HTTP request, in a UDP datagram), uploads and processes it, then:

* requests **every GET route** in the OpenAPI document (all 52 are probeable; path/query parameters filled from the run) and asserts the marker is absent from every response in raw, hex, HEX, URL-encoded and base64 (all alignments) form; a search for the marker returns nothing;
* asserts the marker is absent from the engine's in-memory flow/detection buffers;
* scans **every file under the data directory** and asserts the marker occurs in exactly one place.

It passes, and it is not vacuous: with a deliberate leak injected into the parser (payload hex added to the flow record) the probe fails on the API responses *and* on the at-rest scan; the leak was reverted.

**Finding (needs the owner):** the one place the marker exists is `captures/cap_<uuid>.pcap` — the managed capture store keeps uploaded files **verbatim**, payload bytes included. No route returns them and no code path writes payload anywhere else, but "never persist payload" is therefore true of Spectra's own derived data, not of the operator's uploaded evidence file. The test pins this exactly, so changing it (e.g. truncating each packet to headers and handshake on ingest, or documenting retention and permissions) forces a conscious update. Documented in `docs/security.md` §4.

## 3. Not run

* **OWASP ZAP baseline / API scan: NOT RUN.** It needs the ZAP Docker image (about 1–2 GB) or the Java distribution; no download has been approved.
* Authenticated-session abuse beyond the existing auth tests (fixation, concurrent-session limits), TLS configuration (the app serves plain HTTP on loopback by design; TLS termination is a deployment matter), and any scan of a non-local host.
