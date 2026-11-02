# Spectra — Security

Local accounts, role-based access, guarded file handling, artifact integrity,
and a tamper-evident audit chain — plus the assumptions the deployment relies
on. Code: `backend/spectra/auth/`, `authz.py`, `api/security.py`,
`services/auth.py`, `capture/storage.py`, `services/model_registry.py`,
`modules/audit/`.

---

## 1. Threat model & local-only assumptions

| Assumption | Consequence |
|---|---|
| Binds **`127.0.0.1:8787`** by default; no `0.0.0.0` | The API is reachable only from the machine unless an operator explicitly rebinds it |
| **No TLS termination** in-process | Traffic is loopback-only; set `SPECTRA_SESSION_COOKIE_SECURE=true` if you front it with HTTPS |
| **CORS allowlist** — `http://localhost:5173,http://127.0.0.1:5173`, credentials on, no wildcard | Only the dev console can call the API from a browser; the same list gates the WebSocket Origin (`4403` otherwise) |
| **Local accounts only** | No OAuth/OIDC/LDAP; identity = the `users` table |
| **Read-only passive capture** | Spectra never transmits packets; there is no injection/rewrite path |
| **No payload decryption** | Features and alerts are metadata-only — a privacy boundary, not a missing feature |
| Single process, single user population | Rate limits are in-process; there is no per-tenant isolation to reason about |

## 2. Authentication

**Hashing** (`auth/passwords.py`):

* `hashlib.scrypt` with **n = 2¹⁶ (65 536), r = 8, p = 1**, 16-byte random
  salt, 32-byte key, 128 MiB max-memory cap.
* Self-describing encoding `scrypt$<n>$<r>$<p>$<salt>$<hash>`; parameters are
  re-read on verify, and `password_needs_rehash` **upgrades** older rows on the
  next successful login.
* Constant-time comparison (`hmac.compare_digest`); malformed rows fail closed.
* Policy (≥ 8, ≤ 1024 chars) is enforced only when a password is *set*,
  never at login, so a failed login reveals nothing.

**Enumeration resistance:** unknown usernames still burn a full scrypt verify
(`verify_dummy`), and every failure returns the same
`401 invalid username or password`.

**Sessions** (`services/auth.py`):

* 256-bit token; the server stores only its **SHA-256 hash**
  (`sessions.token_hash`), delivered as an **HttpOnly, SameSite=Lax** cookie
  (`spectra_session`) and also accepted as `Authorization: Bearer` or a
  WebSocket `?token=`.
* **Absolute TTL** `SPECTRA_SESSION_TTL_MINUTES` (default 720 = 12 h);
  expired rows are deleted on access and purged opportunistically.
* Logout deletes the row by hash; changing a password revokes **all** of that
  user's sessions; deleting a user cascades their sessions. Role changes take
  effect on the next request (role is re-read, not cached in the token).
* `/api/auth/*` responses carry `Cache-Control: no-store`.

**Login throttling** (`LoginThrottle`, checked *before* any scrypt work):
10 failures / 60 s per *(ip, username)*, 40 / 60 s per ip → `429` +
`Retry-After`. In-process and memory-only (resets on restart) — see
[limitations.md §7](./limitations.md).

**WebSocket:** handshake authenticated (cookie or `?token=`) before accept —
failure closes `4401`; Origin must be allowlisted else `4403`; the session is
**revalidated every 30 s** while streaming, so logout/expiry closes the socket
with `4401`.

**Log hygiene:** query strings are never logged (so `?token=` cannot leak),
credentials are redacted by the formatter, and `serve` disables uvicorn's
access log so no plain-text handler exists outside the redacting one.

**Bootstrap (first run only):** with an empty user table, one `ADMIN` is
created from `SPECTRA_ADMIN_PASSWORD` (policy-checked) or from a random
password written to `data/admin_bootstrap.txt` (mode 600) with a warning.
Later starts never reset or overwrite accounts. Setup details:
[local-setup §4.1](./local-setup.md).

## 3. Authorization (RBAC)

Permissions are data (`authz.py`); routes declare which they need; middleware
makes `/api/*` **default-deny** (public: `GET /api/health`,
`POST /api/auth/login`).

| Permission | VIEWER | ANALYST | ADMIN |
|---|:---:|:---:|:---:|
| `read` (status, flows, detections, history, captures, model reads) | ✅ | ✅ | ✅ |
| `investigate` (audit, graph, twin, TEE, investigations, search, drift/robustness) | — | ✅ | ✅ |
| `incidents:manage` (create/correlate/acknowledge/resolve/notes, alert triage) | — | — | ✅ |
| `capture:manage` (import/process/delete captures, live start/stop) | — | — | ✅ |
| `model:manage` (train, validate/activate/retire, rollback) | — | — | ✅ |
| `config:manage` (edge link/deploy) | — | — | ✅ |
| `users:manage` (user CRUD) | — | — | ✅ |

* Violations return `403` with the missing permission named; no session → `401`.
* The public surface is exactly `GET /api/health`, `POST /api/auth/login`, and
  FastAPI's own `/docs`, `/redoc`, `/openapi.json` (route *descriptions* — they
  return no data and every `/api/*` call from them still needs a session).
* Guards: you cannot delete your own account, and the **last ADMIN** cannot be
  deleted or demoted (`409`) — no self-lockout.
* Usernames: `^[A-Za-z0-9][A-Za-z0-9_.-]{2,31}$`.
* `test_auth.py` sweeps **every** registered route for default-deny behaviour
  and role expectations; the dashboard mirrors the same permissions (server
  enforces regardless).

## 4. Managed captures (file handling)

No route ever accepts a server filesystem path. `POST /api/captures` streams the
upload through (`capture/storage.py`):

1. **Filename** — basename only (backslashes normalised, `.`/`..` rejected),
   ≤ 255 chars, no control characters; the name is metadata, never a path.
2. **Extension** — `.pcap` / `.pcapng` only.
3. **Magic bytes** — must match a known pcap/pcapng/gzip signature.
4. **Size** — streamed in 64 KiB chunks under `SPECTRA_CAPTURE_MAX_BYTES`
   (256 MiB) → `413`; empty or < 24 bytes → `400`. The body limit for this
   route is `capture_max_bytes + 1 MiB`; every other JSON body is capped at
   **4 MiB** (`413`, counted even for chunked bodies).
5. **Storage** — written to a temp `.part`, then `os.replace`d to
   `cap_<uuid4><ext>` inside the store; sha256 computed while streaming.
6. **Containment** — reads re-derive `realpath` from the store root and refuse
   anything that escapes it (`400`), so traversal is impossible even if a row
   were tampered with.
7. **Dedup / delete** — identical content → `409` with the existing id;
   `DELETE` removes row + file and is refused while the capture is running.
8. **Read path** — every scapy read is clamped to the file's own size, so a
   crafted record length cannot trigger a multi-gigabyte allocation.

## 5. Model & sidecar artifact integrity

| Control | Where |
|---|---|
| `<artifact>.sha256` sidecar; mismatch ⇒ **do not load** (INFO-logged legacy load only when the sidecar is absent) | `ml/integrity.py` |
| Registry artifacts are immutable, one file per registration, path-contained to `<data_dir>/model_artifacts/` | `services/model_registry.py` |
| Every load re-runs containment + sha256 + `SpectraDetector.load` (version + class + **feature-schema digest**) | `trust_load()` |
| 8-check validation gate before `VALIDATED` (existence, digest, loads, trained, threshold, ≥ 10 rows, schema) | `validate()` |
| `model.train` / `model.activate` / `model.rollback` audit entries carry `model_sha256` and the actor | `services/training.py`, registry |
| Compliance certificate re-derives the artifact digest for the `model_lineage` claim | `modules/audit/certify.py` |
| TEE quote `model_measurement` = streamed SHA-256, re-measured on activation | `modules/tee/enclave.py` |

Sidecars for the bio and edge micro-detector artifacts follow the same rule: a
failed digest skips that subsystem rather than loading it.

## 6. Audit chain

* **Chain:** `entry_hash = sha256(canonical_json(seq, ts, kind, actor, payload,
  leaves, prev_hash))`, genesis = 64 zeros, sequence gap ⇒ verification
  failure. `test_audit.py` mutates rows and asserts detection.
* **Leaves:** processed flow records become Merkle leaves (≤ 5000/entry), so a
  capture's evidence set is provably included.
* **Checkpoints:** Merkle root over the entries since the previous checkpoint,
  Schnorr-signed (`audit_signing.key`, mode 600 next to the DB). Verification
  = range completeness + root + chain links + entry hashes + signature.
* **Scope:** `capture.start`, `capture.stop`, `model.*`, auth/user-management
  actions, incident/alert actions — with the acting user as `actor`.
* **Reads:** `/api/audit/*` requires `investigate` (ANALYST/ADMIN); the CLI
  (`spectra audit …`) runs locally.
* **Never pruned:** retention explicitly excludes `audit_log`, because the
  chain needs the full sequence.
* **Guarded appends:** an audit failure is counted and logged; capture and
  detection continue.

## 7. Environment variable reference

Booleans accept `1/true/yes/on`. Defaults are the safe local values.

| Variable | Default | Notes |
|---|---|---|
| `SPECTRA_DATA_DIR` | `backend/data` | DB, captures, artifacts, bootstrap key file |
| `SPECTRA_DB_PATH` | `<data_dir>/spectra.db` | |
| `SPECTRA_MODEL_PATH` | `backend/models/spectra_model.joblib` | deployed detector |
| `SPECTRA_CAPTURE_STORE_DIR` | `<data_dir>/captures` | |
| `SPECTRA_ADMIN_USERNAME` | `admin` | bootstrap account name |
| `SPECTRA_ADMIN_PASSWORD` | *(unset)* | unset ⇒ random, written to `data/admin_bootstrap.txt` (600) |
| `SPECTRA_SESSION_TTL_MINUTES` | `720` | absolute session lifetime |
| `SPECTRA_SESSION_COOKIE_SECURE` | `false` | set `true` behind TLS |
| `SPECTRA_CORS_ORIGINS` | `http://localhost:5173,http://127.0.0.1:5173` | comma-separated; also gates WS Origin |
| `SPECTRA_API_HOST` / `SPECTRA_API_PORT` | `127.0.0.1` / `8787` | **not read by `serve`** — use `--host`/`--port` |
| `SPECTRA_LOG_LEVEL` | `INFO` | structured JSON, redacting formatter |
| `SPECTRA_CAPTURE_MAX_BYTES` | `268435456` | upload cap (→ 413) |
| `SPECTRA_PACKET_QUEUE_SIZE` / `FLOW_QUEUE_SIZE` / `PUBLISH_QUEUE_SIZE` | `4096` / `1024` / `1024` | bounded stages |
| `SPECTRA_MAX_ACTIVE_FLOWS` / `FLOW_MAX_PACKETS` / `FLOW_MAX_LIFETIME` | `5000` / `512` / `900` | flow-table bounds |
| `SPECTRA_IDLE_TIMEOUT` / `BUCKET_SECONDS` / `TIMELINE_BUCKETS` | `30` / `5` / `120` | flow finalisation & timeline |
| `SPECTRA_FLOW_BUFFER` / `DETECTION_BUFFER` | `5000` / `2000` | ring buffers |
| `SPECTRA_PERSIST` | `true` | SQLite on/off |
| `SPECTRA_DB_BATCH_SIZE` / `DB_FLUSH_INTERVAL` | `256` / `1.0` | batched writes |
| `SPECTRA_MAX_HISTORY_ROWS` / `EVENT_MAX_ROWS` | `200000` / `50000` | row caps |
| `SPECTRA_FLOW_RETENTION_DAYS` / `DETECTION_RETENTION_DAYS` / `CAPTURE_RETENTION_DAYS` / `EVENT_RETENTION_DAYS` | `0` (off) | age policies |
| `SPECTRA_STALE_SESSION_HOURS` | `24` | crashed-session sweep |
| `SPECTRA_CONTAMINATION` | `0.02` | training threshold |
| `SPECTRA_ALERT_GROUP_SECONDS` / `INCIDENT_WINDOW_SECONDS` | `600` / `1800` | alert grouping / incident window |
| `SPECTRA_INVESTIGATION_FLOW_LIMIT` / `EVIDENCE_ROWS` / `SEARCH_SECTION_LIMIT` | `100` / `500` / `10` | response bounds |
| `SPECTRA_SHUTDOWN_TIMEOUT` | `10` | stage drain on stop |

## 8. Verified by

`test_hardening.py` (28 tests: body limits, login throttle, scrypt work factor,
WS origin/revalidation, 422/500 shaping, runtime budgets), `test_auth.py`
(login/session/RBAC/default-deny/WS), `test_capture_resources.py`
(traversal/limits/lifecycle), `test_integrity.py` + `test_module_contracts.py`
(capability honesty, federated privacy surface), `test_model_registry.py`
(lifecycle/gates), `test_audit.py` (chain tamper detection), and the 156-check
acceptance runner. See [testing.md](./testing.md).
