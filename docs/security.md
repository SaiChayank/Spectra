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

**Login throttling with escalating backoff** (`LoginThrottle`, checked
*before* any scrypt work): 10 failures / 60 s per *(ip, username)* or 40 / 60 s
per ip start a block of 60 s answered `429` + `Retry-After`; every repeat
episode **doubles** the block (60, 120, 240, ... capped at 900 s). Properties,
each covered by `test_login_backoff.py`:

* **No permanent lockout.** Blocks expire; strikes are forgotten after 1 h of
  quiet or a successful login; the state is memory-only, so a restart clears
  it. That restart is the recovery path for a locked-out single-host admin.
* **No lockout of the real admin from elsewhere.** Keys are *(ip, username)*
  and *ip*, never the username alone, so an attacker guessing `admin` from one
  address cannot block `admin` logging in from another.
* **No account enumeration.** The decision depends on the source and the
  *attempted* name only; real and non-existent usernames get identical
  statuses, bodies and `Retry-After` values. Blocked attempts are not counted
  again (a block cannot be extended by hammering it).
* **Bounded memory** under key spraying (10 000 keys per table).
* **Known limit - reverse proxies:** the key is the TCP peer address. Behind a
  proxy every client shares the proxy's address, so one guesser can block them
  all for up to the cap. Trusting `X-Forwarded-For` is a separate setting that
  is deliberately not enabled; configure the proxy's own rate limiting too.

**Optional second factor (TOTP, RFC 6238).** Any signed-in user can enrol an
authenticator app for their own account; it is off unless they do (Phase 10 §6,
**awaiting your security review before merge**). Flow, all through the API:
`POST /api/auth/totp/setup` (password re-entry; returns the secret and an
`otpauth://` URI once) → `POST /api/auth/totp/enable` (a first valid code;
returns 8 single-use recovery codes once) → from then on `POST /api/auth/login`
takes `totp_code` **in the same request**. Properties (`test_totp.py`, 24 tests,
mutation-checked):

* **No oracle.** An account with a factor answers a missing or wrong code with
  the same generic `401` as a wrong password, and counts it against the login
  throttle, so a response never says the password was right or that a factor
  exists. Brute-forcing a 6-digit code is bounded by the escalating throttle.
* **Single-use codes.** The newest accepted time step is recorded
  (`last_counter`) with an atomic compare-and-set, so a code cannot be replayed
  - including by two simultaneous requests. Clock skew of one step is accepted.
* **Secrets encrypted at rest.** The shared secret must be recoverable, so it
  is AES-256-GCM encrypted under a 32-byte key in `totp.key` (mode 0600, next to
  the database, never inside it), bound to the account id. A stolen database
  alone reveals no secret; a stolen database **plus** the key file does. The key
  is created when the first secret is encrypted and is never silently re-created.
* **Recovery codes** are random, single-use, stored only as SHA-256 hashes.
* **Setup/disable need the password** (and disable a valid code), so a stolen
  session cannot enrol its own authenticator or strip the owner's.
* **Lost device or lost `totp.key`:** an ADMIN can `DELETE /api/users/{id}/totp`;
  on the host `spectra auth totp-reset USERNAME` does the same without the
  second factor. Both are audit-chained (`auth.totp_reset`). Without the key
  file the affected users cannot log in until reset - back it up with the
  database (`docs/34_ship_plan.md` §11).
* **Not built:** an enrolment screen (API only today), enforcing the factor for
  all admins, WebAuthn, and the plan's wording "stored as scrypt'd secret"
  (impossible for a recoverable secret - see `HANDOFF_FINDINGS.md`).

See [limitations.md §7](./limitations.md).

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
9. **At rest, uploads are verbatim.** The managed store keeps the uploaded
   file byte-for-byte, so if the capture contains payload (ciphertext, or
   plaintext for unencrypted protocols) those bytes sit in
   `captures/cap_<uuid>.pcap`. No route returns them and Spectra's own derived
   data (database, audit log, API responses, logs) carries none -
   `tests/test_metadata_only_probe.py` checks exactly that and pins this single
   exception. Protect `SPECTRA_DATA_DIR` like the evidence it is (directory
   permissions, disk encryption, retention via `SPECTRA_CAPTURE_RETENTION_DAYS`
   - which now removes the stored file together with a finished capture's row;
   an upload that is never processed is exempt, see `docs/retention.md`);
   deleting a capture removes the file. Stripping payload on ingest is an open
   design option (HANDOFF_FINDINGS.md, Phase 10).

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

### 6.1 Signing-key epochs and the provider seam (Phase 9F)

The hash chain itself is unkeyed (sha256); the signing key signs
**checkpoints** and **compliance certificates**. Keys now have epochs:

* **Rotation:** `POST /api/audit/rotate-key` (ADMIN, `config:manage`) swaps the
  key, records the new *public* key in `audit_key_epochs` (migration v12) and
  appends an `audit.key_rotated` entry whose `seq` is the new epoch's
  `start_seq`. The old secret is overwritten (the file provider keeps no key
  history), so a rotated-out key can no longer sign.
* **Validity window:** a checkpoint names its epoch inside the signed message
  and is valid only if (1) that epoch's key signed it and (2) its covered
  range ends in `[start_seq(e), start_seq(e+1))`. Therefore a stolen *current*
  key cannot forge checkpoints over entries that predate it, and a stolen
  *old* key cannot sign anything after the rotation. `verify()` also checks
  every epoch after the first is backed by a matching `audit.key_rotated`
  entry. Checkpoints written before 9F carry no epoch and verify as epoch 1.
* **What rotation does NOT give you:** a key stolen *before* it was rotated can
  still forge checkpoints for its own epoch's range, and the chain is unkeyed,
  so anyone who can rewrite the database and recompute every hash can rewrite
  history; only checkpoints exported/anchored outside the host close that
  gap. Certificates are checked against the epoch window at their signed
  `chain_head.seq`.
* **Key replaced outside `rotate_key`** (lost key file, crash between the
  swap and the registration): the next start registers the new key as an epoch
  and chains an `audit.key_rotated` entry saying so - it is never silent.
* **KMS/HSM contract:** implement `spectra.modules.audit.keys.AuditKeyProvider`
  - `public_key()` (compressed secp256k1 point, hex), `sign(msg)`
  (`schnorr_sign`-format signature by the current key; the secret never leaves
  the provider) and `rotate()` (switch to a new key, return its public key) -
  and pass it as `AuditLog(store, provider=...)`. No cloud dependency ships
  in v1; `FileKeyProvider` (mode-0600 file, atomic replace) is the only
  provider. The Schnorr/secp256k1 code is Spectra's own implementation
  (`modules/audit/curve.py`) and has not had an independent cryptographic
  review.
* **Upgrade / rollback:** v12 only adds a table. Roll back by restoring the
  pre-upgrade database backup; older code ignores the table.

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
| `SPECTRA_PROFILE` | `local` | `hardened` turns retention on with the proposed defaults ([retention.md](./retention.md)) |
| `SPECTRA_TOTP_KEY_PATH` | `<data dir>/totp.key` | key file that encrypts enrolled TOTP secrets (back it up with the database) |
| `SPECTRA_TOTP_ISSUER` | `Spectra` | label shown in authenticator apps |
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
| `SPECTRA_PAIR_WINDOW_FLOWS` | `32` | flow starts kept per (source, SNI-or-IP) pair for beacon-cadence scoring (9D) |
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
