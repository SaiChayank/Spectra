# Operations runbook

Status of each procedure is stated per section: **Rehearsed** = executed on a private instance with the output kept under
`docs/evidence/`. Limits of each rehearsal are stated where they apply.

Paths: `~/.local/share/spectra/{data,models}` for an installed copy (override with `SPECTRA_DATA_DIR`, `SPECTRA_MODEL_PATH`).
Health: `GET /api/health`; metrics: `GET /api/metrics` (see `docs/monitoring.md`).

## Backup (rehearsed)

```bash
spectra backup create --out /safe/place/spectra-$(date +%F).tar.gz            # DB + models; online, safe while serving
spectra backup create --out ... --include-keys                                # also private keys: store like a secret
spectra backup verify /safe/place/spectra-2026-11-07.tar.gz                   # checks every member against the manifest
```

The default archive excludes private keys and uploaded captures. Choose per the table below.

| Archive | Restores | Costs |
|---|---|---|
| default | users, flows, detections, audit log, models | new audit signing-key epoch (old entries and checkpoints still verify); every TOTP user is locked out until `spectra auth totp-reset <user>` |
| `--include-keys` | everything above, with the same keys | the archive is a credential - encrypt it at rest, restrict access |
| `--include-captures` | adds uploaded pcaps | size; pcaps hold metadata only but are still sensitive |

## Restore (rehearsed)

1. Stop Spectra (`restore` refuses to run over a live database).
2. `spectra backup verify <archive>`; then `spectra backup restore <archive>` (add `--force` when a database already exists - the
   old files are **moved aside** to a `pre-restore-*` directory, never deleted).
3. Start Spectra. The first start records a `backup.restore` entry in the audit chain.
4. Check: sign in, `GET /api/audit/verify` returns ok, `GET /api/model` shows the model.
5. Without keys in the archive: reset TOTP for each enrolled user (`spectra auth totp-reset <user>`).

Evidence: `docs/evidence/2026-11-07/phase11/restore-drill.txt` / `.json` (28 checks, wheel in a clean Python 3.13 venv).
Measured at demo scale on one machine (13 flows): backup 0.8 s, restore 0.25 s, restore + start to healthy 5.3-5.8 s; data written
after the last backup (13 flows) was lost, as designed - **RPO equals your backup interval**. These numbers say nothing about
production volume; re-run `scripts/restore_drill.py` with representative data before quoting an RTO.

## Lost keys / TOTP reset (rehearsed in the drill)

* `totp.key` lost: all enrolled users fail the second factor. Stop the server, `spectra auth totp-reset <user>` per user, start,
  users re-enroll.
* Audit signing key lost: restore creates a new key epoch automatically; history stays verifiable from the public keys stored in
  the database. Nothing to do beyond noting the epoch change.

## Failure scenarios (rehearsed 2026-11-07)

`scripts/runbook_drill.py` (19 checks, clean Python 3.13 venv, output in `docs/evidence/2026-11-07/phase11/runbook-drill.txt`)
and a size-limited container (`disk-full-drill.txt`). What an operator actually sees:

* **Capture failure** - a truncated upload ends `FAILED` with "the file ends inside a record"; the server stays healthy. Fix:
  re-upload an intact file (verified).
* **Database locked** - while another process holds the write lock, writes wait the 5 s busy timeout and then return **HTTP 500**
  (not 503); reads and `/api/health` keep working; once the lock is released writes succeed with no restart. Look for a second
  `spectra serve` or a CLI/backup job holding a transaction. SQLite is WAL, so a `-wal` file is normal - never delete it.
* **Disk full** - login (it writes a session row) returns **HTTP 500**, and `/api/health` still says 200, so a plain health
  check will not notice. Free space (or grow the volume); recovery needed no restart. Watch free space on the data volume
  yourself; retention (`docs/retention.md`) bounds growth.
* **Model artifact corrupt** - the server starts, but the damaged model is **not** loaded and there is **no fallback to an
  older model** (the registry is authoritative). `GET /api/model` shows `trained: false`, `spectra_model_trained` is 0 (alert
  `SpectraModelUntrained`). Captures processed in that state still complete with 0 detections, but the capture resource now reports
  `unscored_flows` and a `warnings` entry, and the UI shows an "unscored" badge (added after the drill; covered by
  `tests/test_unscored_captures.py`, not re-run in the drill); alert on the gauge as well. Fix: retrain from a baseline capture (verified), or restore a backup.
* **Login storm** - after 10 bad attempts the pair gets HTTP 429 with `Retry-After` (observed 60 s); metrics stay behind auth.
  A restart clears throttle state.
* **Upgrade / rollback** - back up with keys; stop; install the new wheel; start (migrations run at start); check
  `/api/audit/verify`. Rollback: stop, `spectra backup restore <pre-upgrade archive> --force` (the replaced files are moved to
  a `pre-restore-<time>` directory). Rehearsed only as a same-version reinstall: no real version change or migration was
  exercised.

## Container (rehearsed once, 2026-11-07)

```bash
scripts/build_release.sh && docker compose up -d api      # http://127.0.0.1:${SPECTRA_PORT:-8000}, data in volume spectra-data
docker compose exec api cat /data/admin_bootstrap.txt     # first-run admin password (mode 0600, never logged)
```

Image: `python:3.13-slim` pinned by digest, non-root uid 10001, read-only root filesystem, all capabilities dropped,
`no-new-privileges`, healthcheck on `/api/health`, dependencies constrained to `backend/requirements.lock`, pip/setuptools removed.
Observed: container reaches `healthy`, `/api/health` and `/` return 200, writing outside `/data` and `/tmp` fails.
Trivy 0.58.1 (`--severity HIGH,CRITICAL --ignore-unfixed`): 0 findings -> `docs/evidence/2026-11-07/phase11/trivy-image.txt`
(the first build had 5 HIGH, all from pip's vendored msgpack/urllib3/setuptools; removing pip fixed them).
The optional `capture` profile (`docker compose --profile capture up -d capture`, own volume, port `SPECTRA_CAPTURE_PORT`) was run:
it reaches `healthy`, runs read-only, and can open an `AF_PACKET` raw socket. It has to run as root with only `NET_RAW` and
`DAC_OVERRIDE` (a non-root user gets `NET_RAW` in the bounding set but not the effective set - the first version of this
profile would have failed to capture; found by checking `CapEff`). **Packets were not captured from a real interface** in
that run. Not covered: image signing, a Kubernetes manifest, trivy secret/misconfig scanners, scapy's GPL-2.0-only
licence in the image (open decision for the owner).
