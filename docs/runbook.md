# Operations runbook

Status of each procedure is stated per section: **Rehearsed** = executed end to end on a private instance with the output kept
under `docs/evidence/`; **Not yet rehearsed** = written from the code, never run as a drill - treat as a draft until it is.

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

## Not yet rehearsed (drafts)

* **Capture failure** (`spectra_ingest_*` counters stop moving / capture status FAILED): check the capture's error, whether it is
  truncated (the reader now reports truncated files rather than silently stopping), and disk space; re-upload.
* **Database locked**: stop extra writers (a second `spectra serve`, a CLI command run during heavy ingest); SQLite is WAL, so a
  `-wal` file next to the DB is normal. Never delete it by hand.
* **Disk full**: free space, then check `GET /api/health`; retention (`docs/retention.md`) bounds growth - confirm it is enabled.
* **Corrupt model**: the service falls back to the previous registered model; retrain from a baseline capture if none is left.
* **Session storm / login flood**: per-account back-off and the rate limits already apply; look at `spectra_auth_*` metrics before
  changing limits.
* **Upgrade**: back up with keys, install the new wheel, start (migrations run on start and are forward-only), verify health and the
  audit chain; roll back by reinstalling the old wheel and restoring the backup taken first.
