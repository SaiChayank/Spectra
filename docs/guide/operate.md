# Operating Spectra

This page only points to where each procedure lives. The [runbook](../runbook.md) is the source; it states for each
procedure whether it was rehearsed and what the rehearsal did not cover.

The runbook writes `spectra ...`; from a source checkout without the package installed, read that as
`python -m spectra.cli ...` run in `backend/`.

| Task | Where | Short version |
|---|---|---|
| Backup | [runbook](../runbook.md), "Backup" | `spectra backup create --out <file>.tar.gz` (safe while serving); `spectra backup verify <file>`. The default archive leaves out private keys and uploaded captures; `--include-keys` makes the archive a credential. |
| Restore | [runbook](../runbook.md), "Restore" | Stop Spectra, verify, `spectra backup restore <archive>` (`--force` moves old files aside, never deletes). Without keys in the archive, reset TOTP per user with `spectra auth totp-reset <user>`. Your recovery point equals your backup interval. |
| Upgrade and rollback | [runbook](../runbook.md), "Failure scenarios" | Back up with keys, stop, install the new wheel, start (migrations run at start), check `GET /api/audit/verify`. Only a same-version reinstall has been rehearsed; no real version change was. |
| Monitoring | [monitoring.md](../monitoring.md) | `GET /api/metrics` serves Prometheus text. An optional static `SPECTRA_METRICS_TOKEN` (32+ characters) lets a scraper in; it works only on that route. Example scrape config and rules are in `deploy/prometheus/`; they have not been scraped by a real Prometheus. |
| Retention | [retention.md](../retention.md) | Default profile `local` deletes nothing by age; row caps bound growth. `SPECTRA_PROFILE=hardened` turns on 30/90/14/30-day retention for flows, detections, captures and events. The audit log is never pruned. Retention runs when the store opens and after each capture, not on a timer. |
| Security and access | [security.md](../security.md) | Roles, sessions, managed captures, environment variable reference (section 7). |
| Reporting a vulnerability | [SECURITY.md](../../SECURITY.md) | GitHub private vulnerability reporting; do not open a public issue. |

## Health checks

`GET /api/health` is public and returns JSON. Besides `ok` it reports `writable.data_dir` and `writable.database`.

* Healthy: HTTP 200, `"ok":true` (see the real output in [first run](./first-run.md), step 2).
* **Database locked or busy:** writes that hit the 5 s busy timeout return HTTP **503** with `Retry-After` and the
  plain body `storage temporarily unavailable`. Reads keep working, `/api/health` stays 200 and reports
  `writable.database: "busy"`, and writes succeed again once the lock is released, with no restart. Look for a second
  `spectra serve` or a CLI or backup job holding a transaction. A `-wal` file next to the database is normal; never
  delete it.
* **Disk full:** failed writes return the same 503, and `/api/health` itself returns **503** with `ok: false` and
  `writable.data_dir` or `writable.database` set to `"failed"`. Free space or grow the volume; no restart needed.
* The locked and full-disk behaviour was changed after the drill and is covered by automated tests, not re-drilled
  ([runbook](../runbook.md)).
* The container healthcheck uses the same endpoint.

Watch free space on the data volume yourself. Spectra runs as one process with one SQLite writer and has no failover
([limitations](../limitations.md) section 7).
