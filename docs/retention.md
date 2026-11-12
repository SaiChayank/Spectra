# Spectra — data retention and deployment profiles

**Status:** the mechanism is implemented and tested. The hardened numbers were **approved as proposed by the project owner in chat on 2026-11-07** (the owner's decision, recorded here by the agent at their instruction; no separate data-governance sign-off document exists). Nothing here changes behaviour unless you set `SPECTRA_PROFILE=hardened` or an explicit `SPECTRA_*_RETENTION_DAYS`.

## Profiles

| Profile | Set with | Retention | For |
|---|---|---|---|
| `local` (default) | nothing | **off** — nothing is deleted by age; growth is bounded only by the row caps (`SPECTRA_MAX_HISTORY_ROWS`, `SPECTRA_EVENT_MAX_ROWS`, alert cap) | a developer's machine, demos, evaluation runs |
| `hardened` | `SPECTRA_PROFILE=hardened` | **on**, using the approved defaults below | a shipped, monitored deployment |

An unknown profile name stops startup with an error. An explicit `SPECTRA_FLOW_RETENTION_DAYS`, `SPECTRA_DETECTION_RETENTION_DAYS`, `SPECTRA_CAPTURE_RETENTION_DAYS` or `SPECTRA_EVENT_RETENTION_DAYS` always wins over the profile, including `0` (retention off for that table).

## Hardened defaults (days) — approved 2026-11-07

| Setting | Days | Why |
|---|---|---|
| `SPECTRA_FLOW_RETENTION_DAYS` (non-flagged flow rows) | 30 | behavioural metadata about connections; 30 days covers most baselining and review windows |
| `SPECTRA_DETECTION_RETENTION_DAYS` (flagged rows) | 90 | investigation evidence outlives ordinary flows |
| `SPECTRA_CAPTURE_RETENTION_DAYS` (finished capture sessions **and their stored files**) | 14 | uploads are rewritten to metadata only by default (`docs/security.md` §4.9); with `SPECTRA_STORE_RAW_CAPTURES=1` they may hold payload bytes, so they are kept shortest |
| `SPECTRA_EVENT_RETENTION_DAYS` (system event feed) | 30 | operational noise |

**Never pruned by any profile:** the audit log and its key epochs (the hash chain needs the full sequence). Back it up instead; growth is bounded by archive practice (`docs/security.md` §6).

## How it runs

Retention runs when the store opens and after every capture finishes (there is no timer), in one transaction, together with the stale-session sweep (`SPECTRA_STALE_SESSION_HOURS`, default 24). A long-idle server therefore does not prune until its next capture or restart.

**Stored upload files follow their rows.** Fixed in this phase: previously retention deleted the capture *row* but left the verbatim PCAP on disk until the next process start, so a long-running server kept payload bytes past the configured age. Now the orphan sweep runs right after any retention run that removed capture rows (`test_retention_files.py`); files younger than an hour are never touched, so an import in flight is safe.

## Known limits

* **Uploaded-but-never-processed captures** (`UPLOADED`) age out under `SPECTRA_CAPTURE_RETENTION_DAYS` like finished captures (row and stored file), measured from upload time; live/`PROCESSING` sessions are never aged. Changed after the drill; covered by `test_retention_files.py`. With retention off (the `local` profile) nothing expires.
* Flow and detection rows are aged by the flow's **own timestamp** against the current time, so the flows of a freshly imported old PCAP (say 2 months old) are removed by the next retention run under a 30-day flow retention.
* Backups are not pruned by retention: restore drills and snapshots (Phase 11) keep whatever they captured until you delete them.
* Row-level deletes do not scrub SQLite free pages; use full-disk encryption if deleted metadata must be unrecoverable.

## Operator checklist (shipping deployment)

1. Get the numbers approved by whoever owns data governance; edit them in `HARDENED_RETENTION_DAYS` (`backend/spectra/config.py`) or set the four environment variables explicitly.
2. Start with `SPECTRA_PROFILE=hardened`; confirm `GET /api/stats` row counts stop growing past the window.
3. Protect `SPECTRA_DATA_DIR` (permissions, disk encryption) — see `docs/security.md` §4.9 and the `totp.key` note in §2.
4. Keep audit/database backups under the same retention rules.
