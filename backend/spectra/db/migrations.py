"""Versioned schema migrations: idempotent, atomic, never destructive.

Every schema change lands here (nothing else may ``CREATE``/``ALTER`` tables).
The runner records applied versions in ``schema_migrations`` and executes each
pending migration inside its own transaction, so a failure rolls back and the
next start retries from the last applied version.

**Existing user databases.** Databases created before this module existed have
the tables of migration 1 but no bookkeeping row; running the full list against
them is safe: migration 1 is all ``IF NOT EXISTS`` (it adopts the legacy schema
instead of replacing it) and migration 2 copies rows into the rebuilt table and
verifies the row count before dropping anything. Data survives; only the
``flows`` table shape evolves (adds the capture foreign key).

Normalized-entity review (what this layer stores today, and what it does not):

===============  =========================================================
entity           decision
===============  =========================================================
captures         table (existing) - sessions, retention + stale sweep; v4
                  adds managed-resource columns (original/stored name,
                  size, source type, import time, content hash, status)
flows            table (existing) - rebuilt with FK, row-capped + aged
detections       not a table: flagged flows are rows with ``anomaly=1`` in
                 ``flows``; duplicating them would double storage and the
                 read paths (``query_flows(anomaly_only=True)``) already
                 project them. Retention ages them independently.
events           table (new) - system feed (status/alert/drift/model);
                 ``flow``/``detection`` events are already durable as flow
                 rows and are skipped by the publisher
model runs       table (existing) - training lineage
audit entries    table (existing) - hash-chained, exempt from retention
users/sessions   tables (v5) - local authentication: scrypt password hashes,
                 three RBAC roles, session rows keyed by a SHA-256 *hash* of
                 the bearer token (the raw token exists only in the client's
                 HttpOnly cookie) with an absolute expiry
incidents        table (v6) - analyst triage workflow (OPEN -> ACKNOWLEDGED
                 -> RESOLVED), optionally referencing the flagged flow that
                 raised it
analyst notes    table (v6) - author-attributed comments on an incident
models           deferred: artifacts are joblib files + ``model_runs``
                 lineage; a registry belongs with baseline concern C7
settings         deferred: configuration is env-driven (``SPECTRA_*``); a
                 settings table needs a settings API nobody consumes yet
alerts           no separate table: durable alert history = ``events`` rows
                 of alert types plus hash-chained audit entries; a managed
                 alerts table becomes useful with ack/silence workflows
===============  =========================================================
"""

from __future__ import annotations

import sqlite3
import time
from dataclasses import dataclass
from typing import Callable

from .connection import Database, StoreError

#: Exact column list of ``flows`` (used by the rebuild copy and tests).
FLOW_COLUMNS = (
    "id, capture_id, ts, proto, src, dst, duration, packets, bytes, "
    "tls_version, sni, alpn, ja3, ja4, score, anomaly, reasons, record"
)

# Indexes recreated after the flows table rebuild (the four the pre-migration
# schema shipped, plus the composite that makes detection retention cheap).
_FLOW_INDEXES: tuple[str, ...] = (
    "CREATE INDEX IF NOT EXISTS idx_flows_ts ON flows(ts)",
    "CREATE INDEX IF NOT EXISTS idx_flows_anomaly ON flows(anomaly, score)",
    "CREATE INDEX IF NOT EXISTS idx_flows_sni ON flows(sni)",
    "CREATE INDEX IF NOT EXISTS idx_flows_capture ON flows(capture_id)",
    # retention: DELETE flagged rows older than N scans (anomaly, ts)
    "CREATE INDEX IF NOT EXISTS idx_flows_anomaly_ts ON flows(anomaly, ts)",
)

_BASELINE: tuple[str, ...] = (
    """CREATE TABLE IF NOT EXISTS captures (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        mode        TEXT NOT NULL,
        source      TEXT,
        started_at  REAL NOT NULL,
        stopped_at  REAL,
        packets     INTEGER DEFAULT 0,
        flows       INTEGER DEFAULT 0,
        detections  INTEGER DEFAULT 0,
        error       TEXT
    )""",
    """CREATE TABLE IF NOT EXISTS flows (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        capture_id  INTEGER,
        ts          REAL NOT NULL,
        proto       TEXT,
        src         TEXT,
        dst         TEXT,
        duration    REAL,
        packets     INTEGER,
        bytes       INTEGER,
        tls_version TEXT,
        sni         TEXT,
        alpn        TEXT,
        ja3         TEXT,
        ja4         TEXT,
        score       REAL,
        anomaly     INTEGER DEFAULT 0,
        reasons     TEXT,
        record      TEXT NOT NULL
    )""",
    "CREATE INDEX IF NOT EXISTS idx_flows_ts ON flows(ts)",
    "CREATE INDEX IF NOT EXISTS idx_flows_anomaly ON flows(anomaly, score)",
    "CREATE INDEX IF NOT EXISTS idx_flows_sni ON flows(sni)",
    "CREATE INDEX IF NOT EXISTS idx_flows_capture ON flows(capture_id)",
    """CREATE TABLE IF NOT EXISTS model_runs (
        id            INTEGER PRIMARY KEY AUTOINCREMENT,
        trained_at    REAL NOT NULL,
        pcap          TEXT,
        n_train       INTEGER,
        contamination REAL,
        metrics       TEXT
    )""",
    """CREATE TABLE IF NOT EXISTS audit_log (
        seq        INTEGER PRIMARY KEY,
        ts         REAL NOT NULL,
        kind       TEXT NOT NULL,
        actor      TEXT,
        payload    TEXT NOT NULL,
        leaves     TEXT,
        prev_hash  TEXT NOT NULL,
        entry_hash TEXT NOT NULL
    )""",
    "CREATE INDEX IF NOT EXISTS idx_audit_kind ON audit_log(kind, seq)",
)


@dataclass(frozen=True)
class Migration:
    """One schema step: version number, name and the work it does."""

    version: int
    name: str
    run: Callable[[Database], None]


def _baseline(db: Database) -> None:
    """v1: the schema the pre-migration release shipped (adopts legacy DBs)."""
    for stmt in _BASELINE:
        db.execute(stmt)


def _flows_capture_foreign_key(db: Database) -> None:
    """v2: rebuild ``flows`` with ``capture_id -> captures(id) ON DELETE SET NULL``.

    SQLite cannot add a constraint in place, so the table is copied, verified,
    then swapped - inside the migration transaction, with FK enforcement
    disabled by the runner. History rows are never dropped: references to
    captures that no longer exist are nulled instead.
    """
    db.execute(
        "UPDATE flows SET capture_id = NULL "
        "WHERE capture_id IS NOT NULL "
        "AND capture_id NOT IN (SELECT id FROM captures)"
    )
    db.execute(
        """CREATE TABLE flows_migrated (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            capture_id  INTEGER REFERENCES captures(id) ON DELETE SET NULL,
            ts          REAL NOT NULL,
            proto       TEXT,
            src         TEXT,
            dst         TEXT,
            duration    REAL,
            packets     INTEGER,
            bytes       INTEGER,
            tls_version TEXT,
            sni         TEXT,
            alpn        TEXT,
            ja3         TEXT,
            ja4         TEXT,
            score       REAL,
            anomaly     INTEGER DEFAULT 0,
            reasons     TEXT,
            record      TEXT NOT NULL
        )"""
    )
    db.execute(
        f"INSERT INTO flows_migrated ({FLOW_COLUMNS}) "
        f"SELECT {FLOW_COLUMNS} FROM flows"
    )
    before = int(db.execute("SELECT COUNT(*) FROM flows").fetchone()[0])
    after = int(db.execute("SELECT COUNT(*) FROM flows_migrated").fetchone()[0])
    if before != after:
        raise StoreError(f"flow rebuild would lose rows ({before} -> {after})")
    db.execute("DROP TABLE flows")   # takes the old indexes with it
    db.execute("ALTER TABLE flows_migrated RENAME TO flows")
    for stmt in _FLOW_INDEXES:
        db.execute(stmt)


def _events_and_retention_indexes(db: Database) -> None:
    """v3: system-event feed plus the indexes retention and queries lean on."""
    db.execute(
        """CREATE TABLE IF NOT EXISTS events (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            ts         REAL NOT NULL,
            type       TEXT NOT NULL,
            capture_id INTEGER REFERENCES captures(id) ON DELETE SET NULL,
            payload    TEXT NOT NULL
        )"""
    )
    db.execute("CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts)")
    db.execute(
        "CREATE INDEX IF NOT EXISTS idx_events_type ON events(type, ts)"
    )
    db.execute(
        "CREATE INDEX IF NOT EXISTS idx_captures_started ON captures(started_at)"
    )


def _capture_resources(db: Database) -> None:
    """v4: managed capture resources - upload metadata + status lifecycle.

    Adds (never rewrites) the columns the managed workflow persists per
    capture: original and stored filename, size, source type, import time,
    content hash and a lifecycle ``status``. SQLite adds columns in place, so
    existing rows keep their ids and data; they are then backfilled from what
    the old schema recorded - finished sessions become ``COMPLETED``, ones
    that ended in an error become ``FAILED``, still-open ones (a crashed
    process, before the stale sweep closes them) become ``PROCESSING``. Their
    provenance becomes ``source_type``: ``live`` sessions and pre-management
    path-driven ones (``path``); managed uploads are always created as
    ``upload`` from then on.
    """
    existing = {r["name"] for r in db.query("PRAGMA table_info(captures)")}
    columns = (
        # Default 'PROCESSING': a row with no explicit status is an open
        # session (legacy writers / raw inserts), which the stale sweep can
        # close; managed uploads always insert 'UPLOADED' explicitly.
        ("status", "TEXT NOT NULL DEFAULT 'PROCESSING'"),
        ("original_name", "TEXT"),
        ("stored_name", "TEXT"),
        ("size_bytes", "INTEGER NOT NULL DEFAULT 0"),
        ("source_type", "TEXT NOT NULL DEFAULT 'path'"),
        ("imported_at", "REAL"),
        ("content_hash", "TEXT"),
    )
    for name, decl in columns:
        if name not in existing:
            db.execute(f"ALTER TABLE captures ADD COLUMN {name} {decl}")
    db.execute(
        """UPDATE captures SET
               status = CASE WHEN error IS NOT NULL THEN 'FAILED'
                             WHEN stopped_at IS NOT NULL THEN 'COMPLETED'
                             ELSE 'PROCESSING' END,
               source_type = CASE WHEN mode = 'live' THEN 'live' ELSE 'path' END
           WHERE imported_at IS NULL"""
    )
    db.execute(
        "CREATE INDEX IF NOT EXISTS idx_captures_status ON captures(status, id)"
    )


def _auth_users_sessions(db: Database) -> None:
    """v5: local authentication - users + expiring sessions.

    ``users`` stores only scrypt encodings (see :mod:`spectra.auth.passwords`)
    under a case-insensitive unique username; ``sessions`` stores a SHA-256
    hash of the bearer token, never the token itself, so a stolen database
    cannot be replayed as a login. Deleting a user cascades to their sessions.
    """
    db.execute(
        """CREATE TABLE IF NOT EXISTS users (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            username      TEXT NOT NULL COLLATE NOCASE UNIQUE,
            password_hash TEXT NOT NULL,
            role          TEXT NOT NULL
                          CHECK (role IN ('ADMIN','ANALYST','VIEWER')),
            created_at    REAL NOT NULL,
            updated_at    REAL NOT NULL,
            last_login_at REAL
        )"""
    )
    db.execute(
        """CREATE TABLE IF NOT EXISTS sessions (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id      INTEGER NOT NULL REFERENCES users(id)
                         ON DELETE CASCADE,
            token_hash   TEXT NOT NULL UNIQUE,
            created_at   REAL NOT NULL,
            expires_at   REAL NOT NULL,
            last_seen_at REAL NOT NULL
        )"""
    )
    db.execute("CREATE INDEX IF NOT EXISTS idx_sessions_user "
               "ON sessions(user_id)")
    db.execute("CREATE INDEX IF NOT EXISTS idx_sessions_expires "
               "ON sessions(expires_at)")


def _incidents_and_notes(db: Database) -> None:
    """v6: incident triage + analyst notes (the ANALYST workflow).

    An incident optionally points at the flagged flow that raised it; flow
    history is pruned by retention, so the reference is ``ON DELETE SET
    NULL`` - losing the detection never deletes the triage record. Notes
    cascade with their incident and record the authoring user.
    """
    db.execute(
        """CREATE TABLE IF NOT EXISTS incidents (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            title           TEXT NOT NULL,
            detection_id    INTEGER REFERENCES flows(id) ON DELETE SET NULL,
            status          TEXT NOT NULL DEFAULT 'OPEN'
                            CHECK (status IN ('OPEN','ACKNOWLEDGED','RESOLVED')),
            created_by      TEXT NOT NULL,
            created_at      REAL NOT NULL,
            acknowledged_by TEXT,
            acknowledged_at REAL,
            resolved_by     TEXT,
            resolved_at     REAL
        )"""
    )
    db.execute(
        """CREATE TABLE IF NOT EXISTS incident_notes (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            incident_id INTEGER NOT NULL REFERENCES incidents(id)
                         ON DELETE CASCADE,
            author      TEXT NOT NULL,
            body        TEXT NOT NULL,
            created_at  REAL NOT NULL
        )"""
    )
    db.execute("CREATE INDEX IF NOT EXISTS idx_incidents_status "
               "ON incidents(status, id)")
    db.execute("CREATE INDEX IF NOT EXISTS idx_incident_notes "
               "ON incident_notes(incident_id, id)")


MIGRATIONS: tuple[Migration, ...] = (
    Migration(1, "baseline_schema", _baseline),
    Migration(2, "flows_capture_foreign_key", _flows_capture_foreign_key),
    Migration(3, "events_and_retention_indexes", _events_and_retention_indexes),
    Migration(4, "capture_resources", _capture_resources),
    Migration(5, "auth_users_sessions", _auth_users_sessions),
    Migration(6, "incidents_and_notes", _incidents_and_notes),
)


def migrate(db: Database) -> list[str]:
    """Apply pending migrations; returns the names applied (empty = up to date)."""
    with db.lock:
        db.execute(
            "CREATE TABLE IF NOT EXISTS schema_migrations ("
            "version INTEGER PRIMARY KEY, "
            "name TEXT NOT NULL, "
            "applied_at REAL NOT NULL)"
        )
        applied = {int(r["version"])
                   for r in db.query("SELECT version FROM schema_migrations")}
        # Table drops/renames run with FK enforcement off; the pragma is a
        # no-op inside a transaction, so it must wrap the whole run.
        db.set_foreign_keys(False)
        done: list[str] = []
        try:
            for migration in MIGRATIONS:
                if migration.version in applied:
                    continue
                try:
                    with db.transaction():
                        migration.run(db)
                        db.execute(
                            "INSERT INTO schema_migrations "
                            "(version, name, applied_at) VALUES (?, ?, ?)",
                            (migration.version, migration.name, time.time()),
                        )
                except Exception as exc:  # noqa: BLE001 - any failure must roll back
                    raise StoreError(
                        f"migration {migration.version} ({migration.name}) "
                        f"failed: {exc}"
                    ) from exc
                done.append(migration.name)
        finally:
            db.set_foreign_keys(True)
        return done


def schema_version(db: Database) -> int:
    """Highest applied migration version (0 when the database is empty)."""
    rows = db.query(
        "SELECT COALESCE(MAX(version), 0) AS v FROM schema_migrations"
    )
    return int(rows[0]["v"])


def applied_migrations(db: Database) -> list[tuple[int, str]]:
    """``(version, name)`` for every applied migration, ascending."""
    rows = db.query(
        "SELECT version, name FROM schema_migrations ORDER BY version ASC"
    )
    return [(int(r["version"]), str(r["name"])) for r in rows]
