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
incidents        table (v6, rebuilt v8) - analyst triage workflow (OPEN ->
                  INVESTIGATING -> ACKNOWLEDGED -> RESOLVED / FALSE_POSITIVE),
                  optionally referencing the flagged flow that raised it; v8
                  adds the rollup columns (severity, confidence, first/last
                  seen, affected entities, alert count, primary threat class,
                  related graph nodes, model versions, evidence summary)
analyst notes    table (v6) - author-attributed comments on an incident
incident links   table (v8) - the IncidentAlert relation: which alerts belong
                  to which incident, with attribution + correlation reason
incident events  table (v8) - incident timeline: creations, alert joins,
                  state changes and notes in order (auditable history)
alerts           table (v7) - analyst alerts from the threat classifier:
                 severity/evidence/lifecycle grouped per behaviour, next to
                 (never instead of) the raw detection; the flow row carries
                 the reverse link ``alert_id`` and ``flow_id`` is
                 ON DELETE SET NULL so retention never eats an alert
investigation    indexes (v9) - flow endpoints + TLS fingerprints + score,
                 alert endpoints + severity, incident severity, audit ts:
                 the investigation bundle, global search and the history
                 filter routes stay index-backed as the tables grow
models           table (v10) - the model registry: one row per artifact
                 (joblib files in ``<data_dir>/model_artifacts``, sha256
                 recorded here) with the CANDIDATE/VALIDATED/ACTIVE/
                 RETIRED/FAILED lifecycle, a partial unique index enforcing
                 a single ACTIVE, and ``last_activated_at`` as the rollback
                 cursor; ``model_runs`` stays the training-lineage feed
settings         deferred: configuration is env-driven (``SPECTRA_*``); a
                 settings table needs a settings API nobody consumes yet
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


def _alerts(db: Database) -> None:
    """v7: analyst alerts - correlated, persisted verdicts over detections.

    An alert is the analyst-facing object produced by the threat classifier
    (severity, evidence, lifecycle); the raw detection stays a flagged flow
    row.  ``flow_id`` points at the source detection *when its durable id is
    known* (batched flow writes may leave it NULL — the flow row carries the
    reverse link ``alert_id`` in its record JSON either way), and retention
    pruning the flow must never eat the alert, hence ``ON DELETE SET NULL``.
    Evidence, severity derivation, related metadata and module annotations
    are read-mostly JSON documents, not queryable columns.
    """
    db.execute(
        """CREATE TABLE IF NOT EXISTS alerts (
            alert_id         TEXT PRIMARY KEY,
            flow_id          INTEGER REFERENCES flows(id) ON DELETE SET NULL,
            capture_id       INTEGER,
            timestamp        REAL NOT NULL,
            first_seen       REAL NOT NULL,
            last_seen        REAL NOT NULL,
            updated_at       REAL NOT NULL,
            source           TEXT NOT NULL,
            destination      TEXT NOT NULL,
            protocol         TEXT NOT NULL,
            threat_type      TEXT NOT NULL,
            anomaly_score    REAL,
            confidence       REAL NOT NULL,
            severity         TEXT NOT NULL
                             CHECK (severity IN ('LOW','MEDIUM','HIGH','CRITICAL')),
            model_id         TEXT,
            model_version    TEXT,
            evidence         TEXT NOT NULL,
            severity_factors TEXT NOT NULL,
            metadata         TEXT NOT NULL,
            module_annotations TEXT NOT NULL,
            status           TEXT NOT NULL DEFAULT 'OPEN'
                             CHECK (status IN ('OPEN','ACKNOWLEDGED','RESOLVED')),
            occurrences      INTEGER NOT NULL DEFAULT 1
        )"""
    )
    db.execute("CREATE INDEX IF NOT EXISTS idx_alerts_last_seen "
               "ON alerts(last_seen)")
    db.execute("CREATE INDEX IF NOT EXISTS idx_alerts_status "
               "ON alerts(status, last_seen)")
    db.execute("CREATE INDEX IF NOT EXISTS idx_alerts_threat "
               "ON alerts(threat_type, last_seen)")


def _incident_alert_layer(db: Database) -> None:
    """v8: the incident layer above alerts (correlation, timeline, rollups).

    Rebuilds ``incidents`` because SQLite cannot ``ALTER`` a CHECK constraint
    into admitting ``INVESTIGATING``/``FALSE_POSITIVE``, and adds the rollup
    columns the correlation layer maintains next to the rows.  Rows copy
    across unchanged (existing triage history survives); ``incident_notes``
    keeps resolving by table name after the rename - foreign keys are off for
    the whole run, so the drop/rename window is safe.  The membership table
    enforces single ownership of an alert (``UNIQUE(alert_id)``): one alert
    belongs to at most one incident, which is what keeps correlation
    conservative.  The timeline table gives every incident an ordered,
    actor-attributed history independent of the global audit log.
    """
    db.execute(
        """CREATE TABLE incidents_v8 (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            title           TEXT NOT NULL,
            detection_id    INTEGER REFERENCES flows(id) ON DELETE SET NULL,
            status          TEXT NOT NULL DEFAULT 'OPEN'
                            CHECK (status IN ('OPEN','INVESTIGATING',
                                   'ACKNOWLEDGED','RESOLVED','FALSE_POSITIVE')),
            created_by      TEXT NOT NULL,
            created_at      REAL NOT NULL,
            acknowledged_by TEXT,
            acknowledged_at REAL,
            resolved_by     TEXT,
            resolved_at     REAL,
            updated_by      TEXT,
            updated_at      REAL,
            summary         TEXT,
            severity        TEXT CHECK (severity IN ('LOW','MEDIUM',
                                       'HIGH','CRITICAL')),
            confidence      REAL,
            first_seen      REAL,
            last_seen       REAL,
            affected_entities TEXT NOT NULL DEFAULT '[]',
            alert_count     INTEGER NOT NULL DEFAULT 0,
            primary_threat_class TEXT,
            related_graph_nodes  TEXT NOT NULL DEFAULT '[]',
            model_versions       TEXT NOT NULL DEFAULT '[]',
            evidence_summary     TEXT
        )"""
    )
    db.execute(
        """INSERT INTO incidents_v8
           (id, title, detection_id, status, created_by, created_at,
            acknowledged_by, acknowledged_at, resolved_by, resolved_at)
           SELECT id, title, detection_id, status, created_by, created_at,
                  acknowledged_by, acknowledged_at, resolved_by, resolved_at
           FROM incidents"""
    )
    db.execute("DROP TABLE incidents")
    db.execute("ALTER TABLE incidents_v8 RENAME TO incidents")
    db.execute("CREATE INDEX IF NOT EXISTS idx_incidents_status "
               "ON incidents(status, id)")
    db.execute(
        """CREATE TABLE IF NOT EXISTS incident_alerts (
            incident_id INTEGER NOT NULL REFERENCES incidents(id)
                         ON DELETE CASCADE,
            alert_id    TEXT NOT NULL REFERENCES alerts(alert_id)
                         ON DELETE CASCADE,
            added_at    REAL NOT NULL,
            added_by    TEXT NOT NULL,
            source      TEXT NOT NULL
                        CHECK (source IN ('manual','auto','correlate')),
            reason      TEXT NOT NULL DEFAULT '',
            score       REAL,
            PRIMARY KEY (incident_id, alert_id)
        )"""
    )
    # An alert belongs to exactly one incident (single ownership).
    db.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_incident_alerts_alert "
               "ON incident_alerts(alert_id)")
    db.execute("CREATE INDEX IF NOT EXISTS idx_incident_alerts_incident "
               "ON incident_alerts(incident_id, added_at)")
    db.execute(
        """CREATE TABLE IF NOT EXISTS incident_events (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            incident_id INTEGER NOT NULL REFERENCES incidents(id)
                         ON DELETE CASCADE,
            ts          REAL NOT NULL,
            kind        TEXT NOT NULL,
            actor       TEXT NOT NULL,
            data        TEXT NOT NULL DEFAULT '{}'
        )"""
    )
    db.execute("CREATE INDEX IF NOT EXISTS idx_incident_events "
               "ON incident_events(incident_id, id)")


def _investigation_indexes(db: Database) -> None:
    """v9: index set for the investigation surface (bundle, search, filters).

    Every column the SOC routes filter or match on gets an index: flow
    endpoints and TLS fingerprints (related-flow lookup in the bundle and
    the global search), flow score + alert endpoints/severity/incident
    severity (the history filter set) and ``audit_log.ts`` (time-range
    pages).  ``IF NOT EXISTS`` keeps the step safe to re-run; the batched
    flow writer absorbs the extra index entries per row easily.
    """
    for stmt in (
        "CREATE INDEX IF NOT EXISTS idx_flows_src ON flows(src)",
        "CREATE INDEX IF NOT EXISTS idx_flows_dst ON flows(dst)",
        "CREATE INDEX IF NOT EXISTS idx_flows_ja3 ON flows(ja3)",
        "CREATE INDEX IF NOT EXISTS idx_flows_ja4 ON flows(ja4)",
        "CREATE INDEX IF NOT EXISTS idx_flows_score ON flows(score)",
        "CREATE INDEX IF NOT EXISTS idx_alerts_source ON alerts(source)",
        "CREATE INDEX IF NOT EXISTS idx_alerts_destination "
        "ON alerts(destination)",
        "CREATE INDEX IF NOT EXISTS idx_alerts_severity "
        "ON alerts(severity, last_seen)",
        "CREATE INDEX IF NOT EXISTS idx_incidents_severity "
        "ON incidents(severity, id)",
        "CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_log(ts)",
    ):
        db.execute(stmt)


def _model_registry(db: Database) -> None:
    """v10: model registry - artifact lineage + the single-active invariant.

    One row per trained/adopted model artifact (Prompt 14).  ``status`` walks
    CANDIDATE -> VALIDATED -> ACTIVE -> RETIRED (plus FAILED from the
    validation gate); the partial unique index below is the database-level
    half of "exactly one ACTIVE", the ``BEGIN IMMEDIATE`` promote/retire pair
    in :mod:`spectra.db.repositories` the other half.  ``last_activated_at``
    is the rollback cursor: the previous active model is the RETIRED row with
    the greatest value below the current one's.

    JSON columns (``metrics``) are parsed by the repository on read; the
    artifact bytes live in ``<data_dir>/model_artifacts/`` (joblib files,
    immutable), never in the database - this row records name + sha256.
    """
    db.execute(
        """CREATE TABLE IF NOT EXISTS model_registry (
            id                INTEGER PRIMARY KEY AUTOINCREMENT,
            model_id          TEXT NOT NULL UNIQUE,
            created_at        REAL NOT NULL,
            source            TEXT,
            artifact          TEXT NOT NULL,
            artifact_sha256   TEXT NOT NULL,
            status            TEXT NOT NULL DEFAULT 'CANDIDATE',
            trained_at        REAL,
            n_train           INTEGER,
            contamination     REAL,
            n_features        INTEGER,
            feature_schema    TEXT,
            model_version     TEXT,
            threshold         REAL,
            metrics           TEXT,
            error             TEXT,
            activated_count   INTEGER NOT NULL DEFAULT 0,
            last_activated_at REAL,
            retired_at        REAL
        )"""
    )
    db.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_models_single_active "
        "ON model_registry(status) WHERE status = 'ACTIVE'"
    )
    db.execute(
        "CREATE INDEX IF NOT EXISTS idx_models_status "
        "ON model_registry(status, created_at)"
    )


def _lookup_indexes(db: Database) -> None:
    """v11: indexes for the two lookup columns that still had none.

    ``audit_log.actor`` drives the actor-filtered audit page (equality
    predicate combined with the ``seq`` sort - same shape as
    ``idx_audit_kind``), and ``captures.content_hash`` is the
    duplicate-import gate (:meth:`~spectra.db.repositories.`
    ``CaptureRepository.by_hash`` runs one equality per upload, so a table
    scan there grows with every import).  ``IF NOT EXISTS`` keeps the step
    safe to re-run against an existing database.
    """
    for stmt in (
        "CREATE INDEX IF NOT EXISTS idx_audit_actor ON audit_log(actor, seq)",
        "CREATE INDEX IF NOT EXISTS idx_captures_hash "
        "ON captures(content_hash)",
    ):
        db.execute(stmt)


MIGRATIONS: tuple[Migration, ...] = (
    Migration(1, "baseline_schema", _baseline),
    Migration(2, "flows_capture_foreign_key", _flows_capture_foreign_key),
    Migration(3, "events_and_retention_indexes", _events_and_retention_indexes),
    Migration(4, "capture_resources", _capture_resources),
    Migration(5, "auth_users_sessions", _auth_users_sessions),
    Migration(6, "incidents_and_notes", _incidents_and_notes),
    Migration(7, "alerts", _alerts),
    Migration(8, "incident_alert_layer", _incident_alert_layer),
    Migration(9, "investigation_indexes", _investigation_indexes),
    Migration(10, "model_registry", _model_registry),
    Migration(11, "lookup_indexes", _lookup_indexes),
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
