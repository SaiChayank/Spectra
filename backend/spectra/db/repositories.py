"""Repository classes: all SQL for one entity, no business logic.

Each repository owns the queries for a table and nothing else - no config, no
policy, no event fan-out. They read through :class:`Database` and write through
:class:`WriteBuffer` (flows/events, batched) or single autocommit statements
(captures, model runs, audit entries - low volume, and the audit chain needs
every entry durable the moment it is appended).

Business logic stays outside: services call the :mod:`spectra.store` facade,
which composes these repositories.
"""

from __future__ import annotations

import json
import time

from .batch import WriteBuffer
from .connection import Database, StoreError


def row_to_flow(row: dict) -> dict:
    """Hydrate one ``flows`` row: JSON columns back to objects."""
    out = json.loads(row["record"])
    out["score"] = row["score"]
    out["anomaly"] = bool(row["anomaly"])
    out["reasons"] = json.loads(row["reasons"]) if row["reasons"] else None
    out["id"] = row["id"]
    out["ts"] = row["ts"]
    return out


class FlowRepository:
    """Scored flow rows (detections are flagged rows), bounded by a row cap."""

    def __init__(self, db: Database, buffer: WriteBuffer, max_rows: int = 200_000):
        self._db = db
        self._buffer = buffer
        self.max_rows = max(1, int(max_rows))
        self._rows = self.count()
        buffer.on_flush(self._on_flush)

    # -- accounting -----------------------------------------------------------

    def count(self) -> int:
        return int(self._db.query("SELECT COUNT(*) AS n FROM flows")[0]["n"])

    def get(self, flow_id: int) -> dict | None:
        """One row by id (incident triage checks the flagged detection)."""
        rows = self._db.query("SELECT * FROM flows WHERE id = ?", (flow_id,))
        return row_to_flow(rows[0]) if rows else None

    @property
    def rows(self) -> int:
        """Locally tracked row count (refreshed by :meth:`resync`)."""
        return self._rows

    def resync(self) -> None:
        """Recount after retention deleted rows behind our back."""
        self._rows = self.count()

    def _on_flush(self, counts: dict[str, int]) -> None:
        n = counts.get("flows", 0)
        if n:
            self._rows += n
            self._prune()

    def _prune(self) -> None:
        """Row cap: drop the oldest rows beyond ``max_rows`` (bulk-history bound)."""
        overflow = self._rows - self.max_rows
        if overflow <= 0:
            return
        with self._db.transaction():
            self._db.conn.execute(
                """DELETE FROM flows WHERE id IN (
                       SELECT id FROM flows ORDER BY id ASC LIMIT ?)""",
                (overflow,),
            )
        self._rows = self.count()

    # -- writes -----------------------------------------------------------------

    def enqueue(self, record: dict, score: float | None, anomaly: bool,
                reasons: list[dict] | None = None,
                capture_id: int | None = None) -> int:
        """Stage one scored flow for a batched commit (no transaction here).

        Returns 0: the durable row id is only assigned at flush time, and no
        caller has ever used it (write throughput comes before last-rowids).
        """
        row = (
            capture_id,
            record.get("last_ts") or record.get("start_ts") or time.time(),
            record.get("proto"),
            record.get("src"),
            record.get("dst"),
            record.get("duration"),
            record.get("packets"),
            record.get("bytes"),
            record.get("tls_version"),
            record.get("sni"),
            json.dumps(record.get("alpn")) if record.get("alpn") else None,
            record.get("ja3"),
            record.get("ja4"),
            score,
            1 if anomaly else 0,
            json.dumps(reasons) if reasons else None,
            json.dumps(record),
        )
        self._buffer.add("flows", row)
        return 0

    # -- reads -------------------------------------------------------------------

    def query(self, limit: int = 100, offset: int = 0, anomaly_only: bool = False,
              since: float | None = None, until: float | None = None,
              sni: str | None = None) -> dict:
        self._buffer.flush_if_pending()   # read-your-writes
        where, params = [], []
        if anomaly_only:
            where.append("anomaly = 1")
        if since is not None:
            where.append("ts >= ?")
            params.append(since)
        if until is not None:
            where.append("ts <= ?")
            params.append(until)
        if sni:
            where.append("sni LIKE ?")
            params.append(f"%{sni}%")
        clause = f"WHERE {' AND '.join(where)}" if where else ""
        limit = min(max(1, limit), 1000)
        offset = max(0, offset)
        rows = self._db.query(
            f"SELECT * FROM flows {clause} ORDER BY id DESC LIMIT ? OFFSET ?",
            (*params, limit, offset),
        )
        total = int(self._db.query(
            f"SELECT COUNT(*) AS n FROM flows {clause}", params)[0]["n"])
        return {"count": total, "offset": offset,
                "items": [row_to_flow(r) for r in rows]}

    def stats(self) -> dict:
        self._buffer.flush_if_pending()
        row = self._db.query(
            """SELECT COUNT(*) AS flows,
                      COALESCE(SUM(anomaly), 0) AS detections,
                      AVG(score) AS avg_score,
                      MIN(ts) AS first_ts,
                      MAX(ts) AS last_ts
               FROM flows"""
        )[0]
        by_proto = self._db.query(
            "SELECT proto, COUNT(*) AS n FROM flows "
            "GROUP BY proto ORDER BY n DESC")
        by_sni = self._db.query(
            """SELECT sni, COUNT(*) AS n FROM flows
               WHERE sni IS NOT NULL AND sni != ''
               GROUP BY sni ORDER BY n DESC LIMIT 10""")
        return {
            "flows": int(row["flows"]),
            "detections": int(row["detections"]),
            "anomaly_rate": round(row["detections"] / row["flows"], 4)
            if row["flows"] else 0.0,
            "avg_score": round(row["avg_score"], 2)
            if row["avg_score"] is not None else None,
            "first_ts": row["first_ts"],
            "last_ts": row["last_ts"],
            "by_proto": {r["proto"]: r["n"] for r in by_proto},
            "top_sni": [{"sni": r["sni"], "flows": r["n"]} for r in by_sni],
        }


class CaptureRepository:
    """Capture sessions + managed capture resources.

    Written immediately (low volume, ids must exist right away): a managed
    upload inserts its row as ``UPLOADED`` before any processing, a live
    session inserts ``PROCESSING`` at start, and finalisation closes the row
    with its counts and lifecycle status (see ``CaptureResourceService`` for
    the state machine).
    """

    def __init__(self, db: Database):
        self._db = db

    def start(self, mode: str, source: str | None) -> int:
        source_type = "live" if mode == "live" else "path"
        with self._db.lock:
            cur = self._db.execute(
                "INSERT INTO captures (mode, source, started_at, status, "
                "source_type) VALUES (?, ?, ?, 'PROCESSING', ?)",
                (mode, source, time.time(), source_type),
            )
            self._db.commit()
            return int(cur.lastrowid)

    def insert_resource(self, *, original_name: str, stored_name: str,
                        size_bytes: int, content_hash: str, source: str,
                        imported_at: float) -> int:
        """Persist one validated upload (status UPLOADED, source_type upload)."""
        with self._db.lock:
            cur = self._db.execute(
                """INSERT INTO captures
                   (mode, source, started_at, status, original_name,
                    stored_name, size_bytes, source_type, imported_at,
                    content_hash)
                   VALUES ('pcap', ?, ?, 'UPLOADED', ?, ?, ?, 'upload', ?, ?)""",
                (source, imported_at, original_name, stored_name, size_bytes,
                 imported_at, content_hash),
            )
            self._db.commit()
            return int(cur.lastrowid)

    def attach(self, capture_id: int, mode: str, source: str) -> None:
        """Claim an existing resource row for a processing run.

        Resets the run counters and any previous error so a reprocess starts
        clean; raises :class:`StoreError` when the row no longer exists.
        """
        with self._db.lock:
            cur = self._db.execute(
                """UPDATE captures
                   SET mode = ?, source = ?, started_at = ?, stopped_at = NULL,
                       status = 'PROCESSING', error = NULL,
                       packets = 0, flows = 0, detections = 0
                   WHERE id = ?""",
                (mode, source, time.time(), capture_id),
            )
            self._db.commit()
            if cur.rowcount == 0:
                raise StoreError(f"capture {capture_id} does not exist")

    def fail(self, capture_id: int, error: str) -> None:
        """Mark a resource FAILED with the reason (no-op if the row is gone)."""
        with self._db.lock:
            self._db.execute(
                """UPDATE captures
                   SET status = 'FAILED', error = ?,
                       stopped_at = COALESCE(stopped_at, ?)
                   WHERE id = ?""",
                (error, time.time(), capture_id),
            )
            self._db.commit()

    def get(self, capture_id: int) -> dict | None:
        rows = self._db.query("SELECT * FROM captures WHERE id = ?",
                              (capture_id,))
        return rows[0] if rows else None

    def list(self, limit: int = 20, offset: int = 0,
             status: str | None = None) -> dict:
        where, params = [], []
        if status:
            where.append("status = ?")
            params.append(status)
        clause = f"WHERE {' AND '.join(where)}" if where else ""
        limit = min(max(1, limit), 500)
        offset = max(0, offset)
        rows = self._db.query(
            f"SELECT * FROM captures {clause} ORDER BY id DESC LIMIT ? OFFSET ?",
            (*params, limit, offset),
        )
        total = int(self._db.query(
            f"SELECT COUNT(*) AS n FROM captures {clause}", params)[0]["n"])
        return {"count": total, "offset": offset, "items": rows}

    def by_hash(self, content_hash: str) -> dict | None:
        rows = self._db.query(
            "SELECT * FROM captures WHERE content_hash = ? "
            "ORDER BY id DESC LIMIT 1",
            (content_hash,),
        )
        return rows[0] if rows else None

    def stored_names(self) -> set[str]:
        """Every stored filename a row references (orphan-sweep input)."""
        rows = self._db.query(
            "SELECT stored_name FROM captures WHERE stored_name IS NOT NULL")
        return {str(r["stored_name"]) for r in rows}

    def delete(self, capture_id: int) -> bool:
        with self._db.lock:
            cur = self._db.execute("DELETE FROM captures WHERE id = ?",
                                   (capture_id,))
            self._db.commit()
            return cur.rowcount > 0

    def finish(self, capture_id: int, packets: int, flows: int,
               detections: int, error: str | None = None,
               status: str | None = None) -> None:
        """Close a session: counts + terminal lifecycle status.

        ``status`` lets the caller distinguish an explicit stop (STOPPED)
        from a natural completion (COMPLETED); an error always wins and
        records FAILED.
        """
        final = "FAILED" if error else (status or "COMPLETED")
        with self._db.lock:
            self._db.execute(
                """UPDATE captures
                   SET stopped_at = ?, packets = ?, flows = ?, detections = ?,
                       error = ?, status = ?
                   WHERE id = ?""",
                (time.time(), packets, flows, detections, error, final,
                 capture_id),
            )
            self._db.commit()

    def recent(self, limit: int = 20) -> list[dict]:
        return self._db.query(
            "SELECT * FROM captures ORDER BY id DESC LIMIT ?", (min(limit, 500),)
        )


class ModelRunRepository:
    """Training lineage rows (one per model fit)."""

    def __init__(self, db: Database):
        self._db = db

    def add(self, pcap: str, n_train: int, contamination: float,
            metrics: dict) -> int:
        with self._db.lock:
            cur = self._db.execute(
                """INSERT INTO model_runs (trained_at, pcap, n_train, contamination, metrics)
                   VALUES (?, ?, ?, ?, ?)""",
                (time.time(), pcap, n_train, contamination, json.dumps(metrics)),
            )
            self._db.commit()
            return int(cur.lastrowid)

    def recent(self, limit: int = 20) -> list[dict]:
        return self._db.query(
            "SELECT * FROM model_runs ORDER BY id DESC LIMIT ?",
            (min(limit, 200),),
        )


class AuditRepository:
    """Hash-chained audit entries.

    Every insert commits on its own (integrity: an entry must be durable the
    moment the log computes its hash) and retention never touches this table -
    see :mod:`spectra.db.retention`.
    """

    def __init__(self, db: Database):
        self._db = db

    def insert(self, seq: int, ts: float, kind: str, actor: str,
               payload_json: str, leaves_json: str | None,
               prev_hash: str, entry_hash: str) -> None:
        with self._db.lock:
            self._db.execute(
                """INSERT INTO audit_log
                   (seq, ts, kind, actor, payload, leaves, prev_hash, entry_hash)
                   VALUES (?,?,?,?,?,?,?,?)""",
                (seq, ts, kind, actor, payload_json, leaves_json,
                 prev_hash, entry_hash),
            )
            self._db.commit()

    def head(self) -> dict | None:
        rows = self._db.query(
            "SELECT seq, ts, kind, entry_hash FROM audit_log "
            "ORDER BY seq DESC LIMIT 1")
        return rows[0] if rows else None

    def count(self) -> int:
        return int(self._db.query("SELECT COUNT(*) AS n FROM audit_log")[0]["n"])

    def get(self, seq: int) -> dict | None:
        rows = self._db.query("SELECT * FROM audit_log WHERE seq = ?", (seq,))
        return rows[0] if rows else None

    def entries(self, limit: int = 50, offset: int = 0,
                kind: str | None = None) -> list[dict]:
        where, params = [], []
        if kind:
            where.append("kind = ?")
            params.append(kind)
        clause = f"WHERE {' AND '.join(where)}" if where else ""
        return self._db.query(
            f"SELECT * FROM audit_log {clause} ORDER BY seq DESC LIMIT ? OFFSET ?",
            (*params, min(max(1, limit), 1000), max(0, offset)),
        )

    def range(self, start: int, end: int) -> list[dict]:
        """Entries with start <= seq <= end, ascending (chain verification)."""
        return self._db.query(
            "SELECT * FROM audit_log WHERE seq >= ? AND seq <= ? ORDER BY seq ASC",
            (start, end),
        )

    def all(self, limit: int = 200_000) -> list[dict]:
        return self._db.query(
            "SELECT * FROM audit_log ORDER BY seq ASC LIMIT ?",
            (min(limit, 500_000),),
        )

    def last_checkpoint(self) -> dict | None:
        rows = self._db.query(
            "SELECT * FROM audit_log WHERE kind = 'checkpoint' "
            "ORDER BY seq DESC LIMIT 1")
        return rows[0] if rows else None


class EventRepository:
    """System event feed (status/alert/drift/model), batched + row-capped.

    ``flow`` and ``detection`` events are intentionally not stored here: they
    are already durable as ``flows`` rows, and persisting them again would
    double the write volume the batch buffer exists to reduce.
    """

    def __init__(self, db: Database, buffer: WriteBuffer, max_rows: int = 50_000):
        self._db = db
        self._buffer = buffer
        self.max_rows = max(1, int(max_rows))
        self._rows = self.count()
        buffer.on_flush(self._on_flush)

    def count(self) -> int:
        return int(self._db.query("SELECT COUNT(*) AS n FROM events")[0]["n"])

    @property
    def rows(self) -> int:
        return self._rows

    def resync(self) -> None:
        self._rows = self.count()

    def _on_flush(self, counts: dict[str, int]) -> None:
        n = counts.get("events", 0)
        if n:
            self._rows += n
            self._prune()

    def _prune(self) -> None:
        overflow = self._rows - self.max_rows
        if overflow <= 0:
            return
        with self._db.transaction():
            self._db.conn.execute(
                """DELETE FROM events WHERE id IN (
                       SELECT id FROM events ORDER BY id ASC LIMIT ?)""",
                (overflow,),
            )
        self._rows = self.count()

    def enqueue(self, ts: float, type: str, payload_json: str,
                capture_id: int | None = None) -> int:
        self._buffer.add("events", (ts, type, capture_id, payload_json))
        return 0

    def query(self, limit: int = 100, offset: int = 0,
              type: str | None = None) -> dict:
        self._buffer.flush_if_pending()
        where, params = [], []
        if type:
            where.append("type = ?")
            params.append(type)
        clause = f"WHERE {' AND '.join(where)}" if where else ""
        limit = min(max(1, limit), 1000)
        offset = max(0, offset)
        rows = self._db.query(
            f"SELECT * FROM events {clause} ORDER BY id DESC LIMIT ? OFFSET ?",
            (*params, limit, offset),
        )
        total = int(self._db.query(
            f"SELECT COUNT(*) AS n FROM events {clause}", params)[0]["n"])
        items = []
        for r in rows:
            items.append({
                "id": r["id"],
                "ts": r["ts"],
                "type": r["type"],
                "capture_id": r["capture_id"],
                "data": json.loads(r["payload"]),
            })
        return {"count": total, "offset": offset, "items": items}


class UserRepository:
    """Local accounts: scrypt encodings + one of three RBAC roles.

    Rows include ``password_hash``; the facade (:mod:`spectra.store`) projects
    every API-facing read through a public view so the hash never leaves the
    process, and only the credential-lookup path below returns it.
    """

    def __init__(self, db: Database):
        self._db = db

    def count(self) -> int:
        return int(self._db.query("SELECT COUNT(*) AS n FROM users")[0]["n"])

    def count_role(self, role: str) -> int:
        return int(self._db.query(
            "SELECT COUNT(*) AS n FROM users WHERE role = ?", (role,))[0]["n"])

    def create(self, username: str, password_hash: str, role: str,
               now: float) -> int:
        with self._db.lock:
            cur = self._db.execute(
                """INSERT INTO users
                   (username, password_hash, role, created_at, updated_at)
                   VALUES (?, ?, ?, ?, ?)""",
                (username, password_hash, role, now, now),
            )
            self._db.commit()
            return int(cur.lastrowid)

    def by_username(self, username: str) -> dict | None:
        rows = self._db.query(
            "SELECT * FROM users WHERE username = ? COLLATE NOCASE",
            (username,),
        )
        return rows[0] if rows else None

    def get(self, user_id: int) -> dict | None:
        rows = self._db.query("SELECT * FROM users WHERE id = ?", (user_id,))
        return rows[0] if rows else None

    def list(self) -> list[dict]:
        return self._db.query("SELECT * FROM users ORDER BY id ASC")

    def update(self, user_id: int, *, role: str | None = None,
               password_hash: str | None = None, now: float = 0.0) -> bool:
        sets, params = ["updated_at = ?"], [now]
        if role is not None:
            sets.append("role = ?")
            params.append(role)
        if password_hash is not None:
            sets.append("password_hash = ?")
            params.append(password_hash)
        params.append(user_id)
        with self._db.lock:
            cur = self._db.execute(
                f"UPDATE users SET {', '.join(sets)} WHERE id = ?", tuple(params))
            self._db.commit()
            return cur.rowcount > 0

    def touch_login(self, user_id: int, now: float) -> None:
        with self._db.lock:
            self._db.execute(
                "UPDATE users SET last_login_at = ? WHERE id = ?",
                (now, user_id),
            )
            self._db.commit()

    def delete(self, user_id: int) -> bool:
        """Remove an account; its session rows go with it (FK cascade)."""
        with self._db.lock:
            cur = self._db.execute("DELETE FROM users WHERE id = ?",
                                   (user_id,))
            self._db.commit()
            return cur.rowcount > 0


class SessionRepository:
    """Expiring bearer sessions keyed by SHA-256 token hash.

    The raw token is never stored: only its hex digest, so database readers
    cannot impersonate a live session. Writes are immediate (low volume).
    """

    def __init__(self, db: Database):
        self._db = db

    def create(self, user_id: int, token_hash: str, created_at: float,
               expires_at: float) -> int:
        with self._db.lock:
            cur = self._db.execute(
                """INSERT INTO sessions
                   (user_id, token_hash, created_at, expires_at, last_seen_at)
                   VALUES (?, ?, ?, ?, ?)""",
                (user_id, token_hash, created_at, expires_at, created_at),
            )
            self._db.commit()
            return int(cur.lastrowid)

    def by_token_hash(self, token_hash: str) -> dict | None:
        rows = self._db.query(
            "SELECT * FROM sessions WHERE token_hash = ?", (token_hash,))
        return rows[0] if rows else None

    def touch(self, token_hash: str, seen_at: float) -> None:
        with self._db.lock:
            self._db.execute(
                "UPDATE sessions SET last_seen_at = ? WHERE token_hash = ?",
                (seen_at, token_hash),
            )
            self._db.commit()

    def delete(self, token_hash: str) -> bool:
        with self._db.lock:
            cur = self._db.execute(
                "DELETE FROM sessions WHERE token_hash = ?", (token_hash,))
            self._db.commit()
            return cur.rowcount > 0

    def delete_for_user(self, user_id: int) -> int:
        """Invalidate every session of one user (password change, deletion)."""
        with self._db.lock:
            cur = self._db.execute(
                "DELETE FROM sessions WHERE user_id = ?", (user_id,))
            self._db.commit()
            return cur.rowcount

    def purge_expired(self, now: float) -> int:
        """Drop expired rows (opportunistic housekeeping on login)."""
        with self._db.lock:
            cur = self._db.execute(
                "DELETE FROM sessions WHERE expires_at <= ?", (now,))
            self._db.commit()
            return cur.rowcount


class IncidentRepository:
    """Incident triage rows + their analyst notes (see services.incidents)."""

    def __init__(self, db: Database):
        self._db = db

    def create(self, title: str, detection_id: int | None, created_by: str,
               now: float) -> int:
        with self._db.lock:
            cur = self._db.execute(
                """INSERT INTO incidents
                   (title, detection_id, status, created_by, created_at)
                   VALUES (?, ?, 'OPEN', ?, ?)""",
                (title, detection_id, created_by, now),
            )
            self._db.commit()
            return int(cur.lastrowid)

    def get(self, incident_id: int) -> dict | None:
        rows = self._db.query("SELECT * FROM incidents WHERE id = ?",
                              (incident_id,))
        return rows[0] if rows else None

    def list(self, limit: int = 50, offset: int = 0,
             status: str | None = None) -> dict:
        where, params = [], []
        if status:
            where.append("status = ?")
            params.append(status)
        clause = f"WHERE {' AND '.join(where)}" if where else ""
        limit = min(max(1, limit), 500)
        offset = max(0, offset)
        rows = self._db.query(
            f"SELECT * FROM incidents {clause} "
            f"ORDER BY id DESC LIMIT ? OFFSET ?",
            (*params, limit, offset),
        )
        total = int(self._db.query(
            f"SELECT COUNT(*) AS n FROM incidents {clause}", params)[0]["n"])
        return {"count": total, "offset": offset, "items": rows}

    def acknowledge(self, incident_id: int, by: str, now: float) -> bool:
        """OPEN -> ACKNOWLEDGED (guarded: a resolved incident is terminal)."""
        with self._db.lock:
            cur = self._db.execute(
                """UPDATE incidents
                   SET status = 'ACKNOWLEDGED', acknowledged_by = ?,
                       acknowledged_at = ?
                   WHERE id = ? AND status = 'OPEN'""",
                (by, now, incident_id),
            )
            self._db.commit()
            return cur.rowcount > 0

    def resolve(self, incident_id: int, by: str, now: float) -> bool:
        """OPEN/ACKNOWLEDGED -> RESOLVED (idempotent guard: stays terminal)."""
        with self._db.lock:
            cur = self._db.execute(
                """UPDATE incidents
                   SET status = 'RESOLVED', resolved_by = ?, resolved_at = ?
                   WHERE id = ? AND status <> 'RESOLVED'""",
                (by, now, incident_id),
            )
            self._db.commit()
            return cur.rowcount > 0

    def add_note(self, incident_id: int, author: str, body: str,
                 now: float) -> int:
        with self._db.lock:
            cur = self._db.execute(
                """INSERT INTO incident_notes
                   (incident_id, author, body, created_at) VALUES (?, ?, ?, ?)""",
                (incident_id, author, body, now),
            )
            self._db.commit()
            return int(cur.lastrowid)

    def notes(self, incident_id: int) -> list[dict]:
        return self._db.query(
            "SELECT * FROM incident_notes WHERE incident_id = ? "
            "ORDER BY id ASC",
            (incident_id,),
        )

    def note_count(self, incident_id: int) -> int:
        return int(self._db.query(
            "SELECT COUNT(*) AS n FROM incident_notes WHERE incident_id = ?",
            (incident_id,),
        )[0]["n"])
