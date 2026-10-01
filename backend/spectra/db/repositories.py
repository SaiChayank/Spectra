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
    """Incident triage rows + their analyst notes (see services.incidents).

    The incident layer above alerts keeps two extra relations:
    ``incident_alerts`` (membership with attribution + correlation reason,
    one incident per alert) and ``incident_events`` (ordered timeline).
    Column names of the rollup fields match
    :func:`spectra.incident_correlation.rollup` one-to-one.
    """

    #: Incident columns whose values are JSON documents (rows -> objects).
    JSON_FIELDS = ("affected_entities", "related_graph_nodes",
                   "model_versions")
    #: Rollup columns ``set_aggregates`` may write (never status/title).
    AGGREGATE_COLUMNS = (
        "summary", "severity", "confidence", "first_seen", "last_seen",
        "affected_entities", "alert_count", "primary_threat_class",
        "related_graph_nodes", "model_versions", "evidence_summary",
    )
    #: Extra columns a transition may set, per action (never user input).
    TRANSITION_EXTRA = ("acknowledged_by", "acknowledged_at",
                        "resolved_by", "resolved_at")

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

    @staticmethod
    def hydrate(row: dict) -> dict:
        """One ``incidents`` row: JSON columns back to objects."""
        out = dict(row)
        for field in IncidentRepository.JSON_FIELDS:
            raw = out.get(field)
            try:
                out[field] = json.loads(raw) if raw else []
            except (TypeError, json.JSONDecodeError):  # pragma: no cover
                out[field] = []
        out["alert_count"] = int(out.get("alert_count") or 0)
        return out

    def get(self, incident_id: int) -> dict | None:
        rows = self._db.query("SELECT * FROM incidents WHERE id = ?",
                              (incident_id,))
        return self.hydrate(rows[0]) if rows else None

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
        return {"count": total, "offset": offset,
                "items": [self.hydrate(r) for r in rows]}

    def transition(self, incident_id: int, from_statuses: tuple[str, ...],
                   *, status: str, actor: str, now: float,
                   extra: dict | None = None) -> bool:
        """Compare-and-swap status transition (``WHERE status IN (...)``).

        Returns False when the incident is gone or no longer in
        ``from_statuses`` - the caller turns that into a 409.  ``extra`` sets
        the per-action attribution columns and is validated against a
        whitelist (it is built from literals, never user input).
        """
        sets = ["status = ?", "updated_by = ?", "updated_at = ?"]
        params: list = [status, actor, now]
        for key, value in (extra or {}).items():
            if key not in IncidentRepository.TRANSITION_EXTRA:
                raise StoreError(f"unknown transition column: {key}")
            sets.append(f"{key} = ?")
            params.append(value)
        marks = ",".join("?" * len(from_statuses))
        with self._db.lock:
            cur = self._db.execute(
                f"UPDATE incidents SET {', '.join(sets)} "
                f"WHERE id = ? AND status IN ({marks})",
                (*params, incident_id, *from_statuses),
            )
            self._db.commit()
            return cur.rowcount > 0

    def acknowledge(self, incident_id: int, by: str, now: float) -> bool:
        """OPEN -> ACKNOWLEDGED (guarded: a resolved incident is terminal)."""
        return self.transition(
            incident_id, ("OPEN",), status="ACKNOWLEDGED", actor=by, now=now,
            extra={"acknowledged_by": by, "acknowledged_at": now})

    def resolve(self, incident_id: int, by: str, now: float) -> bool:
        """Active -> RESOLVED (idempotent guard: terminal states stay put)."""
        return self.transition(
            incident_id, ("OPEN", "INVESTIGATING", "ACKNOWLEDGED"),
            status="RESOLVED", actor=by, now=now,
            extra={"resolved_by": by, "resolved_at": now})

    def set_aggregates(self, incident_id: int, fields: dict) -> bool:
        """Write the correlation rollup columns of one incident."""
        unknown = set(fields) - set(IncidentRepository.AGGREGATE_COLUMNS)
        if unknown:
            raise StoreError(f"unknown incident aggregate: {sorted(unknown)}")
        if not fields:
            return False
        encoded = dict(fields)
        for key in ("affected_entities", "related_graph_nodes",
                    "model_versions"):
            if key in encoded:
                encoded[key] = json.dumps(encoded[key] or [])
        sets = ", ".join(f"{key} = ?" for key in encoded)
        with self._db.lock:
            cur = self._db.execute(
                f"UPDATE incidents SET {sets} WHERE id = ?",
                (*encoded.values(), incident_id),
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

    # -- the incident layer above alerts (membership + rollups + timeline) -----

    def link_alert(self, incident_id: int, alert_id: str, *,
                   added_at: float, added_by: str, source: str,
                   reason: str = "", score: float | None = None) -> str:
        """Attach an alert; returns ``linked``, ``exists`` or ``claimed``.

        ``exists`` = the alert is already in this incident (idempotent no-op);
        ``claimed`` = the alert belongs to a *different* incident (single
        ownership - the caller surfaces that as a conflict).
        """
        with self._db.lock:
            rows = self._db.query(
                "SELECT incident_id FROM incident_alerts WHERE alert_id = ?",
                (alert_id,))
            if rows:
                owner = int(rows[0]["incident_id"])
                return "exists" if owner == incident_id else "claimed"
            self._db.execute(
                """INSERT INTO incident_alerts
                   (incident_id, alert_id, added_at, added_by, source,
                    reason, score)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (incident_id, alert_id, added_at, added_by, source, reason,
                 score),
            )
            self._db.commit()
            return "linked"

    def incident_for_alert(self, alert_id: str) -> int | None:
        rows = self._db.query(
            "SELECT incident_id FROM incident_alerts WHERE alert_id = ?",
            (alert_id,))
        return int(rows[0]["incident_id"]) if rows else None

    def incident_alert_ids(self, incident_id: int) -> list[str]:
        """Member alert ids, oldest link first (stable for sampling)."""
        return [str(r["alert_id"]) for r in self._db.query(
            "SELECT alert_id FROM incident_alerts "
            "WHERE incident_id = ? ORDER BY added_at ASC, alert_id ASC",
            (incident_id,),
        )]

    def incident_alerts(self, incident_id: int) -> list[dict]:
        """Full member alerts (hydrated), newest activity first."""
        rows = self._db.query(
            "SELECT a.* FROM alerts a "
            "JOIN incident_alerts l ON l.alert_id = a.alert_id "
            "WHERE l.incident_id = ? "
            "ORDER BY a.last_seen DESC, a.alert_id ASC",
            (incident_id,),
        )
        return [AlertRepository.hydrate(r) for r in rows]

    def unassigned_alerts(self, limit: int = 500) -> list[dict]:
        """Alerts not yet claimed by any incident (resolved ones excluded)."""
        rows = self._db.query(
            "SELECT a.* FROM alerts a "
            "WHERE a.status <> 'RESOLVED' "
            "AND NOT EXISTS (SELECT 1 FROM incident_alerts l "
            "                WHERE l.alert_id = a.alert_id) "
            "ORDER BY a.last_seen DESC, a.alert_id DESC LIMIT ?",
            (min(max(1, limit), 500),),
        )
        return [AlertRepository.hydrate(r) for r in rows]

    def active_incidents(self, start: float, end: float,
                         limit: int = 50) -> list[dict]:
        """Open incidents whose sighting window overlaps ``[start, end]``.

        Detection-only incidents (no member alerts, NULL window) are skipped:
        there is nothing to correlate an alert against.
        """
        rows = self._db.query(
            "SELECT * FROM incidents "
            "WHERE status IN ('OPEN','INVESTIGATING','ACKNOWLEDGED') "
            "AND alert_count > 0 "
            "AND first_seen <= ? AND last_seen >= ? "
            "ORDER BY last_seen DESC, id DESC LIMIT ?",
            (end, start, min(max(1, limit), 200)),
        )
        return [self.hydrate(r) for r in rows]

    def add_event(self, incident_id: int, ts: float, kind: str,
                  actor: str, data: dict | None = None) -> int:
        with self._db.lock:
            cur = self._db.execute(
                "INSERT INTO incident_events "
                "(incident_id, ts, kind, actor, data) VALUES (?, ?, ?, ?, ?)",
                (incident_id, ts, kind, actor,
                 json.dumps(data or {})),
            )
            self._db.commit()
            return int(cur.lastrowid)

    def events(self, incident_id: int) -> list[dict]:
        rows = self._db.query(
            "SELECT * FROM incident_events WHERE incident_id = ? "
            "ORDER BY id ASC",
            (incident_id,),
        )
        out = []
        for row in rows:
            event = dict(row)
            try:
                event["data"] = json.loads(event.get("data") or "{}")
            except (TypeError, json.JSONDecodeError):  # pragma: no cover
                event["data"] = {}
            out.append(event)
        return out


#: Alert columns whose values are JSON documents (rows -> objects on read).
ALERT_JSON_FIELDS = ("evidence", "severity_factors", "metadata",
                     "module_annotations")


class AlertRepository:
    """Analyst alert rows (see services.threat_alerts).

    Column names match :class:`spectra.domain.ThreatAlert` one-to-one, so a
    hydrated row *is* the alert dict; only the JSON documents are parsed.
    Writes are immediate single commits — alerts are rare next to flows.
    """

    def __init__(self, db: Database):
        self._db = db

    _COLUMNS = ("alert_id, flow_id, capture_id, timestamp, first_seen, "
                "last_seen, updated_at, source, destination, protocol, "
                "threat_type, anomaly_score, confidence, severity, model_id, "
                "model_version, evidence, severity_factors, metadata, "
                "module_annotations, status, occurrences")

    @staticmethod
    def hydrate(row: dict) -> dict:
        """One ``alerts`` row: JSON columns back to objects."""
        out = dict(row)
        for field in ALERT_JSON_FIELDS:
            raw = out.get(field)
            try:
                out[field] = json.loads(raw) if raw else None
            except (TypeError, json.JSONDecodeError):  # pragma: no cover
                out[field] = None
        out["occurrences"] = int(out.get("occurrences") or 1)
        return out

    def insert(self, alert: dict) -> None:
        with self._db.lock:
            self._db.execute(
                f"INSERT INTO alerts ({self._COLUMNS}) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    alert["alert_id"],
                    alert.get("flow_id"),
                    alert.get("capture_id"),
                    float(alert["timestamp"]),
                    float(alert["first_seen"]),
                    float(alert["last_seen"]),
                    float(alert.get("updated_at") or alert["timestamp"]),
                    alert.get("source") or "",
                    alert.get("destination") or "",
                    alert.get("protocol") or "",
                    alert["threat_type"],
                    alert.get("anomaly_score"),
                    float(alert.get("confidence") or 0.0),
                    alert["severity"],
                    alert.get("model_id"),
                    alert.get("model_version"),
                    json.dumps(alert.get("evidence") or {}),
                    json.dumps(alert.get("severity_factors") or []),
                    json.dumps(alert.get("metadata") or {}),
                    json.dumps(alert.get("module_annotations") or {}),
                    alert.get("status") or "OPEN",
                    int(alert.get("occurrences") or 1),
                ),
            )
            self._db.commit()

    def get(self, alert_id: str) -> dict | None:
        rows = self._db.query("SELECT * FROM alerts WHERE alert_id = ?",
                              (alert_id,))
        return self.hydrate(rows[0]) if rows else None

    def list(self, limit: int = 50, offset: int = 0,
             status: str | None = None,
             threat_type: str | None = None) -> dict:
        where, params = [], []
        if status:
            where.append("status = ?")
            params.append(status)
        if threat_type:
            where.append("threat_type = ?")
            params.append(threat_type)
        clause = f"WHERE {' AND '.join(where)}" if where else ""
        limit = min(max(1, limit), 500)
        offset = max(0, offset)
        rows = self._db.query(
            f"SELECT * FROM alerts {clause} "
            f"ORDER BY last_seen DESC, alert_id DESC LIMIT ? OFFSET ?",
            (*params, limit, offset),
        )
        total = int(self._db.query(
            f"SELECT COUNT(*) AS n FROM alerts {clause}", params)[0]["n"])
        return {"count": total, "offset": offset,
                "items": [self.hydrate(r) for r in rows]}

    def update_group(self, alert_id: str, *, last_seen: float,
                     updated_at: float, occurrences: int,
                     anomaly_score: float | None, severity: str,
                     severity_factors: list) -> bool:
        """Persist a grouped re-sighting (newest sighting + re-scored severity)."""
        with self._db.lock:
            cur = self._db.execute(
                """UPDATE alerts
                   SET last_seen = ?, updated_at = ?, occurrences = ?,
                       anomaly_score = ?, severity = ?, severity_factors = ?
                   WHERE alert_id = ?""",
                (last_seen, updated_at, occurrences, anomaly_score, severity,
                 json.dumps(severity_factors), alert_id),
            )
            self._db.commit()
            return cur.rowcount > 0

    def acknowledge(self, alert_id: str, now: float) -> bool:
        """OPEN -> ACKNOWLEDGED (guarded: resolved stays terminal)."""
        with self._db.lock:
            cur = self._db.execute(
                "UPDATE alerts SET status = 'ACKNOWLEDGED', updated_at = ? "
                "WHERE alert_id = ? AND status = 'OPEN'",
                (now, alert_id),
            )
            self._db.commit()
            return cur.rowcount > 0

    def resolve(self, alert_id: str, now: float) -> bool:
        """OPEN/ACKNOWLEDGED -> RESOLVED (terminal)."""
        with self._db.lock:
            cur = self._db.execute(
                "UPDATE alerts SET status = 'RESOLVED', updated_at = ? "
                "WHERE alert_id = ? AND status <> 'RESOLVED'",
                (now, alert_id),
            )
            self._db.commit()
            return cur.rowcount > 0
