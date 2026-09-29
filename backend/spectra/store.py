"""SQLite persistence for flows, detections, capture sessions and model runs.

Keeps detection history across restarts so the API can serve trends and the
analyst can query what happened earlier. One connection guarded by a lock:
writes always come from the capture thread, reads from request handlers.
"""

from __future__ import annotations

import json
import os
import sqlite3
import threading
import time
from typing import Any

SCHEMA = """
CREATE TABLE IF NOT EXISTS captures (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    mode        TEXT NOT NULL,
    source      TEXT,
    started_at  REAL NOT NULL,
    stopped_at  REAL,
    packets     INTEGER DEFAULT 0,
    flows       INTEGER DEFAULT 0,
    detections  INTEGER DEFAULT 0,
    error       TEXT
);
CREATE TABLE IF NOT EXISTS flows (
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
);
CREATE INDEX IF NOT EXISTS idx_flows_ts ON flows(ts);
CREATE INDEX IF NOT EXISTS idx_flows_anomaly ON flows(anomaly, score);
CREATE INDEX IF NOT EXISTS idx_flows_sni ON flows(sni);
CREATE INDEX IF NOT EXISTS idx_flows_capture ON flows(capture_id);
CREATE TABLE IF NOT EXISTS model_runs (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    trained_at    REAL NOT NULL,
    pcap          TEXT,
    n_train       INTEGER,
    contamination REAL,
    metrics       TEXT
);
CREATE TABLE IF NOT EXISTS audit_log (
    seq        INTEGER PRIMARY KEY,
    ts         REAL NOT NULL,
    kind       TEXT NOT NULL,
    actor      TEXT,
    payload    TEXT NOT NULL,
    leaves     TEXT,
    prev_hash  TEXT NOT NULL,
    entry_hash TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_audit_kind ON audit_log(kind, seq);
"""


class StoreError(RuntimeError):
    pass


class Store:
    def __init__(self, path: str, max_rows: int = 200_000):
        self.path = path
        self.max_rows = max_rows
        self._lock = threading.RLock()
        try:
            if path != ":memory:":
                os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
            self._conn = sqlite3.connect(path, check_same_thread=False)
        except (sqlite3.Error, OSError) as exc:
            raise StoreError(f"cannot open database {path}: {exc}") from exc
        self._conn.row_factory = sqlite3.Row
        with self._lock:
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA synchronous=NORMAL")
            self._conn.executescript(SCHEMA)
            self._conn.commit()
            self._rows = int(
                self._conn.execute("SELECT COUNT(*) FROM flows").fetchone()[0]
            )

    # -- capture sessions ---------------------------------------------------

    def start_capture(self, mode: str, source: str | None) -> int:
        with self._lock:
            cur = self._conn.execute(
                "INSERT INTO captures (mode, source, started_at) VALUES (?, ?, ?)",
                (mode, source, time.time()),
            )
            self._conn.commit()
            return int(cur.lastrowid)

    def finish_capture(self, capture_id: int, packets: int, flows: int,
                       detections: int, error: str | None = None) -> None:
        with self._lock:
            self._conn.execute(
                """UPDATE captures
                   SET stopped_at = ?, packets = ?, flows = ?, detections = ?, error = ?
                   WHERE id = ?""",
                (time.time(), packets, flows, detections, error, capture_id),
            )
            self._conn.commit()
            self._prune()

    def recent_captures(self, limit: int = 20) -> list[dict]:
        return self._query(
            "SELECT * FROM captures ORDER BY id DESC LIMIT ?", (min(limit, 500),)
        )

    # -- flows --------------------------------------------------------------

    def save_flow(self, record: dict, score: float | None, anomaly: bool,
                  reasons: list[dict] | None = None, capture_id: int | None = None) -> int:
        with self._lock:
            cur = self._conn.execute(
                """INSERT INTO flows
                   (capture_id, ts, proto, src, dst, duration, packets, bytes,
                    tls_version, sni, alpn, ja3, ja4, score, anomaly, reasons, record)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
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
                ),
            )
            self._conn.commit()
            self._rows += 1
            if self._rows > self.max_rows:
                self._prune()
            return int(cur.lastrowid)

    def query_flows(self, limit: int = 100, offset: int = 0,
                    anomaly_only: bool = False, since: float | None = None,
                    until: float | None = None,
                    sni: str | None = None) -> dict:
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
        rows = self._query(
            f"SELECT * FROM flows {clause} ORDER BY id DESC LIMIT ? OFFSET ?",
            (*params, limit, offset),
        )
        total = self._count(clause, params)
        items = [self._row_to_flow(r) for r in rows]
        return {"count": total, "offset": offset, "items": items}

    def _count(self, clause: str, params: tuple) -> int:
        row = self._query(f"SELECT COUNT(*) AS n FROM flows {clause}", params)
        return int(row[0]["n"])

    def detections(self, limit: int = 100, offset: int = 0) -> dict:
        return self.query_flows(limit=limit, offset=offset, anomaly_only=True)

    def stats(self) -> dict:
        with self._lock:
            row = self._conn.execute(
                """SELECT COUNT(*) AS flows,
                          COALESCE(SUM(anomaly), 0) AS detections,
                          AVG(score) AS avg_score,
                          MIN(ts) AS first_ts,
                          MAX(ts) AS last_ts
                   FROM flows"""
            ).fetchone()
            by_proto = self._query(
                "SELECT proto, COUNT(*) AS n FROM flows GROUP BY proto ORDER BY n DESC", ()
            )
            by_sni = self._query(
                """SELECT sni, COUNT(*) AS n FROM flows
                   WHERE sni IS NOT NULL AND sni != ''
                   GROUP BY sni ORDER BY n DESC LIMIT 10""",
                (),
            )
        return {
            "flows": row["flows"],
            "detections": row["detections"],
            "anomaly_rate": round(row["detections"] / row["flows"], 4) if row["flows"] else 0.0,
            "avg_score": round(row["avg_score"], 2) if row["avg_score"] is not None else None,
            "first_ts": row["first_ts"],
            "last_ts": row["last_ts"],
            "by_proto": {r["proto"]: r["n"] for r in by_proto},
            "top_sni": [{"sni": r["sni"], "flows": r["n"]} for r in by_sni],
        }

    # -- model lineage ------------------------------------------------------

    def add_model_run(self, pcap: str, n_train: int, contamination: float,
                      metrics: dict) -> int:
        with self._lock:
            cur = self._conn.execute(
                """INSERT INTO model_runs (trained_at, pcap, n_train, contamination, metrics)
                   VALUES (?, ?, ?, ?, ?)""",
                (time.time(), pcap, n_train, contamination, json.dumps(metrics)),
            )
            self._conn.commit()
            return int(cur.lastrowid)

    def model_runs(self, limit: int = 20) -> list[dict]:
        return self._query(
            "SELECT * FROM model_runs ORDER BY id DESC LIMIT ?", (min(limit, 200),)
        )

    # -- Module 5: audit log -------------------------------------------------

    def audit_insert(self, seq: int, ts: float, kind: str, actor: str,
                     payload_json: str, leaves_json: str | None,
                     prev_hash: str, entry_hash: str) -> None:
        """Append one hash-chained audit entry (seq is assigned by the log)."""
        with self._lock:
            try:
                self._conn.execute(
                    """INSERT INTO audit_log
                       (seq, ts, kind, actor, payload, leaves, prev_hash, entry_hash)
                       VALUES (?,?,?,?,?,?,?,?)""",
                    (seq, ts, kind, actor, payload_json, leaves_json,
                     prev_hash, entry_hash),
                )
                self._conn.commit()
            except sqlite3.Error as exc:
                raise StoreError(str(exc)) from exc

    def audit_head(self) -> dict | None:
        rows = self._query(
            "SELECT seq, ts, kind, entry_hash FROM audit_log "
            "ORDER BY seq DESC LIMIT 1", ()
        )
        return rows[0] if rows else None

    def audit_count(self) -> int:
        rows = self._query("SELECT COUNT(*) AS n FROM audit_log", ())
        return int(rows[0]["n"])

    def audit_get(self, seq: int) -> dict | None:
        rows = self._query("SELECT * FROM audit_log WHERE seq = ?", (seq,))
        return rows[0] if rows else None

    def audit_entries(self, limit: int = 50, offset: int = 0,
                      kind: str | None = None) -> list[dict]:
        where, params = [], []
        if kind:
            where.append("kind = ?")
            params.append(kind)
        clause = f"WHERE {' AND '.join(where)}" if where else ""
        return self._query(
            f"SELECT * FROM audit_log {clause} ORDER BY seq DESC LIMIT ? OFFSET ?",
            (*params, min(max(1, limit), 1000), max(0, offset)),
        )

    def audit_range(self, start: int, end: int) -> list[dict]:
        """Entries with start <= seq <= end, ascending (chain verification)."""
        return self._query(
            "SELECT * FROM audit_log WHERE seq >= ? AND seq <= ? ORDER BY seq ASC",
            (start, end),
        )

    def audit_all(self, limit: int = 200_000) -> list[dict]:
        return self._query(
            "SELECT * FROM audit_log ORDER BY seq ASC LIMIT ?", (min(limit, 500_000),)
        )

    def audit_last_checkpoint(self) -> dict | None:
        rows = self._query(
            "SELECT * FROM audit_log WHERE kind = 'checkpoint' "
            "ORDER BY seq DESC LIMIT 1", ()
        )
        return rows[0] if rows else None

    # -- helpers ------------------------------------------------------------

    def _query(self, sql: str, params: tuple) -> list[dict]:
        with self._lock:
            try:
                rows = self._conn.execute(sql, params).fetchall()
            except sqlite3.Error as exc:
                raise StoreError(str(exc)) from exc
        return [dict(r) for r in rows]

    @staticmethod
    def _row_to_flow(row: sqlite3.Row) -> dict:
        out = json.loads(row["record"])
        out["score"] = row["score"]
        out["anomaly"] = bool(row["anomaly"])
        out["reasons"] = json.loads(row["reasons"]) if row["reasons"] else None
        out["id"] = row["id"]
        out["ts"] = row["ts"]
        return out

    def _prune(self) -> None:
        """Keep the table bounded: drop the oldest rows beyond max_rows."""
        with self._lock:
            overflow = self._rows - self.max_rows
            if overflow <= 0:
                return
            self._conn.execute(
                """DELETE FROM flows WHERE id IN (
                       SELECT id FROM flows ORDER BY id ASC LIMIT ?)""",
                (overflow,),
            )
            self._conn.commit()
            self._rows = int(
                self._conn.execute("SELECT COUNT(*) FROM flows").fetchone()[0]
            )

    def close(self) -> None:
        with self._lock:
            try:
                self._conn.close()
            except sqlite3.Error:
                pass
