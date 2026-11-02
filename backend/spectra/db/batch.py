"""Batched writes: stage rows in memory, commit them as one transaction.

The publish stage produces one row per flow; committing each of them is what
made persistence the slowest stage. :class:`WriteBuffer` stages those rows in
Python and commits when

* the batch reaches ``batch_size`` rows,
* ``flush_interval`` seconds elapsed (checked on the next write), or
* a read, capture finalisation, retention sweep or shutdown asks for durable
  data (``flush_if_pending``).

Staging happens in memory rather than in an open SQLite transaction, so an
idle engine holds no write lock at all - other local processes can read and
write between flushes.  A crash therefore loses at most one batch (``batch_size``
rows / ``flush_interval`` seconds), the same window the old per-flow commits
traded for throughput; every read path flushes first, so callers always read
their own writes.
"""

from __future__ import annotations

import sqlite3
import time
from typing import Callable

from .connection import Database, StoreError

# table -> INSERT used for the staged rows (column order fixed here).
INSERTS: dict[str, str] = {
    "flows": (
        "INSERT INTO flows (capture_id, ts, proto, src, dst, duration, packets, "
        "bytes, tls_version, sni, alpn, ja3, ja4, score, anomaly, reasons, record) "
        "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)"
    ),
    "events": "INSERT INTO events (ts, type, capture_id, payload) VALUES (?,?,?,?)",
}

FlushCallback = Callable[[dict[str, int]], None]


class WriteBuffer:
    """Staged rows for one batched commit, shared by flows and events."""

    def __init__(self, db: Database, batch_size: int = 256,
                 flush_interval: float = 1.0):
        self._db = db
        self._batch_size = max(1, int(batch_size))
        self._flush_interval = max(0.0, float(flush_interval))
        self._pending: dict[str, list[tuple]] = {"flows": [], "events": []}
        self._callbacks: list[FlushCallback] = []
        self._last_flush = time.monotonic()
        self.flush_count = 0   # batched transactions committed
        self.enqueued = 0      # rows staged since open

    # -- staging ------------------------------------------------------------

    def add(self, table: str, row: tuple) -> None:
        """Stage one row; commits immediately once the batch is full."""
        with self._db.lock:
            if table not in self._pending:
                raise StoreError(f"unknown batch table {table!r}")
            self._pending[table].append(row)
            self.enqueued += 1
            self._maybe_flush()

    def _maybe_flush(self) -> None:
        """Called with the lock held; size- or time-triggered commit."""
        if self.pending() >= self._batch_size:
            self.flush()
        elif (self._flush_interval
              and time.monotonic() - self._last_flush >= self._flush_interval):
            self.flush()

    def on_flush(self, callback: FlushCallback) -> None:
        """Register ``callback(counts_by_table)`` to run after every commit."""
        with self._db.lock:
            self._callbacks.append(callback)

    def pending(self) -> int:
        with self._db.lock:
            return sum(len(rows) for rows in self._pending.values())

    # -- durability ---------------------------------------------------------

    def flush(self) -> int:
        """Commit every staged row in one transaction; returns rows written."""
        with self._db.lock:
            staged = {t: rows for t, rows in self._pending.items() if rows}
            if not staged:
                self._last_flush = time.monotonic()
                return 0
            try:
                with self._db.transaction():
                    for table, rows in staged.items():
                        self._db.conn.executemany(INSERTS[table], rows)
            except (sqlite3.Error, StoreError) as exc:
                # Drop the batch: a poison row would block every future flush
                # (and the retry would fail identically). The caller already
                # treats persistence errors as non-fatal.  StoreError is in
                # the tuple because a failed *commit* surfaces as one - those
                # rows must be discarded too, or they would stay staged and
                # wedge every later flush while the batch kept re-raising.
                self._discard()
                if isinstance(exc, StoreError):
                    raise
                raise StoreError(str(exc)) from exc
            counts = {t: len(rows) for t, rows in staged.items()}
            self._discard()
            self.flush_count += 1
            self._last_flush = time.monotonic()
            for callback in self._callbacks:
                callback(counts)
            return sum(counts.values())

    def flush_if_pending(self) -> int:
        """Read-your-writes: commit staged rows before serving a read."""
        if self.pending():
            return self.flush()
        return 0

    def _discard(self) -> None:
        for table in self._pending:
            self._pending[table] = []
