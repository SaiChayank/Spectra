"""SQLite connection ownership: pragmas, errors, transactions.

This is the only module allowed to touch a raw ``sqlite3`` connection. Every
repository goes through :class:`Database`, so WAL mode, foreign keys, the busy
timeout, the process-wide lock and transaction boundaries are decided once.

The connection runs with ``isolation_level=None`` (autocommit): single-statement
writes are durable immediately, and multi-statement work opens an explicit
``BEGIN IMMEDIATE`` through :meth:`Database.transaction`. Nothing ever sits in an
open transaction while idle, so other local processes (CLI, a second engine)
can use the file between batched flushes.
"""

from __future__ import annotations

import os
import sqlite3
import threading
import time
from contextlib import contextmanager
from typing import Iterator

from ..health import LatencyReservoir

#: Statement verbs that make ``execute`` a write (reads are not timed).
_WRITE_VERBS = frozenset({"INSERT", "UPDATE", "DELETE", "REPLACE"})


class StoreError(RuntimeError):
    """Every persistence failure surfaced to callers uses this type."""


class Database:
    """One guarded connection plus transaction/exec helpers.

    Also owns write telemetry for the health layer: a bounded reservoir of
    recent write/commit durations (ms) and a lifetime error counter - both
    cheap enough to sit on the hot path and never raise.
    """

    def __init__(self, path: str, timeout: float = 5.0):
        self.path = path
        self.lock = threading.RLock()
        # Explicit transactions committed through this layer (batch flushes,
        # migrations, retention). Used as evidence for write-throughput work.
        self.commit_count = 0
        # Health telemetry: recent write/commit latency + SQL error count.
        self.write_latency = LatencyReservoir()
        self.error_count = 0
        try:
            if path != ":memory:":
                os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
            self._conn = sqlite3.connect(
                path, check_same_thread=False, isolation_level=None,
                timeout=timeout,
            )
        except (sqlite3.Error, OSError) as exc:
            raise StoreError(f"cannot open database {path}: {exc}") from exc
        self._conn.row_factory = sqlite3.Row
        with self.lock:
            self._conn.execute("PRAGMA journal_mode=WAL")   # concurrent readers
            self._conn.execute("PRAGMA synchronous=NORMAL")  # safe + fast on WAL
            self._conn.execute(f"PRAGMA busy_timeout={int(timeout * 1000)}")
            self._conn.execute("PRAGMA foreign_keys=ON")

    @property
    def conn(self) -> sqlite3.Connection:
        """The raw connection (repositories and tests only)."""
        return self._conn

    def set_foreign_keys(self, enabled: bool) -> None:
        """Toggle FK enforcement (a no-op inside an open transaction)."""
        with self.lock:
            self._conn.execute(
                f"PRAGMA foreign_keys={'ON' if enabled else 'OFF'}"
            )

    @staticmethod
    def _is_write(sql: str) -> bool:
        parts = sql.lstrip().split(None, 1)
        return bool(parts) and parts[0].upper() in _WRITE_VERBS

    def _observe_write(self, started: float) -> None:
        self.write_latency.observe((time.perf_counter() - started) * 1000.0)

    def execute(self, sql: str, params: tuple = ()) -> sqlite3.Cursor:
        with self.lock:
            started = time.perf_counter()
            try:
                cursor = self._conn.execute(sql, params)
            except sqlite3.Error as exc:
                self.error_count += 1
                raise StoreError(str(exc)) from exc
            if self._is_write(sql):
                self._observe_write(started)
            return cursor

    def query(self, sql: str, params: tuple = ()) -> list[dict]:
        with self.lock:
            try:
                rows = self._conn.execute(sql, params).fetchall()
            except sqlite3.Error as exc:
                self.error_count += 1
                raise StoreError(str(exc)) from exc
        return [dict(r) for r in rows]

    def commit(self) -> None:
        """Durability point for a single-statement write (no-op under autocommit)."""
        with self.lock:
            started = time.perf_counter()
            try:
                self._conn.commit()
            except sqlite3.Error as exc:
                self.error_count += 1
                raise StoreError(str(exc)) from exc
            self.commit_count += 1
            self._observe_write(started)

    @contextmanager
    def transaction(self) -> Iterator[None]:
        """``BEGIN IMMEDIATE`` .. ``COMMIT``/``ROLLBACK``; never nestable.

        Everything inside shares one lock, so no other thread of this process
        can observe the half-applied state; other processes see either all of
        it (after COMMIT) or none of it (WAL snapshot).
        """
        with self.lock:
            try:
                self._conn.execute("BEGIN IMMEDIATE")
            except sqlite3.Error as exc:
                self.error_count += 1
                raise StoreError(str(exc)) from exc
            try:
                yield
            except BaseException:
                try:
                    self._conn.execute("ROLLBACK")
                except sqlite3.Error:
                    pass
                raise
            else:
                started = time.perf_counter()
                try:
                    self._conn.execute("COMMIT")
                except sqlite3.Error as exc:
                    self.error_count += 1
                    try:
                        self._conn.execute("ROLLBACK")
                    except sqlite3.Error:
                        pass
                    raise StoreError(str(exc)) from exc
                self.commit_count += 1
                self._observe_write(started)

    def close(self) -> None:
        with self.lock:
            try:
                self._conn.close()
            except sqlite3.Error:
                pass
