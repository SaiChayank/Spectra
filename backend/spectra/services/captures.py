"""Managed capture resources: validated import, processing, lifecycle.

Application service behind ``/api/captures``. It turns an uploaded file into a
capture resource and is the **only** component that maps capture ids to files:

* import   - filename/extension/signature/size validation
  (:class:`spectra.capture.storage.CaptureStorage`), storage under a
  generated name, duplicate detection by content hash, then a persisted
  ``UPLOADED`` row carrying the metadata (original name, size, source type,
  import time, status)
* process  - attaches the row to the existing streaming capture runtime
  (``CaptureService``) as ``PROCESSING``; finalisation closes it as
  ``COMPLETED``, ``FAILED`` (with the error) or ``STOPPED``. Reprocessing
  reuses the same resource id and resets the run counters.
* delete   - removes the row and its stored file when no run is active;
  flow history survives (the FK is ``ON DELETE SET NULL``).

Routers never receive a filesystem path from a client: they pass file bytes
(import) or a generated capture id (everything else), and
:meth:`CaptureResourceService.path_for` hands a re-validated store path to
offline tools that need to read a file (training, PQC scan, shadow mode).

Status lifecycle::

    UPLOADED -> PROCESSING -> COMPLETED | FAILED | STOPPED

Live sessions use the same rows without ``stored_name`` (nothing to import);
they enter at ``PROCESSING`` straight from ``CaptureService.start``.
"""

from __future__ import annotations

import logging
import os
import time
from typing import Iterable

from ..capture import CaptureError, CaptureFileError, CaptureStorage
from ..config import Config
from ..store import Store
from .capture import CaptureService
from .events import EventBus

log = logging.getLogger("spectra.engine")

#: Every status a capture resource may hold (routers validate against this).
CAPTURE_STATUSES: tuple[str, ...] = (
    "UPLOADED", "PROCESSING", "COMPLETED", "FAILED", "STOPPED",
)


class CaptureResourceError(Exception):
    """Base class for capture-resource failures (routers map these to HTTP)."""


class CaptureNotFound(CaptureResourceError):
    """No capture row for the requested id (HTTP 404)."""


class CaptureConflict(CaptureResourceError):
    """The request conflicts with the capture's state (HTTP 409)."""


class CaptureDuplicate(CaptureConflict):
    """Identical bytes are already stored (HTTP 409 + existing id)."""

    def __init__(self, message: str, capture_id: int):
        super().__init__(message)
        self.capture_id = capture_id


class CaptureResourceService:
    """Owns the capture store directory and the resource state machine."""

    def __init__(self, config: Config, store: Store | None,
                 capture: CaptureService, events: EventBus) -> None:
        self.config = config
        self.store = store                 # rebound by the engine's fan-out
        self._capture = capture
        self._events = events
        self.storage = CaptureStorage(
            config.capture_store_dir, max_bytes=config.capture_max_bytes)
        self.sweep_orphans()

    # -- housekeeping ---------------------------------------------------------

    def sweep_orphans(self, older_than: float = 3600.0) -> int:
        """Delete store files no capture row references (best effort).

        Covers crash debris (``.part`` uploads, a file written before its
        insert failed) and rows removed by retention. Files younger than an
        hour are kept - another import may still be mid-flight - and without
        a store nothing can be proven orphaned, so the sweep then does
        nothing rather than risk deleting real data.
        """
        if self.store is None:
            return 0
        try:
            referenced = self.store.stored_capture_names()
            now = time.time()
            removed = 0
            with os.scandir(self.storage.directory) as entries:
                for entry in entries:
                    if not entry.is_file() or entry.name in referenced:
                        continue
                    try:
                        if now - entry.stat().st_mtime < older_than:
                            continue
                        os.unlink(entry.path)
                        removed += 1
                    except OSError:
                        continue
            if removed:
                log.info("capture store: removed %d orphaned file(s)", removed)
            return removed
        except OSError as exc:
            log.warning("capture store orphan sweep failed: %s", exc)
            return 0

    # -- validation + import ----------------------------------------------------

    def import_file(self, filename: str | None,
                    chunks: Iterable[bytes]) -> dict:
        """Validate an upload, store it, persist it as UPLOADED, return metadata."""
        if self.store is None:
            raise CaptureConflict(
                "persistence is disabled - captures cannot be recorded")
        name = self.storage.sanitize_name(filename)   # metadata only, never a path
        self.storage.check_extension(name)
        staged = self.storage.save_stream(chunks)     # size + signature gates
        try:
            existing = self.store.find_capture_by_hash(staged.sha256)
            if existing is not None:
                raise CaptureDuplicate(
                    f"identical capture already imported as "
                    f"capture {existing['id']}",
                    int(existing["id"]),
                )
            capture_id = self.store.insert_capture_resource(
                original_name=name,
                stored_name=staged.stored_name,
                size_bytes=staged.size,
                content_hash=staged.sha256,
                source=name,
                imported_at=time.time(),
            )
        except BaseException:
            # a row we could not persist must not leave a stray file behind
            self.storage.remove(staged.stored_name)
            raise
        self._emit("import", capture_id, name)
        return self.details(capture_id)

    # -- reads -------------------------------------------------------------------

    def list_captures(self, limit: int = 20, offset: int = 0,
                      status: str | None = None) -> dict:
        if self.store is None:
            raise CaptureConflict("persistence is disabled")
        page = self.store.list_captures(limit=limit, offset=offset,
                                        status=status)
        return {"count": page["count"], "offset": page["offset"],
                "items": [self._meta(r) for r in page["items"]]}

    def details(self, capture_id: int) -> dict:
        return self._meta(self._row(capture_id))

    def path_for(self, capture_id: int) -> str:
        """Re-validated store path for a stored capture (offline tools).

        Raises :class:`CaptureNotFound` for unknown ids and
        :class:`CaptureConflict` when the resource has no file (live/legacy
        row) or its file went missing - never returns anything outside the
        store directory.
        """
        row = self._row(capture_id)
        stored = row.get("stored_name")
        if not stored:
            raise CaptureConflict(
                f"capture {capture_id} has no stored file "
                "(live or legacy session)")
        path = self.storage.path_for(stored)
        if not os.path.isfile(path):
            raise CaptureConflict(
                f"stored file for capture {capture_id} is missing")
        return path

    # -- lifecycle ----------------------------------------------------------------

    def process(self, capture_id: int) -> dict:
        """Run (or re-run) detection over a stored capture. Non-blocking."""
        row = self._row(capture_id)
        if not row.get("stored_name"):
            raise CaptureConflict(
                f"capture {capture_id} has no stored file to process")
        if self._capture.running:
            if self._capture.session.capture_id == capture_id:
                raise CaptureConflict(
                    f"capture {capture_id} is already processing")
            raise CaptureConflict(
                "another capture is running - stop it first")
        stored = row["stored_name"]
        path = self.storage.path_for(stored)
        if not os.path.isfile(path):
            try:
                self.store.mark_capture_failed(capture_id,
                                               "stored file is missing")
            except Exception:  # noqa: BLE001 - repair is best effort
                log.warning("could not mark capture %s failed", capture_id)
            raise CaptureConflict(
                f"stored file for capture {capture_id} is missing")
        label = row.get("original_name") or stored
        try:
            self._capture.start("pcap", path=path, capture_id=capture_id,
                                source_label=label)
        except CaptureError as exc:
            if self._capture.running:
                # start() refused before touching this row: nothing failed.
                raise CaptureConflict(str(exc)) from exc
            try:
                self.store.mark_capture_failed(capture_id, str(exc))
            except Exception:  # noqa: BLE001 - repair is best effort
                log.warning("could not mark capture %s failed", capture_id)
            raise CaptureFileError(str(exc)) from exc
        self._emit("process", capture_id, label)
        return self.details(capture_id)

    def delete(self, capture_id: int) -> dict:
        """Remove a capture row and its stored file when it is not running."""
        row = self._row(capture_id)
        if (self._capture.running
                and self._capture.session.capture_id == capture_id):
            raise CaptureConflict(
                f"capture {capture_id} is running - stop it before deleting")
        if not self.store.delete_capture(capture_id):
            raise CaptureNotFound(f"capture {capture_id} not found")
        # Row first (flows keep their history via FK SET NULL), then the
        # file: a failed unlink is caught later by the orphan sweep.
        removed = self.storage.remove(row.get("stored_name"))
        self._emit("delete", capture_id, row.get("original_name"))
        return {"deleted": capture_id, "file_removed": removed,
                "original_name": row.get("original_name")}

    # -- helpers --------------------------------------------------------------------

    def _row(self, capture_id: int) -> dict:
        if self.store is None:
            raise CaptureConflict("persistence is disabled")
        row = self.store.get_capture(capture_id)
        if row is None:
            raise CaptureNotFound(f"capture {capture_id} not found")
        return row

    def _meta(self, row: dict) -> dict:
        """Public metadata projection.

        Deliberately excludes the absolute store path: the API may show the
        generated ``stored_name`` but never where the store lives on disk.
        """
        active = bool(self._capture.running
                      and self._capture.session.capture_id == row["id"])
        return {
            "capture_id": row["id"],
            "original_name": row.get("original_name"),
            "stored_name": row.get("stored_name"),
            "size_bytes": row.get("size_bytes") or 0,
            "source_type": row.get("source_type") or "path",
            "mode": row["mode"],
            "status": row.get("status") or "COMPLETED",
            "imported_at": row.get("imported_at"),
            "started_at": row["started_at"],
            "stopped_at": row["stopped_at"],
            "packets": row["packets"] or 0,
            "flows": row["flows"] or 0,
            "detections": row["detections"] or 0,
            "error": row["error"],
            "running": active,
        }

    def _emit(self, action: str, capture_id: int,
              original_name: str | None) -> None:
        """Publish a capture lifecycle event (bus isolates listener errors)."""
        try:
            self._events.emit({"type": "capture", "data": {
                "action": action,
                "capture_id": capture_id,
                "original_name": original_name,
            }})
        except Exception:  # noqa: BLE001 - events must never break the API
            log.warning("capture event emit failed", exc_info=True)
