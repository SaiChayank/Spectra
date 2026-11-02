"""Persistence facade: the single API services, modules and routers use.

Business logic talks to :class:`Store` only; every SQL statement, migration,
batched commit and retention sweep lives in :mod:`spectra.db` (connection ->
migrations -> repositories -> retention). The public method set is unchanged
from the pre-repository implementation, so routers, services, the audit log,
graph hydration and the test-suite keep working as-is.

Write path (throughput): ``save_flow``/``record_event`` stage rows in a
:class:`~spectra.db.batch.WriteBuffer` instead of committing per row. Batches
commit on size/interval, and every read, capture finalisation, retention sweep
and ``close()`` flushes first - callers always read their own writes, at the
cost of at most one batch uncommitted during a crash.

Durability rules by table:

* ``flows`` / ``events``  - batched (see above)
* ``captures`` / ``model_runs`` - immediate (ids must exist right away)
* ``model_registry``         - immediate (audited status transitions; one
                               row per immutable artifact)
* ``audit_log``           - immediate (hash-chain integrity) and never pruned
* ``users`` / ``sessions`` - immediate (login must observe its own row now)
* ``incidents`` / ``incident_notes`` - immediate (triage writes are rare)
* ``alerts``              - immediate (verdict writes are rare; an alert must
                            be durable the moment it is streamed)
* ``schema_migrations``   - written by the migration runner only
"""

from __future__ import annotations

import json
import logging
import time

from .db import (
    AlertRepository,
    AuditRepository,
    CaptureRepository,
    Database,
    EventRepository,
    FlowRepository,
    IncidentRepository,
    ModelRegistryRepository,
    ModelRunRepository,
    RetentionPolicy,
    SessionRepository,
    StoreError,
    UserRepository,
    WriteBuffer,
    apply_retention,
    migrate,
    schema_version,
)

log = logging.getLogger("spectra.store")

__all__ = ["Store", "StoreError"]


def _public_user(row: dict) -> dict:
    """Project a ``users`` row for API responses - without ``password_hash``.

    Every user read except the login credential lookup goes through this
    projector, so the scrypt encoding cannot leak into a router by accident.
    """
    return {
        "id": row["id"],
        "username": row["username"],
        "role": row["role"],
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
        "last_login_at": row["last_login_at"],
    }


class Store:
    """Composed repositories behind the historical persistence API."""

    def __init__(self, path: str, max_rows: int = 200_000, *,
                 batch_size: int = 256, flush_interval: float = 1.0,
                 event_max_rows: int = 50_000,
                 retention: RetentionPolicy | None = None):
        self.path = path
        self.max_rows = max_rows
        self._db = Database(path)            # pragmas + single guarded conn
        applied = migrate(self._db)          # schema changes happen only here
        if applied:
            log.info("applied migrations: %s", ", ".join(applied))
        self._buffer = WriteBuffer(self._db, batch_size=batch_size,
                                   flush_interval=flush_interval)
        self._flows = FlowRepository(self._db, self._buffer, max_rows=max_rows)
        self._events_repo = EventRepository(self._db, self._buffer,
                                            max_rows=event_max_rows)
        self._captures = CaptureRepository(self._db)
        self._runs = ModelRunRepository(self._db)
        self._models = ModelRegistryRepository(self._db)
        self._audit = AuditRepository(self._db)
        self._users = UserRepository(self._db)
        self._sessions = SessionRepository(self._db)
        self._incidents = IncidentRepository(self._db)
        self._alerts = AlertRepository(self._db)
        self.retention = retention if retention is not None else RetentionPolicy()
        self._lock = self._db.lock           # compat: historical attribute
        # Startup sweep: close sessions a crashed process left open and apply
        # configured age policies before this process writes anything. A sweep
        # failure must not disable persistence (schema and data are fine).
        try:
            self.run_retention()
        except StoreError as exc:  # noqa: BLE001 - retention is best-effort
            log.warning("retention sweep at open failed: %s", exc)

    # -- compat surface ------------------------------------------------------

    @property
    def _conn(self):
        """The raw connection (tests tamper with rows through it)."""
        return self._db.conn

    @property
    def schema_version(self) -> int:
        return schema_version(self._db)

    # -- capture sessions + managed resources --------------------------------

    def start_capture(self, mode: str, source: str | None) -> int:
        return self._captures.start(mode, source)

    def finish_capture(self, capture_id: int, packets: int, flows: int,
                       detections: int, error: str | None = None,
                       status: str | None = None) -> None:
        """Close a session with counts and its terminal lifecycle status.

        ``status`` distinguishes an explicit stop (STOPPED) from a natural
        completion; an error always records FAILED.
        """
        self.flush()   # the session's flows become durable before its record
        self._captures.finish(capture_id, packets, flows, detections, error,
                              status)
        self.run_retention()

    def recent_captures(self, limit: int = 20) -> list[dict]:
        return self._captures.recent(limit)

    # Managed capture resources (spectra/services/captures.py owns the rules;
    # these are the persistence calls behind them).

    def insert_capture_resource(self, *, original_name: str, stored_name: str,
                                size_bytes: int, content_hash: str,
                                source: str, imported_at: float) -> int:
        """Persist a validated upload (status UPLOADED)."""
        return self._captures.insert_resource(
            original_name=original_name, stored_name=stored_name,
            size_bytes=size_bytes, content_hash=content_hash, source=source,
            imported_at=imported_at)

    def attach_capture(self, capture_id: int, mode: str, source: str) -> None:
        """Claim a resource row for a (re)processing run."""
        self._captures.attach(capture_id, mode, source)

    def mark_capture_failed(self, capture_id: int, error: str) -> None:
        """Record why a resource could not be processed."""
        self._captures.fail(capture_id, error)

    def get_capture(self, capture_id: int) -> dict | None:
        return self._captures.get(capture_id)

    def list_captures(self, limit: int = 20, offset: int = 0,
                      status: str | None = None) -> dict:
        return self._captures.list(limit=limit, offset=offset, status=status)

    def find_capture_by_hash(self, content_hash: str) -> dict | None:
        """Existing resource with identical bytes (duplicate-import gate)."""
        return self._captures.by_hash(content_hash)

    def stored_capture_names(self) -> set[str]:
        """Stored filenames referenced by any row (orphan-sweep input)."""
        return self._captures.stored_names()

    def delete_capture(self, capture_id: int) -> bool:
        """Remove one capture row (flows keep their history, FK SET NULL)."""
        return self._captures.delete(capture_id)

    # -- flows / detections ---------------------------------------------------

    def save_flow(self, record: dict, score: float | None, anomaly: bool,
                  reasons: list[dict] | None = None,
                  capture_id: int | None = None) -> int:
        """Stage one scored flow for a batched commit.

        Returns 0 while the row is buffered (the durable id is assigned at
        flush; no caller has ever used the return value).
        """
        return self._flows.enqueue(record, score, anomaly, reasons, capture_id)

    def query_flows(self, limit: int = 100, offset: int = 0,
                    anomaly_only: bool = False, since: float | None = None,
                    until: float | None = None, sni: str | None = None,
                    proto: str | None = None, src: str | None = None,
                    dst: str | None = None,
                    min_score: float | None = None,
                    max_score: float | None = None,
                    capture_id: int | None = None) -> dict:
        return self._flows.query(limit=limit, offset=offset,
                                 anomaly_only=anomaly_only, since=since,
                                 until=until, sni=sni, proto=proto, src=src,
                                 dst=dst, min_score=min_score,
                                 max_score=max_score, capture_id=capture_id)

    def related_flows(self, *, flow_ids=(), alert_ids=(), hosts=(), snis=(),
                      since: float | None = None,
                      until: float | None = None,
                      limit: int = 100, offset: int = 0) -> dict:
        """Flows an incident points at (see FlowRepository.related)."""
        return self._flows.related(flow_ids=flow_ids, alert_ids=alert_ids,
                                   hosts=hosts, snis=snis, since=since,
                                   until=until, limit=limit, offset=offset)

    def search_flows(self, q: str, limit: int = 10, *, endpoint: bool = False,
                     sni: bool = False, fingerprint: bool = False) -> dict:
        """Global-search flow hits (see FlowRepository.search)."""
        return self._flows.search(q, limit=limit, endpoint=endpoint,
                                  sni=sni, fingerprint=fingerprint)

    def detections(self, limit: int = 100, offset: int = 0) -> dict:
        return self._flows.query(limit=limit, offset=offset, anomaly_only=True)

    def get_flow(self, flow_id: int) -> dict | None:
        """One persisted flow by id (incident triage validates detections)."""
        return self._flows.get(flow_id)

    def stats(self) -> dict:
        return self._flows.stats()

    # -- local authentication: users + sessions --------------------------------
    #
    # API-facing reads go through _public_user so ``password_hash`` can never
    # reach a router; find_user_credentials is the one narrow path that
    # returns it (login verification inside AuthService).

    def count_users(self) -> int:
        return self._users.count()

    def count_admin_users(self) -> int:
        """ADMIN accounts remaining (the last-admin deletion guard)."""
        return self._users.count_role("ADMIN")

    def create_user(self, username: str, password_hash: str,
                    role: str) -> dict:
        user_id = self._users.create(username, password_hash, role,
                                     now=time.time())
        return _public_user(self._users.get(user_id))

    def find_user_credentials(self, username: str) -> dict | None:
        """Username + role + hash for login verification (internal only)."""
        row = self._users.by_username(username)
        if row is None:
            return None
        return {"id": row["id"], "username": row["username"],
                "password_hash": row["password_hash"], "role": row["role"]}

    def get_user(self, user_id: int) -> dict | None:
        row = self._users.get(user_id)
        return _public_user(row) if row else None

    def list_users(self) -> list[dict]:
        return [_public_user(r) for r in self._users.list()]

    def update_user(self, user_id: int, *, role: str | None = None,
                    password_hash: str | None = None) -> dict | None:
        if not self._users.update(user_id, role=role,
                                  password_hash=password_hash,
                                  now=time.time()):
            return None
        return _public_user(self._users.get(user_id))

    def set_user_login_time(self, user_id: int) -> None:
        self._users.touch_login(user_id, now=time.time())

    def delete_user(self, user_id: int) -> bool:
        """Delete an account; its sessions are removed by the FK cascade."""
        return self._users.delete(user_id)

    def create_session(self, user_id: int, token_hash: str,
                       expires_at: float) -> int:
        now = time.time()
        return self._sessions.create(user_id, token_hash, now, expires_at)

    def get_session(self, token_hash: str) -> dict | None:
        return self._sessions.by_token_hash(token_hash)

    def touch_session(self, token_hash: str, seen_at: float) -> None:
        self._sessions.touch(token_hash, seen_at)

    def delete_session(self, token_hash: str) -> bool:
        return self._sessions.delete(token_hash)

    def invalidate_user_sessions(self, user_id: int) -> int:
        """Revoke every session of one user (password change / deletion)."""
        return self._sessions.delete_for_user(user_id)

    def purge_expired_sessions(self, now: float | None = None) -> int:
        return self._sessions.purge_expired(
            time.time() if now is None else now)

    # -- incidents + analyst notes (ANALYST triage workflow) --------------------

    def create_incident(self, title: str, detection_id: int | None,
                        created_by: str) -> dict:
        incident_id = self._incidents.create(title, detection_id, created_by,
                                             now=time.time())
        return self.get_incident(incident_id)

    def get_incident(self, incident_id: int) -> dict | None:
        row = self._incidents.get(incident_id)
        return dict(row) if row else None

    def list_incidents(self, limit: int = 50, offset: int = 0,
                       status: str | None = None,
                       severity: str | None = None,
                       threat_type: str | None = None,
                       since: float | None = None,
                       until: float | None = None) -> dict:
        return self._incidents.list(limit=limit, offset=offset, status=status,
                                    severity=severity, threat_type=threat_type,
                                    since=since, until=until)

    def search_incidents(self, q: str, limit: int = 10, *,
                         exact_id: int | None = None, entity: bool = True,
                         title: bool = True) -> dict:
        """Global-search incident hits (see IncidentRepository.search)."""
        return self._incidents.search(q, limit=limit, exact_id=exact_id,
                                      entity=entity, title=title)

    def acknowledge_incident(self, incident_id: int, by: str) -> bool:
        return self._incidents.acknowledge(incident_id, by, now=time.time())

    def resolve_incident(self, incident_id: int, by: str) -> bool:
        return self._incidents.resolve(incident_id, by, now=time.time())

    def add_incident_note(self, incident_id: int, author: str,
                          body: str) -> dict:
        note_id = self._incidents.add_note(incident_id, author, body,
                                           now=time.time())
        for row in self._incidents.notes(incident_id):
            if row["id"] == note_id:
                return dict(row)
        return {}  # pragma: no cover - the insert above just succeeded

    def incident_notes(self, incident_id: int) -> list[dict]:
        return [dict(r) for r in self._incidents.notes(incident_id)]

    def incident_note_count(self, incident_id: int) -> int:
        return self._incidents.note_count(incident_id)

    # -- incident layer above alerts (membership, rollups, timeline) -----------

    def transition_incident(self, incident_id: int, from_statuses,
                            *, status: str, actor: str,
                            extra: dict | None = None) -> bool:
        """Guarded status transition; False = not in an allowed source state."""
        return self._incidents.transition(
            incident_id, tuple(from_statuses), status=status, actor=actor,
            now=time.time(), extra=extra)

    def set_incident_aggregates(self, incident_id: int, fields: dict) -> bool:
        """Persist the correlation rollup fields of one incident."""
        return self._incidents.set_aggregates(incident_id, fields)

    def link_incident_alert(self, incident_id: int, alert_id: str, *,
                            source: str, added_by: str,
                            reason: str = "",
                            score: float | None = None) -> str:
        """Attach an alert: ``linked`` | ``exists`` (idempotent) | ``claimed``."""
        return self._incidents.link_alert(
            incident_id, alert_id, added_at=time.time(), added_by=added_by,
            source=source, reason=reason, score=score)

    def incident_for_alert(self, alert_id: str) -> int | None:
        return self._incidents.incident_for_alert(alert_id)

    def incident_alert_ids(self, incident_id: int) -> list[str]:
        return self._incidents.incident_alert_ids(incident_id)

    def get_incident_alerts(self, incident_id: int) -> list[dict]:
        return self._incidents.incident_alerts(incident_id)

    def unassigned_alerts(self, limit: int = 500) -> list[dict]:
        return self._incidents.unassigned_alerts(limit=limit)

    def active_incidents(self, start: float, end: float,
                         limit: int = 50) -> list[dict]:
        return self._incidents.active_incidents(start, end, limit=limit)

    def add_incident_event(self, incident_id: int, kind: str, actor: str,
                           data: dict | None = None,
                           ts: float | None = None) -> int:
        return self._incidents.add_event(
            incident_id, time.time() if ts is None else ts, kind, actor, data)

    def incident_events(self, incident_id: int) -> list[dict]:
        return self._incidents.events(incident_id)

    # -- analyst alerts (threat-classification layer) ---------------------------

    def insert_alert(self, alert: dict) -> None:
        """Persist one newly raised alert (immediate single commit)."""
        self._alerts.insert(alert)

    def get_alert(self, alert_id: str) -> dict | None:
        return self._alerts.get(alert_id)

    def list_alerts(self, limit: int = 50, offset: int = 0,
                    status: str | None = None,
                    threat_type: str | None = None,
                    severity: str | None = None,
                    protocol: str | None = None,
                    source: str | None = None,
                    destination: str | None = None,
                    since: float | None = None,
                    until: float | None = None,
                    min_score: float | None = None,
                    max_score: float | None = None) -> dict:
        return self._alerts.list(limit=limit, offset=offset, status=status,
                                 threat_type=threat_type, severity=severity,
                                 protocol=protocol, source=source,
                                 destination=destination, since=since,
                                 until=until, min_score=min_score,
                                 max_score=max_score)

    def search_alerts(self, q: str, limit: int = 10, *, alert_id: bool = False,
                      endpoint: bool = False, text: bool = False,
                      model: bool = False) -> dict:
        """Global-search alert hits (see AlertRepository.search)."""
        return self._alerts.search(q, limit=limit, alert_id=alert_id,
                                   endpoint=endpoint, text=text, model=model)

    def alert_models(self, q: str, limit: int = 20) -> list[dict]:
        """Distinct scoring identities whose id/version matches ``q``."""
        return self._alerts.models(q, limit)

    def update_alert_group(self, alert_id: str, **fields) -> bool:
        """Persist a grouped re-sighting of an existing alert."""
        return self._alerts.update_group(alert_id, **fields)

    def acknowledge_alert(self, alert_id: str) -> bool:
        return self._alerts.acknowledge(alert_id, now=time.time())

    def resolve_alert(self, alert_id: str) -> bool:
        return self._alerts.resolve(alert_id, now=time.time())

    # -- system events --------------------------------------------------------

    def record_event(self, type: str, data: dict, ts: float | None = None,
                     capture_id: int | None = None) -> int:
        """Stage one system event (batched like flows)."""
        payload = json.dumps(data, default=str)
        return self._events_repo.enqueue(
            time.time() if ts is None else ts, type, payload, capture_id)

    def query_events(self, limit: int = 100, offset: int = 0,
                     type: str | None = None, since: float | None = None,
                     until: float | None = None) -> dict:
        return self._events_repo.query(limit=limit, offset=offset, type=type,
                                       since=since, until=until)

    # -- model lineage --------------------------------------------------------

    def add_model_run(self, pcap: str, n_train: int, contamination: float,
                      metrics: dict) -> int:
        return self._runs.add(pcap, n_train, contamination, metrics)

    def model_runs(self, limit: int = 20, offset: int = 0) -> list[dict]:
        return self._runs.recent(limit, offset=offset)

    def model_run_count(self) -> int:
        return self._runs.count()

    # -- model registry (Prompt 14: lineage + single ACTIVE) ------------------

    def model_registry_add(self, fields: dict) -> dict:
        """Insert one CANDIDATE row for a freshly saved artifact."""
        return self._models.add(fields)

    def model_registry_get(self, model_id: str) -> dict | None:
        return self._models.get(model_id)

    def model_registry_list(self, limit: int = 100,
                             offset: int = 0) -> dict:
        return self._models.list(limit, offset=offset)

    def model_registry_count(self) -> int:
        return self._models.count()

    def model_registry_active(self) -> dict | None:
        return self._models.active()

    def model_registry_previous_active(self, before_ts: float) -> dict | None:
        return self._models.previous_active(before_ts)

    def model_registry_set_status(self, model_id: str, status: str, *,
                                  metrics: dict | None = None,
                                  error: str | None = None,
                                  clear_error: bool = False,
                                  retired_at: float | None = None) -> dict | None:
        return self._models.set_status(
            model_id, status, metrics=metrics, error=error,
            clear_error=clear_error, retired_at=retired_at)

    def model_registry_activate(self, model_id: str, now: float) -> dict:
        """Atomic retire-current + promote-target (single ACTIVE)."""
        return self._models.activate(model_id, now)

    # -- Module 5: audit log (immediate, never pruned) ------------------------

    def audit_insert(self, seq: int, ts: float, kind: str, actor: str,
                     payload_json: str, leaves_json: str | None,
                     prev_hash: str, entry_hash: str) -> None:
        """Append one hash-chained audit entry (seq is assigned by the log)."""
        self._audit.insert(seq, ts, kind, actor, payload_json, leaves_json,
                           prev_hash, entry_hash)

    def audit_head(self) -> dict | None:
        return self._audit.head()

    def audit_count(self, kind: str | None = None, *,
                    kind_prefix: str | None = None,
                    since: float | None = None,
                    until: float | None = None,
                    actor: str | None = None) -> int:
        return self._audit.count(kind, kind_prefix=kind_prefix, since=since,
                                 until=until, actor=actor)

    def audit_get(self, seq: int) -> dict | None:
        return self._audit.get(seq)

    def audit_entries(self, limit: int = 50, offset: int = 0,
                      kind: str | None = None, *,
                      kind_prefix: str | None = None,
                      since: float | None = None,
                      until: float | None = None,
                      actor: str | None = None) -> list[dict]:
        return self._audit.entries(limit=limit, offset=offset, kind=kind,
                                   kind_prefix=kind_prefix, since=since,
                                   until=until, actor=actor)

    def audit_range(self, start: int, end: int) -> list[dict]:
        return self._audit.range(start, end)

    def audit_all(self, limit: int = 200_000) -> list[dict]:
        return self._audit.all(limit=limit)

    def audit_last_checkpoint(self) -> dict | None:
        return self._audit.last_checkpoint()

    # -- batch control / introspection ------------------------------------------

    def flush(self) -> int:
        """Commit staged rows now; returns how many became durable."""
        return self._buffer.flush()

    def run_retention(self) -> dict:
        """Apply the stale-session sweep + configured age policies (one txn)."""
        with self._db.lock:
            self._buffer.flush_if_pending()
            counts = apply_retention(self._db, self.retention)
            self._flows.resync()
            self._events_repo.resync()
            return counts

    def write_stats(self) -> dict:
        """Batching/commit telemetry (throughput + debugging aid)."""
        latency = self._db.write_latency.summary()
        return {
            "commits": self._db.commit_count,
            "flushes": self._buffer.flush_count,
            "staged": self._buffer.pending(),
            "staged_total": self._buffer.enqueued,
            "flow_rows": self._flows.rows,
            "event_rows": self._events_repo.rows,
            "schema_version": self.schema_version,
            # health-layer write telemetry (recent ring + lifetime errors)
            "write_p50_ms": latency["p50_ms"],
            "write_p95_ms": latency["p95_ms"],
            "write_samples": latency["samples"],
            "write_total": latency["total_samples"],
            "errors": self._db.error_count,
        }

    def incident_count(self) -> int:
        """Total incidents on disk (health/rate telemetry)."""
        return self._incidents.count()

    def close(self) -> None:
        with self._db.lock:
            try:
                self._buffer.flush()
            except StoreError:  # database already unusable; nothing to save
                pass
            self._db.close()
