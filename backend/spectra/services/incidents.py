"""Incident triage + analyst notes: the ANALYST workflow over flagged flows.

An incident is a durable work item (title, state machine, attribution)
optionally pointing at the detection - a flagged flow - that raised it.
Transitions follow ``OPEN -> ACKNOWLEDGED -> RESOLVED``; ``RESOLVED`` is
terminal. Notes are author-attributed comments kept with their incident.

State checks live here (service layer); the repository performs guarded
updates underneath, and routers only translate exceptions to HTTP.
"""

from __future__ import annotations

from ..store import Store

STATUS_OPEN = "OPEN"
STATUS_ACKNOWLEDGED = "ACKNOWLEDGED"
STATUS_RESOLVED = "RESOLVED"
STATUSES: tuple[str, ...] = (STATUS_OPEN, STATUS_ACKNOWLEDGED, STATUS_RESOLVED)


class IncidentError(Exception):
    """Mapped to an HTTP error by the incidents router."""

    status_code = 400
    default_detail = "incident error"

    def __init__(self, detail: str | None = None):
        self.detail = self.default_detail if detail is None else detail
        super().__init__(self.detail)


class IncidentUnavailable(IncidentError):
    status_code = 503
    default_detail = "incidents require persistence to be enabled"


class IncidentNotFound(IncidentError):
    status_code = 404
    default_detail = "incident not found"


class DetectionNotFound(IncidentError):
    status_code = 404
    default_detail = "detection not found"


class InvalidDetection(IncidentError):
    status_code = 400


class IncidentStateError(IncidentError):
    """Illegal transition (acknowledging a resolved incident, ...)."""

    status_code = 409


class IncidentValidationError(IncidentError):
    status_code = 400


class IncidentService:
    """Create/list/transition incidents and attach analyst notes."""

    def __init__(self, store: Store | None):
        self.store = store

    # -- reads ----------------------------------------------------------------

    def list(self, status: str | None = None, limit: int = 50,
             offset: int = 0) -> dict:
        self._require_store()
        if status is not None and status not in STATUSES:
            raise IncidentValidationError(
                f"status must be one of {', '.join(STATUSES)}")
        page = self.store.list_incidents(limit=limit, offset=offset,
                                         status=status)
        for row in page["items"]:
            row["note_count"] = self.store.incident_note_count(row["id"])
        return page

    def detail(self, incident_id: int) -> dict:
        incident = self._get(incident_id)
        incident["notes"] = self.store.incident_notes(incident_id)
        incident["note_count"] = len(incident["notes"])
        return incident

    # -- create / transitions -------------------------------------------------

    def create(self, title: str, detection_id: int | None,
               actor: str) -> dict:
        self._require_store()
        title = (title or "").strip()
        if not title:
            raise IncidentValidationError("title must not be empty")
        if detection_id is not None:
            flow = self.store.get_flow(detection_id)
            if flow is None:
                raise DetectionNotFound()
            if not flow["anomaly"]:
                raise InvalidDetection(
                    f"flow {detection_id} is not a flagged detection "
                    "(detections are flows with anomaly=1)")
        return self.store.create_incident(title, detection_id, actor)

    def acknowledge(self, incident_id: int, actor: str) -> dict:
        incident = self._get(incident_id)
        if incident["status"] != STATUS_OPEN:
            raise IncidentStateError(
                f"incident is {incident['status']}; only OPEN incidents can "
                "be acknowledged")
        if not self.store.acknowledge_incident(incident_id, actor):
            raise IncidentStateError(
                "incident changed state concurrently; reload and retry")
        return self._get(incident_id)

    def resolve(self, incident_id: int, actor: str) -> dict:
        incident = self._get(incident_id)
        if incident["status"] == STATUS_RESOLVED:
            raise IncidentStateError("incident is already resolved")
        if not self.store.resolve_incident(incident_id, actor):
            raise IncidentStateError(
                "incident changed state concurrently; reload and retry")
        return self._get(incident_id)

    def add_note(self, incident_id: int, body: str, actor: str) -> dict:
        self._get(incident_id)  # 404 before writing
        body = (body or "").strip()
        if not body:
            raise IncidentValidationError("note body must not be empty")
        return self.store.add_incident_note(incident_id, actor, body)

    # -- internals ------------------------------------------------------------

    def _get(self, incident_id: int) -> dict:
        self._require_store()
        incident = self.store.get_incident(incident_id)
        if incident is None:
            raise IncidentNotFound()
        return incident

    def _require_store(self) -> None:
        if self.store is None:
            raise IncidentUnavailable()
