"""Incident layer above analyst alerts: correlation, state machine, timeline.

An incident represents *related security activity* - a cluster of alerts that
share anchors (same endpoints, SNI, graph links, threat class, temporal
proximity - see :mod:`spectra.incident_correlation`), or a single flagged
detection raised by hand.  Correlation is deliberately conservative: an
automatic path only ever *attaches* an alert to an already-open incident, an
analyst creates incidents (explicit alerts or ``correlate``), and unrelated
alerts are never merged.

State machine (every change is timeline- and audit-recorded)::

    acknowledge:    OPEN                            -> ACKNOWLEDGED
    investigate:    OPEN | ACKNOWLEDGED             -> INVESTIGATING
    resolve:        OPEN | ACKNOWLEDGED | INVESTIGATING -> RESOLVED
    reopen:         RESOLVED | FALSE_POSITIVE       -> INVESTIGATING
    false_positive: OPEN | ACKNOWLEDGED | INVESTIGATING | RESOLVED
                                                          -> FALSE_POSITIVE

State checks live here (service layer); the repository performs guarded
compare-and-swap updates underneath, and routers only translate exceptions
to HTTP.  ``RESOLVED``/``FALSE_POSITIVE`` incidents stop growing: new alerts
attach only to OPEN/INVESTIGATING/ACKNOWLEDGED incidents (``reopen`` brings
one back).  Rollups (severity, primary threat, affected entities, evidence
summary, ...) are re-derived from member alerts on every membership or
re-sighting change - see :func:`spectra.incident_correlation.rollup`.
"""

from __future__ import annotations

import logging
import time

from ..incident_correlation import auto_title, cluster, related, rollup
from ..store import Store

log = logging.getLogger("spectra.engine")

STATUS_OPEN = "OPEN"
STATUS_INVESTIGATING = "INVESTIGATING"
STATUS_ACKNOWLEDGED = "ACKNOWLEDGED"
STATUS_RESOLVED = "RESOLVED"
STATUS_FALSE_POSITIVE = "FALSE_POSITIVE"
STATUSES: tuple[str, ...] = (STATUS_OPEN, STATUS_INVESTIGATING,
                             STATUS_ACKNOWLEDGED, STATUS_RESOLVED,
                             STATUS_FALSE_POSITIVE)
#: States an active incident may be in (only these keep auto-attaching).
ACTIVE_STATUSES: tuple[str, ...] = (STATUS_OPEN, STATUS_INVESTIGATING,
                                    STATUS_ACKNOWLEDGED)

#: action -> (allowed source states, resulting state) - see module docstring.
TRANSITIONS: dict[str, tuple[tuple[str, ...], str]] = {
    "acknowledge": ((STATUS_OPEN,), STATUS_ACKNOWLEDGED),
    "investigate": ((STATUS_OPEN, STATUS_ACKNOWLEDGED), STATUS_INVESTIGATING),
    "resolve": ((STATUS_OPEN, STATUS_ACKNOWLEDGED, STATUS_INVESTIGATING),
                STATUS_RESOLVED),
    "reopen": ((STATUS_RESOLVED, STATUS_FALSE_POSITIVE), STATUS_INVESTIGATING),
    "false_positive": ((STATUS_OPEN, STATUS_ACKNOWLEDGED, STATUS_INVESTIGATING,
                        STATUS_RESOLVED), STATUS_FALSE_POSITIVE),
}

#: Default temporal window for correlation (config.incident_window_seconds).
_DEFAULT_WINDOW = 1800.0
#: Bounds: one incident, one correlate pass, one auto-attach scan.
_MAX_ALERTS_PER_INCIDENT = 200
_MAX_CORRELATE_ALERTS = 500
_MAX_ACTIVE_INCIDENTS = 50
#: Member alerts compared against a streaming alert (most recent links).
_MAX_MEMBERS_SCANNED = 10
#: Actor recorded for correlation the system performs on its own.
_SYSTEM_ACTOR = "spectra"


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


class LinkedAlertNotFound(IncidentError):
    status_code = 404
    default_detail = "alert not found"


class InvalidDetection(IncidentError):
    status_code = 400


class IncidentStateError(IncidentError):
    """Illegal transition (acknowledging a resolved incident, ...)."""

    status_code = 409


class AlertClaimed(IncidentError):
    """The alert already belongs to a different incident (single owner)."""

    status_code = 409
    default_detail = "alert already belongs to another incident"


class IncidentValidationError(IncidentError):
    status_code = 400


class IncidentService:
    """Correlate alerts into incidents, run the state machine, keep history."""

    def __init__(self, store: Store | None, config=None, *,
                 failures=None, audit=None, graph_provider=None) -> None:
        self.store = store
        self.config = config
        self.failures = failures
        self.audit = audit
        #: Callable returning the live CorrelationGraph (or None) - passed by
        #: the pipeline so the service never imports the correlation service.
        self._graph_provider = graph_provider

    # -- reads ----------------------------------------------------------------

    def list(self, status: str | None = None, limit: int = 50,
             offset: int = 0, severity: str | None = None,
             threat_type: str | None = None,
             since: float | None = None, until: float | None = None) -> dict:
        self._require_store()
        if status is not None and status not in STATUSES:
            raise IncidentValidationError(
                f"status must be one of {', '.join(STATUSES)}")
        page = self.store.list_incidents(limit=limit, offset=offset,
                                         status=status, severity=severity,
                                         threat_type=threat_type,
                                         since=since, until=until)
        for row in page["items"]:
            row["note_count"] = self.store.incident_note_count(row["id"])
        return page

    def detail(self, incident_id: int) -> dict:
        """Incident with its notes, member alerts, and ordered timeline."""
        incident = self._get(incident_id)
        incident["notes"] = self.store.incident_notes(incident_id)
        incident["note_count"] = len(incident["notes"])
        incident["alerts"] = self.store.get_incident_alerts(incident_id)
        incident["timeline"] = self.store.incident_events(incident_id)
        return incident

    # -- create / correlate / attach -------------------------------------------

    def create(self, title: str, detection_id: int | None, actor: str,
               *, alert_ids: list[str] | None = None,
               summary: str | None = None) -> dict:
        """Open an incident from a detection and/or hand-picked alerts.

        Explicit alert selection is analyst judgment (not blind correlation),
        so membership is accepted as given; rollups are derived afterwards.
        An empty title is allowed only when alerts can name the incident.
        """
        self._require_store()
        title = (title or "").strip()
        if not title and not alert_ids:
            raise IncidentValidationError("title must not be empty")
        if detection_id is not None:
            flow = self.store.get_flow(detection_id)
            if flow is None:
                raise DetectionNotFound()
            if not flow["anomaly"]:
                raise InvalidDetection(
                    f"flow {detection_id} is not a flagged detection "
                    "(detections are flows with anomaly=1)")
        alerts = self._load_alerts(alert_ids)
        if not title:
            title = auto_title(alerts)
        incident = self._create_with(
            title, detection_id, alerts, actor,
            source="manual", summary=summary)
        self._audit("incident.create",
                    {"id": incident["id"], "title": incident["title"],
                     "detection_id": incident["detection_id"],
                     "alert_count": len(alerts)},
                    actor)
        return incident

    def correlate(self, actor: str, *,
                  alert_ids: list[str] | None = None) -> dict:
        """Cluster unassigned alerts conservatively; one incident per cluster.

        Without ``alert_ids`` every unassigned, unresolved alert is
        considered (bounded); with them, only the analyst's selection is.
        Clusters of one are never promoted to incidents - they come back in
        ``ungrouped`` so unrelated activity stays unmerged.  Each alert's
        link records the signals that justified its cluster.
        """
        self._require_store()
        if alert_ids is not None:
            alerts = self._load_alerts(alert_ids)
        else:
            alerts = self.store.unassigned_alerts(_MAX_CORRELATE_ALERTS)
        window, graph = self._window(), self._graph()
        groups = cluster(alerts, window=window, graph=graph)
        created: list[dict] = []
        ungrouped: list[str] = []
        for group in groups:
            if len(group) < 2:
                ungrouped.extend(str(a.get("alert_id")) for a in group)
                continue
            incident = self._create_from_group(group, actor, window, graph)
            created.append(incident)
        self._audit("incident.correlate",
                    {"created": [i["id"] for i in created],
                     "grouped": sum(i["alert_count"] for i in created),
                     "ungrouped": len(ungrouped)},
                    actor)
        return {"created": created, "clusters": len(created),
                "considered": len(alerts), "ungrouped": ungrouped}

    def attach(self, incident_id: int, alert_ids: list[str],
               actor: str) -> dict:
        """Add hand-picked alerts to an active incident (manual relation)."""
        self._require_store()
        incident = self._get(incident_id)
        if incident["status"] not in ACTIVE_STATUSES:
            raise IncidentStateError(
                f"incident is {incident['status']}; reopen it before "
                "attaching alerts")
        alerts = self._load_alerts(alert_ids)
        for alert in alerts:
            owner = self.store.incident_for_alert(alert["alert_id"])
            if owner is not None and owner != incident_id:
                raise AlertClaimed(
                    f"alert {alert['alert_id']} already belongs to incident "
                    f"{owner}")
        linked: list[str] = []
        for alert in alerts:
            outcome = self._link(incident_id, alert, actor, source="manual",
                                 reason=f"attached by {actor}")
            if outcome:
                linked.append(alert["alert_id"])
        if linked:
            self._refresh_rollups(incident_id)
            self._audit("incident.alert_add",
                        {"id": incident_id, "alert_ids": linked,
                         "source": "manual"},
                        actor)
        return self.detail(incident_id)

    # -- state machine ----------------------------------------------------------

    def acknowledge(self, incident_id: int, actor: str) -> dict:
        return self._transition(incident_id, "acknowledge", actor)

    def investigate(self, incident_id: int, actor: str) -> dict:
        return self._transition(incident_id, "investigate", actor)

    def resolve(self, incident_id: int, actor: str) -> dict:
        return self._transition(incident_id, "resolve", actor)

    def reopen(self, incident_id: int, actor: str) -> dict:
        return self._transition(incident_id, "reopen", actor)

    def mark_false_positive(self, incident_id: int, actor: str) -> dict:
        """Record that the correlated activity was assessed as benign."""
        return self._transition(incident_id, "false_positive", actor)

    def _transition(self, incident_id: int, action: str, actor: str) -> dict:
        self._require_store()
        from_states, to_state = TRANSITIONS[action]
        incident = self._get(incident_id)
        current = incident["status"]
        if current not in from_states:
            raise IncidentStateError(self._transition_error(action, current))
        now = time.time()
        extra = None
        if action == "acknowledge":
            extra = {"acknowledged_by": actor, "acknowledged_at": now}
        elif action == "resolve":
            extra = {"resolved_by": actor, "resolved_at": now}
        if not self.store.transition_incident(
                incident_id, from_states, status=to_state, actor=actor,
                extra=extra):
            raise IncidentStateError(
                "incident changed state concurrently; reload and retry")
        self.store.add_incident_event(
            incident_id, "status_changed", actor,
            {"from": current, "to": to_state, "action": action}, ts=now)
        self._audit(f"incident.{action}",
                    {"id": incident_id, "from": current, "to": to_state},
                    actor)
        return self._get(incident_id)

    @staticmethod
    def _transition_error(action: str, current: str) -> str:
        """Legacy-stable wording for the two transitions tests pin down."""
        if action == "acknowledge":
            return (f"incident is {current}; only OPEN incidents can "
                    "be acknowledged")
        if action == "resolve" and current == STATUS_RESOLVED:
            return "incident is already resolved"
        if action == "resolve" and current == STATUS_FALSE_POSITIVE:
            return ("incident is FALSE_POSITIVE; reopen it before "
                    "resolving")
        return f"cannot {action} a {current} incident"

    def add_note(self, incident_id: int, body: str, actor: str) -> dict:
        self._get(incident_id)  # 404 before writing
        body = (body or "").strip()
        if not body:
            raise IncidentValidationError("note body must not be empty")
        note = self.store.add_incident_note(incident_id, actor, body)
        self.store.add_incident_event(
            incident_id, "note_added", actor, {"note_id": note.get("id")})
        self._audit("incident.note",
                    {"incident_id": incident_id, "note_id": note.get("id")},
                    actor)
        return note

    # -- auto-attach (bus listener on alert events; never raises) ---------------

    def observe_alert(self, alert: dict) -> None:
        """Feed one new/updated alert to the correlation layer.

        Called from the engine's event bus after the alert row is durable.
        An already-linked alert refreshes its incident's rollups (re-sightings
        advance ``last_seen``/severity); an unlinked, unresolved alert joins
        the single best-matching **active** incident whose member signals
        reach the correlation threshold, and otherwise nothing happens - no
        incident is ever created from here.  Failures are counted, never
        raised (this runs on the publication thread).
        """
        try:
            if self.store is None or not alert:
                return
            alert_id = str(alert.get("alert_id") or "")
            if not alert_id:
                return
            owner = self.store.incident_for_alert(alert_id)
            if owner is not None:
                self._refresh_rollups(owner)
                return
            if alert.get("status") == "RESOLVED":
                return  # dismissed alerts never start new groupings
            window, graph = self._window(), self._graph()
            try:
                first = float(alert.get("first_seen") or 0.0)
                last = float(alert.get("last_seen") or first)
            except (TypeError, ValueError):
                return
            best: tuple[float, int, list[str]] | None = None
            candidates = self.store.active_incidents(
                first - window, last + window, limit=_MAX_ACTIVE_INCIDENTS)
            for incident in candidates:
                incident_id = int(incident["id"])
                for member in self._sample_members(incident_id):
                    ok, score, signals = related(
                        alert, member, window=window, graph=graph)
                    if ok and (best is None or score > best[0]):
                        best = (score, incident_id, signals)
            if best is None:
                return
            score, incident_id, signals = best
            outcome = self._link(incident_id, alert, _SYSTEM_ACTOR,
                                 source="auto",
                                 reason="; ".join(signals), score=score)
            if outcome:
                self._refresh_rollups(incident_id)
                self._audit("incident.alert_add",
                            {"id": incident_id, "alert_id": alert_id,
                             "source": "auto", "score": score},
                            _SYSTEM_ACTOR)
        except Exception as exc:  # noqa: BLE001 - never break publication
            self._record_failure(exc)

    def _sample_members(self, incident_id: int) -> list[dict]:
        """Bounded set of member alerts to compare a streaming alert against."""
        ids = self.store.incident_alert_ids(incident_id)[-_MAX_MEMBERS_SCANNED:]
        members = []
        for alert_id in ids:
            alert = self.store.get_alert(alert_id)
            if alert is not None:
                members.append(alert)
        return members

    # -- internals --------------------------------------------------------------

    def _create_from_group(self, group: list[dict], actor: str,
                           window: float, graph) -> dict:
        """Create one incident from a correlated cluster (reasons per alert)."""
        threats = sorted({str(a.get("threat_type") or "?") for a in group})
        incident = self._create_with(
            auto_title(group), None, group, actor, source="correlate",
            summary=f"Correlated from {len(group)} related alerts "
                    f"({', '.join(threats)}).",
            reason_of=lambda alert: self._cluster_reason(
                alert, group, window, graph))
        self._audit("incident.create",
                    {"id": incident["id"], "title": incident["title"],
                     "detection_id": None, "alert_count": len(group),
                     "source": "correlate"},
                    actor)
        return incident

    @staticmethod
    def _cluster_reason(alert: dict, members: list[dict],
                        window: float, graph) -> str:
        """Best-scoring pair's signals as the link reason (or the anchor)."""
        if alert is members[0]:
            return "cluster anchor"
        best: tuple[float, list[str]] = (0.0, [])
        for member in members:
            if member is alert:
                continue
            ok, score, signals = related(alert, member,
                                         window=window, graph=graph)
            if score > best[0]:
                best = (score, signals)
        return "; ".join(best[1]) if best[1] else "correlated"

    def _create_with(self, title: str, detection_id: int | None,
                     alerts: list[dict], actor: str, *, source: str,
                     summary: str | None = None,
                     reason_of=None) -> dict:
        """Insert the incident row, link alerts, roll up, timeline it."""
        incident = self.store.create_incident(title, detection_id, actor)
        incident_id = int(incident["id"])
        self.store.add_incident_event(
            incident_id, "created", actor,
            {"alert_count": len(alerts), "detection_id": detection_id})
        for alert in alerts:
            reason = reason_of(alert) if reason_of else \
                f"selected by {actor}" if source == "manual" else "correlated"
            self._link(incident_id, alert, actor, source=source, reason=reason)
        if alerts:
            self._refresh_rollups(incident_id)
        if summary:
            self.store.set_incident_aggregates(incident_id,
                                               {"summary": summary})
        return self._get(incident_id)

    def _link(self, incident_id: int, alert: dict, actor: str, *,
              source: str, reason: str,
              score: float | None = None) -> bool:
        """Persist one membership + timeline entry; True when it was new."""
        outcome = self.store.link_incident_alert(
            incident_id, alert["alert_id"], source=source, added_by=actor,
            reason=reason, score=score)
        if outcome == "claimed":
            raise AlertClaimed(
                f"alert {alert['alert_id']} already belongs to incident "
                f"{self.store.incident_for_alert(alert['alert_id'])}")
        if outcome != "linked":
            return False
        data = {"alert_id": alert["alert_id"], "source": source,
                "reason": reason}
        if score is not None:
            data["score"] = score
        self.store.add_incident_event(incident_id, "alert_added", actor, data)
        return True

    def _refresh_rollups(self, incident_id: int) -> None:
        """Re-derive incident fields from member alerts (idempotent)."""
        if self.store is None:
            return
        alerts = self.store.get_incident_alerts(incident_id)
        if not alerts:
            return  # detection-only incident: nothing to roll up
        fields = rollup(alerts, graph=self._graph())
        self.store.set_incident_aggregates(incident_id, fields)

    def _load_alerts(self, alert_ids: list[str] | None) -> list[dict]:
        """Validate + hydrate alerts (order kept, duplicates dropped)."""
        if not alert_ids:
            return []
        if len(alert_ids) > _MAX_ALERTS_PER_INCIDENT:
            raise IncidentValidationError(
                f"at most {_MAX_ALERTS_PER_INCIDENT} alerts per incident")
        alerts: list[dict] = []
        seen: set[str] = set()
        for raw_id in alert_ids:
            alert_id = str(raw_id or "").strip()
            if not alert_id or alert_id in seen:
                continue
            seen.add(alert_id)
            alert = self.store.get_alert(alert_id)
            if alert is None:
                raise LinkedAlertNotFound(f"alert {alert_id} not found")
            alerts.append(alert)
        return alerts

    def _window(self) -> float:
        if self.config is None:
            return _DEFAULT_WINDOW
        try:
            return float(self.config.incident_window_seconds)
        except (AttributeError, TypeError, ValueError):
            return _DEFAULT_WINDOW

    def _graph(self):
        if self._graph_provider is None:
            return None
        try:
            return self._graph_provider()
        except Exception:  # noqa: BLE001 - correlation must not break actions
            return None

    def _audit(self, kind: str, payload: dict, actor: str) -> None:
        """Append to the hash-chained audit log (never raises)."""
        if self.audit is None:
            return
        try:
            self.audit.append(kind, payload, actor=actor)
        except Exception as exc:  # noqa: BLE001 - audit must not undo actions
            self._record_failure(exc)

    def _record_failure(self, exc: BaseException) -> None:
        if self.failures is not None:
            self.failures.record("incidents", exc)
        else:  # pragma: no cover - pipeline always provides the tracker
            log.warning("incident layer failure: %s", exc)

    def _get(self, incident_id: int) -> dict:
        self._require_store()
        incident = self.store.get_incident(incident_id)
        if incident is None:
            raise IncidentNotFound()
        return incident

    def _require_store(self) -> None:
        if self.store is None:
            raise IncidentUnavailable()


__all__ = [
    "ACTIVE_STATUSES",
    "AlertClaimed",
    "DetectionNotFound",
    "IncidentError",
    "IncidentNotFound",
    "IncidentStateError",
    "IncidentUnavailable",
    "IncidentValidationError",
    "IncidentService",
    "LinkedAlertNotFound",
    "STATUSES",
    "STATUS_ACKNOWLEDGED",
    "STATUS_FALSE_POSITIVE",
    "STATUS_INVESTIGATING",
    "STATUS_OPEN",
    "STATUS_RESOLVED",
    "TRANSITIONS",
]
