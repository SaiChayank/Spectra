"""Analyst alerts: correlated, persisted, streamed verdicts over detections.

An alert is the **analyst-facing object**; the detection buffer keeps the raw
per-flow anomaly record.  They stay distinct end to end: a detection says
*"the model flagged this flow, here is why"*, an alert says *"this behaviour
keeps happening, here is what it looks like, how sure we are, how urgent it
is, and what to look at first"*.  Every alert carries the four concepts side
by side, independent of each other:

=================  =======================================================
concept            meaning
=================  =======================================================
``anomaly_score``  detector percentile (how far from the training data)
``confidence``     classifier evidence share for the chosen threat type
``severity``       ordinal triage level (see :mod:`spectra.severity`)
``threat_type``    behaviour category (see :mod:`spectra.threats`)
=================  =======================================================

Grouping (correlation): sightings of the same behaviour — threat type x
protocol x endpoint pair — within ``config.alert_group_seconds`` of the
previous sighting update one open alert (``occurrences`` grows,
``last_seen`` advances, severity is re-scored with the correlation factor)
instead of creating duplicates.  A gap longer than the window, or a
RESOLVED group, starts a fresh alert.  The open-group map is bounded
(``_MAX_OPEN_GROUPS``, oldest evicted) and swept on every observation, so
memory cannot grow without cap.

Persistence: alerts are written immediately (rare next to flow rows) and
read back through :class:`spectra.store.Store`; with persistence disabled
the reads serve from the bounded in-memory groups instead.  Lifecycle
``OPEN -> ACKNOWLEDGED -> RESOLVED`` (terminal) follows the incident
pattern; the routers attribute transitions to the caller in the audit log.

Streaming: creation emits ``alert``, re-sightings and status changes emit
``alert_updated`` on the event bus, which the WebSocket forwards verbatim
(both types are skipped by the events-table publisher — the alert row is
the durable copy).
"""

from __future__ import annotations

import ipaddress
import logging
import threading
import time
import uuid
from typing import Callable

from ..config import Config
from ..evidence import build_evidence
from ..sectors import SENSITIVITY, get_classifier
from ..severity import (
    ASSET_CRITICAL,
    ASSET_INTERNAL,
    calculate_severity,
)
from ..store import Store
from ..threats import UNKNOWN
from .events import EventBus
from .resilience import FailureTracker

log = logging.getLogger("spectra.engine")

STATUS_OPEN = "OPEN"
STATUS_ACKNOWLEDGED = "ACKNOWLEDGED"
STATUS_RESOLVED = "RESOLVED"
STATUSES: tuple[str, ...] = (STATUS_OPEN, STATUS_ACKNOWLEDGED, STATUS_RESOLVED)

#: Bound on the in-memory open-group map (oldest inserted is evicted first).
_MAX_OPEN_GROUPS = 500

#: Internal destination ports whose use marks an administrative service
#: (a scan or beacon hitting one of these internally is more urgent).
_ADMIN_PORTS = frozenset({22, 23, 135, 445, 3389, 5985, 5986, 3306, 5432,
                          6379, 9200, 11211, 27017})

#: Sector sensitivity at/above which the affected asset counts as critical
#: (healthcare 1.0 / fintech 0.9 — see spectra.sectors.SENSITIVITY).
_CRITICAL_SENSITIVITY = 0.9


class ThreatAlertError(Exception):
    """Mapped to an HTTP error by the alerts router."""

    status_code = 400
    default_detail = "alert error"

    def __init__(self, detail: str | None = None):
        self.detail = self.default_detail if detail is None else detail
        super().__init__(self.detail)


class AlertNotFound(ThreatAlertError):
    status_code = 404
    default_detail = "alert not found"


class AlertStateError(ThreatAlertError):
    """Illegal transition (acknowledging a resolved alert, ...)."""

    status_code = 409


class AlertValidationError(ThreatAlertError):
    status_code = 400


def _split(addr: object) -> tuple[str, str]:
    """``"10.0.0.1:443"`` -> ``("10.0.0.1", "443")`` (IPv6-safe rpartition)."""
    if not isinstance(addr, str) or not addr:
        return "", ""
    host, sep, port = addr.rpartition(":")
    return (host, port) if sep else (addr, "")


class ThreatAlertService:
    """Raise, group, persist and stream analyst alerts over flagged flows."""

    def __init__(self, store: Store | None, config: Config,
                 events: EventBus | None = None,
                 failures: FailureTracker | None = None, *,
                 model_info: Callable[[], dict] | None = None) -> None:
        self.store = store
        self.config = config
        self.events = events
        self.failures = failures
        self._model_info = model_info
        #: group key -> open alert (bounded; guarded by ``self._lock``)
        self._open: dict[str, dict] = {}
        self._lock = threading.Lock()

    # -- hot path (publication worker) -----------------------------------------

    def observe(self, record: dict, threat: dict, *,
                score: float | None = None,
                capture_id: int | None = None) -> dict:
        """Create or update the alert for one flagged, classified flow.

        Never raises into the pipeline: persistence/streaming failures are
        recorded as ``store``/``events`` failures and the alert object is
        still returned, so the source flow keeps its ``alert_id`` back-link.
        """
        now = time.time()
        try:
            seen = float(record.get("last_ts") or record.get("start_ts")
                         or now)
        except (TypeError, ValueError):
            seen = now
        threat_type = str((threat or {}).get("threat_type") or UNKNOWN)
        ttl = float(self.config.alert_group_seconds)
        key = self._group_key(record, threat_type)

        with self._lock:
            # Flow-time sweep: groups whose last sighting left the window are
            # stale (negative gaps — out-of-order replay — are kept).
            for stale in [k for k, a in self._open.items()
                          if seen - a["last_seen"] > ttl]:
                del self._open[stale]

            existing = self._open.get(key)
            if (existing is not None
                    and existing["status"] != STATUS_RESOLVED):
                alert = self._resight(existing, score, seen, now)
            else:
                alert = self._create(record, threat, score, seen, now,
                                     capture_id, threat_type)
                self._open[key] = alert
                while len(self._open) > _MAX_OPEN_GROUPS:
                    del self._open[next(iter(self._open))]
                self._persist_insert(alert)
                self._emit("alert", alert)
            return dict(alert)

    def _create(self, record: dict, threat: dict, score: float | None,
                seen: float, now: float, capture_id: int | None,
                threat_type: str) -> dict:
        confidence = float((threat or {}).get("confidence") or 0.0)
        criticality, sector = self._asset_context(record)
        severity, factors = calculate_severity(
            threat_type=threat_type, confidence=confidence,
            anomaly_score=score, asset_criticality=criticality,
            occurrences=1)
        model_id, model_version = self._model_identity()
        return {
            "alert_id": "alrt_" + uuid.uuid4().hex[:12],
            # Durable flow id only when the store hands one back (batched
            # flow writes usually have not committed yet — the flow row
            # carries ``alert_id`` as the reverse link either way).
            "flow_id": None,
            "capture_id": capture_id,
            "timestamp": now,
            "first_seen": seen,
            "last_seen": seen,
            "updated_at": now,
            "source": str(record.get("src") or ""),
            "destination": str(record.get("dst") or ""),
            "protocol": str(record.get("proto") or ""),
            "threat_type": threat_type,
            "anomaly_score": score,
            "confidence": confidence,
            "severity": severity,
            "severity_factors": factors,
            "model_id": model_id,
            "model_version": model_version,
            "evidence": build_evidence(record, threat),
            "metadata": self._metadata(record, sector, criticality),
            "module_annotations": self._annotations(record),
            "status": STATUS_OPEN,
            "occurrences": 1,
        }

    def _resight(self, alert: dict, score: float | None, seen: float,
                 now: float) -> dict:
        """Group another sighting into the open alert (correlation)."""
        alert["occurrences"] = int(alert.get("occurrences") or 1) + 1
        if seen > alert["last_seen"]:
            alert["last_seen"] = seen
        alert["updated_at"] = now
        if score is not None and (
                alert.get("anomaly_score") is None
                or score > alert["anomaly_score"]):
            alert["anomaly_score"] = score  # intensity high-water mark
        # Severity is re-derived: the correlation factor may escalate it.
        severity, factors = calculate_severity(
            threat_type=alert["threat_type"],
            confidence=float(alert.get("confidence") or 0.0),
            anomaly_score=alert.get("anomaly_score"),
            asset_criticality=(alert.get("metadata") or {}).get(
                "asset_criticality"),
            occurrences=alert["occurrences"])
        alert["severity"] = severity
        alert["severity_factors"] = factors
        if self.store is not None:
            try:
                self.store.update_alert_group(
                    alert["alert_id"],
                    last_seen=alert["last_seen"],
                    updated_at=alert["updated_at"],
                    occurrences=alert["occurrences"],
                    anomaly_score=alert["anomaly_score"],
                    severity=alert["severity"],
                    severity_factors=alert["severity_factors"])
            except Exception as exc:  # noqa: BLE001 - never stop publication
                self._record_failure("store", exc)
        self._emit("alert_updated", alert)
        return alert

    # -- context enrichment -----------------------------------------------------

    @staticmethod
    def _group_key(record: dict, threat_type: str) -> str:
        """Behaviour identity: threat type + protocol + endpoint *hosts*.

        Hosts (not ports) so a fan-out scan groups into one alert instead of
        one per probed port.
        """
        src, _ = _split(record.get("src"))
        dst, _ = _split(record.get("dst"))
        return f"{threat_type}|{record.get('proto')}|{src}|{dst}"

    @staticmethod
    def _asset_context(record: dict) -> tuple[str | None, str]:
        """``(criticality, sector)`` for the affected asset — honest about
        what is unknown: an unclassifiable destination is ``None``, never
        assumed safe."""
        dst_host, dst_port = _split(record.get("dst"))
        sni = record.get("sni")
        sector = get_classifier().classify(sni or dst_host)
        if SENSITIVITY.get(sector, 0.4) >= _CRITICAL_SENSITIVITY:
            return ASSET_CRITICAL, sector
        try:
            internal = ipaddress.ip_address(dst_host).is_private
        except ValueError:
            internal = False  # hostname — cannot tell from the address
        if internal:
            try:
                admin_port = int(dst_port) in _ADMIN_PORTS
            except ValueError:
                admin_port = False
            if admin_port:
                return ASSET_CRITICAL, sector
            return ASSET_INTERNAL, sector
        return None, sector

    @staticmethod
    def _metadata(record: dict, sector: str,
                  criticality: str | None) -> dict:
        """Related flow context an analyst needs next to the verdict."""
        _, src_port = _split(record.get("src"))
        _, dst_port = _split(record.get("dst"))
        return {
            "sni": record.get("sni"),
            "tls_version": record.get("tls_version"),
            "quic_version": record.get("quic_version"),
            "alpn": record.get("alpn"),
            "ja3": record.get("ja3"),
            "ja4": record.get("ja4"),
            "duration": record.get("duration"),
            "packets": record.get("packets"),
            "bytes": record.get("bytes"),
            "src_port": src_port or None,
            "dst_port": dst_port or None,
            "slice": record.get("slice"),
            "sector": sector,
            "asset_criticality": criticality,
        }

    @staticmethod
    def _annotations(record: dict) -> dict:
        """Per-module verdicts riding the source flow (present ones only)."""
        return {key: record[key]
                for key in ("immune", "snn_score", "swarm_flag", "pqc")
                if record.get(key) is not None}

    def _model_identity(self) -> tuple[str | None, str | None]:
        """``(model_id, model_version)`` of the scoring model at alert time."""
        if self._model_info is None:
            return None, None
        try:
            info = self._model_info() or {}
        except Exception as exc:  # noqa: BLE001 - never break alert creation
            self._record_failure("model", exc)
            return None, None
        mid = info.get("id")
        ver = info.get("version")
        return (str(mid) if mid else None,
                str(ver) if ver is not None else None)

    # -- reads (API worker threads) ----------------------------------------------

    def list(self, status: str | None = None, threat_type: str | None = None,
             limit: int = 50, offset: int = 0) -> dict:
        if status is not None and status not in STATUSES:
            raise AlertValidationError(
                f"status must be one of {', '.join(STATUSES)}")
        limit = min(max(1, limit), 500)
        offset = max(0, offset)
        if self.store is not None:
            return self.store.list_alerts(limit=limit, offset=offset,
                                          status=status,
                                          threat_type=threat_type)
        with self._lock:
            items = sorted(self._open.values(),
                           key=lambda a: a.get("last_seen") or 0.0,
                           reverse=True)
        if status:
            items = [a for a in items if a.get("status") == status]
        if threat_type:
            items = [a for a in items if a.get("threat_type") == threat_type]
        return {"count": len(items), "offset": offset,
                "items": [dict(a) for a in items[offset:offset + limit]]}

    def get(self, alert_id: str) -> dict:
        if self.store is not None:
            row = self.store.get_alert(alert_id)
            if row is None:
                raise AlertNotFound()
            return row
        with self._lock:
            for alert in self._open.values():
                if alert.get("alert_id") == alert_id:
                    return dict(alert)
        raise AlertNotFound()

    # -- lifecycle (API worker threads) -------------------------------------------

    def acknowledge(self, alert_id: str) -> dict:
        alert = self.get(alert_id)
        if alert["status"] != STATUS_OPEN:
            raise AlertStateError(
                f"alert is {alert['status']}; only OPEN alerts can be "
                "acknowledged")
        return self._transition(alert_id, STATUS_ACKNOWLEDGED)

    def resolve(self, alert_id: str) -> dict:
        alert = self.get(alert_id)
        if alert["status"] == STATUS_RESOLVED:
            raise AlertStateError("alert is already resolved")
        return self._transition(alert_id, STATUS_RESOLVED)

    def _transition(self, alert_id: str, status: str) -> dict:
        now = time.time()
        if self.store is not None:
            done = (self.store.acknowledge_alert(alert_id)
                    if status == STATUS_ACKNOWLEDGED
                    else self.store.resolve_alert(alert_id))
            if not done:
                raise AlertStateError(
                    "alert changed state concurrently; reload and retry")
        alert = self.get(alert_id)
        alert["status"] = status
        alert["updated_at"] = now
        with self._lock:
            for open_alert in self._open.values():
                if open_alert.get("alert_id") == alert_id:
                    open_alert["status"] = status
                    open_alert["updated_at"] = now
                    break
        self._emit("alert_updated", alert)
        return alert

    # -- infrastructure ------------------------------------------------------------

    def _persist_insert(self, alert: dict) -> None:
        if self.store is None:
            return
        try:
            self.store.insert_alert(alert)
        except Exception as exc:  # noqa: BLE001 - never stop publication
            self._record_failure("store", exc)

    def _emit(self, event_type: str, alert: dict) -> None:
        if self.events is None:
            return
        try:
            self.events.emit({"type": event_type, "data": dict(alert)})
        except Exception as exc:  # noqa: BLE001 - never stop publication
            self._record_failure("events", exc)

    def _record_failure(self, component: str, exc: BaseException) -> None:
        if self.failures is not None:
            self.failures.record(component, exc)
        else:  # pragma: no cover - pipeline always provides the tracker
            log.warning("%s failure in alert layer: %s", component, exc)


__all__ = [
    "AlertNotFound",
    "AlertStateError",
    "AlertValidationError",
    "STATUSES",
    "STATUS_ACKNOWLEDGED",
    "STATUS_OPEN",
    "STATUS_RESOLVED",
    "ThreatAlertError",
    "ThreatAlertService",
]
