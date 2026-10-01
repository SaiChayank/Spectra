"""Internal domain models shared by the application services.

Two kinds of model live here:

* **Structural records** (``TypedDict``) name the dict payloads that already
  flow through the pipeline, over the API and into SQLite.  They document and
  type-check those shapes without changing the runtime representation, so no
  call site and no wire contract has to change.
* **Stateful objects** (``dataclass``) cluster genuine object state that was
  previously spread over loose engine attributes: a capture run's identity
  plus its committed evidence, and a trained model artifact's identity.

This module imports nothing from the rest of Spectra, so every service can
depend on it without risking a circular import.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, TypedDict


# -- structural records (dicts on the wire, in SQLite, and in events) --------


class SystemEvent(TypedDict):
    """Event published on the :class:`EventBus` and forwarded over WebSocket."""

    type: str
    data: dict


class FlowRecord(TypedDict, total=False):
    """A completed conversation, enriched with module verdicts.

    Keys produced by :meth:`parse.flow.Flow.record()` plus per-flow enrichment
    added by the hot path (score, slice, bio/PQC verdicts).  ``total=False``
    because individual keys are optional depending on traffic (e.g. only TLS
    flows carry ``tls_version``).
    """

    ts: float
    last_ts: float
    proto: str
    src: str
    dst: str
    sni: str | None
    tls_version: str | None
    quic_version: str | None
    packets: int
    bytes: int
    duration: float
    score: float | None
    anomaly: bool
    slice: str
    immune: dict | None
    snn_score: float | None
    swarm_flag: bool | None
    pqc: dict | None
    #: Anomalies only: explainable threat verdict (spectra.threats) —
    #: ``threat_type``/``confidence`` plus supporting/contradicting signals.
    threat: dict | None
    #: Anomalies that produced an alert: the alert's id (reverse link; the
    #: alert itself references the flow — see spectra.services.threat_alerts).
    alert_id: str | None


class DetectionRecord(TypedDict, total=False):
    """An anomalous flow as stored in the detection buffer and emitted on WS."""

    score: float | None
    reasons: list
    detected_at: float


class AlertRecord(TypedDict, total=False):
    """Payload of an ``evasion``/``drift`` event and its audit entry."""

    alert_type: str
    available: bool
    n: int
    psi: float
    level: str
    near_miss_rate: float
    reasons: list


class EvidenceItem(TypedDict, total=False):
    """One technical evidence item on an alert (machine + human readable).

    ``key``/``value``/``unit`` are the machine-readable form (e.g.
    ``periodicity = 30.2 s``); ``label``/``detail`` phrase it for an analyst.
    ``value`` is ``None`` when the signal carries no direct measurement.
    """

    key: str
    value: float | str | bool | None
    unit: str | None
    label: str
    detail: str


class Evidence(TypedDict, total=False):
    """Structured evidence document carried by :class:`ThreatAlert`."""

    supporting: list[EvidenceItem]
    contradicting: list[EvidenceItem]
    #: One plain-sentence analyst explanation of the behaviour.
    summary: str


class ThreatAlert(TypedDict, total=False):
    """The analyst-facing alert, separate from the raw detection.

    Carries the four concepts side by side, deliberately independent:
    ``anomaly_score`` (detector percentile), ``confidence`` (classifier
    evidence share), ``severity`` (ordinal triage level from
    :mod:`spectra.severity`, with its derivation in ``severity_factors``),
    and ``threat_type`` (behaviour category).  ``metadata`` holds related
    flow context, ``module_annotations`` the per-module verdicts.
    """

    #: Stable id (``alrt_<hex>``); also stamped onto the source flow record.
    alert_id: str
    #: Source flow row id when its durable id is known at alert time
    #: (batched flow writes often leave this ``None`` — the flow row carries
    #: ``alert_id`` as the reverse link either way).
    flow_id: int | None
    capture_id: int | None
    #: Wall-clock time the alert was created.
    timestamp: float
    #: Flow-observation time of the first / latest grouped sighting.
    first_seen: float
    last_seen: float
    updated_at: float
    source: str
    destination: str
    protocol: str
    threat_type: str
    anomaly_score: float | None
    confidence: float
    #: LOW | MEDIUM | HIGH | CRITICAL (ordinal — see spectra.severity).
    severity: str
    #: Every severity input's contribution, human-readable.
    severity_factors: list[str]
    model_id: str | None
    model_version: str | None
    evidence: Evidence
    #: Related flow context (sni, ports, size, sector, slice, ...).
    metadata: dict
    #: Per-module verdicts riding the source flow (immune/snn/swarm/pqc).
    module_annotations: dict
    #: OPEN -> ACKNOWLEDGED -> RESOLVED (terminal).
    status: str
    #: How many sightings are grouped into this alert.
    occurrences: int


class EvidenceRecord(FlowRecord, total=False):
    """A committed flow record used as a Merkle leaf in the audit chain."""


# -- stateful domain objects -------------------------------------------------


@dataclass
class CaptureSession:
    """One capture run: identity, time bounds and committed evidence.

    Replaces the loose ``_capture_id`` / ``_session_leaves`` engine attributes;
    capture writes the identity, the hot path appends evidence leaves, the
    audit trail reads both when the run ends.
    """

    capture_id: int | None = None
    mode: str | None = None
    source: str | None = None
    started_at: float | None = None
    bpf_filter: str | None = None
    leaves: list[EvidenceRecord] = field(default_factory=list)

    def begin(self, mode: str, source: str, started_at: float,
              bpf_filter: str = "") -> None:
        """Arm a fresh run: identity set, previous run's evidence dropped."""
        self.capture_id = None
        self.mode = mode
        self.source = source
        self.started_at = started_at
        self.bpf_filter = bpf_filter or None
        self.leaves = []

    def add_leaf(self, record: EvidenceRecord, cap: int) -> None:
        """Commit a flow record as evidence (bounded per session)."""
        if len(self.leaves) < cap:
            self.leaves.append(record)

    def end(self) -> None:
        """Release the store's capture row handle; evidence stays for audit."""
        self.capture_id = None


@dataclass(frozen=True)
class ModelVersion:
    """Immutable identity of a trained model artifact."""

    path: str
    trained: bool
    trained_at: float | None
    n_train: int
    n_features: int
    contamination: float
    threshold: float | None
    version: str

    @classmethod
    def from_info(cls, path: str, info: dict) -> "ModelVersion":
        return cls(
            path=path,
            trained=bool(info.get("trained")),
            trained_at=info.get("trained_at"),
            n_train=int(info.get("n_train") or 0),
            n_features=int(info.get("n_features") or 0),
            contamination=float(info.get("contamination") or 0.02),
            threshold=info.get("threshold"),
            version=str(info.get("version") or ""),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "trained": self.trained,
            "trained_at": self.trained_at,
            "n_train": self.n_train,
            "n_features": self.n_features,
            "contamination": self.contamination,
            "threshold": self.threshold,
            "version": self.version,
        }
