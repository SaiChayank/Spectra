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
