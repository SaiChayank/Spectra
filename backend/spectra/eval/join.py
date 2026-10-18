"""Flow-to-label join: which scored flows belong to which ground truth.

Implements ``docs/evaluation.md`` §5.  Inputs are the scored flow dicts the
pipeline already produces (``Flow.record()`` + score/anomaly/threat keys)
and the :class:`~spectra.eval.labels.LabelRow` list; the output is a join
result with per-flow label assignments and the counters the metrics engine
needs.

Pure logic (no pipeline imports) so it is unit-testable on hand-built dicts.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .labels import ANY, LabelRow

#: Default time tolerance around a label window (seconds).
DEFAULT_TOLERANCE_S = 10.0


@dataclass(frozen=True)
class ScoredFlow:
    """Minimal view of one scored pipeline flow the join consumes."""

    start_ts: float
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    proto: str              # "TCP" | "UDP" (Flow.record() names)
    score: float | None
    anomaly: bool
    #: Classified threat category (only for anomalies; None otherwise).
    threat_type: str | None = None
    #: True when the flow yielded usable TLS/QUIC metadata or a valid
    #: transport record (parser-coverage accounting).
    parseable: bool = True

    @classmethod
    def from_record(cls, rec: dict, anomaly: bool | None = None) -> "ScoredFlow":
        """Build from a pipeline flow record (``Flow.record()`` shape).

        ``src``/``dst`` are ``"ip:port"`` strings; the port split handles
        IPv6 literals by splitting on the *last* colon.
        """
        def split(ep: str) -> tuple[str, int]:
            host, _, port = ep.rpartition(":")
            return host, int(port)

        src_ip, src_port = split(str(rec.get("src", ":0")))
        dst_ip, dst_port = split(str(rec.get("dst", ":0")))
        threat = rec.get("threat") or {}
        return cls(
            start_ts=float(rec.get("start_ts") or rec.get("ts") or 0.0),
            src_ip=src_ip, dst_ip=dst_ip,
            src_port=src_port, dst_port=dst_port,
            proto=str(rec.get("proto", "TCP")).upper(),
            score=rec.get("score"),
            anomaly=bool(rec.get("anomaly") if anomaly is None else anomaly),
            threat_type=threat.get("threat_type"),
        )


@dataclass
class FlowJoin:
    """One flow's ground-truth assignment (None when it joined nothing)."""

    flow: ScoredFlow
    label: LabelRow | None = None
    time_distance: float = field(default=float("inf"))

    @property
    def joined(self) -> bool:
        return self.label is not None


@dataclass
class JoinResult:
    """Everything the metrics engine needs from one evaluation join."""

    #: Per-flow assignments, in flow order.
    joins: list[FlowJoin]
    #: Anomalous flows that joined only METADATA_INVISIBLE labels.
    invisible_joined: int = 0
    #: Label rows never hit by an anomalous flow (per-category counts live in
    #: metrics; this is the raw list for report inspection).
    missed_labels: list[LabelRow] = field(default_factory=list)

    @property
    def flows(self) -> list[ScoredFlow]:
        return [j.flow for j in self.joins]


def _port_ok(want: int | None, have: int) -> bool:
    return want is None or want == have


def _proto_ok(want: str, have: str) -> bool:
    return want == ANY or want == have.upper()


def label_matches_flow(label: LabelRow, flow: ScoredFlow,
                       tolerance_s: float = DEFAULT_TOLERANCE_S) -> float:
    """Time distance when the flow joins the label, else ``inf``.

    Endpoint pair matches in either direction (label rows are unordered
    host pairs), ports/proto per the ``*`` convention, and the flow's
    ``start_ts`` must fall inside ``[t_start - tolerance, t_end + tolerance]``
    (docs/evaluation.md §5.1-5.2) — beyond that the flow does not join at
    all (``inf``).  Inside the window the returned distance is how far the
    flow start is from the inner label window (0.0 when strictly inside) and
    is used only to pick the closest label on multi-joins.
    """
    fwd = (label.src_ip == flow.src_ip and label.dst_ip == flow.dst_ip
           and _port_ok(label.src_port, flow.src_port)
           and _port_ok(label.dst_port, flow.dst_port))
    rev = (label.src_ip == flow.dst_ip and label.dst_ip == flow.src_ip
           and _port_ok(label.src_port, flow.dst_port)
           and _port_ok(label.dst_port, flow.src_port))
    if not (fwd or rev):
        return float("inf")
    if not _proto_ok(label.proto, flow.proto):
        return float("inf")

    if flow.start_ts < label.t_start - tolerance_s:
        return float("inf")          # beyond tolerance: no match at all
    if flow.start_ts > label.t_end + tolerance_s:
        return float("inf")
    # inside the tolerance window: distance to the inner (label) window
    # breaks ties between overlapping labels (0.0 when strictly inside)
    if flow.start_ts < label.t_start:
        return label.t_start - flow.start_ts
    if flow.start_ts > label.t_end:
        return flow.start_ts - label.t_end
    return 0.0


def join_flows(flows: list[ScoredFlow], labels: list[LabelRow],
               tolerance_s: float = DEFAULT_TOLERANCE_S) -> JoinResult:
    """Join scored flows to ground-truth labels (docs/evaluation.md §5).

    Every flow is kept (even unjoined ones - they are the unlabeled pool);
    on multiple matching labels the smallest time distance wins, ties break
    on ``THREAT_TYPES`` order then ``METADATA_INVISIBLE``.
    """
    from ..threats import THREAT_TYPES

    order = {c: i for i, c in enumerate(THREAT_TYPES)}
    order["METADATA_INVISIBLE"] = len(order)

    joins: list[FlowJoin] = []
    hit_labels: set[int] = set()

    for flow in flows:
        best_idx: int | None = None
        best_dist = float("inf")
        best_rank = len(order)
        for li, label in enumerate(labels):
            dist = label_matches_flow(label, flow, tolerance_s)
            if dist == float("inf"):
                continue
            rank = order.get(label.mapped_category, len(order))
            if best_idx is None or (dist, rank) < (best_dist, best_rank):
                best_idx, best_dist, best_rank = li, dist, rank
        if best_idx is not None:
            hit_labels.add(best_idx)
            joins.append(FlowJoin(flow=flow, label=labels[best_idx],
                                  time_distance=best_dist))
        else:
            joins.append(FlowJoin(flow=flow))

    missed = [lab for i, lab in enumerate(labels)
              if i not in hit_labels and not lab.benign]
    invisible = sum(
        1 for j in joins
        if j.flow.anomaly and j.label is not None
        and j.label.mapped_category == "METADATA_INVISIBLE")
    return JoinResult(joins=joins, invisible_joined=invisible,
                      missed_labels=missed)
