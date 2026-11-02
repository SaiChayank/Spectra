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


#: Time-slice width (seconds) of the candidate index.  A label is registered
#: in every slice its tolerance-widened window touches; a flow only ever
#: scans its own slice (docs/evaluation.md §5).
SLICE_S = 60.0

#: Windows wider than this many slices (coarse hand-written rows spanning
#: hours/days) are not fanned out slice-by-slice - they go on a small
#: per-pair linear list that every flow of that pair re-checks.  Real dataset
#: rows are per-flow (short), so this list stays tiny; correctness never
#: depends on it being small.
_MAX_SLICES = 64


def _build_label_index(labels: list[LabelRow], tolerance_s: float):
    """Bucket labels by endpoint pair + time slice for candidate pruning.

    Soundness: ``label_matches_flow`` can only return non-``inf`` when the
    unordered host pair matches AND the flow start lies inside
    ``[t_start - tol, t_end + tol]``; ``floor`` is monotonic, so such a flow
    always falls in a slice this label was registered in.  Anything the index
    skips provably returns ``inf`` anyway - every candidate still goes through
    :func:`label_matches_flow`, so ports/proto/tolerance semantics are
    untouched.  Inverted windows (``t_end < t_start``) match nothing and are
    skipped, exactly like the naive scan.

    Returns ``(slices, longs)``: pair -> slice -> label indices, and pair ->
    label indices for windows too wide to fan out.
    """
    slices: dict[frozenset[str], dict[int, list[int]]] = {}
    longs: dict[frozenset[str], list[int]] = {}
    for li, label in enumerate(labels):
        lo = label.t_start - tolerance_s
        hi = label.t_end + tolerance_s
        s0 = int(lo // SLICE_S)
        s1 = int(hi // SLICE_S)
        if s1 < s0:
            continue                       # inverted window: never matches
        pair = frozenset((label.src_ip, label.dst_ip))
        if s1 - s0 + 1 > _MAX_SLICES:
            longs.setdefault(pair, []).append(li)
            continue
        per_pair = slices.setdefault(pair, {})
        for s in range(s0, s1 + 1):
            per_pair.setdefault(s, []).append(li)
    return slices, longs


def make_lookup(labels: list[LabelRow],
                tolerance_s: float = DEFAULT_TOLERANCE_S):
    """Build a per-flow label lookup sharing :func:`join_flows`' winner rule.

    Returns a callable ``f(flow) -> (dist, rank, li) | None``: the winning
    candidate is the minimum over ``(dist, rank, li)`` - identical to the
    batch join (see :func:`join_flows`), so a streaming consumer and the
    evaluation join can never disagree about which label a flow gets.
    ``None`` means the flow joins nothing.
    """
    from ..threats import THREAT_TYPES

    order = {c: i for i, c in enumerate(THREAT_TYPES)}
    order["METADATA_INVISIBLE"] = len(order)
    slices, longs = _build_label_index(labels, tolerance_s)

    def lookup(flow: ScoredFlow) -> tuple[float, int, int] | None:
        pair = frozenset((flow.src_ip, flow.dst_ip))
        per_pair = slices.get(pair)
        window: tuple[int, ...] = ()
        if per_pair is not None:
            window = per_pair.get(int(flow.start_ts // SLICE_S), ())
        long = longs.get(pair, ())
        # min over (dist, rank, li): exactly the naive ascending scan's pick.
        best: tuple[float, int, int] | None = None
        for group in (window, long):
            for li in group:
                dist = label_matches_flow(labels[li], flow, tolerance_s)
                if dist == float("inf"):
                    continue
                rank = order.get(labels[li].mapped_category, len(order))
                key = (dist, rank, li)
                if best is None or key < best:
                    best = key
        return best

    return lookup


def join_flows(flows: list[ScoredFlow], labels: list[LabelRow],
               tolerance_s: float = DEFAULT_TOLERANCE_S) -> JoinResult:
    """Join scored flows to ground-truth labels (docs/evaluation.md §5).

    Every flow is kept (even unjoined ones - they are the unlabeled pool);
    on multiple matching labels the smallest time distance wins, ties break
    on ``THREAT_TYPES`` order then ``METADATA_INVISIBLE``, and a full tie
    falls to the first row in list order (min over ``(dist, rank, li)`` -
    identical to scanning rows ascending and replacing only on strict
    improvement).

    The scan is indexed: a label can only match a flow whose unordered host
    pair equals the label's (``label_matches_flow`` compares IPs literally in
    either direction), and only when the flow's start falls inside the
    tolerance-widened window ``[t_start - tol, t_end + tol]``.  Labels are
    therefore bucketed by endpoint pair and registered in every 60s time
    slice their window touches, so each flow examines just its own slice -
    ~constant candidate work instead of O(F x L) full comparisons (the CTU-13
    corpora are ~100k+ label rows; correctness against the naive full scan is
    pinned by tests/test_eval.py).

    Still authoritative: every candidate runs through
    :func:`label_matches_flow`, so ports/proto/tolerance semantics are
    unchanged - the index only prunes rows that provably cannot match.
    The candidate scan itself lives in :func:`make_lookup`, shared with the
    streaming ``eval train`` baseline selection.
    """
    lookup = make_lookup(labels, tolerance_s)

    joins: list[FlowJoin] = []
    hit_labels: set[int] = set()

    for flow in flows:
        best = lookup(flow)
        if best is not None:
            hit_labels.add(best[2])
            joins.append(FlowJoin(flow=flow, label=labels[best[2]],
                                  time_distance=best[0]))
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
