"""Evaluation runner: the real pipeline offline, joined to ground truth.

Streams ``stream_flows`` (the same offline reader the CLI and API use) over
a PCAP, scoring each flow as it completes with an explicit
:class:`SpectraDetector`, applies the production threat classifier to
anomalies, then joins predictions to label rows and computes metrics.  No
live serving state is touched and no database is required, so an evaluation
is reproducible from artifact + inputs alone.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

import numpy as np

from ..features.extractor import extract_features
from ..threats import classify_threat
from .join import DEFAULT_TOLERANCE_S, ScoredFlow, join_flows, make_lookup
from .labels import LabelRow
from .metrics import compute_metrics, parser_coverage
from .report import build_report

log = logging.getLogger("spectra.eval")

#: Ports whose flows are expected to carry a TLS/QUIC handshake; a flow on
#: these ports without parsed handshake metadata counts against parser
#: coverage (this is how truncated captures like MAWI show up honestly).
TLS_PORTS: frozenset[int] = frozenset({443, 853})


@dataclass
class EvalParams:
    """Run parameters (stamped into the report)."""

    idle_timeout: float = 30.0
    join_tolerance_s: float = DEFAULT_TOLERANCE_S
    contamination: float | None = None
    max_flows: int = 250_000


def _parseable(flow) -> bool:
    """True when the flow yielded usable metadata for its class.

    Handshake parsed (TLS or QUIC) -> usable.  Otherwise: flows *not*
    expected to handshake (non-TLS ports) are fine as plain transport
    records; flows on TLS-ish ports without a parsed handshake count as
    unparseable (truncated capture or segmentation loss).
    """
    if flow.client_tls is not None or flow.server_tls is not None:
        return True
    if flow.quic is not None:
        return True
    if flow.src_port in TLS_PORTS or flow.dst_port in TLS_PORTS:
        return False
    return True


def score_one(flow, detector, window) -> ScoredFlow:
    """Score one completed flow against the shared classifier context window.

    The single-flow core of :func:`score_flows`; extracting it lets the
    streaming evaluation path score inside ``FlowTracker.on_complete`` (the
    Flow dies right after the callback returns, so a multi-GB capture never
    materialises its flow list).  ``window`` is the 500-record classifier
    context, appended to after scoring - exactly the batch semantics.
    """
    rec = flow.record()
    feats = extract_features(flow)
    score: float | None = None
    anomaly = False
    threat_type: str | None = None
    if detector.is_trained:
        scores, flags = detector.score_and_predict(np.asarray(feats)[None, :])
        score = float(scores[0])
        anomaly = bool(flags[0])
        if anomaly:
            threat = classify_threat(rec, feats, list(window))
            threat_type = threat.get("threat_type")
    rec["score"] = score
    rec["anomaly"] = anomaly
    if threat_type:
        rec["threat"] = {"threat_type": threat_type}
    scored = ScoredFlow(
        start_ts=float(rec["start_ts"]),
        src_ip=flow.src_ip, dst_ip=flow.dst_ip,
        src_port=flow.src_port, dst_port=flow.dst_port,
        proto=str(rec["proto"]).upper(), score=score, anomaly=anomaly,
        threat_type=threat_type, parseable=_parseable(flow))
    window.append(rec)
    return scored


def score_flows(flows, detector) -> list[ScoredFlow]:
    """Score collected flows with an explicit detector (no side effects).

    Anomalies get the production classifier applied to the flow's feature
    vector + context window, exactly as the live path does, so precision is
    measured against what an analyst would actually see.
    """
    from collections import deque

    window: deque = deque(maxlen=500)
    return [score_one(flow, detector, window) for flow in flows]


def run_eval(detector, pcap_path: str, labels: list[LabelRow],
             *, dataset_name: str, model_path: str = "",
             params: EvalParams | None = None) -> dict:
    """Full evaluation: PCAP -> scores (streamed) -> join -> report dict.

    Flows are scored as they complete (:func:`stream_flows`) instead of
    buffered first, so evaluation of a multi-GB capture runs in bounded
    memory; ``score_one`` keeps scoring semantics identical to
    :func:`score_flows`.  A run cut short by ``max_flows`` is reported via
    ``flows.truncated`` + a report caveat - never silently.
    """
    from collections import deque

    from ..tools import stream_flows

    p = params or EvalParams()
    window: deque = deque(maxlen=500)
    scored: list[ScoredFlow] = []

    def _score(flow) -> None:
        scored.append(score_one(flow, detector, window))

    info = stream_flows(pcap_path, _score, idle_timeout=p.idle_timeout,
                        max_flows=p.max_flows)
    result = join_flows(scored, labels, tolerance_s=p.join_tolerance_s)
    metrics = compute_metrics(result, labels)
    coverage = parser_coverage(scored)

    n_anom = sum(1 for f in scored if f.anomaly)
    report = build_report(
        dataset_name=dataset_name,
        artifact_path=pcap_path,
        model_path=model_path,
        model_info=(detector.info() if hasattr(detector, "info") else {}),
        params={
            "idle_timeout": p.idle_timeout,
            "join_tolerance_s": p.join_tolerance_s,
            "max_flows": p.max_flows,
            "contamination": (p.contamination if p.contamination is not None
                              else getattr(detector, "contamination", None)),
        },
        metrics=metrics,
        coverage=coverage,
        flows={
            "total": len(scored),
            "anomalous": n_anom,
            "joined": sum(1 for j in result.joins if j.joined),
            "unlabeled": sum(1 for j in result.joins if not j.joined),
            "truncated": info["truncated"],
        },
    )
    return report


def train_from_labels(pcap_path: str, labels: list[LabelRow], *,
                      out_path: str, dataset_name: str = "ad-hoc",
                      contamination: float | None = None,
                      params: EvalParams | None = None) -> dict:
    """Train a detector on the *benign-labeled* flows of a PCAP.

    Where ``spectra train`` assumes the whole capture is benign,
    ``eval train`` admits only flows whose joined label is explicitly
    benign - attack windows and unlabeled flows never enter the baseline
    (unlabeled is *not* benign, honesty rule: absence of evidence).  The
    selection uses :func:`spectra.eval.join.make_lookup`, the same indexed
    winner rule ``run_eval`` joins with, so the trained set is exactly the
    set the evaluation would call the benign reference - train and eval
    cannot disagree.

    Streams the capture (bounded memory via ``stream_flows``); a run cut
    short by ``max_flows`` is reported in the summary, never silent.
    Saves the fitted model to ``out_path`` and returns a summary with the
    per-pool flow counts.  Fewer than 10 benign-joined flows raises
    ``ValueError`` with the breakdown instead of training on whatever
    happened to join.
    """
    from ..ml.model import SpectraDetector
    from ..tools import stream_flows

    p = params or EvalParams()
    lookup = make_lookup(labels, p.join_tolerance_s)
    counts = {"flows": 0, "benign_joined": 0, "attack_joined": 0,
              "unlabeled": 0}
    rows: list[np.ndarray] = []

    def _consider(flow) -> None:
        counts["flows"] += 1
        best = lookup(ScoredFlow.from_record(flow.record(), anomaly=False))
        if best is None:
            counts["unlabeled"] += 1
            return
        if not labels[best[2]].benign:
            counts["attack_joined"] += 1
            return
        counts["benign_joined"] += 1
        rows.append(np.asarray(extract_features(flow)))

    info = stream_flows(pcap_path, _consider, idle_timeout=p.idle_timeout,
                        max_flows=p.max_flows)
    if len(rows) < 10:
        raise ValueError(
            f"{pcap_path} joined only {len(rows)} benign flows "
            f"({counts['flows']} seen: {counts['attack_joined']} attack-"
            f"labeled, {counts['unlabeled']} unlabeled) - need >= 10 "
            "benign-labeled flows to train; extend the label coverage or "
            "use a capture with more benign traffic")
    detector = (SpectraDetector() if contamination is None
                else SpectraDetector(contamination=contamination))
    fit_info = detector.fit(np.vstack(rows))
    detector.save(out_path)
    return {
        "model_path": out_path,
        "dataset": dataset_name,
        "n_train": fit_info["n_train"],
        "contamination": detector.contamination,
        "flows": {**counts, "truncated": info["truncated"]},
        "fit": fit_info,
    }
