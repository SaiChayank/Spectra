"""Ground-truth evaluation harness: label schema, join rules, metrics.

Every test runs on hand-built fixtures (label CSVs written to tmp_path and
plain scored-flow dicts) — no PCAPs, no model, no external datasets.  The
honesty rules of docs/evaluation.md §2 are asserted directly: invisible
attacks are never scored, absent benign labels never become fpr=0.
"""

from __future__ import annotations

import json
import os
import random

import pytest

from spectra.eval import (
    METADATA_INVISIBLE,
    EvalParams,
    LabelError,
    LabelRow,
    ScoredFlow,
    build_report,
    compare,
    compute_metrics,
    join_flows,
    label_summary,
    load_labels,
    parser_coverage,
    roc_auc,
)


# -- label schema -------------------------------------------------------------

CSV_HEADER = ("t_start,t_end,src_ip,src_port,dst_ip,dst_port,proto,"
              "dataset_label,mapped_category\n")


def _write_labels(tmp_path, rows: str, header: str = CSV_HEADER):
    p = tmp_path / "labels.csv"
    p.write_text(header + rows, encoding="utf-8")
    return str(p)


def test_load_labels_parses_rows(tmp_path):
    path = _write_labels(tmp_path,
        "100,200,10.0.0.1,*,10.0.0.2,443,TCP,PortScan,RECONNAISSANCE\n"
        "100,200,10.0.0.3,*,10.0.0.4,*,UDP,BENIGN,RECONNAISSANCE\n")
    rows = load_labels(path)
    assert len(rows) == 2
    assert rows[0].mapped_category == "RECONNAISSANCE"
    assert rows[0].src_port is None          # `*` = any
    assert rows[0].dst_port == 443
    assert rows[0].benign is False
    assert rows[1].benign is True            # BENIGN wording -> benign window
    assert rows[1].proto == "UDP"


def test_load_labels_rejects_unknown_category(tmp_path):
    path = _write_labels(tmp_path,
        "100,200,10.0.0.1,*,10.0.0.2,443,TCP,Bad,MAGIC_CATEGORY\n")
    with pytest.raises(LabelError, match="MAGIC_CATEGORY"):
        load_labels(path)


def test_load_labels_rejects_bad_time_range(tmp_path):
    path = _write_labels(tmp_path,
        "200,100,10.0.0.1,*,10.0.0.2,443,TCP,PortScan,RECONNAISSANCE\n")
    with pytest.raises(LabelError, match="t_end < t_start"):
        load_labels(path)


def test_load_labels_missing_file(tmp_path):
    with pytest.raises(LabelError, match="not found"):
        load_labels(str(tmp_path / "nope.csv"))


def test_load_labels_missing_columns(tmp_path):
    p = tmp_path / "bad.csv"
    p.write_text("t_start,t_end\n1,2\n", encoding="utf-8")
    with pytest.raises(LabelError, match="missing columns"):
        load_labels(str(p))


def test_label_summary_counts():
    rows = [
        LabelRow(0, 1, "a", "b", None, None, "*", "PortScan", "RECONNAISSANCE"),
        LabelRow(0, 1, "a", "b", None, None, "*", "Web Attack", METADATA_INVISIBLE),
        LabelRow(0, 1, "a", "b", None, None, "*", "BENIGN", "RECONNAISSANCE",
                 benign=True),
    ]
    s = label_summary(rows)
    assert s["rows"] == 3
    assert s["attack_rows"] == 2
    assert s["benign_windows"] == 1
    assert s["by_category"]["RECONNAISSANCE"] == 1
    assert s["by_category"][METADATA_INVISIBLE] == 1


# -- join rules ---------------------------------------------------------------

def _flow(src="10.0.0.1", dst="10.0.0.2", ts=150.0, anomaly=True,
          threat="RECONNAISSANCE", score=5.0) -> ScoredFlow:
    return ScoredFlow(start_ts=ts, src_ip=src, dst_ip=dst,
                      src_port=50000, dst_port=443, proto="TCP",
                      score=score, anomaly=anomaly, threat_type=threat)


def _label(src="10.0.0.1", dst="10.0.0.2", t0=100.0, t1=200.0,
           category="RECONNAISSANCE", dataset_label="PortScan",
           src_port=None, dst_port=None, proto="*") -> LabelRow:
    return LabelRow(t0, t1, src, dst, src_port, dst_port, proto,
                    dataset_label, category)


def test_join_matches_within_window_and_both_directions():
    labels = [_label()]
    # forward direction
    r1 = join_flows([_flow(ts=150.0)], labels)
    assert r1.joins[0].joined
    # reversed endpoints (flow src/dst flipped) still joins
    r2 = join_flows([_flow(src="10.0.0.2", dst="10.0.0.1", ts=150.0)], labels)
    assert r2.joins[0].joined


def test_join_respects_tolerance_boundary():
    labels = [_label(t0=100.0, t1=200.0)]
    inside = join_flows([_flow(ts=105.0)], labels)   # within +10s of t0
    assert inside.joins[0].joined
    outside = join_flows([_flow(ts=89.0)], labels)   # beyond 10s tolerance
    assert not outside.joins[0].joined


def test_join_respects_port_and_proto_constraints():
    labels = [_label(src_port=50000, proto="TCP")]
    assert join_flows([_flow()], labels).joins[0].joined
    other_port = _flow()
    object.__setattr__(other_port, "src_port", 40000)
    assert not join_flows([other_port], labels).joins[0].joined
    udp = _flow()
    object.__setattr__(udp, "proto", "UDP")
    assert not join_flows([udp], labels).joins[0].joined


def test_join_closest_label_wins():
    near = _label(t0=140.0, t1=160.0, category="C2_BEACONING",
                  dataset_label="Bot")
    far = _label(t0=100.0, t1=130.0)
    r = join_flows([_flow(ts=150.0)], [far, near])
    assert r.joins[0].label is near


def test_invisible_joined_counted_never_scored():
    inv = _label(category=METADATA_INVISIBLE, dataset_label="Web Attack")
    r = join_flows([_flow(anomaly=True, threat="UNKNOWN_ANOMALY")], [inv])
    assert r.invisible_joined == 1
    m = compute_metrics(r, [inv])
    # no TP/FP/FN for the invisible bucket; per_category must not score it
    assert m["invisible_joined"] == 1
    assert METADATA_INVISIBLE not in m["per_category"] or \
        m["per_category"][METADATA_INVISIBLE]["tp"] == 0


# -- indexed join (parity with the naive O(F*L) reference) --------------------

def _naive_join(flows, labels, tolerance_s=10.0):
    """Reference implementation: the original full scan over every label.

    Kept inside the test suite so the indexed join in ``join_flows`` is proven
    *exactly* equivalent - same label per flow, same distances, same missed
    rows - not merely similar on hand-picked fixtures.
    """
    from spectra.eval.join import label_matches_flow
    from spectra.threats import THREAT_TYPES

    order = {c: i for i, c in enumerate(THREAT_TYPES)}
    order[METADATA_INVISIBLE] = len(order)
    joins, hit = [], set()
    for flow in flows:
        best_idx, best_dist, best_rank = None, float("inf"), len(order)
        for li, label in enumerate(labels):
            dist = label_matches_flow(label, flow, tolerance_s)
            if dist == float("inf"):
                continue
            rank = order.get(label.mapped_category, len(order))
            if best_idx is None or (dist, rank) < (best_dist, best_rank):
                best_idx, best_dist, best_rank = li, dist, rank
        if best_idx is not None:
            hit.add(best_idx)
            joins.append((best_idx, best_dist))
        else:
            joins.append((None, float("inf")))
    missed = [i for i, lab in enumerate(labels) if i not in hit and not lab.benign]
    return joins, missed


def test_join_matches_naive_reference_on_random_inputs():
    """The indexed join returns byte-identical results to the naive scan.

    Random labels/flows over a small endpoint pool force every hard case:
    reversed endpoints, overlapping windows, port/proto mismatches, benign
    rows, METADATA_INVISIBLE rows, flows outside every tolerance window, and
    exact (distance, rank) ties.
    """
    from spectra.threats import THREAT_TYPES

    rng = random.Random(20261019)          # fixed seed: deterministic suite
    ips = [f"10.{i // 250}.{i % 250}.1" for i in range(8)]
    cats = list(THREAT_TYPES) + [METADATA_INVISIBLE]
    for trial in range(40):
        labels: list[LabelRow] = []
        for _ in range(rng.randrange(0, 25)):
            t0 = rng.uniform(0, 800)
            labels.append(LabelRow(
                t0, t0 + rng.uniform(0, 300),
                rng.choice(ips), rng.choice([None, None, 443, 50000]),
                rng.choice(ips), rng.choice([None, None, 80, 443]),
                rng.choice(["TCP", "UDP", "*"]),
                rng.choice(["PortScan", "BENIGN", "Bot", "Fancy-App"]),
                rng.choice(cats)))
        flows: list[ScoredFlow] = []
        for _ in range(rng.randrange(0, 40)):
            flows.append(ScoredFlow(
                start_ts=rng.uniform(-50, 1050),
                src_ip=rng.choice(ips), dst_ip=rng.choice(ips),
                src_port=rng.choice([443, 80, 50000]),
                dst_port=rng.choice([443, 53]),
                proto=rng.choice(["TCP", "UDP"]),
                score=rng.uniform(0, 10),
                anomaly=bool(rng.getrandbits(1)),
                threat_type=rng.choice(THREAT_TYPES)))
        tol = rng.choice([0.0, 10.0, 30.0])
        got = join_flows(flows, labels, tolerance_s=tol)
        exp_pairs, exp_missed = _naive_join(flows, labels, tol)
        idmap = {id(lab): i for i, lab in enumerate(labels)}
        got_pairs = [(idmap[id(j.label)] if j.label is not None else None,
                      j.time_distance) for j in got.joins]
        assert got_pairs == exp_pairs, f"trial {trial}: join mismatch"
        assert [idmap[id(l)] for l in got.missed_labels] == exp_missed, \
            f"trial {trial}: missed-label mismatch"
        invisible_expected = sum(
            1 for idx, (li, _) in enumerate(exp_pairs)
            if flows[idx].anomaly and li is not None
            and labels[li].mapped_category == METADATA_INVISIBLE)
        assert got.invisible_joined == invisible_expected, \
            f"trial {trial}: invisible count mismatch"


def test_join_tie_break_is_deterministic():
    from spectra.threats import THREAT_TYPES

    assert THREAT_TYPES.index("C2_BEACONING") < THREAT_TYPES.index(
        "RECONNAISSANCE")
    # equal time distance: THREAT_TYPES order beats list order...
    a = _label(category="RECONNAISSANCE", t0=100.0, t1=200.0)
    b = _label(category="C2_BEACONING", t0=100.0, t1=200.0)
    assert join_flows([_flow(ts=150.0)], [a, b]).joins[0].label is b
    assert join_flows([_flow(ts=150.0)], [b, a]).joins[0].label is b
    # ...and on a full (distance, rank) tie the first row in list order wins.
    c = _label(category="C2_BEACONING", dataset_label="Bot-A",
               t0=100.0, t1=200.0)
    d = _label(category="C2_BEACONING", dataset_label="Bot-B",
               t0=100.0, t1=200.0)
    assert join_flows([_flow(ts=150.0)], [c, d]).joins[0].label is c
    assert join_flows([_flow(ts=150.0)], [d, c]).joins[0].label is d


def test_join_scales_with_index(monkeypatch):
    """A 100k-label corpus must cost ~constant candidate work per flow.

    The pre-index implementation scanned every label for every flow
    (F x L calls); this pins the indexed join to a small multiple of the flow
    count instead - the CTU-13 corpora are ~100k+ label rows.
    """
    import spectra.eval.join as jmod

    calls = 0
    real = jmod.label_matches_flow

    def counting(label, flow, tolerance_s=10.0):
        nonlocal calls
        calls += 1
        return real(label, flow, tolerance_s)

    monkeypatch.setattr(jmod, "label_matches_flow", counting)

    rng = random.Random(7)
    pairs = [(f"10.1.{i // 250}.{i % 250}", f"172.16.{i // 250}.{i % 250}")
             for i in range(20)]
    labels: list[LabelRow] = []
    for _ in range(100_000):
        a, b = pairs[rng.randrange(len(pairs))]
        t0 = rng.uniform(0, 1_000_000)
        labels.append(LabelRow(t0, t0 + rng.uniform(0, 30), a, None, b, None,
                               "*", "Bot", "C2_BEACONING"))
    flows: list[ScoredFlow] = []
    for _ in range(50):
        a, b = pairs[rng.randrange(len(pairs))]
        flows.append(ScoredFlow(start_ts=rng.uniform(0, 1_000_000),
                                src_ip=a, dst_ip=b, src_port=0, dst_port=0,
                                proto="TCP", score=1.0, anomaly=False,
                                threat_type=None))
    result = join_flows(flows, labels)
    assert len(result.joins) == len(flows)
    # naive scan = 50 * 100k = 5,000,000 calls; indexed stays near-linear in
    # the *flow* count (bucket + time slice of the matching endpoint pair).
    assert calls < len(flows) * 30, \
        f"join is not indexed: {calls} match calls for {len(flows)} flows"


# -- metrics ------------------------------------------------------------------

def test_perfect_detection_metrics():
    labels = [_label()]
    flows = [_flow(anomaly=True, threat="RECONNAISSANCE")]
    m = compute_metrics(join_flows(flows, labels), labels)
    cat = m["per_category"]["RECONNAISSANCE"]
    assert cat["tp"] == 1 and cat["fp"] == 0 and cat["fn"] == 0
    assert cat["precision"] == 1.0 and cat["recall"] == 1.0
    assert cat["f1"] == 1.0
    assert cat["support"] == 1


def test_miss_counts_as_fn():
    labels = [_label()]
    flows = [_flow(anomaly=False, threat=None)]
    m = compute_metrics(join_flows(flows, labels), labels)
    cat = m["per_category"]["RECONNAISSANCE"]
    assert cat["fn"] == 1 and cat["recall"] == 0.0


def test_benign_window_alert_counts_as_fp():
    labels = [_label(dataset_label="BENIGN", src="10.9.9.1", dst="10.9.9.2")]
    flows = [_flow(src="10.9.9.1", dst="10.9.9.2", anomaly=True,
                   threat="RECONNAISSANCE")]
    m = compute_metrics(join_flows(flows, labels), labels)
    cat = m["per_category"]["RECONNAISSANCE"]
    assert cat["fp"] == 1
    assert m["benign_flows"] == 1
    assert m["overall"]["benign_fpr"] == 1.0


def test_fpr_is_none_without_benign_labels():
    # honesty rule 2: no benign labels -> fpr is null, never 0
    labels = [_label()]
    flows = [_flow(anomaly=True, threat="RECONNAISSANCE")]
    m = compute_metrics(join_flows(flows, labels), labels)
    assert m["overall"]["benign_fpr"] is None
    assert m["benign_flows"] == 0


def test_unlabeled_anomaly_counts_as_fp_conservative():
    # an alert on unknown ground truth cannot be assumed correct
    labels: list[LabelRow] = []
    flows = [_flow(anomaly=True, threat="C2_BEACONING")]
    m = compute_metrics(join_flows(flows, labels), labels)
    assert m["per_category"]["C2_BEACONING"]["fp"] == 1
    assert m["overall"]["precision"] == 0.0


def test_wrong_category_alert_is_fp_not_tp():
    labels = [_label(category="C2_BEACONING", dataset_label="Bot")]
    flows = [_flow(anomaly=True, threat="RECONNAISSANCE")]
    m = compute_metrics(join_flows(flows, labels), labels)
    assert m["per_category"]["C2_BEACONING"]["tp"] == 0
    assert m["per_category"]["C2_BEACONING"]["fp"] == 0  # FP booked to RECON
    assert m["per_category"]["RECONNAISSANCE"]["fp"] == 1


def test_roc_auc_perfect_and_ties():
    assert roc_auc([2.0, 3.0], [0.0, 1.0]) == 1.0
    assert roc_auc([0.0, 1.0], [2.0, 3.0]) == 0.0
    assert roc_auc([1.0], [1.0]) == 0.5
    assert roc_auc([], [1.0]) is None
    assert roc_auc([1.0], []) is None


def test_auc_uses_benign_scores_as_negatives():
    labels = [
        _label(),
        _label(src="10.9.9.1", dst="10.9.9.2", dataset_label="BENIGN"),
    ]
    flows = [
        _flow(anomaly=True, threat="RECONNAISSANCE", score=9.0),
        _flow(src="10.9.9.1", dst="10.9.9.2", anomaly=False, threat=None,
              score=1.0),
    ]
    m = compute_metrics(join_flows(flows, labels), labels)
    assert m["per_category"]["RECONNAISSANCE"]["anomaly_auc"] == 1.0


# -- parser coverage ----------------------------------------------------------

def test_parser_coverage_ratio():
    flows = [
        _flow(),
        ScoredFlow(1.0, "a", "b", 1, 2, "TCP", 0.0, False, parseable=False),
    ]
    cov = parser_coverage(flows)
    assert cov == {"total": 2, "parseable": 1, "ratio": 0.5}


def test_parser_coverage_empty_is_none_ratio():
    assert parser_coverage([])["ratio"] is None


# -- report schema ------------------------------------------------------------

def _mini_report(**kw):
    labels = [_label()]
    flows = [_flow(anomaly=True, threat="RECONNAISSANCE")]
    m = compute_metrics(join_flows(flows, labels), labels)
    args = dict(
        dataset_name="synthetic", artifact_path=__file__,
        model_path="", model_info={"n_train": 10, "contamination": 0.02},
        params={"idle_timeout": 30.0, "join_tolerance_s": 10.0},
        metrics=m, coverage=parser_coverage([]),
        flows={"total": 1, "anomalous": 1, "joined": 1, "unlabeled": 0},
    )
    args.update(kw)
    return build_report(**args)


def test_report_schema_v1_fields():
    rep = _mini_report()
    assert rep["report_version"] == 1
    for key in ("created_at", "dataset", "model", "params", "flows",
                "parser_coverage", "per_category", "overall",
                "invisible_joined", "caveats"):
        assert key in rep
    assert rep["model"]["feature_schema_version"] >= 1
    assert any("baseline-matching" in c for c in rep["caveats"])


def test_report_adds_low_coverage_caveat():
    cov = {"total": 10, "parseable": 5, "ratio": 0.5}
    rep = _mini_report(coverage=cov)
    assert any("Parser coverage" in c for c in rep["caveats"])


def test_report_adds_no_benign_caveat():
    rep = _mini_report()
    assert any("No benign labels" in c for c in rep["caveats"])


def test_compare_diffs_f1():
    a = _mini_report()
    b = _mini_report()
    b["per_category"]["RECONNAISSANCE"]["f1"] = 0.5
    out = compare(a, b)
    row = next(r for r in out["rows"]
               if r["category"] == "RECONNAISSANCE")
    assert row["a_f1"] == 1.0 and row["b_f1"] == 0.5
    assert row["delta"] == pytest.approx(-0.5)
    assert out["same_dataset"] is True


# -- runner (light: no scapy pcap, mocked detector interface) -----------------

def test_score_flows_and_run_eval_shape(tmp_path, monkeypatch):
    """run_eval end-to-end on a stub detector + tiny generated PCAP."""
    from spectra.demo import make_baseline_pcap
    from spectra.eval.runner import run_eval
    from spectra.ml.model import SpectraDetector

    pcap = str(tmp_path / "baseline.pcap")
    make_baseline_pcap(pcap, n_flows=6)

    detector = SpectraDetector()
    # a detector that flags everything - exercises the join + metrics path
    class _FlagAll:
        is_trained = True
        contamination = 0.02

        def score_and_predict(self, X):
            import numpy as np
            n = X.shape[0]
            return np.full(n, 7.5), np.ones(n, dtype=bool)

        def info(self):
            return {"trained": True, "n_train": 5, "contamination": 0.02}

    # benign labels covering the demo baseline's client endpoints
    # (make_baseline_pcap: clients 10.0.0.5-8 -> 93.184.216.34 + QUIC)
    labels = [
        LabelRow(0, 10**10, f"10.0.0.{c}", "93.184.216.34", None, None, "*",
                 "BENIGN", "RECONNAISSANCE")
        for c in (5, 6, 7, 8)
    ]
    rep = run_eval(_FlagAll(), pcap, labels, dataset_name="synthetic",
                   model_path="")
    assert rep["flows"]["total"] > 0
    assert rep["flows"]["anomalous"] == rep["flows"]["total"]
    assert rep["overall"]["benign_fpr"] == 1.0  # everything flagged on benign
    assert rep["dataset"]["sha256"] is not None
    # json-serialisable end to end
    json.dumps(rep)


# -- streaming eval (bounded memory over multi-GB captures) ------------------

def test_stream_flows_matches_collect_and_flags_truncation(tmp_path):
    """stream_flows yields the same flows in the same order as collect_flows,
    never buffers, and reports truncation only when a completion past the
    budget actually occurred (exactly-at-budget is NOT truncated)."""
    from spectra.demo import make_baseline_pcap
    from spectra.tools import collect_flows, stream_flows

    pcap = str(tmp_path / "baseline.pcap")
    make_baseline_pcap(pcap, n_flows=6)
    ref = collect_flows(pcap)
    assert len(ref) >= 2

    key = lambda f: (f.src_ip, f.dst_ip, f.src_port, f.dst_port,
                     f.proto, float(f.start_ts))
    seen = []
    info = stream_flows(pcap, on_flow=seen.append)
    assert info == {"flows": len(ref), "truncated": False}
    assert [key(f) for f in seen] == [key(f) for f in ref]

    # exactly at the budget: every flow delivered, nothing dropped
    at_cap = []
    info = stream_flows(pcap, on_flow=at_cap.append, max_flows=len(ref))
    assert info == {"flows": len(ref), "truncated": False}

    # one below the budget: the next completion proves flows were dropped
    cut = []
    info = stream_flows(pcap, on_flow=cut.append, max_flows=len(ref) - 1)
    assert info == {"flows": len(ref) - 1, "truncated": True}
    assert len(cut) == len(ref) - 1


def test_stream_scoring_equals_batch_scoring(tmp_path):
    """The streaming per-flow scoring path is bit-identical to the batch
    collect-then-score path (same completion order, same 500-record window)."""
    from collections import deque

    from spectra.demo import make_baseline_pcap
    from spectra.eval.runner import score_flows, score_one
    from spectra.tools import collect_flows, stream_flows

    pcap = str(tmp_path / "baseline.pcap")
    make_baseline_pcap(pcap, n_flows=6)

    class _FlagAll:
        is_trained = True
        contamination = 0.02

        def score_and_predict(self, X):
            import numpy as np
            n = X.shape[0]
            return np.full(n, 7.5), np.ones(n, dtype=bool)

        def info(self):
            return {"trained": True, "n_train": 5, "contamination": 0.02}

    batch = score_flows(collect_flows(pcap), _FlagAll())

    streamed = []
    window = deque(maxlen=500)
    stream_flows(pcap,
                 on_flow=lambda f: streamed.append(score_one(f, _FlagAll(),
                                                             window)))
    assert streamed == batch          # ScoredFlow is a frozen dataclass
    assert len(batch) > 0


def test_run_eval_streams_and_reports_truncation(tmp_path):
    """run_eval scores flows as they complete (no full-flow buffering) and
    the report carries params.max_flows, flows.truncated and a loud caveat."""
    from spectra.demo import make_baseline_pcap
    from spectra.eval.runner import EvalParams, run_eval

    pcap = str(tmp_path / "baseline.pcap")
    make_baseline_pcap(pcap, n_flows=6)

    class _FlagAll:
        is_trained = True
        contamination = 0.02

        def score_and_predict(self, X):
            import numpy as np
            n = X.shape[0]
            return np.full(n, 7.5), np.ones(n, dtype=bool)

        def info(self):
            return {"trained": True, "n_train": 5, "contamination": 0.02}

    labels = [
        LabelRow(0, 10**10, f"10.0.0.{c}", "93.184.216.34", None, None, "*",
                 "BENIGN", "RECONNAISSANCE")
        for c in (5, 6, 7, 8)
    ]

    truncated = run_eval(_FlagAll(), pcap, labels, dataset_name="synthetic",
                         model_path="", params=EvalParams(max_flows=3))
    assert truncated["flows"]["total"] == 3
    assert truncated["flows"]["truncated"] is True
    assert truncated["params"]["max_flows"] == 3
    assert any("truncated at max_flows=3" in c for c in truncated["caveats"]), \
        truncated["caveats"]

    full = run_eval(_FlagAll(), pcap, labels, dataset_name="synthetic",
                    model_path="", params=EvalParams())
    assert full["flows"]["truncated"] is False
    assert full["params"]["max_flows"] == EvalParams().max_flows
    assert full["flows"]["total"] > 3
    assert not any("truncated at max_flows" in c for c in full["caveats"])


def test_eval_run_cli_accepts_max_flows():
    from spectra.cli import build_parser

    args = build_parser().parse_args(
        ["eval", "run", "--pcap", "x.pcap", "--labels", "l.csv",
         "--max-flows", "500000"])
    assert args.max_flows == 500000


# -- eval train (baseline trained on labeled-benign flows) --------------------

def _train_labels():
    """Benign windows for clients .5/.6, an attack window for .7; .8 stays
    unlabeled - training must use exactly the benign-joined flows."""
    dst = "93.184.216.34"
    return [
        LabelRow(0, 10**10, "10.0.0.5", dst, None, None, "*",
                 "BENIGN", "RECONNAISSANCE"),
        LabelRow(0, 10**10, "10.0.0.6", dst, None, None, "*",
                 "BENIGN", "RECONNAISSANCE"),
        LabelRow(0, 10**10, "10.0.0.7", dst, None, None, "*",
                 "Bot", "C2_BEACONING"),
    ]


def test_eval_train_trains_only_benign_joined_flows(tmp_path):
    """`eval train` fits on flows that join BENIGN labels only: attack-
    labeled and unlabeled flows never enter the baseline."""
    from spectra.demo import make_baseline_pcap
    from spectra.eval.runner import train_from_labels
    from spectra.ml.model import SpectraDetector

    pcap = str(tmp_path / "baseline.pcap")
    make_baseline_pcap(pcap, n_flows=24)   # clients .5-.8 get 6 TLS each
    out = str(tmp_path / "model.joblib")

    summary = train_from_labels(pcap, _train_labels(), out_path=out,
                                dataset_name="synthetic")

    # 24 TLS (6 per client) + 2 QUIC (.7 and .8).
    assert summary["flows"] == {"flows": 26, "benign_joined": 12,
                                "attack_joined": 7, "unlabeled": 7,
                                "truncated": False}
    assert summary["n_train"] == 12
    det = SpectraDetector.load(out)
    assert det.is_trained and det.n_train == 12


def test_eval_train_selection_matches_join(tmp_path):
    """The training set is exactly the set run_eval's join calls benign -
    same index, same winner rule, so train/eval can never disagree about
    which flows are the benign baseline."""
    from spectra.demo import make_baseline_pcap
    from spectra.eval.join import ScoredFlow, join_flows
    from spectra.eval.runner import train_from_labels
    from spectra.tools import collect_flows

    pcap = str(tmp_path / "baseline.pcap")
    make_baseline_pcap(pcap, n_flows=24)
    labels = _train_labels()

    placeholders = [ScoredFlow.from_record(f.record(), anomaly=False)
                    for f in collect_flows(pcap)]
    expected = sum(1 for j in join_flows(placeholders, labels).joins
                   if j.label is not None and j.label.benign)

    summary = train_from_labels(pcap, labels, out_path=str(tmp_path / "m.joblib"))
    assert summary["flows"]["benign_joined"] == expected
    assert expected > 0


def test_eval_train_refuses_fewer_than_ten_benign_flows(tmp_path):
    """A capture whose labels cover too little benign traffic is refused
    with the exclusion breakdown - never silently trained on attacks."""
    from spectra.demo import make_baseline_pcap
    from spectra.eval.runner import train_from_labels

    pcap = str(tmp_path / "small.pcap")
    make_baseline_pcap(pcap, n_flows=6)    # client .5 gets 2 TLS flows
    labels = [_train_labels()[0]]          # benign window for .5 only
    with pytest.raises(ValueError, match="benign"):
        train_from_labels(pcap, labels, out_path=str(tmp_path / "m.joblib"))


def test_eval_train_cli_parser():
    from spectra.cli import build_parser

    args = build_parser().parse_args(
        ["eval", "train", "--pcap", "x.pcap", "--labels", "l.csv",
         "--out", "m.joblib", "--contamination", "0.05", "--max-flows", "1000"])
    assert args.eval_cmd == "train"
    assert args.contamination == 0.05 and args.max_flows == 1000


# -- report store ---------------------------------------------------------------

def _store_cfg(tmp_path):
    from spectra.config import Config
    c = Config()
    c.data_dir = str(tmp_path / "data")
    return c


def test_store_save_load_roundtrip(tmp_path):
    from spectra.eval.store import load, save
    rep = _mini_report()
    path = save(rep, name="unit.json", config=_store_cfg(tmp_path))
    assert path.endswith("unit.json")
    loaded = load("unit.json", config=_store_cfg(tmp_path))
    assert loaded["report_version"] == 1
    assert loaded["dataset"]["name"] == "synthetic"


def test_store_default_name_from_dataset(tmp_path):
    from spectra.eval.store import default_name
    name = default_name(_mini_report())
    assert name.startswith("synthetic-") and name.endswith(".json")


def test_store_rejects_unsafe_names(tmp_path):
    from spectra.eval.store import ReportStoreError, load, save
    for bad in ("../evil.json", "a/b.json", "..\\x.json", "no-ext"):
        with pytest.raises(ReportStoreError):
            save(_mini_report(), name=bad, config=_store_cfg(tmp_path))
        with pytest.raises(ReportStoreError):
            load(bad, config=_store_cfg(tmp_path))
    # empty name means "default" on save, but is never a valid lookup
    with pytest.raises(ReportStoreError):
        load("", config=_store_cfg(tmp_path))


def test_store_load_unknown_report(tmp_path):
    from spectra.eval.store import ReportStoreError, load
    with pytest.raises(ReportStoreError, match="not found"):
        load("ghost.json", config=_store_cfg(tmp_path))


def test_store_list_summarises_and_flags_corrupt(tmp_path):
    from spectra.eval.store import list_reports, reports_dir, save
    cfg = _store_cfg(tmp_path)
    save(_mini_report(), name="good.json", config=cfg)
    os.makedirs(reports_dir(cfg), exist_ok=True)
    with open(os.path.join(reports_dir(cfg), "bad.json"), "w",
              encoding="utf-8") as f:
        f.write("{not json")
    out = list_reports(cfg)
    assert out["count"] == 2
    by_name = {r["name"]: r for r in out["reports"]}
    assert by_name["good.json"]["corrupt"] is False
    assert by_name["good.json"]["dataset"] == "synthetic"
    assert by_name["good.json"]["overall"] is not None
    assert by_name["bad.json"]["corrupt"] is True   # flagged, not hidden


def test_store_list_empty_dir(tmp_path):
    from spectra.eval.store import list_reports
    out = list_reports(_store_cfg(tmp_path))
    assert out == {"directory": out["directory"], "count": 0, "reports": []}


# -- eval read API routes ---------------------------------------------------------

def test_eval_list_and_get_routes(client, tmp_path, monkeypatch):
    from spectra.eval.store import reports_dir, save
    # the store resolves its directory from SPECTRA_DATA_DIR (from_env),
    # so the env var - not engine.config - is what routes read
    monkeypatch.setenv("SPECTRA_DATA_DIR", str(tmp_path / "data"))
    save(_mini_report(), name="sample.json")
    assert os.path.isfile(os.path.join(reports_dir(), "sample.json"))

    res = client.get("/api/model/eval")
    assert res.status_code == 200
    body = res.json()
    assert body["count"] == 1
    assert body["reports"][0]["name"] == "sample.json"
    assert body["reports"][0]["corrupt"] is False

    res = client.get("/api/model/eval/sample.json")
    assert res.status_code == 200
    assert res.json()["report_version"] == 1
    assert res.json()["caveats"]


def test_eval_get_missing_is_404(client):
    assert client.get("/api/model/eval/ghost.json").status_code == 404


def test_eval_routes_need_auth(raw_client):
    assert raw_client.get("/api/model/eval").status_code == 401
    assert raw_client.get("/api/model/eval/x.json").status_code == 401
