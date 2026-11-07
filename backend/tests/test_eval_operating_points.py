"""Phase B metrics: PR-AUC, recall at a fixed benign FPR, bootstrap CIs (hand-computed cases)."""
from __future__ import annotations

import pytest

from spectra.eval.metrics import bootstrap_ci, pr_auc, recall_at_fpr, roc_auc

POS = [0.9, 0.8, 0.4]
NEG = [0.7, 0.3, 0.2, 0.1]


def test_pr_auc_is_average_precision():
    # ranked: P P N P N N N -> precision at each positive 1, 1, 3/4
    assert pr_auc(POS, NEG) == pytest.approx((1 + 1 + 0.75) / 3)


def test_pr_auc_perfect_and_worst():
    assert pr_auc([0.9, 0.8], [0.2, 0.1]) == pytest.approx(1.0)
    assert pr_auc([0.1], [0.9, 0.8, 0.7]) == pytest.approx(0.25)   # the one positive ranks last of 4


def test_pr_auc_needs_both_classes():
    assert pr_auc([], NEG) is None and pr_auc(POS, []) is None


@pytest.mark.parametrize("fpr,expected", [(0.0, 2 / 3), (0.25, 1.0), (0.5, 1.0)])
def test_recall_at_fpr(fpr, expected):
    assert recall_at_fpr(POS, NEG, fpr)["recall"] == pytest.approx(expected)


def test_recall_at_fpr_never_exceeds_the_budget():
    out = recall_at_fpr(POS, NEG, 0.25)
    assert out["fpr"] <= 0.25


def test_ties_are_not_split():
    # all scores equal: any threshold flags everything, so a 1% budget can only be met by flagging nothing
    out = recall_at_fpr([0.5, 0.5], [0.5] * 100, 0.01)
    assert out["recall"] == 0.0 and out["fpr"] == 0.0


def test_recall_at_fpr_needs_both_classes():
    assert recall_at_fpr([], NEG, 0.01) is None


def test_bootstrap_is_seeded_and_brackets_the_point():
    a = bootstrap_ci(POS * 20, NEG * 20, lambda p, n: roc_auc(p, n), n=200, seed=7)
    b = bootstrap_ci(POS * 20, NEG * 20, lambda p, n: roc_auc(p, n), n=200, seed=7)
    assert a == b
    assert a["lo"] <= a["point"] <= a["hi"] and a["n"] == 200
    c = bootstrap_ci(POS * 20, NEG * 20, lambda p, n: roc_auc(p, n), n=200, seed=8)
    assert c != a


def test_bootstrap_interval_shrinks_with_more_data():
    small = bootstrap_ci(POS * 2, NEG * 2, roc_auc, n=300, seed=1)
    big = bootstrap_ci(POS * 40, NEG * 40, roc_auc, n=300, seed=1)
    assert (big["hi"] - big["lo"]) < (small["hi"] - small["lo"])


def test_bootstrap_keeps_class_sizes_fixed():
    seen = set()

    def stat(p, n):
        seen.add((len(p), len(n)))
        return 0.5

    bootstrap_ci(POS, NEG, stat, n=20, seed=3)
    assert seen == {(len(POS), len(NEG))}


# -- wired into compute_metrics ------------------------------------------------

def _eval_inputs():
    from spectra.eval import LabelRow, ScoredFlow

    labels = [LabelRow(100.0, 200.0, "10.0.0.1", "10.0.0.2", None, None, "*", "PortScan", "RECONNAISSANCE"),
              LabelRow(100.0, 200.0, "10.9.0.1", "10.9.0.2", None, None, "*", "BENIGN", "BENIGN")]
    flows = []
    for i, sc in enumerate([0.9, 0.8, 0.4]):
        flows.append(ScoredFlow(start_ts=150.0, src_ip="10.0.0.1", dst_ip="10.0.0.2", src_port=40000 + i,
                                dst_port=443, proto="TCP", score=sc, anomaly=sc > 0.5, threat_type="RECONNAISSANCE"))
    for i, sc in enumerate([0.7, 0.3, 0.2, 0.1]):
        flows.append(ScoredFlow(start_ts=150.0, src_ip="10.9.0.1", dst_ip="10.9.0.2", src_port=41000 + i,
                                dst_port=443, proto="TCP", score=sc, anomaly=sc > 0.5, threat_type="RECONNAISSANCE"))
    return flows, labels


def test_compute_metrics_reports_score_metrics_and_intervals():
    from spectra.eval import compute_metrics, join_flows

    flows, labels = _eval_inputs()
    plain = compute_metrics(join_flows(flows, labels), labels)["overall"]["score_metrics"]
    assert plain["pr_auc"] == pytest.approx((1 + 1 + 0.75) / 3)
    assert plain["recall_at_fpr_1pct"] == pytest.approx(2 / 3)     # 4 benign flows: a 1% budget allows none
    assert "pr_auc_ci95" not in plain
    boot = compute_metrics(join_flows(flows, labels), labels, bootstrap=100, seed=5)["overall"]["score_metrics"]
    lo, hi = boot["pr_auc_ci95"]
    assert lo <= boot["pr_auc"] <= hi and boot["bootstrap"] == 100


def test_score_metrics_are_null_without_benign_labels():
    from spectra.eval import compute_metrics, join_flows

    flows, labels = _eval_inputs()
    only_attack = [labels[0]]
    out = compute_metrics(join_flows(flows[:3], only_attack), only_attack)["overall"]
    assert out["score_metrics"] is None and out["benign_fpr"] is None
