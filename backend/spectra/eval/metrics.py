"""Metrics engine: precision / recall / F1 / AUC / FPR from a join result.

Definitions are fixed in ``docs/evaluation.md`` §6 and the honesty rules in
§2 are enforced here:

* ``METADATA_INVISIBLE`` joins are counted (``invisible_joined``) but never
  contribute to TP/FP/FN for a scored category;
* ``benign_fpr`` is ``None`` (not 0) when the dataset provides no benign
  labels - absence of evidence is never reported as a good score.

Pure functions over :class:`~spectra.eval.join.JoinResult`; no pipeline or
numpy imports, so every metric is unit-testable by hand.
"""

from __future__ import annotations

from .join import JoinResult, ScoredFlow
from .labels import METADATA_INVISIBLE, label_summary

#: Micro-average over all scored categories goes under this key.
OVERALL = "overall"


def _safe_div(num: float, den: float) -> float | None:
    return (num / den) if den else None


def _prf(tp: int, fp: int, fn: int) -> dict:
    precision = _safe_div(tp, tp + fp)
    recall = _safe_div(tp, tp + fn)
    if precision is None or recall is None or (precision + recall) == 0:
        f1 = None
    else:
        f1 = 2 * precision * recall / (precision + recall)
    return {
        "tp": tp, "fp": fp, "fn": fn,
        "precision": precision, "recall": recall, "f1": f1,
    }


def roc_auc(scores_pos: list[float], scores_neg: list[float]) -> float | None:
    """Mann-Whitney ROC-AUC of positive vs negative scores (null if either
    class is absent).  Ties contribute 0.5."""
    if not scores_pos or not scores_neg:
        return None
    sorted_all = sorted(scores_pos + scores_neg)
    # rank with tie handling
    ranks: dict[float, float] = {}
    i = 0
    while i < len(sorted_all):
        j = i
        while j + 1 < len(sorted_all) and sorted_all[j + 1] == sorted_all[i]:
            j += 1
        avg = (i + j) / 2.0 + 1.0        # 1-based average rank
        for k in range(i, j + 1):
            ranks[sorted_all[k]] = avg
        i = j + 1
    rank_sum_pos = sum(ranks[s] for s in scores_pos)
    n_pos, n_neg = len(scores_pos), len(scores_neg)
    return (rank_sum_pos - n_pos * (n_pos + 1) / 2.0) / (n_pos * n_neg)


def compute_metrics(result: JoinResult,
                    labels: list) -> dict:
    """Per-category + overall metrics from one join (docs/evaluation.md §6).

    ``labels`` is the label list the join ran against (needed for support
    counts and benign-window identification).
    """
    # index label rows by identity for support counting
    benign_label_ids = {id(lab) for lab in labels if lab.benign}

    # collect per-category stats
    per_cat: dict[str, dict] = {}
    # support: attack label rows per category
    for lab in labels:
        if lab.benign:
            continue
        cat = lab.mapped_category
        per_cat.setdefault(cat, {"support": 0, "hits": 0})
        per_cat[cat]["support"] += 1

    # score bookkeeping for AUC + FPR
    pos_scores: dict[str, list[float]] = {}
    benign_scores: list[float] = []
    benign_flows = 0

    tp: dict[str, int] = {}
    fp: dict[str, int] = {}

    hit_label_ids: set[int] = set()

    for j in result.joins:
        flow = j.flow
        lab = j.label
        is_benign_join = lab is not None and id(lab) in benign_label_ids
        scored_cat = flow.threat_type if flow.anomaly else None

        if is_benign_join:
            benign_flows += 1
            if flow.score is not None:
                benign_scores.append(flow.score)
            # a benign-window flow that fired is FP for its predicted category
            if flow.anomaly and scored_cat:
                fp[scored_cat] = fp.get(scored_cat, 0) + 1
            continue

        if lab is None:
            # unlabeled flow: if anomalous, count as FP against its predicted
            # category (conservative: an alert on unknown ground truth cannot
            # be assumed correct)
            if flow.anomaly and scored_cat:
                fp[scored_cat] = fp.get(scored_cat, 0) + 1
            continue

        # attack label: every joined flow's score feeds this category's AUC
        # (the *continuous* score, regardless of the anomaly verdict)
        cat = lab.mapped_category
        if cat == METADATA_INVISIBLE:
            continue  # counted separately, never scored
        if flow.score is not None:
            pos_scores.setdefault(cat, []).append(flow.score)
        if flow.anomaly and scored_cat:
            if scored_cat == cat:
                tp[cat] = tp.get(cat, 0) + 1
                hit_label_ids.add(id(lab))
            else:
                # anomaly of a *different* category joined this label: the
                # label was touched but not by the right category - not a TP
                # for `cat`; the flow counts as FP for its own prediction
                fp[scored_cat] = fp.get(scored_cat, 0) + 1
        # an unflagged flow on an attack label may be a miss (counted in fn
        # below); it is deliberately not used as an AUC negative - those come
        # from explicitly labeled benign windows only

    # misses: attack labels never hit by a matching-category anomaly
    fn: dict[str, int] = {}
    for lab in labels:
        if lab.benign or lab.mapped_category == METADATA_INVISIBLE:
            continue
        if id(lab) not in hit_label_ids:
            fn[lab.mapped_category] = fn.get(lab.mapped_category, 0) + 1

    for cat in set(list(per_cat) + list(tp) + list(fp) + list(fn)):
        stats = per_cat.setdefault(cat, {"support": 0, "hits": 0})
        stats.update(_prf(tp.get(cat, 0), fp.get(cat, 0), fn.get(cat, 0)))
        # benign-window scores are negatives for every category (honest
        # source: explicitly labeled benign, never "unlabeled = benign")
        stats["anomaly_auc"] = roc_auc(pos_scores.get(cat, []), benign_scores)
        stats["hits"] = stats["support"] - fn.get(cat, 0)
        stats["misses"] = fn.get(cat, 0)

    # benign FPR (None when no benign labels - honesty rule 2)
    benign_fpr = _safe_div(
        sum(1 for j in result.joins
            if j.label is not None and id(j.label) in benign_label_ids
            and j.flow.anomaly),
        benign_flows,
    )

    # overall (micro): pool all categories
    o_tp = sum(tp.values())
    o_fp = sum(fp.values())
    o_fn = sum(fn.values())
    overall = _prf(o_tp, o_fp, o_fn)
    all_pos = [s for lst in pos_scores.values() for s in lst]
    overall["anomaly_auc"] = roc_auc(all_pos, benign_scores)
    overall["benign_fpr"] = benign_fpr

    return {
        "per_category": dict(sorted(per_cat.items())),
        "overall": overall,
        "invisible_joined": result.invisible_joined,
        "benign_flows": benign_flows,
        "labels": label_summary(labels),
    }


def parser_coverage(flows: list[ScoredFlow]) -> dict:
    """Fraction of flows with usable metadata (docs/evaluation.md §6)."""
    total = len(flows)
    parseable = sum(1 for f in flows if f.parseable)
    return {"total": total, "parseable": parseable,
            "ratio": _safe_div(parseable, total)}
