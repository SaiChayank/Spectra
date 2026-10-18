"""Evaluation report: versioned JSON schema + compare for model A/B.

The schema is pinned in ``docs/evaluation.md`` §7.  A report always carries
its provenance (dataset name + checksum, model artifact hash, feature schema
version, join tolerance) and its caveats — a number without those is not a
Spectra evaluation (honesty rule 3).
"""

from __future__ import annotations

import hashlib
import os
from datetime import datetime, timezone

REPORT_VERSION = 1


def _sha256(path: str) -> str | None:
    if not path or not os.path.isfile(path):
        return None
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


#: Caveats attached to every report (honesty rule 4 + join limitations).
BASE_CAVEATS: tuple[str, ...] = (
    "Unsupervised detector trained on a benign baseline; behaviour on a "
    "different network's traffic is the baseline-matching limitation "
    "(limitations.md §2).",
    "The flow<->label join is endpoint-pair + time-window based; it cannot "
    "distinguish concurrent flows between the same hosts beyond the time "
    "tie-break (evaluation.md §9).",
    "METADATA_INVISIBLE attacks are counted but never scored - absence of "
    "payload evidence is out of scope by design, not a detector failure.",
)


def build_report(*, dataset_name: str, artifact_path: str,
                 model_path: str, model_info: dict,
                 params: dict, metrics: dict, coverage: dict,
                 flows: dict, extra_caveats: list[str] | None = None) -> dict:
    """Assemble a version-1 evaluation report (docs/evaluation.md §7)."""
    from ..features.extractor import FEATURE_SCHEMA_VERSION

    caveats = list(BASE_CAVEATS)
    if coverage.get("ratio") is not None and coverage["ratio"] < 0.9:
        caveats.append(
            f"Parser coverage is {coverage['ratio']:.0%} - metrics describe "
            "the parseable subset, not the full capture.")
    if metrics.get("benign_flows") == 0:
        caveats.append(
            "No benign labels in this dataset - benign_fpr is null "
            "(absence of evidence is not a good score).")
    caveats.extend(extra_caveats or [])

    return {
        "report_version": REPORT_VERSION,
        "created_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "dataset": {
            "name": dataset_name,
            "artifact": os.path.basename(artifact_path),
            "sha256": _sha256(artifact_path),
        },
        "model": {
            "path": model_path,
            "sha256": _sha256(model_path),
            "trained_flows": int(model_info.get("n_train") or 0),
            "contamination": model_info.get("contamination"),
            "feature_schema_version": FEATURE_SCHEMA_VERSION,
        },
        "params": params,
        "flows": flows,
        "parser_coverage": coverage,
        "per_category": metrics.get("per_category", {}),
        "overall": metrics.get("overall", {}),
        "invisible_joined": metrics.get("invisible_joined", 0),
        "benign_flows": metrics.get("benign_flows", 0),
        "labels": metrics.get("labels", {}),
        "caveats": caveats,
    }


def compare(a: dict, b: dict) -> dict:
    """Diff two reports (per-category deltas) for model A/B evaluation.

    ``b - a``: positive delta means b scored higher.  Categories present in
    only one report show as nulls on the other side so nothing hides.
    """

    def _f1(report: dict, cat: str) -> float | None:
        if cat == "overall":
            return report.get("overall", {}).get("f1")
        return report.get("per_category", {}).get(cat, {}).get("f1")

    cats = sorted(
        set(a.get("per_category", {}))
        | set(b.get("per_category", {})))
    rows = []
    for cat in cats + ["overall"]:
        fa, fb = _f1(a, cat), _f1(b, cat)
        delta = None
        if fa is not None and fb is not None:
            delta = round(fb - fa, 6)
        rows.append({"category": cat, "a_f1": fa, "b_f1": fb, "delta": delta})

    return {
        "a": {"dataset": a.get("dataset", {}).get("name"),
              "model": a.get("model", {}).get("path"),
              "created_at": a.get("created_at")},
        "b": {"dataset": b.get("dataset", {}).get("name"),
              "model": b.get("model", {}).get("path"),
              "created_at": b.get("created_at")},
        "same_dataset": (a.get("dataset", {}).get("name")
                         == b.get("dataset", {}).get("name")),
        "rows": rows,
    }
