"""Ground-truth evaluation for Spectra's detector (docs/evaluation.md).

Offline harness: run the real pipeline over a labeled PCAP, join predictions
to ground truth, compute per-category precision/recall/F1/AUC/FPR, and emit
a versioned report carrying its provenance and caveats.

Submodules are pure (no service/database imports) so the schema, join and
metrics are unit-testable on hand-written fixtures:

* :mod:`spectra.eval.labels`   - label schema + CSV loading
* :mod:`spectra.eval.join`     - flow <-> label join rules
* :mod:`spectra.eval.metrics`  - precision/recall/F1/AUC/FPR (honesty rules)
* :mod:`spectra.eval.runner`   - pipeline integration (pcap -> report)
* :mod:`spectra.eval.report`   - versioned JSON report + compare
"""

from __future__ import annotations

from .join import DEFAULT_TOLERANCE_S, JoinResult, ScoredFlow, join_flows
from .labels import (
    BENIGN_LABELS,
    LABEL_COLUMNS,
    MAPPED_CATEGORIES,
    METADATA_INVISIBLE,
    LabelError,
    LabelRow,
    label_summary,
    load_labels,
)
from .metrics import compute_metrics, parser_coverage, roc_auc
from .report import REPORT_VERSION, build_report, compare
from .runner import EvalParams, run_eval, score_flows

__all__ = [
    "BENIGN_LABELS", "DEFAULT_TOLERANCE_S", "LABEL_COLUMNS",
    "MAPPED_CATEGORIES", "METADATA_INVISIBLE", "REPORT_VERSION",
    "EvalParams", "JoinResult", "LabelError", "LabelRow", "ScoredFlow",
    "build_report", "compare", "compute_metrics", "join_flows",
    "label_summary", "load_labels", "parser_coverage", "roc_auc",
    "run_eval", "score_flows",
]
