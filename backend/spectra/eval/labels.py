"""Ground-truth label schema: load and validate per-dataset label CSVs.

Label files follow ``docs/evaluation.md`` §3 — one row per labeled
interval, with the dataset's own label preserved verbatim and a
``mapped_category`` that is either one of Spectra's ``THREAT_TYPES`` or the
explicit ``METADATA_INVISIBLE`` bucket (payload-level attacks that
metadata-only detection cannot see and must never be scored as misses).

Pure data + parsing: no pipeline imports, so the schema is unit-testable on
hand-written CSV fixtures without scapy or a model.
"""

from __future__ import annotations

import csv
import os
from dataclasses import dataclass, field

from ..threats import THREAT_TYPES

#: Attacks that are payload-level by design: counted, never scored.
METADATA_INVISIBLE = "METADATA_INVISIBLE"

#: Sentinel: any value matches (ports/proto columns in a label row).
ANY = "*"

#: Every value ``mapped_category`` may take.
MAPPED_CATEGORIES: tuple[str, ...] = THREAT_TYPES + (METADATA_INVISIBLE,)

#: Columns of a label CSV, in order.  ``dataset_label``/``mapped_category``
#: carry the dataset's own wording and our fixed mapping.
LABEL_COLUMNS: tuple[str, ...] = (
    "t_start", "t_end", "src_ip", "src_port", "dst_ip", "dst_port",
    "proto", "dataset_label", "mapped_category",
)


class LabelError(ValueError):
    """A label file is malformed (unknown category, bad time range, ...)."""


@dataclass(frozen=True)
class LabelRow:
    """One labeled interval (see docs/evaluation.md §3)."""

    t_start: float
    t_end: float
    src_ip: str
    dst_ip: str
    src_port: int | None      # None = any (``*``)
    dst_port: int | None      # None = any
    proto: str                # "TCP" | "UDP" | "*"
    dataset_label: str
    mapped_category: str
    #: benign reference window (not an attack) - derived from the dataset's
    #: own wording (``BENIGN_LABELS``) so the invariant holds however the row
    #: was constructed (CSV loader, adapter, test fixture).
    benign: bool = field(default=False)

    def __post_init__(self) -> None:
        if self.dataset_label.strip().lower() in BENIGN_LABELS:
            object.__setattr__(self, "benign", True)

    def endpoint_pair(self) -> frozenset[str]:
        return frozenset((self.src_ip, self.dst_ip))


#: Dataset wordings treated as "benign reference" (FPR window, never attack).
BENIGN_LABELS: frozenset[str] = frozenset({
    "benign", "normal", "background-benign", "legitimate",
})


def _norm(value: str) -> str:
    return value.strip().lower()


def _parse_port(raw: str) -> int | None:
    raw = raw.strip()
    if raw in (ANY, "", "-"):
        return None
    port = int(raw)
    if not 0 <= port <= 65535:
        raise LabelError(f"port out of range: {raw}")
    return port


def _parse_proto(raw: str) -> str:
    raw = raw.strip().upper()
    if raw in (ANY, "", "-"):
        return "*"
    if raw not in ("TCP", "UDP"):
        raise LabelError(f"proto must be TCP, UDP or *: {raw}")
    return raw


def parse_row(cells: dict[str, str], lineno: int) -> LabelRow:
    """Validate one CSV row into a :class:`LabelRow`.

    Raises :class:`LabelError` naming the line, so a per-dataset adapter
    fails loudly instead of quietly corrupting an evaluation.
    """
    def need(col: str) -> str:
        v = (cells.get(col) or "").strip()
        if v == "":
            raise LabelError(f"line {lineno}: missing column {col!r}")
        return v

    try:
        t_start = float(need("t_start"))
        t_end = float(need("t_end"))
    except ValueError as exc:
        raise LabelError(f"line {lineno}: bad timestamp: {exc}") from exc
    if t_end < t_start:
        raise LabelError(f"line {lineno}: t_end < t_start")

    src_ip = need("src_ip")
    dst_ip = need("dst_ip")
    dataset_label = need("dataset_label")
    category = _norm(need("mapped_category")).upper()
    if category not in MAPPED_CATEGORIES:
        raise LabelError(
            f"line {lineno}: mapped_category {category!r} not in "
            f"{sorted(MAPPED_CATEGORIES)}")

    return LabelRow(
        t_start=t_start, t_end=t_end,
        src_ip=src_ip, dst_ip=dst_ip,
        src_port=_parse_port(need("src_port")),
        dst_port=_parse_port(need("dst_port")),
        proto=_parse_proto(need("proto")),
        dataset_label=dataset_label,
        mapped_category=category,
        benign=_norm(dataset_label) in BENIGN_LABELS,
    )


def load_labels(path: str) -> list[LabelRow]:
    """Load a label CSV; the header must contain every ``LABEL_COLUMNS``."""
    if not os.path.isfile(path):
        raise LabelError(f"label file not found: {path}")
    rows: list[LabelRow] = []
    with open(path, "r", encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f)
        header = {h.strip().lower() for h in (reader.fieldnames or [])}
        missing = [c for c in LABEL_COLUMNS if c not in header]
        if missing:
            raise LabelError(
                f"label file missing columns: {missing} (expected {list(LABEL_COLUMNS)})")
        for i, raw in enumerate(reader, start=2):
            cells = {(k or "").strip().lower(): (v or "")
                     for k, v in raw.items()}
            rows.append(parse_row(cells, i))
    return rows


def label_summary(rows: list[LabelRow]) -> dict:
    """Counts per category + benign windows (goes into the report)."""
    by_cat: dict[str, int] = {}
    benign = 0
    for r in rows:
        if r.benign:
            benign += 1
        else:
            by_cat[r.mapped_category] = by_cat.get(r.mapped_category, 0) + 1
    return {
        "rows": len(rows),
        "attack_rows": sum(by_cat.values()),
        "benign_windows": benign,
        "by_category": dict(sorted(by_cat.items())),
    }
