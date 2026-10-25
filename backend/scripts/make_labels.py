#!/usr/bin/env python
"""Generate Spectra ground-truth label CSVs from a dataset's own label files.

Schema: docs/evaluation.md §3.  Mapping: docs/evaluation.md §4 (fixed,
revision-stamped — an unknown label wording fails the conversion rather
than being guessed).  Write output next to the dataset under
``backend/data/datasets/`` — never into git.

    cd backend
    python scripts/make_labels.py ctu13 ^
        --labels data/datasets/ctu13--capture20110810.binetflow.2format ^
        --pcap   data/datasets/ctu13--botnet-capture-20110810-neris.pcap ^
        --out    data/datasets/ctu13-s1-labels.csv
    python scripts/make_labels.py cicids2017 ^
        --labels MachineLearningCSV/Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv ^
        --pcap   ... --out data/datasets/cicids2017-fri-portscan-labels.csv

Always pass ``--pcap``: dataset timestamps are naive *local* time and the
UTC offset is derived from the capture's first packet (rounded to whole
hours, residual recorded in the JSON summary).  Without it the adapter
assumes UTC and says so (``"source": null``) — expect 1-3 h misalignment.

Prints the conversion summary as JSON (rows read / written, per-category
counts, skipped quirk counts, raw label census, timezone provenance).

Exit code 0 = labels written; 2 = LabelError (mapping/structure problem).
"""
from __future__ import annotations

import argparse
import json
import os
import sys

BACKEND = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BACKEND not in sys.path:
    sys.path.insert(0, BACKEND)

from spectra.eval.adapters import (  # noqa: E402
    cicids2017_to_labels,
    ctu13_to_labels,
)
from spectra.eval.labels import LabelError  # noqa: E402

CONVERTERS = {
    "ctu13": ctu13_to_labels,
    "cicids2017": cicids2017_to_labels,
}


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="make_labels.py",
        description="Generate a Spectra label CSV from a dataset's own "
                    "ground-truth file (docs/evaluation.md §3/§4).")
    sub = p.add_subparsers(dest="adapter", required=True)
    for name in sorted(CONVERTERS):
        sp = sub.add_parser(name, help=f"{name} label adapter")
        sp.add_argument("--labels", required=True,
                        help="dataset ground-truth file (binetflow / flow CSV)")
        sp.add_argument("--out", required=True,
                        help="output label CSV (write next to the dataset)")
        sp.add_argument("--pcap", default=None,
                        help="pcap the labels belong to — used to derive the "
                             "UTC offset of the naive label timestamps")
        sp.add_argument("--tz-offset", type=float, default=None,
                        dest="tz_offset",
                        help="explicit UTC offset in seconds (overrides --pcap)")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        summary = CONVERTERS[args.adapter](
            args.labels, args.out,
            pcap_path=args.pcap, tz_offset_s=args.tz_offset)
    except LabelError as exc:
        print(f"make_labels: {exc}", file=sys.stderr)
        return 2
    if summary["tz"]["source"] is None:
        print("make_labels: WARNING - no --pcap/--tz-offset: timestamps "
              "assumed UTC (dataset is likely local time)", file=sys.stderr)
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
