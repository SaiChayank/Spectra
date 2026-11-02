"""Evaluation report store: the conventional home of finished reports.

``spectra eval run`` writes its report here (``<data_dir>/eval/``) and the
read routes (``GET /api/model/eval``) serve what is on disk - the API never
computes an evaluation itself, it only lists and returns what the offline
harness produced.  Filenames are constrained to ``[A-Za-z0-9._-]`` leaves so
a stored report can never address the filesystem.
"""

from __future__ import annotations

import json
import os
import re
from datetime import datetime, timezone

from ..config import Config

#: Safe report filename: leaf-only, no separators, must end in .json.
_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*\.json$")


class ReportStoreError(ValueError):
    """Unknown, malformed or unsafe report name."""


def reports_dir(config: Config | None = None) -> str:
    cfg = config or Config.from_env()
    return os.path.join(cfg.data_dir, "eval")


def _check_name(name: str) -> str:
    if not _NAME_RE.match(name) or ".." in name:
        raise ReportStoreError(f"unsafe report name: {name!r}")
    return name


def default_name(report: dict) -> str:
    """``<dataset>-<created_at>.json`` from the report itself."""
    dataset = re.sub(r"[^A-Za-z0-9._-]+", "-",
                     str(report.get("dataset", {}).get("name") or "report"))
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return f"{dataset}-{stamp}.json"


def save(report: dict, name: str | None = None,
         config: Config | None = None) -> str:
    """Persist a report; returns the stored path (atomic write)."""
    name = _check_name(name or default_name(report))
    directory = reports_dir(config)
    os.makedirs(directory, exist_ok=True)
    path = os.path.join(directory, name)
    tmp = f"{path}.tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)
    os.replace(tmp, path)
    return path


def load(name: str, config: Config | None = None) -> dict:
    """Read one stored report; raises on unknown name or bad JSON."""
    name = _check_name(name)
    path = os.path.join(reports_dir(config), name)
    if not os.path.isfile(path):
        raise ReportStoreError(f"report not found: {name}")
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def list_reports(config: Config | None = None) -> dict:
    """Summary rows for every stored report (newest first).

    A corrupt file is listed as such instead of poisoning the whole route -
    transparency about a broken artifact beats a 500.
    """
    directory = reports_dir(config)
    rows: list[dict] = []
    if os.path.isdir(directory):
        for fname in sorted(os.listdir(directory)):
            if not fname.endswith(".json") or not _NAME_RE.match(fname):
                continue
            path = os.path.join(directory, fname)
            row: dict = {"name": fname, "path": path,
                         "size": os.path.getsize(path)}
            try:
                with open(path, "r", encoding="utf-8") as f:
                    rep = json.load(f)
                row.update({
                    "report_version": rep.get("report_version"),
                    "created_at": rep.get("created_at"),
                    "dataset": rep.get("dataset", {}).get("name"),
                    "model_sha256": rep.get("model", {}).get("sha256"),
                    "feature_schema_version":
                        rep.get("model", {}).get("feature_schema_version"),
                    "overall": rep.get("overall"),
                    "flows": rep.get("flows"),
                    "parser_coverage": rep.get("parser_coverage"),
                    "caveats": len(rep.get("caveats") or []),
                    "corrupt": False,
                })
            except (json.JSONDecodeError, OSError, AttributeError):
                row["corrupt"] = True
            rows.append(row)
    rows.sort(key=lambda r: str(r.get("created_at") or ""), reverse=True)
    return {"directory": directory, "count": len(rows), "reports": rows}


__all__ = ["ReportStoreError", "default_name", "list_reports", "load", "save",
           "reports_dir"]
