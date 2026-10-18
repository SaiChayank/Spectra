"""Dataset artifact registry: provenance, import and integrity for eval data.

Evaluation (see :mod:`spectra.eval` and ``docs/evaluation.md``) runs the real
pipeline over *public labeled datasets*.  This module owns what those datasets
are, where their bytes live (``<data_dir>/datasets/`` — git-ignored, never in
version control), and a SHA-256 manifest proving an artifact was not altered
between import and evaluation.

Deliberately **no network client**: fetching multi-GB pcaps is an operator
task (``backend/scripts/fetch_datasets.ps1``); this runtime only imports
files that already exist on disk, so the service gains no egress path.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
from dataclasses import dataclass, field
from datetime import datetime, timezone

from .config import Config

#: Manifest file inside the datasets directory.
MANIFEST_NAME = "manifest.json"

#: Copy buffer for imports (bounded memory on multi-GB files).
_COPY_CHUNK = 1 << 20


@dataclass(frozen=True)
class DatasetSpec:
    """One known evaluation dataset (catalog entry, not a downloaded file)."""

    name: str
    title: str
    purpose: str
    #: Where an operator can get the data (documentation only - never fetched).
    source: str
    license_note: str
    #: Filename hints that identify this dataset's artifacts on import.
    filename_hints: tuple[str, ...] = ()
    #: True when the dataset provides attack labels usable for recall.
    labeled: bool = True


#: The catalog from ``docs/evaluation.md`` §8.  Adding a dataset means adding
#: an entry here *and* documenting its label mapping in docs/evaluation.md §4.
DATASET_CATALOG: tuple[DatasetSpec, ...] = (
    DatasetSpec(
        name="cicids2017",
        title="CICIDS2017 (Canadian Institute for Cybersecurity)",
        purpose="Primary precision/recall benchmark: benign Monday + Friday "
                "attacks (PortScan, Bot, DoS, Web Attack, Infiltration)",
        source="https://www.unb.ca/cic/datasets/ids-2017.html",
        license_note="Research use; UNB CIC terms apply",
        filename_hints=("monday", "friday", "workinghours", "cicids"),
        labeled=True,
    ),
    DatasetSpec(
        name="ctu13",
        title="CTU-13 botnet scenarios (Stratosphere Laboratory)",
        purpose="C2_BEACONING recall on a purpose-built botnet benchmark",
        source="https://www.stratosphereips.org/datasets-ctu13",
        license_note="Research use; Stratosphere terms apply",
        filename_hints=("ctu", "scenario", "botnet", "capture"),
        labeled=True,
    ),
    DatasetSpec(
        name="vpn2016",
        title="ISCX VPN-nonVPN 2016 (UNB CIC)",
        purpose="Encrypted-app / VPN behaviour: FPR on VPN traffic + "
                "UNUSUAL_ENDPOINT_BEHAVIOR validation",
        source="https://www.unb.ca/cic/datasets/vpn.html",
        license_note="Research use; UNB CIC terms apply",
        filename_hints=("vpn", "nonvpn", "iscx"),
        labeled=True,
    ),
    DatasetSpec(
        name="mawi",
        title="MAWI Working Group daily traces (WIDE backbone)",
        purpose="Real-world benign FPR reference + parser coverage under "
                "payload truncation",
        source="https://mawi.wide.ad.jp/mawi/",
        license_note="MAWI trace use policy applies; anonymised backbone data",
        filename_hints=("mawi", "samplepoint", "daily"),
        labeled=False,   # benign reference only - no attack labels
    ),
    DatasetSpec(
        name="sslbl_ja3",
        title="abuse.ch SSLBL JA3 fingerprint blacklist",
        purpose="Seed threat-intel list for JA3 matching (spectra intel)",
        source="https://sslbl.abuse.ch/blacklist/",
        license_note="CC0; list frozen in 2021 - FP caution applies",
        filename_hints=("ja3_fingerprints", "sslbl"),
        labeled=False,
    ),
    DatasetSpec(
        name="synthetic",
        title="Synthetic fixtures (spectra demo + adv module)",
        purpose="CI-safe harness self-test; no external data",
        source="in-repo generator (spectra demo)",
        license_note="n/a (generated)",
        filename_hints=("baseline.pcap", "suspicious.pcap"),
        labeled=False,
    ),
)

CATALOG_BY_NAME: dict[str, DatasetSpec] = {d.name: d for d in DATASET_CATALOG}


class DatasetError(ValueError):
    """Unknown dataset, missing artifact or integrity failure."""


@dataclass
class ManifestEntry:
    """One imported artifact (JSON-serialisable via :meth:`to_dict`)."""

    dataset: str
    filename: str
    sha256: str
    size: int
    imported_at: str
    source_note: str = ""
    extra: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "dataset": self.dataset, "filename": self.filename,
            "sha256": self.sha256, "size": self.size,
            "imported_at": self.imported_at, "source_note": self.source_note,
            "extra": self.extra,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "ManifestEntry":
        return cls(
            dataset=str(d.get("dataset", "")),
            filename=str(d.get("filename", "")),
            sha256=str(d.get("sha256", "")),
            size=int(d.get("size", 0)),
            imported_at=str(d.get("imported_at", "")),
            source_note=str(d.get("source_note", "")),
            extra=dict(d.get("extra") or {}),
        )


def sha256_file(path: str, chunk: int = _COPY_CHUNK) -> str:
    """Streaming SHA-256 of a file (bounded memory for multi-GB artifacts)."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(chunk), b""):
            h.update(block)
    return h.hexdigest()


def datasets_dir(config: Config | None = None) -> str:
    """Directory holding imported dataset artifacts (git-ignored)."""
    cfg = config or Config.from_env()
    return os.path.join(cfg.data_dir, "datasets")


def _manifest_path(config: Config | None = None) -> str:
    return os.path.join(datasets_dir(config), MANIFEST_NAME)


def load_manifest(config: Config | None = None) -> list[ManifestEntry]:
    """Read the manifest; a missing file is an empty (not an error) list."""
    path = _manifest_path(config)
    if not os.path.isfile(path):
        return []
    with open(path, "r", encoding="utf-8") as f:
        raw = json.load(f)
    entries = raw.get("entries") if isinstance(raw, dict) else raw
    return [ManifestEntry.from_dict(e) for e in (entries or [])]


def _save_manifest(entries: list[ManifestEntry], config: Config | None = None) -> None:
    path = _manifest_path(config)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    payload = {
        "manifest_version": 1,
        "entries": [e.to_dict() for e in entries],
    }
    tmp = f"{path}.tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)
    os.replace(tmp, path)


def catalog() -> list[dict]:
    """Machine-readable dataset catalog (for CLI + docs cross-checks)."""
    return [
        {"name": d.name, "title": d.title, "purpose": d.purpose,
         "source": d.source, "license_note": d.license_note,
         "labeled": d.labeled, "filename_hints": list(d.filename_hints)}
        for d in DATASET_CATALOG
    ]


def import_artifact(config: Config, path: str, dataset: str,
                    source_note: str = "", rename: str | None = None) -> ManifestEntry:
    """Copy an on-disk artifact into the datasets dir and record its hash.

    The file is *copied* (the operator's original is left alone) under a
    sanitised name; the manifest entry proves which bytes the evaluation ran
    against.  Raises :class:`DatasetError` for unknown datasets or missing
    source files.
    """
    spec = CATALOG_BY_NAME.get(dataset)
    if spec is None:
        raise DatasetError(
            f"unknown dataset {dataset!r} - known: {sorted(CATALOG_BY_NAME)}")
    src = os.path.abspath(path)
    if not os.path.isfile(src):
        raise DatasetError(f"artifact not found: {src}")

    name = rename or os.path.basename(src)
    # No path separators can survive: this is a leaf filename only.
    name = os.path.basename(name.replace("\\", "/").split("/")[-1])
    if not name or name in (".", ".."):
        raise DatasetError("invalid artifact name")

    dest_dir = datasets_dir(config)
    os.makedirs(dest_dir, exist_ok=True)
    dest = os.path.join(dest_dir, f"{dataset}--{name}")
    if os.path.abspath(src) != os.path.abspath(dest):
        shutil.copy2(src, dest)

    entry = ManifestEntry(
        dataset=dataset,
        filename=os.path.basename(dest),
        sha256=sha256_file(dest),
        size=os.path.getsize(dest),
        imported_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
        source_note=source_note or src,
    )
    entries = [e for e in load_manifest(config)
               if not (e.dataset == entry.dataset and e.filename == entry.filename)]
    entries.append(entry)
    _save_manifest(entries, config)
    return entry


def artifact_path(entry: ManifestEntry, config: Config | None = None) -> str:
    return os.path.join(datasets_dir(config), entry.filename)


def verify(config: Config | None = None,
           dataset: str | None = None) -> dict:
    """Re-hash every manifest entry; report ok / missing / changed per file.

    This is the integrity gate an evaluation run should pass before trusting
    its inputs (``spectra dataset verify``).
    """
    entries = load_manifest(config)
    if dataset is not None:
        entries = [e for e in entries if e.dataset == dataset]
    results = []
    for e in entries:
        path = artifact_path(e, config)
        if not os.path.isfile(path):
            results.append({"filename": e.filename, "dataset": e.dataset,
                            "status": "missing", "sha256": e.sha256})
            continue
        actual = sha256_file(path)
        results.append({
            "filename": e.filename, "dataset": e.dataset,
            "status": "ok" if actual == e.sha256 else "changed",
            "sha256": e.sha256, "actual_sha256": actual,
            "size": e.size,
        })
    ok = sum(1 for r in results if r["status"] == "ok")
    return {
        "entries": len(results),
        "ok": ok,
        "missing": sum(1 for r in results if r["status"] == "missing"),
        "changed": sum(1 for r in results if r["status"] == "changed"),
        "results": results,
    }


def list_artifacts(config: Config | None = None,
                   dataset: str | None = None) -> dict:
    """Catalog + imported artifacts (with live existence/size status)."""
    entries = load_manifest(config)
    if dataset is not None:
        if dataset not in CATALOG_BY_NAME:
            raise DatasetError(
                f"unknown dataset {dataset!r} - known: {sorted(CATALOG_BY_NAME)}")
        entries = [e for e in entries if e.dataset == dataset]
    items = []
    for e in entries:
        path = artifact_path(e, config)
        items.append({
            **e.to_dict(),
            "present": os.path.isfile(path),
            "path": path,
        })
    return {"catalog": catalog(), "artifacts": items}
