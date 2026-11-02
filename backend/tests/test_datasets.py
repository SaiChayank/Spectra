"""Dataset artifact registry: catalog, import, checksum verification.

Hermetic: every test runs against a temp data dir (Config with explicit
data_dir), a tiny fixture file is "imported" as an artifact, and the
manifest round-trip is asserted.  No network, no external datasets.
"""

from __future__ import annotations

import hashlib
import json
import os

import pytest

from spectra.config import Config
from spectra.datasets import (
    CATALOG_BY_NAME,
    DATASET_CATALOG,
    MANIFEST_NAME,
    DatasetError,
    artifact_path,
    catalog,
    datasets_dir,
    import_artifact,
    list_artifacts,
    load_manifest,
    sha256_file,
    verify,
)


@pytest.fixture()
def cfg(tmp_path) -> Config:
    c = Config()
    c.data_dir = str(tmp_path / "data")
    return c


@pytest.fixture()
def artifact(tmp_path):
    p = tmp_path / "sample.pcap"
    p.write_bytes(b"\xd4\xc3\xb2\xa1" + os.urandom(64))
    return str(p)


def test_catalog_matches_docs_mapping():
    """The catalog must list exactly the datasets docs/evaluation.md names."""
    names = {d.name for d in DATASET_CATALOG}
    assert names == {"cicids2017", "ctu13", "vpn2016", "mawi",
                     "sslbl_ja3", "synthetic"}
    # mawi is reference-only (no attack labels); the rest carry labels
    assert CATALOG_BY_NAME["mawi"].labeled is False
    assert CATALOG_BY_NAME["cicids2017"].labeled is True


def test_catalog_is_json_serialisable():
    json.dumps(catalog())


def test_import_artifact_records_hash(cfg, artifact):
    entry = import_artifact(cfg, artifact, "synthetic", source_note="unit test")
    assert entry.dataset == "synthetic"
    assert entry.sha256 == sha256_file(artifact)
    assert entry.size == os.path.getsize(artifact)
    assert entry.source_note == "unit test"
    # file copied under the dataset-prefixed name
    dest = artifact_path(entry, cfg)
    assert os.path.isfile(dest)
    assert os.path.basename(dest).startswith("synthetic--")


def test_import_unknown_dataset_rejected(cfg, artifact):
    with pytest.raises(DatasetError, match="unknown dataset"):
        import_artifact(cfg, artifact, "not-a-dataset")


def test_import_missing_file_rejected(cfg, tmp_path):
    with pytest.raises(DatasetError, match="not found"):
        import_artifact(cfg, str(tmp_path / "nope.pcap"), "synthetic")


def test_import_rename_is_leaf_only(cfg, artifact, tmp_path):
    # a traversal attempt in --rename must not escape the datasets dir
    entry = import_artifact(cfg, artifact, "synthetic",
                            rename="../../evil.pcap")
    dest = artifact_path(entry, cfg)
    assert os.path.dirname(dest) == datasets_dir(cfg)
    assert os.path.basename(dest) == "synthetic--evil.pcap"


def test_reimport_same_name_replaces_entry(cfg, artifact):
    import_artifact(cfg, artifact, "synthetic")
    import_artifact(cfg, artifact, "synthetic")
    entries = load_manifest(cfg)
    assert len(entries) == 1


def test_verify_detects_tamper_and_missing(cfg, artifact, tmp_path):
    entry = import_artifact(cfg, artifact, "synthetic")
    ok = verify(cfg)
    assert ok["ok"] == 1 and ok["changed"] == 0 and ok["missing"] == 0

    # tamper: rewrite the imported artifact
    with open(artifact_path(entry, cfg), "wb") as f:
        f.write(b"tampered")
    out = verify(cfg)
    assert out["changed"] == 1 and out["ok"] == 0

    # missing: delete it
    os.remove(artifact_path(entry, cfg))
    out = verify(cfg)
    assert out["missing"] == 1


def test_verify_dataset_filter(cfg, artifact):
    import_artifact(cfg, artifact, "synthetic")
    out = verify(cfg, dataset="cicids2017")
    assert out["entries"] == 0


def test_list_artifacts_reports_presence(cfg, artifact):
    import_artifact(cfg, artifact, "synthetic")
    out = list_artifacts(cfg)
    assert len(out["artifacts"]) == 1
    assert out["artifacts"][0]["present"] is True
    assert out["artifacts"][0]["dataset"] == "synthetic"
    assert len(out["catalog"]) == len(DATASET_CATALOG)


def test_list_artifacts_unknown_dataset(cfg):
    with pytest.raises(DatasetError):
        list_artifacts(cfg, dataset="nope")


def test_manifest_not_tracked_by_git(tmp_path):
    """Manifest + artifacts live under backend/data (git-ignored)."""
    # tests/ -> backend/ -> repo root
    repo = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
    gitignore = os.path.join(repo, ".gitignore")
    if not os.path.isfile(gitignore):
        pytest.skip("no repo gitignore visible")
    with open(gitignore, "r", encoding="utf-8") as f:
        rules = [ln.strip() for ln in f if ln.strip() and not ln.startswith("#")]
    assert "backend/data/" in rules
