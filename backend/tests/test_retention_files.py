"""Capture retention must remove the stored upload files, not only their rows.

Uploaded captures are stored verbatim (docs/security.md §4.9), so the stored
file is the payload-bearing artifact.  Retention used to delete the database
row and leave the file until the next process start (the orphan sweep ran only
at startup).  This pins that retention takes the file with it, right away.
"""

from __future__ import annotations

import os
import time

from spectra.config import Config
from spectra.db import RetentionPolicy
from spectra.demo import make_baseline_pcap
from spectra.pipeline import SpectraEngine

DAY = 86_400.0


def _engine(tmp_path):
    cfg = Config(persist=True)
    cfg.data_dir = str(tmp_path / "d")
    cfg.db_path = str(tmp_path / "d" / "spectra.db")
    cfg.capture_store_dir = str(tmp_path / "d" / "caps")
    cfg.model_path = str(tmp_path / "d" / "m.joblib")
    cfg.ensure_dirs()
    return SpectraEngine(config=cfg)


def _import(engine, tmp_path, seed):
    path = make_baseline_pcap(str(tmp_path / f"up{seed}.pcap"), n_flows=6, seed=seed)
    with open(path, "rb") as fh:
        meta = engine.capture_resources.import_file(f"up{seed}.pcap", [fh.read()])
    return meta


def _stored_file(engine, capture_id):
    row = engine.store.get_capture(capture_id)
    return os.path.join(engine.config.capture_store_dir, row["stored_name"])


def test_retention_deletes_the_stored_file_with_the_row(tmp_path):
    e = _engine(tmp_path)
    old, fresh = _import(e, tmp_path, 1), _import(e, tmp_path, 2)
    old_path, fresh_path = _stored_file(e, old["capture_id"]), _stored_file(e, fresh["capture_id"])
    assert os.path.isfile(old_path) and os.path.isfile(fresh_path)

    # the first upload was finished 100 days ago; its file is old on disk too
    now = time.time()
    e.store._conn.execute("UPDATE captures SET started_at = ?, stopped_at = ? WHERE id = ?",
                          (now - 100 * DAY, now - 100 * DAY + 5, old["capture_id"]))
    e.store._conn.execute("UPDATE captures SET started_at = ?, stopped_at = ? WHERE id = ?",
                          (now - 60, now - 30, fresh["capture_id"]))
    e.store._conn.commit()
    os.utime(old_path, (now - 100 * DAY, now - 100 * DAY))

    e.store.retention = RetentionPolicy(capture_retention_days=30.0, stale_session_hours=0.0)
    counts = e.store.run_retention()
    assert counts["captures"] == 1
    assert not os.path.exists(old_path), "payload-bearing file outlived its retention"
    assert os.path.isfile(fresh_path)                      # the recent one is untouched
    assert e.store.get_capture(fresh["capture_id"]) is not None


def test_retention_never_removes_a_file_an_import_is_still_writing(tmp_path):
    """The sweep keeps files younger than an hour: a concurrent import writes the file first."""
    e = _engine(tmp_path)
    young = os.path.join(e.config.capture_store_dir, "cap_inflight.pcap")
    with open(young, "wb") as fh:
        fh.write(b"\xd4\xc3\xb2\xa1" + bytes(40))
    e.store.retention = RetentionPolicy(capture_retention_days=0.0, stale_session_hours=0.0)
    e.capture_resources._after_retention({"captures": 1})
    assert os.path.exists(young)
