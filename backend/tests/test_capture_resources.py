"""Managed capture resources: import validation, lifecycle, API contract.

These tests pin the DoD of the managed-capture workflow: clients never send
server filesystem paths, uploads are validated (name/extension/signature/
size/traversal/duplicates) into a controlled store, history is persisted, and
both PCAP processing and the live-only capture API keep working.
"""

from __future__ import annotations

import json
import os
import threading

from fastapi.testclient import TestClient

from spectra.api.app import app, engine
from spectra.capture import (
    CaptureFileError,
    CaptureStorage,
    CaptureTooLargeError,
)
from spectra.demo import make_baseline_pcap, make_suspicious_pcap

client = TestClient(app)

TERMINAL = ("COMPLETED", "FAILED", "STOPPED")


# -- import validation ---------------------------------------------------------

def test_import_validates_and_persists_metadata(tmp_path, upload_capture):
    pcap = make_suspicious_pcap(str(tmp_path / "s.pcap"))
    body = upload_capture(client, pcap)

    assert body["status"] == "UPLOADED"
    assert body["original_name"] == "s.pcap"
    assert body["stored_name"].startswith("cap_")
    assert body["size_bytes"] == os.path.getsize(pcap)
    assert body["source_type"] == "upload"
    assert body["imported_at"] is not None
    assert body["packets"] == 0 and body["flows"] == 0
    assert body["error"] is None and body["running"] is False

    # the bytes live under the generated name inside the store directory
    storage = engine.capture_resources.storage
    stored_path = storage.path_for(body["stored_name"])
    assert os.path.isfile(stored_path)
    assert os.path.dirname(os.path.realpath(stored_path)) == storage.directory


def test_import_sanitizes_traversal_filename(tmp_path, upload_capture):
    """A hostile filename becomes metadata; the store name is generated."""
    pcap = make_baseline_pcap(str(tmp_path / "b.pcap"), n_flows=5)
    body = upload_capture(client, pcap,
                          filename="../../../etc/passwd.pcap")

    assert body["original_name"] == "passwd.pcap"     # basename only
    assert body["stored_name"].startswith("cap_")
    assert "/" not in body["stored_name"] and ".." not in body["stored_name"]
    # no server path appears anywhere in the response
    dump = json.dumps(body)
    assert engine.capture_resources.storage.directory not in dump
    assert str(tmp_path) not in dump


def test_import_rejects_bad_name_extension_and_signature(tmp_path):
    good = make_baseline_pcap(str(tmp_path / "b.pcap"), n_flows=5)
    with open(good, "rb") as fh:
        data = fh.read()

    cases = [
        ("notes.txt", b"hello", "text/plain"),           # extension
        ("junk.pcap", b"totally not a pcap file", None),  # signature
        ("tiny.pcapng", b"\x00\x01", None),               # truncated magic
        ("", b"", None),                                  # missing filename
        ("empty.pcap", b"", None),                        # empty upload
    ]
    for name, payload, ctype in cases:
        res = client.post("/api/captures",
                          files={"file": (name, payload,
                                          ctype or "application/octet-stream")})
        # httpx omits the filename for "", so that case never reaches the
        # filename gate and fails FastAPI's required-file check instead
        assert res.status_code in (400, 422), (name, res.status_code, res.text)

    # no .part debris from the rejected uploads
    leftovers = [f for f in os.listdir(
        engine.capture_resources.storage.directory) if f.startswith(".")]
    assert leftovers == []


def test_import_rejects_duplicates_by_content(tmp_path, upload_capture):
    pcap = make_suspicious_pcap(str(tmp_path / "s1.pcap"))
    with open(pcap, "rb") as fh:
        first = fh.read()
    first_id = upload_capture(client, pcap)["capture_id"]

    # same bytes under a different name is still the same capture
    res = client.post("/api/captures",
                      files={"file": ("renamed-copy.pcap", first,
                                      "application/octet-stream")})
    assert res.status_code == 409, res.text
    detail = res.json()["detail"]
    assert detail["capture_id"] == first_id
    assert detail["error"] == "duplicate capture"


def test_capture_storage_enforces_size_signature_and_paths(tmp_path):
    """Pure storage-level gates (the API's 256 MB cap is not practical here)."""
    capped = CaptureStorage(str(tmp_path / "store"), max_bytes=8)

    try:
        capped.save_stream([b"123456789"])          # 9 > 8 bytes
        raise AssertionError("oversize upload accepted")
    except CaptureTooLargeError:
        pass
    try:
        capped.save_stream([b"not a pcap at all"])  # wrong magic
        raise AssertionError("bad signature accepted")
    except CaptureFileError:
        pass
    try:
        capped.save_stream([b""])                   # empty
        raise AssertionError("empty upload accepted")
    except CaptureFileError:
        pass
    assert os.listdir(tmp_path / "store") == []     # no partial files remain

    store = CaptureStorage(str(tmp_path / "store"))   # API-default size cap

    # a valid stream lands under a generated name with the content's extension
    staged = store.save_stream([b"\xd4\xc3\xb2\xa1" + b"\x00" * 60])
    assert staged.stored_name.startswith("cap_")
    assert staged.stored_name.endswith(".pcap")
    assert os.path.isfile(staged.path) and staged.size == 64
    assert len(staged.sha256) == 64
    assert store.remove(staged.stored_name) is True
    assert store.remove(staged.stored_name) is False  # already gone

    # traversal / absolute names are refused, even for reads
    for bad in ("../escape.pcap", "..\\escape.pcap", "/etc/passwd",
                "", None, ".", ".."):
        try:
            store.path_for(bad)
            raise AssertionError(f"path_for accepted {bad!r}")
        except CaptureFileError:
            pass

    assert store.sanitize_name("C:\\fakepath\\y.pcap") == "y.pcap"
    assert store.sanitize_name("../../z.pcap") == "z.pcap"
    for bad in ("", None, "a" * 300, "bad\nname.pcap", "..", "."):
        try:
            store.sanitize_name(bad)
            raise AssertionError(f"sanitize_name accepted {bad!r}")
        except CaptureFileError:
            pass
    assert store.check_extension("a.PCAPNG") == ".pcapng"
    try:
        store.check_extension("a.pkt")
        raise AssertionError("extension gate accepted .pkt")
    except CaptureFileError:
        pass


# -- processing lifecycle --------------------------------------------------------

def test_process_completes_and_records_metadata(tmp_path, upload_capture,
                                                process_capture):
    pcap = make_suspicious_pcap(str(tmp_path / "s.pcap"))
    cap_id = upload_capture(client, pcap)["capture_id"]

    res = client.post(f"/api/captures/{cap_id}/process")
    assert res.status_code == 200, res.text
    assert res.json()["status"] == "PROCESSING"
    assert res.json()["running"] is True

    det = process_capture(client, cap_id)
    assert det["status"] == "COMPLETED"
    assert det["error"] is None
    assert det["flows"] >= 10 and det["packets"] > 0
    assert det["source_type"] == "upload"
    assert det["original_name"] == "s.pcap"

    # status/audit show the imported name, never a server path
    status = client.get("/api/status").json()
    assert status["source"] == "s.pcap"
    assert not os.path.isabs(status["source"])

    # the scored rows are linked to this resource
    linked = engine.store._db.query(
        "SELECT COUNT(*) AS n FROM flows WHERE capture_id = ?", (cap_id,))
    assert linked[0]["n"] > 0


def test_reprocess_resets_counters_and_runs_again(tmp_path, upload_capture,
                                                  process_capture):
    pcap = make_suspicious_pcap(str(tmp_path / "s.pcap"))
    cap_id = upload_capture(client, pcap)["capture_id"]
    first = process_capture(client, cap_id)
    assert first["flows"] > 0

    res = client.post(f"/api/captures/{cap_id}/process")
    assert res.status_code == 200, res.text
    assert res.json()["status"] == "PROCESSING"
    second = process_capture(client, cap_id)
    assert second["status"] == "COMPLETED"
    assert second["flows"] > 0
    assert second["capture_id"] == cap_id        # one resource, many runs


def test_process_rejects_unknown_and_unstored_captures(tmp_path):
    assert client.post("/api/captures/999999/process").status_code == 404

    # legacy path-session row: exists but has no stored file
    legacy_id = engine.store.start_capture("pcap", "some/old/local/path.pcap")
    try:
        res = client.post(f"/api/captures/{legacy_id}/process")
        assert res.status_code == 409
        assert "no stored file" in res.json()["detail"]
    finally:
        engine.store.delete_capture(legacy_id)


def test_delete_removes_row_and_file(tmp_path, upload_capture):
    pcap = make_suspicious_pcap(str(tmp_path / "s.pcap"))
    cap_id = upload_capture(client, pcap)["capture_id"]
    stored_name = client.get(f"/api/captures/{cap_id}").json()["stored_name"]
    stored_path = engine.capture_resources.storage.path_for(stored_name)
    assert os.path.isfile(stored_path)

    res = client.delete(f"/api/captures/{cap_id}")
    assert res.status_code == 200, res.text
    assert res.json() == {"deleted": cap_id, "file_removed": True,
                          "original_name": "s.pcap"}
    assert not os.path.isfile(stored_path)
    assert client.get(f"/api/captures/{cap_id}").status_code == 404
    assert client.delete(f"/api/captures/{cap_id}").status_code == 404


def test_delete_is_refused_while_the_capture_runs(tmp_path, upload_capture):
    pcap = make_suspicious_pcap(str(tmp_path / "s.pcap"))
    cap_id = upload_capture(client, pcap)["capture_id"]

    # Deterministically present the resource as the active session.
    prev_thread = engine.capture._thread
    prev_id = engine.capture.session.capture_id
    engine.capture._thread = threading.current_thread()   # alive
    engine.capture.session.capture_id = cap_id
    try:
        res = client.delete(f"/api/captures/{cap_id}")
        assert res.status_code == 409
        assert "running" in res.json()["detail"]
    finally:
        engine.capture._thread = prev_thread
        engine.capture.session.capture_id = prev_id

    assert client.delete(f"/api/captures/{cap_id}").status_code == 200


def test_import_disabled_without_persistence(tmp_path):
    """No store -> no recorded history, so imports are refused (409)."""
    prev = engine.store
    try:
        engine.store = None
        res = client.post("/api/captures",
                          files={"file": ("x.pcap", b"\xd4\xc3\xb2\xa1" * 8,
                                          "application/octet-stream")})
        assert res.status_code == 409
        assert client.get("/api/captures").status_code == 409
    finally:
        engine.store = prev


# -- listing + details ------------------------------------------------------------

def test_list_details_and_status_filters(tmp_path, upload_capture):
    pcap = make_baseline_pcap(str(tmp_path / "b.pcap"), n_flows=5)
    cap_id = upload_capture(client, pcap)["capture_id"]

    res = client.get("/api/captures?limit=500")
    assert res.status_code == 200
    page = res.json()
    assert page["count"] >= 1
    assert cap_id in [c["capture_id"] for c in page["items"]]

    res = client.get("/api/captures?status=UPLOADED")
    assert res.status_code == 200
    uploaded = res.json()["items"]
    assert cap_id in [c["capture_id"] for c in uploaded]
    assert all(c["status"] == "UPLOADED" for c in uploaded)

    assert client.get("/api/captures?status=BOGUS").status_code == 422
    assert client.get("/api/captures/999999").status_code == 404

    det = client.get(f"/api/captures/{cap_id}")
    assert det.status_code == 200
    assert det.json()["capture_id"] == cap_id


# -- the unsafe path surface is gone -------------------------------------------------

def test_capture_start_accepts_live_only():
    """File-based starts are gone: pcap mode (with or without path) is 422."""
    assert client.post("/api/capture/start",
                       json={"mode": "pcap"}).status_code == 422
    assert client.post("/api/capture/start",
                       json={"mode": "pcap", "path": "/etc/passwd"}
                       ).status_code == 422
    assert client.post("/api/capture/start",
                       json={"mode": "bogus"}).status_code == 422


def test_offline_tools_take_capture_ids_not_paths(tmp_path, upload_capture):
    baseline = make_baseline_pcap(str(tmp_path / "b.pcap"), n_flows=30)
    cap_id = upload_capture(client, baseline)["capture_id"]

    # the old path field is no longer valid input: training requires
    # capture_id (422 without it), and the scan route requires the query param
    assert client.post("/api/model/train",
                       json={"pcap_path": baseline}).status_code == 422
    assert client.get("/api/pqc/scan?pcap=nope.pcap").status_code == 422

    res = client.post("/api/model/train",
                      json={"capture_id": cap_id, "contamination": 0.05})
    assert res.status_code == 200, res.text
    assert res.json()["n_train"] >= 30

    # unknown ids fail cleanly (404), never by touching a path
    assert client.get("/api/pqc/scan?capture_id=999999").status_code == 404
    assert client.post("/api/model/robustness",
                       json={"capture_id": 999999}).status_code == 404
    assert client.post("/api/twin/shadow",
                       json={"capture_id": 999999}).status_code == 404

    # a live capture row (no stored file) cannot be used by the offline tools
    legacy_id = engine.store.start_capture("live", "eth0")
    try:
        assert client.get(f"/api/pqc/scan?capture_id={legacy_id}"
                          ).status_code == 409
    finally:
        engine.store.delete_capture(legacy_id)
