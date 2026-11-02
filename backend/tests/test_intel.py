"""Local threat intel: list loading, matching, guard-failure, classifier use.

Hermetic: list files are written to a tmp directory, records are plain
dicts.  Asserts the honesty contract too - intel is a signal, never an
auto-verdict (a listed JA3 alone never classifies).
"""

from __future__ import annotations

import os

import pytest

from spectra.intel import IntelService, LIST_FILES
from spectra.threats import classify_threat, unknown_threat

JA3_LISTED = "8f6c918dcb585ebbea05e2cc94530e3d"     # Tofsee sample (SSLBL)
JA3_OTHER = "0cc1e84568e471aa1d62ad4158ade6b5"


@pytest.fixture()
def intel_dir(tmp_path):
    d = tmp_path / "intel"
    d.mkdir()
    return str(d)


def _write(directory, name, text):
    with open(os.path.join(directory, name), "w", encoding="utf-8") as f:
        f.write(text)


# -- loading ---------------------------------------------------------------

def test_empty_directory_is_available_off(intel_dir):
    svc = IntelService(intel_dir)
    st = svc.status()
    assert st["available"] is False       # nothing loaded, but no error
    assert st["error"] is None            # absence is not a failure
    assert st["counts"]["total"] == 0


def test_missing_directory_is_not_a_failure(tmp_path):
    svc = IntelService(str(tmp_path / "nope"))
    assert svc.status()["error"] is None
    assert svc.match({"ja3": JA3_LISTED}) == []


def test_load_ja3_ja4_sni(intel_dir):
    _write(intel_dir, "ja3.txt",
           f"# comment line\n{JA3_LISTED}\n\n{JA3_OTHER.upper()}\n")
    _write(intel_dir, "ja4.txt", "t13d1516h2_8daaf6152771_b0da82dd1658\n")
    _write(intel_dir, "sni.txt", "evil.example.com\n*.bad.net\n")
    svc = IntelService(intel_dir)
    st = svc.status()
    assert st["available"] is True
    assert st["counts"] == {"ja3": 2, "ja4": 1, "sni": 2, "total": 5}
    # uppercase JA3 is normalised to lowercase
    assert JA3_OTHER in svc.lists.ja3
    # provenance: one source entry per file with sha256
    assert {s["file"] for s in st["sources"]} == set(LIST_FILES)


def test_malformed_entries_rejected(intel_dir):
    _write(intel_dir, "ja3.txt",
           f"{JA3_LISTED}\nnot-a-hash\nzzzz\n")
    _write(intel_dir, "sni.txt", "evil.example.com\nnot a domain\n_!!_\n")
    svc = IntelService(intel_dir)
    assert svc.lists.ja3 == {JA3_LISTED}
    assert svc.lists.sni == {"evil.example.com"}
    # rejections are reported, not silently dropped
    rejected = sum(s["rejected"] for s in svc.status()["sources"])
    assert rejected == 4


def test_reload_after_edit(intel_dir):
    _write(intel_dir, "ja3.txt", f"{JA3_LISTED}\n")
    svc = IntelService(intel_dir)
    assert svc.status()["counts"]["ja3"] == 1
    _write(intel_dir, "ja3.txt", f"{JA3_LISTED}\n{JA3_OTHER}\n")
    svc.reload()
    assert svc.status()["counts"]["ja3"] == 2


def test_corrupt_directory_content_degrades(tmp_path):
    # a *file* where the directory should be -> guard path, no exception
    bad = tmp_path / "intel"
    bad.write_text("x", encoding="utf-8")
    svc = IntelService(str(bad))
    st = svc.status()
    assert st["error"] is not None
    assert st["available"] is False
    assert svc.match({"ja3": JA3_LISTED}) == []   # empty, never raises


# -- matching ---------------------------------------------------------------

@pytest.fixture()
def svc(intel_dir):
    _write(intel_dir, "ja3.txt", f"{JA3_LISTED}\n")
    _write(intel_dir, "ja4.txt", "t13d1516h2_8daaf6152771_b0da82dd1658\n")
    _write(intel_dir, "sni.txt", "evil.example.com\n*.bad.net\n")
    return IntelService(intel_dir)


def test_ja3_hit_and_miss(svc):
    hits = svc.match({"ja3": JA3_LISTED})
    assert len(hits) == 1
    assert hits[0]["list"] == "ja3"
    assert hits[0]["value"] == JA3_LISTED
    assert svc.match({"ja3": JA3_OTHER}) == []


def test_ja3_case_insensitive(svc):
    assert svc.match({"ja3": JA3_LISTED.upper()}) != []


def test_ja4_full_and_prefix_match(svc):
    full = "t13d1516h2_8daaf6152771_b0da82dd1658"
    assert svc.match({"ja4": full})[0]["list"] == "ja4"
    # a listed prefix matches a longer observed value
    _svc_lists = svc.lists
    object.__setattr__(_svc_lists, "ja4", frozenset({"t13d"}))
    assert svc.match({"ja4": "t13d1516h2_8daaf6152771_b0da82dd1658"}) != []
    assert svc.match({"ja4": "q13d1516h2_8daaf6152771_b0da82dd1658"}) == []


def test_sni_exact_and_wildcard(svc):
    assert svc.match({"sni": "evil.example.com"})[0]["list"] == "sni"
    # wildcard: any subdomain of bad.net, not bad.net itself
    assert svc.match({"sni": "x.bad.net"})[0]["list"] == "sni"
    assert svc.match({"sni": "y.x.bad.net"})[0]["list"] == "sni"
    assert svc.match({"sni": "bad.net"}) == []
    assert svc.match({"sni": "good.example.org"}) == []


def test_no_handshake_fields_is_empty(svc):
    assert svc.match({}) == []
    assert svc.match({"ja3": None, "sni": ""}) == []


def test_unavailable_lists_never_hit(tmp_path):
    svc = IntelService(str(tmp_path / "missing"))
    assert svc.match({"ja3": JA3_LISTED, "sni": "evil.example.com"}) == []


# -- classifier integration ---------------------------------------------------

def _tls_record(**kw):
    rec = {
        "src": "10.0.0.5:40000", "dst": "93.184.216.34:443",
        "proto": "TCP", "duration": 4.0, "packets": 20, "bytes": 5000,
        "tls_version": "TLS 1.2", "sni": "evil.example.com",
        "alpn": ["h2"], "ja3": JA3_LISTED, "ja4": "t13d1516h2",
    }
    rec.update(kw)
    return rec


def test_intel_hit_is_a_supporting_signal():
    threat = classify_threat(_tls_record(intel=[
        {"list": "ja3", "value": JA3_LISTED,
         "detail": "JA3 is on the local blacklist"}],
    ), feats=None, window=[])
    names = [s["signal"] for s in threat["supporting"]]
    assert "intel_ja3_match" in names
    item = next(s for s in threat["supporting"]
                if s["signal"] == "intel_ja3_match")
    assert item["value"] == JA3_LISTED          # machine-readable
    assert "local blacklist" in item["detail"]


def test_intel_alone_never_classifies():
    # one strong signal alone never classifies: an intel hit with no other
    # evidence stays UNKNOWN (honest "we cannot say" path)
    threat = classify_threat(_tls_record(intel=[
        {"list": "ja3", "value": JA3_LISTED, "detail": "listed"}],
    ), feats=None, window=[])
    assert threat["threat_type"] == "UNKNOWN_ANOMALY"
    assert threat.get("insufficient_evidence") is True
    # but it may name the candidate it was closest to
    assert threat.get("candidate") in ("TLS_ANOMALY", "C2_BEACONING")


def test_no_intel_key_means_no_intel_signal():
    threat = classify_threat(_tls_record(), feats=None, window=[])
    names = [s["signal"] for s in threat["supporting"]]
    assert not any(n.startswith("intel_") for n in names)


def test_malformed_intel_ignored_by_classifier():
    # a bad intel payload must not raise or inject junk
    threat = classify_threat(_tls_record(intel=["garbage", 42, None]),
                             feats=None, window=[])
    names = [s["signal"] for s in threat["supporting"]]
    assert not any(n.startswith("intel_") for n in names)


def test_unknown_threat_unchanged_shape():
    t = unknown_threat()
    assert t["threat_type"] == "UNKNOWN_ANOMALY"
    assert t["supporting"] == []


# -- API surface ---------------------------------------------------------------

def test_intel_status_route(client):
    res = client.get("/api/model/intel")
    assert res.status_code == 200
    body = res.json()
    # hermetic suite: no list files -> available false, but *no* error
    for key in ("available", "directory", "counts", "sources",
                "loaded_at", "error", "failures"):
        assert key in body


def test_intel_status_needs_auth(raw_client):
    res = raw_client.get("/api/model/intel")
    assert res.status_code == 401


# -- capability contract -------------------------------------------------------

def test_intel_capability_declared_honestly():
    """Intel is LOCAL, evidence-only, and names its guard in the contract."""
    from spectra.api.app import engine
    from spectra.capabilities import capability_contracts, module_capabilities
    entry = capability_contracts()["intel"]
    assert entry["status"] == "LOCAL"
    assert entry["affects_alert_scoring"] is False
    assert entry["evidence_only"] is True
    assert entry["hardware_backed"] is False
    assert "component 'intel'" in entry["failure"]
    # live view: probe runs, availability reflects the loaded lists
    live = module_capabilities(engine.capability_status())["modules"]["intel"]
    assert live["available"] is False      # no list files in the hermetic suite
    assert live["detail"]                  # says *why* (never blank)


# -- detection hot path (engine integration) -----------------------------------

def test_score_flow_attaches_intel_hits(tmp_path):
    """A listed JA3 on a real parsed flow lands on the record as intel."""
    from spectra.api.app import engine
    from spectra.demo import make_baseline_pcap
    from spectra.parse.flow import FlowTracker
    from spectra.capture import open_source

    # build one real TLS flow from the demo generator
    pcap = str(tmp_path / "b.pcap")
    make_baseline_pcap(pcap, n_flows=1)
    flows = []
    tracker = FlowTracker(idle_timeout=5.0, on_complete=flows.append)
    for pkt in open_source("pcap", path=pcap).packets():
        tracker.process(pkt, float(pkt.time))
    list(tracker.flush_all())
    assert flows, "fixture produced no flows"
    flow = flows[0]
    record = flow.record()
    assert record.get("ja3"), "demo flow must parse a JA3 (intel target)"

    # point the engine's intel at a list containing exactly this JA3
    intel_dir = tmp_path / "intel"
    intel_dir.mkdir()
    (intel_dir / "ja3.txt").write_text(record["ja3"] + "\n", encoding="utf-8")
    from spectra.intel import IntelService

    saved = engine.detection.intel
    engine.detection.intel = IntelService(str(intel_dir))
    try:
        scored = engine.detection.score_flow(flow)
        assert scored is not None
        hits = scored["record"].get("intel")
        assert hits and hits[0]["value"] == record["ja3"]
        # and the classifier consumes it (independent signal present)
        from spectra.threats import classify_threat
        threat = classify_threat(scored["record"], scored["feats"], [])
        names = [s["signal"] for s in threat["supporting"]]
        assert "intel_ja3_match" in names
    finally:
        engine.detection.intel = saved


def test_score_flow_without_intel_has_no_key(tmp_path):
    """No intel service -> no intel key (absence is not an empty claim)."""
    from spectra.api.app import engine
    from spectra.demo import make_baseline_pcap
    from spectra.parse.flow import FlowTracker
    from spectra.capture import open_source

    pcap = str(tmp_path / "b2.pcap")
    make_baseline_pcap(pcap, n_flows=1)
    flows = []
    tracker = FlowTracker(idle_timeout=5.0, on_complete=flows.append)
    for pkt in open_source("pcap", path=pcap).packets():
        tracker.process(pkt, float(pkt.time))
    list(tracker.flush_all())
    assert flows

    saved = engine.detection.intel
    engine.detection.intel = None       # intel unavailable (guard default)
    try:
        scored = engine.detection.score_flow(flows[0])
        assert scored is not None
        assert "intel" not in scored["record"]
    finally:
        engine.detection.intel = saved
