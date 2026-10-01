"""Threat classification: evidence-backed, explainable classes over anomalies.

Unit tests cover each prompt category with synthetic (record, features,
window) triples plus the unknown/insufficient-evidence and
contradiction-handling paths; one end-to-end test proves the wiring (every
detection carries a valid, classified threat, beacons classify as
C2_BEACONING).
"""

import time

import numpy as np

from spectra.demo import make_baseline_pcap, make_suspicious_pcap
from spectra.features.extractor import FEATURE_NAMES, N_FEATURES
from spectra.pipeline import SpectraEngine
from spectra.threats import (
    THREAT_TYPES,
    UNKNOWN,
    classify_threat,
    unknown_threat,
)


# -- helpers ------------------------------------------------------------------

def feats(**overrides) -> np.ndarray:
    """A zero feature vector with named entries overridden."""
    vec = np.zeros(N_FEATURES, dtype=np.float32)
    for name, value in overrides.items():
        assert name in FEATURE_NAMES, f"unknown feature {name}"
        vec[FEATURE_NAMES.index(name)] = float(value)
    return vec


def rec(**overrides) -> dict:
    """A minimal flow record with named fields overridden."""
    base = {
        "proto": "TCP",
        "src": "10.0.0.5:40000",
        "dst": "10.1.1.1:443",
        "start_ts": 0.0,
        "last_ts": 1.0,
        "duration": 1.0,
        "packets": 10,
        "bytes": 5_000,
        "tls_version": None,
        "sni": None,
        "alpn": None,
        "ja3": None,
        "ja4": None,
        "cipher_count": 0,
        "extension_count": 0,
        "quic_version": None,
        "score": 70.0,
        "anomaly": True,
    }
    base.update(overrides)
    return base


def assert_valid(out: dict) -> None:
    """Every verdict honours the prompt's output contract."""
    assert out["threat_type"] in THREAT_TYPES
    assert 0.0 <= out["confidence"] <= 1.0
    assert isinstance(out["supporting"], list)
    assert isinstance(out["contradicting"], list)
    for signal in out["supporting"] + out["contradicting"]:
        assert set(signal) == {"signal", "weight", "detail"}
        assert 0.0 < signal["weight"] <= 1.0
    if out["threat_type"] == UNKNOWN:
        assert out["confidence"] < 0.5
        assert out.get("insufficient_evidence") is True
    else:
        assert "insufficient_evidence" not in out
        assert len(out["supporting"]) >= 2


def test_threat_types_match_prompt():
    assert THREAT_TYPES == (
        "C2_BEACONING",
        "RECONNAISSANCE",
        "DATA_EXFILTRATION_SUSPECTED",
        "TLS_ANOMALY",
        "QUIC_ANOMALY",
        "VOLUMETRIC_ANOMALY",
        "UNUSUAL_ENDPOINT_BEHAVIOR",
        "UNKNOWN_ANOMALY",
    )
    assert UNKNOWN == "UNKNOWN_ANOMALY"


def test_unknown_fallback_shape():
    assert unknown_threat() == {
        "threat_type": "UNKNOWN_ANOMALY",
        "confidence": 0.0,
        "supporting": [],
        "contradicting": [],
        "insufficient_evidence": True,
    }


# -- one test per prompt category ---------------------------------------------

def test_c2_beaconing_with_repetition_context():
    """Periodic small sessions to a repeated destination = C2 beaconing."""
    window = [
        rec(src="10.0.0.66:43001", dst="198.51.100.7:8443",
            bytes=1_600, packets=28, duration=13.5)
        for _ in range(3)
    ]
    current = rec(src="10.0.0.66:43004", dst="198.51.100.7:8443",
                  bytes=1_600, packets=28, duration=13.5, score=91.0)
    vector = feats(
        iat_fwd_mean_s=0.885, iat_fwd_mad_s=0.0,
        bytes_mean=59.6, bytes_std=4.2, bytes_total=1_600,
        bytes_fwd=1_100, bytes_bwd=500, duration_s=13.5,
        packets_total=28, packets_per_s=2.1, bytes_per_s=118.0,
    )
    out = classify_threat(current, vector, window)
    assert_valid(out)
    assert out["threat_type"] == "C2_BEACONING"
    names = {s["signal"] for s in out["supporting"]}
    assert "periodic_forward_timing" in names
    assert "repeated_destination" in names
    assert out["confidence"] >= 0.6


def test_c2_beaconing_first_flow_without_context():
    """Perfectly periodic uniform cadence qualifies even with an empty window."""
    current = rec(src="10.0.0.66:43000", dst="198.51.100.7:8443",
                  bytes=1_600, packets=28, duration=13.5)
    vector = feats(
        iat_fwd_mean_s=0.885, iat_fwd_mad_s=0.0,
        bytes_mean=59.6, bytes_std=4.2, bytes_total=1_600,
        duration_s=13.5, packets_total=28,
    )
    out = classify_threat(current, vector, [])
    assert_valid(out)
    assert out["threat_type"] == "C2_BEACONING"


def test_reconnaissance_from_fanout_and_short_flows():
    """Many short probe flows to distinct hosts/ports = reconnaissance."""
    window = [
        rec(src="10.0.0.5:41000", dst=f"10.6.6.{i}:80",
            duration=0.1, packets=3, bytes=180)
        for i in range(1, 11)
    ]
    current = rec(src="10.0.0.5:50000", dst="10.5.5.5:445",
                  duration=0.1, packets=3, bytes=300, score=74.0)
    vector = feats(
        duration_s=0.1, packets_total=3, bytes_total=300,
        bytes_fwd=300, bytes_bwd=0, bytes_mean=60.0, bytes_std=10.0,
        packets_per_s=30.0, bytes_per_s=3_000.0,
        rst_count=1.0, payload_ratio=0.05,
    )
    out = classify_threat(current, vector, window)
    assert_valid(out)
    assert out["threat_type"] == "RECONNAISSANCE"
    names = {s["signal"] for s in out["supporting"]}
    assert "destination_fanout" in names
    assert "many_short_flows" in names


def test_data_exfiltration_from_outbound_dominance():
    """Outbound-heavy sustained transfer off any known destination."""
    current = rec(src="10.0.0.9:51000", dst="10.9.9.9:80",
                  duration=8.0, packets=400, bytes=520_000, score=88.0)
    vector = feats(
        duration_s=8.0, packets_total=400, bytes_total=520_000,
        bytes_fwd=500_000, bytes_bwd=20_000,
        packets_per_s=50.0, bytes_per_s=65_000.0,
        bytes_mean=1_300.0, bytes_std=400.0,
    )
    out = classify_threat(current, vector, [])
    assert_valid(out)
    assert out["threat_type"] == "DATA_EXFILTRATION_SUSPECTED"
    names = {s["signal"] for s in out["supporting"]}
    assert "outbound_dominance" in names
    assert "sustained_transfer" in names


def test_tls_anomaly_from_handshake_metadata():
    """Legacy TLS without SNI/ALPN, slow and narrow = TLS anomaly."""
    current = rec(dst="203.0.113.9:443", tls_version="TLS 1.0",
                  sni=None, alpn=None, score=70.0)
    vector = feats(
        duration_s=2.5, packets_total=12, bytes_total=12_000,
        bytes_fwd=4_000, bytes_bwd=8_000, bytes_mean=1_000.0, bytes_std=300.0,
        is_tcp=1.0, dst_port_norm=443 / 65535.0,
        tls_present=1.0, tls_version_norm=0x0301 / 0x0304,
        tls_cipher_count=1.0, sni_present=0.0, alpn_count=0.0,
        handshake_ms=2_400.0, server_hello_ms=2_600.0,
        packets_per_s=4.8, bytes_per_s=4_800.0,
    )
    out = classify_threat(current, vector, [])
    assert_valid(out)
    assert out["threat_type"] == "TLS_ANOMALY"
    names = {s["signal"] for s in out["supporting"]}
    assert "missing_sni" in names
    assert "legacy_version" in names
    assert "slow_handshake" in names


def test_tls_contradictions_reduce_confidence():
    """A common fingerprint + modern version pull the confidence down."""
    base = classify_threat(
        rec(dst="203.0.113.9:443", tls_version="TLS 1.0", sni=None, alpn=None),
        feats(tls_present=1.0, tls_version_norm=0x0301 / 0x0304,
              tls_cipher_count=1.0, sni_present=0.0, alpn_count=0.0,
              handshake_ms=2_400.0, server_hello_ms=2_600.0),
        [],
    )
    window = [
        rec(src="10.7.7.7:2000", dst=f"10.9.8.{i}:443", tls_version="TLS 1.3",
            sni="cdn.example", alpn=["h2"], ja3="abcdef0123456789",
            ja4="1303.888888888888", duration=0.4, packets=20, bytes=8_000)
        for i in range(1, 11)
    ]
    contradicted = classify_threat(
        rec(dst="203.0.113.10:443", tls_version="TLS 1.3", sni=None, alpn=None,
            ja3="abcdef0123456789", score=72.0),
        feats(tls_present=1.0, tls_version_norm=1.0, tls_cipher_count=1.0,
              sni_present=0.0, alpn_count=0.0,
              handshake_ms=2_400.0, server_hello_ms=2_600.0),
        window,
    )
    assert_valid(base)
    assert_valid(contradicted)
    assert base["threat_type"] == "TLS_ANOMALY"
    assert contradicted["threat_type"] == "TLS_ANOMALY"
    opp = {s["signal"] for s in contradicted["contradicting"]}
    assert "common_fingerprint" in opp
    assert "modern_version" in opp
    assert contradicted["confidence"] < base["confidence"]


def test_quic_anomaly_from_unknown_version():
    """Unpublished QUIC version without SNI/ALPN = QUIC anomaly."""
    current = rec(proto="UDP", src="10.0.0.7:52000", dst="10.4.4.4:443",
                  quic_version="QUIC 0x1a2b3c4d", sni=None, alpn=None,
                  duration=0.4, packets=6, bytes=20_000, score=81.0)
    vector = feats(
        duration_s=0.4, packets_total=6, bytes_total=20_000,
        bytes_fwd=10_000, bytes_bwd=10_000, bytes_mean=3_300.0,
        bytes_std=1_200.0, packets_per_s=15.0, bytes_per_s=50_000.0,
        is_tcp=0.0, dst_port_norm=443 / 65535.0, tls_present=0.0,
    )
    out = classify_threat(current, vector, [])
    assert_valid(out)
    assert out["threat_type"] == "QUIC_ANOMALY"
    names = {s["signal"] for s in out["supporting"]}
    assert "unknown_version" in names
    assert "missing_sni" in names


def test_volumetric_anomaly_from_rates():
    """Extreme throughput/packet rate and size = volumetric anomaly."""
    current = rec(proto="UDP", src="10.2.2.2:33000", dst="10.3.3.3:9999",
                  duration=5.0, packets=25_000, bytes=10_000_000, score=93.0)
    vector = feats(
        duration_s=5.0, packets_total=25_000, bytes_total=10_000_000,
        bytes_fwd=5_000_000, bytes_bwd=5_000_000,
        packets_per_s=5_000.0, bytes_per_s=2_000_000.0,
        bytes_mean=400.0, bytes_std=150.0, is_tcp=0.0,
    )
    out = classify_threat(current, vector, [])
    assert_valid(out)
    assert out["threat_type"] == "VOLUMETRIC_ANOMALY"
    names = {s["signal"] for s in out["supporting"]}
    assert "extreme_throughput" in names
    assert "large_transfer" in names


def test_unusual_endpoint_behavior():
    """A known endpoint on a never-used port with a changed traffic shape."""
    window = [
        rec(src="10.7.7.7:2000", dst="10.2.2.2:80",
            duration=0.2, packets=4, bytes=2_000)
        for _ in range(5)
    ]
    current = rec(src="10.8.8.8:49000", dst="10.2.2.2:445",
                  duration=1.0, packets=90, bytes=500_000, score=90.0)
    vector = feats(
        duration_s=1.0, packets_total=90, bytes_total=190_000,
        bytes_fwd=100_000, bytes_bwd=90_000, bytes_mean=2_100.0,
        bytes_std=900.0, packets_per_s=90.0, bytes_per_s=190_000.0,
    )
    out = classify_threat(current, vector, window)
    assert_valid(out)
    assert out["threat_type"] == "UNUSUAL_ENDPOINT_BEHAVIOR"
    names = {s["signal"] for s in out["supporting"]}
    assert "behavior_change" in names
    assert "unexpected_service_port" in names


# -- unknown stays unknown ------------------------------------------------------

def test_plain_anomaly_without_evidence_stays_unknown():
    """No behavioural signal at all -> UNKNOWN, no candidate, low confidence."""
    current = rec(bytes=5_000, duration=1.0, score=61.0)
    vector = feats(duration_s=1.0, packets_total=10, bytes_total=5_000,
                   bytes_mean=500.0, bytes_std=400.0)
    out = classify_threat(current, vector, [])
    assert_valid(out)
    assert out == unknown_threat()
    assert "candidate" not in out


def test_near_miss_keeps_candidate_and_low_confidence():
    """One strong signal is not enough — unknown with the closest candidate."""
    current = rec(src="10.0.0.9:51000", dst="10.9.9.9:80",
                  duration=1.0, packets=80, bytes=105_000, score=71.0)
    vector = feats(
        duration_s=1.0, packets_total=80, bytes_total=105_000,
        bytes_fwd=100_000, bytes_bwd=5_000, bytes_mean=1_300.0,
        bytes_std=500.0, packets_per_s=80.0, bytes_per_s=105_000.0,
    )
    out = classify_threat(current, vector, [])
    assert_valid(out)
    assert out["threat_type"] == UNKNOWN
    assert out["candidate"] == "DATA_EXFILTRATION_SUSPECTED"
    assert out["confidence"] < 0.5
    assert any(s["signal"] == "outbound_dominance" for s in out["supporting"])


def test_missing_features_and_window_do_not_crash():
    out = classify_threat(rec(tls_version="TLS 1.2", sni="example.com",
                              alpn=["h2"]), None, None)
    assert_valid(out)
    assert out["threat_type"] == UNKNOWN


# -- end-to-end wiring ----------------------------------------------------------

def test_detections_carry_explainable_threats(tmp_path):
    """Every detection is classified; beacon traffic lands on C2_BEACONING."""
    baseline = make_baseline_pcap(str(tmp_path / "baseline.pcap"), n_flows=40)
    suspicious = make_suspicious_pcap(str(tmp_path / "suspicious.pcap"))
    engine = SpectraEngine(model_path=str(tmp_path / "model.joblib"),
                           idle_timeout=30.0)
    engine.train_from_pcap(baseline, contamination=0.05)

    detections = []
    engine.subscribe(lambda e: detections.append(e["data"])
                     if e["type"] == "detection" else None)
    engine.start("pcap", path=suspicious)
    deadline = time.time() + 30
    while engine.running and time.time() < deadline:
        time.sleep(0.05)
    assert not engine.running, "capture did not finish"
    assert detections, "no anomalies detected in suspicious traffic"

    for d in detections:
        threat = d.get("threat")
        assert threat, f"detection without threat verdict: {d['src']} -> {d['dst']}"
        assert_valid(threat)

    beacon_threats = [d["threat"]["threat_type"]
                      for d in detections if d["sni"] is None]
    assert "C2_BEACONING" in beacon_threats, \
        f"beacon flows were not classified as C2: {beacon_threats}"
