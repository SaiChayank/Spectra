"""Tests for flow tracking and feature extraction."""

import numpy as np

from spectra.features.extractor import FEATURE_NAMES, extract_features
from spectra.parse.flow import FlowTracker

from spectra.demo import beacon_flow_packets, tls_flow_packets


def track(packets) -> list:
    flows = []
    tracker = FlowTracker(idle_timeout=30.0, on_complete=flows.append)
    for pkt in packets:
        tracker.process(pkt)
    list(tracker.flush_all())
    return flows


def test_tls_flow_is_assembled_bidirectionally():
    flows = track(tls_flow_packets(sni="portal.health.test"))
    assert len(flows) == 1
    flow = flows[0]
    assert flow.is_tcp
    assert flow.packets_fwd > 0 and flow.packets_bwd > 0
    assert flow.duration > 0
    assert flow.client_tls is not None
    assert flow.client_tls.sni == "portal.health.test"
    assert flow.server_tls is not None
    assert flow.server_tls.role == "server"
    assert flow.tls.version_name == "TLS 1.3"


def test_flow_completes_on_reset():
    flows = track(beacon_flow_packets())
    assert len(flows) == 1
    assert len(flows[0].packets) > 10


def test_feature_vector_shape_and_finiteness():
    flows = track(tls_flow_packets(n_data=5))
    feats = extract_features(flows[0])
    assert feats.shape == (len(FEATURE_NAMES),)
    assert np.isfinite(feats).all()
    names = dict(zip(FEATURE_NAMES, feats.tolist()))
    assert names["tls_present"] == 1.0
    assert names["sni_present"] == 1.0
    assert names["sni_length"] == len("example.com")
    assert names["syn_count"] == 2.0   # SYN + SYN-ACK handshake pair
    assert names["is_tcp"] == 1.0
    assert names["packets_total"] == len(flows[0].packets)


def test_beacon_features_differ_from_benign():
    benign = extract_features(track(tls_flow_packets())[0])
    beacon = extract_features(track(beacon_flow_packets())[0])
    names = list(FEATURE_NAMES)

    # Beacons: no TLS handshake, tiny payload fraction, machine-regular timing.
    assert benign[names.index("tls_present")] == 1.0
    assert beacon[names.index("tls_present")] == 0.0
    assert beacon[names.index("payload_ratio")] < benign[names.index("payload_ratio")]
    assert beacon[names.index("iat_fwd_mad_s")] < 1e-4    # machine-regular beacons
    assert benign[names.index("iat_fwd_mad_s")] > 1e-4     # human/network jitter
