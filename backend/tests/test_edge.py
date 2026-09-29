"""Phase 4 edge cases: unusual link/network layers and malformed input.

Nothing in the ingest path may raise on real-world oddities - IPv6, VLAN
tagged frames, non-IP traffic, garbage on TLS ports, mid-stream captures
(no handshake at all) and empty captures all flow through to either a
correctly tracked flow or a clean no-op.
"""

import numpy as np
from scapy.all import ARP, Dot1Q, Ether, IPv6, Raw, TCP, UDP
from scapy.layers.inet import IP
from scapy.utils import PcapWriter

from spectra.demo import make_client_hello, write_pcap
from spectra.features.extractor import N_FEATURES, extract_features
from spectra.parse.flow import FlowTracker
from spectra.tools import collect_flows

BASE = 1_700_000_000.0


def _tcp(src, dst, sport, dport, flags, payload=b"", seq=1, ack=1, t=BASE):
    pkt = IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags=flags,
                                     seq=seq, ack=ack)
    if payload:
        pkt /= Raw(load=payload)
    pkt.time = t
    return pkt


# -- IPv6 ---------------------------------------------------------------------

def test_ipv6_flow_tracked_with_features():
    tracker = FlowTracker()
    syn = IPv6(src="2001:db8::10", dst="2001:db8::20") / TCP(
        sport=50000, dport=443, flags="S", seq=1000)
    syn.time = BASE
    synack = IPv6(src="2001:db8::20", dst="2001:db8::10") / TCP(
        sport=443, dport=50000, flags="SA", seq=2000, ack=1001)
    synack.time = BASE + 0.01
    ch = make_client_hello(sni="v6.example")   # full TLS record for TCP
    data = IPv6(src="2001:db8::10", dst="2001:db8::20") / TCP(
        sport=50000, dport=443, flags="PA", seq=1001, ack=2001) / Raw(load=ch)
    data.time = BASE + 0.02

    for pkt in (syn, synack, data):
        tracker.process(pkt)
    flows = list(tracker.flush_all())
    assert len(flows) == 1
    flow = flows[0]
    assert flow.src_ip == "2001:db8::10"
    assert flow.dst_ip == "2001:db8::20"
    assert flow.client_tls is not None and flow.client_tls.sni == "v6.example"

    feats = extract_features(flow)
    assert feats.shape == (N_FEATURES,)
    assert np.all(np.isfinite(feats))

    rec = flow.record()
    assert rec["proto"] == "TCP"
    assert rec["sni"] == "v6.example"


# -- VLAN ---------------------------------------------------------------------

def test_vlan_tagged_frames_tracked(tmp_path):
    tracker = FlowTracker()
    frames = [
        Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02") / Dot1Q(vlan=100)
        / _tcp("10.1.1.5", "10.1.1.6", 41000, 443, "S", seq=1, ack=0),
        Ether(src="02:00:00:00:00:02", dst="02:00:00:00:00:01") / Dot1Q(vlan=100)
        / _tcp("10.1.1.6", "10.1.1.5", 443, 41000, "SA", seq=500, ack=2,
               t=BASE + 0.01),
        Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02") / Dot1Q(vlan=100)
        / _tcp("10.1.1.5", "10.1.1.6", 41000, 443, "PA", seq=2, ack=501,
               payload=make_client_hello(sni="vlan.example"),
               t=BASE + 0.02),
    ]
    for f in frames:
        assert tracker.process(f) is not None
    flows = list(tracker.flush_all())
    assert len(flows) == 1
    assert flows[0].client_tls is not None
    assert flows[0].client_tls.sni == "vlan.example"

    # ... and survives a full PCAP round trip (linktype 1 with 802.1Q)
    pcap = write_pcap(str(tmp_path / "vlan.pcap"), frames)
    seen = collect_flows(pcap)
    assert len(seen) == 1 and seen[0].client_tls is not None


# -- non-IP / malformed -------------------------------------------------------

def test_arp_and_non_ip_frames_ignored():
    tracker = FlowTracker()
    arp = Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02") / ARP(
        psrc="10.0.0.5", pdst="10.0.0.6")
    arp.time = BASE
    assert tracker.process(arp) is None
    assert len(tracker) == 0

    # bare Ethernet frame with an ethertype nothing understands
    junk = Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02",
                 type=0x88B5) / Raw(load=b"\xde\xad\xbe\xef" * 8)
    junk.time = BASE
    assert tracker.process(junk) is None
    assert len(tracker) == 0


def test_garbage_on_tls_port_yields_flow_without_metadata():
    completed = []
    tracker = FlowTracker(on_complete=completed.append)
    tracker.process(_tcp("10.0.0.5", "10.0.0.6", 42000, 443, "S", seq=1, ack=0))
    tracker.process(_tcp("10.0.0.6", "10.0.0.5", 443, 42000, "SA",
                         seq=900, ack=2, t=BASE + 0.01))
    garbage = bytes(range(256)) * 16          # 4 KiB of junk on 443
    tracker.process(_tcp("10.0.0.5", "10.0.0.6", 42000, 443, "PA",
                         seq=2, ack=901, payload=garbage, t=BASE + 0.02))
    tracker.process(_tcp("10.0.0.6", "10.0.0.5", 443, 42000, "RA",
                         seq=902, ack=2 + len(garbage), t=BASE + 0.03))
    flows = list(tracker.flush_all())
    assert flows == []                          # RST already completed it
    assert len(completed) == 1
    flow = completed[0]
    assert flow.client_tls is None and flow.server_tls is None
    feats = extract_features(flow)
    assert np.all(np.isfinite(feats))


def test_mid_stream_capture_no_handshake():
    """Capture that starts after the handshake: data flows, metadata absent."""
    tracker = FlowTracker()
    tracker.process(_tcp("10.0.0.9", "10.0.0.10", 43000, 80, "PA",
                         seq=50_000, ack=60_000, payload=b"GET / HTTP/1.1\r\n\r\n"))
    tracker.process(_tcp("10.0.0.10", "10.0.0.9", 80, 43000, "PA",
                         seq=60_000, ack=50_018, payload=b"HTTP/1.1 200 OK\r\n\r\n",
                         t=BASE + 0.01))
    flows = list(tracker.flush_all())
    assert len(flows) == 1
    flow = flows[0]
    assert flow.client_tls is None
    assert len(flow.packets) == 2
    assert np.all(np.isfinite(extract_features(flow)))


def test_packet_cap_marks_flow_truncated():
    tracker = FlowTracker(max_packets=3)
    flow = None
    for i in range(6):
        flow = tracker.process(
            _tcp("10.0.0.5", "10.0.0.6", 44000, 443, "PA",
                 seq=100 + i, ack=1, payload=b"x" * 8, t=BASE + i * 0.01))
    assert flow is not None
    assert flow.truncated is True
    assert len(flow.packets) == 3
    # byte counters still track every packet for volume features
    assert flow.packets_fwd == 6


def test_oversized_udp_payload():
    tracker = FlowTracker()
    big = b"\x45" + b"U" * 60000              # not QUIC (form bit clear)
    pkt = IP(src="10.0.0.5", dst="10.0.0.6") / UDP(sport=44000, dport=9999) \
        / Raw(load=big)
    pkt.time = BASE
    flow = tracker.process(pkt)
    assert flow is not None
    assert flow.quic is None
    assert flow.bytes_fwd == len(big) + 28     # UDP payload + UDP/IP headers
    assert np.all(np.isfinite(extract_features(flow)))


# -- empty / degenerate captures ----------------------------------------------

def test_empty_capture_has_no_flows(tmp_path):
    empty = tmp_path / "empty.pcap"
    writer = PcapWriter(str(empty), sync=True)
    writer.close()                             # header-only, zero packets
    assert collect_flows(str(empty)) == []


def test_corrupt_capture_raises_capture_error(tmp_path):
    from spectra.capture.base import CaptureError

    broken = tmp_path / "broken.pcap"
    broken.write_bytes(b"")
    try:
        collect_flows(str(broken))
    except CaptureError as exc:
        assert "cannot read PCAP" in str(exc)
    else:  # pragma: no cover - depends on scapy version behaviour
        raise AssertionError("expected CaptureError for a zero-byte pcap")


def test_flows_without_packets_do_not_break_features():
    """Feature extraction must survive a flow that recorded no packets."""
    from spectra.parse.flow import Flow

    flow = Flow(proto=6, src_ip="10.0.0.5", src_port=1, dst_ip="10.0.0.6",
                dst_port=2, start_ts=BASE, last_ts=BASE)
    feats = extract_features(flow)
    assert feats.shape == (N_FEATURES,)
    assert np.all(np.isfinite(feats))
