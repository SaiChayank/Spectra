"""Metadata-only rewrite of uploaded captures: no payload at rest, features unchanged."""
from __future__ import annotations

import numpy as np
from scapy.all import IP, UDP, PcapWriter, Raw

from spectra.capture.sanitize import sanitize_pcap
from spectra.demo import BASE, _pkt, make_baseline_pcap, quic_flow_packets, tls_flow_packets, write_pcap
from spectra.features.extractor import flows_to_matrix
from spectra.tools import collect_flows

MARK = b"SANITIZE-MARK-5b1e90c4a7d2"


def _marked(path: str) -> str:
    full = tls_flow_packets(src="10.77.0.5", dst="203.0.113.50", sni="probe.example", start=BASE)
    # the demo flow's filler "application data" is not valid TLS framing; keep its handshake packets and add real records
    pkts = [p for p in full if not bytes(p["TCP"].payload) or bytes(p["TCP"].payload)[0] == 0x16]
    rec = b"\x17\x03\x03" + (len(MARK) + 16).to_bytes(2, "big") + MARK + bytes(16)
    pkts.append(_pkt("10.77.0.5", "203.0.113.50", 40000, 443, "PA", 9000, 9000, payload=rec, t=BASE + 3.0))
    # a second record split across two segments (header in the first, body continues in the second)
    rec2 = b"\x17\x03\x03" + (len(MARK) + 40).to_bytes(2, "big") + MARK + bytes(40)
    pkts.append(_pkt("10.77.0.5", "203.0.113.50", 40000, 443, "PA", 9500, 9000, payload=rec2[:20], t=BASE + 3.1))
    pkts.append(_pkt("10.77.0.5", "203.0.113.50", 40000, 443, "PA", 9520, 9000, payload=rec2[20:], t=BASE + 3.2))
    http = b"GET /?token=" + MARK + b" HTTP/1.1\r\nHost: plain.example\r\n\r\n"
    pkts += [_pkt("10.77.0.6", "203.0.113.51", 41000, 80, "S", 1, 0, t=BASE + 4.0),
             _pkt("10.77.0.6", "203.0.113.51", 41000, 80, "PA", 2, 1, payload=http, t=BASE + 4.1)]
    w = PcapWriter(path, sync=True)
    for p in pkts:
        w.write(p)
    w.write(IP(src="10.77.0.7", dst="203.0.113.52") / UDP(sport=5353, dport=5353) / Raw(load=MARK))
    w.close()
    return path


def test_marker_is_gone_from_every_kind_of_payload(tmp_path):
    src, dst = _marked(str(tmp_path / "a.pcap")), str(tmp_path / "s.pcap")
    assert MARK in open(src, "rb").read()
    stats = sanitize_pcap(src, dst)
    assert stats["packets_payload_zeroed_or_trimmed"] >= 3
    assert MARK not in open(dst, "rb").read()


def test_features_and_tls_metadata_are_unchanged(tmp_path):
    src, dst = make_baseline_pcap(str(tmp_path / "b.pcap"), n_flows=30), str(tmp_path / "s.pcap")
    sanitize_pcap(src, dst)
    a, b = collect_flows(src), collect_flows(dst)
    assert len(a) == len(b) > 0
    assert np.array_equal(flows_to_matrix(a), flows_to_matrix(b))
    strip = lambda f: {k: v for k, v in f.record().items() if k not in ("ts", "start_ts", "last_ts")}  # noqa: E731
    assert [strip(f) for f in a] == [strip(f) for f in b]
    assert any(f.record().get("ja3") and f.record().get("sni") for f in b), "handshake metadata was lost"


def test_quic_initial_is_kept_and_parsed(tmp_path):
    src, dst = str(tmp_path / "q.pcap"), str(tmp_path / "sq.pcap")
    write_pcap(src, quic_flow_packets(src="10.1.0.2", dst="198.51.100.9", sni="quic.example", start=BASE))
    sanitize_pcap(src, dst)
    a, b = collect_flows(src), collect_flows(dst)
    assert len(a) == len(b) > 0
    assert [f.record().get("sni") for f in a] == [f.record().get("sni") for f in b]
    assert any(f.record().get("sni") == "quic.example" for f in b)


def test_garbage_stream_is_zeroed_not_kept(tmp_path):
    """A TCP stream that does not start with a TLS record header is zeroed entirely (unsure means zeros)."""
    src, dst = str(tmp_path / "g.pcap"), str(tmp_path / "sg.pcap")
    pk = [_pkt("10.5.0.1", "203.0.113.9", 42000, 25, "PA", 1, 1, payload=b"MAIL FROM:<" + MARK + b">\r\n", t=BASE)]
    write_pcap(src, pk)
    sanitize_pcap(src, dst)
    assert MARK not in open(dst, "rb").read()


def test_a_non_capture_file_fails_closed(tmp_path):
    bad = tmp_path / "x.pcap"
    bad.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 40)
    try:
        sanitize_pcap(str(bad), str(tmp_path / "o.pcap"))
    except Exception as exc:  # noqa: BLE001
        assert "sanitis" in str(exc).lower() or "no packets" in str(exc).lower() or "cannot read" in str(exc).lower()
    else:
        raise AssertionError("expected a failure")
