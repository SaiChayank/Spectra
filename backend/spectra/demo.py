"""Helpers to build synthetic PCAPs with hand-crafted TLS handshakes.

Used by the test suite (and handy for demos): produces realistic benign
traffic plus deliberately odd flows for detection checks.
"""

from __future__ import annotations

import random
import struct

from scapy.all import IP, TCP, UDP, Raw
from scapy.utils import PcapWriter

from .parse.quic import seal_initial

BASE = 1_700_000_000.0


def _u16(v: int) -> bytes:
    return struct.pack("!H", v)


def _u24(v: int) -> bytes:
    return struct.pack("!I", v)[1:]


def _ext(etype: int, data: bytes) -> bytes:
    return _u16(etype) + _u16(len(data)) + data


# Plausible key_share sizes (bytes) so the parser consumes shares correctly.
KEY_SHARE_SIZE = {
    0x0017: 65, 0x0018: 97, 0x0019: 133, 0x001D: 32, 0x001E: 56,
    0x0201: 1184,                       # ML-KEM-768 encapsulation key
    0x11EB: 65 + 1184,                  # SecP256r1MLKEM768
    0x11EC: 32 + 1184,                  # X25519MLKEM768
    0x11ED: 97 + 1088,                  # SecP384r1MLKEM1024
    0x6399: 32 + 1184,                  # X25519Kyber768Draft00
}

DEFAULT_SIGALGS = [0x0403, 0x0804, 0x0401, 0x0501, 0x0601]


def make_client_hello(
    sni: str = "example.com",
    alpn: str = "h2",
    groups: list[int] | None = None,
    key_share_groups: list[int] | None = None,
    sigalgs: list[int] | None = None,
    ciphers: list[int] | None = None,
    include_key_share: bool = True,
    include_supported_versions: bool = True,
) -> bytes:
    if groups is None:
        groups = [0x001D, 0x0017, 0x0018, 0x0019]
    if key_share_groups is None and include_key_share:
        key_share_groups = [groups[0]]
    if ciphers is None:
        ciphers = [0x1301, 0x1302, 0x1303, 0x1304, 0xC02B, 0xC02F, 0xC02C,
                   0xC030, 0x009E, 0x009F]
    sigalgs = DEFAULT_SIGALGS if sigalgs is None else sigalgs

    sni_bytes = sni.encode()
    sni_ext_data = _u16(len(sni_bytes) + 5) + b"\x00" + _u16(len(sni_bytes)) + sni_bytes
    # ^ list length (name_type + name_len + host), name type 0, name length

    alpn_list = (
        bytes([len(alpn)]) + alpn.encode()
        + bytes([len(b"http/1.1")]) + b"http/1.1"
    )
    alpn_data = _u16(len(alpn_list)) + alpn_list

    exts = [
        _ext(0, sni_ext_data),
        _ext(10, _u16(len(groups) * 2) + b"".join(_u16(g) for g in groups)),
        _ext(11, bytes([1, 0])),
        _ext(13, _u16(len(sigalgs) * 2) + b"".join(_u16(s) for s in sigalgs)),
        _ext(16, alpn_data),
    ]
    if include_supported_versions:
        exts.append(_ext(43, bytes([4]) + b"\x03\x04\x03\x03"))
    if key_share_groups:
        entries = b"".join(
            _u16(g) + _u16(KEY_SHARE_SIZE.get(g, 32)) + bytes(KEY_SHARE_SIZE.get(g, 32))
            for g in key_share_groups
        )
        exts.append(_ext(51, _u16(len(entries)) + entries))
    elif include_key_share:
        exts.append(_ext(51, _u16(0)))  # empty key_share (HelloRetryRequest path)

    body = (
        b"\x03\x03"                                  # legacy version TLS 1.2
        + bytes(range(32))                            # random
        + b"\x00"                                     # session id length
        + _u16(len(ciphers) * 2)
        + b"".join(_u16(c) for c in ciphers)
        + bytes([1, 0])                               # compression methods
        + _u16(sum(len(e) for e in exts))
        + b"".join(exts)
    )
    handshake = b"\x01" + _u24(len(body)) + body
    return b"\x16\x03\x01" + _u16(len(handshake)) + handshake


def make_server_hello(
    selected_cipher: int = 0x1301,
    alpn: str = "h2",
    selected_group: int | None = 0x001D,
    negotiated_version: int | None = 0x0304,
) -> bytes:
    alpn_data = _u16(len(alpn) + 3) + bytes([len(alpn)]) + alpn.encode()
    exts = [
        _ext(16, alpn_data),             # ALPN
        _ext(11, bytes([1, 0])),         # ec_point_formats
    ]
    if negotiated_version is not None:
        exts.insert(0, _ext(43, _u16(negotiated_version)))  # supported_versions
    if selected_group is not None:
        size = KEY_SHARE_SIZE.get(selected_group, 32)
        exts.append(_ext(51, _u16(selected_group) + _u16(size) + bytes(size)))

    body = (
        b"\x03\x03"
        + bytes(range(32, 64))
        + b"\x00"
        + _u16(selected_cipher)
        + b"\x00"
        + _u16(sum(len(e) for e in exts))
        + b"".join(exts)
    )
    handshake = b"\x02" + _u24(len(body)) + body
    return b"\x16\x03\x03" + _u16(len(handshake)) + handshake


def _pkt(src: str, dst: str, sport: int, dport: int, flags: str, seq: int,
         ack: int, payload: bytes = b"", t: float = BASE) -> object:
    pkt = IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags=flags,
                                     seq=seq, ack=ack)
    if payload:
        pkt = pkt / Raw(load=payload)
    pkt.time = t
    return pkt


def tls_flow_packets(
    src: str = "10.0.0.5",
    dst: str = "93.184.216.34",
    sport: int = 40000,
    dport: int = 443,
    sni: str = "example.com",
    n_data: int = 6,
    data_size: int = 500,
    start: float = BASE,
    jitter: random.Random | None = None,
    profile: str = "classic",
) -> list:
    """A complete benign-looking TLS session: handshake, data exchange, FINs.

    Profiles control the negotiated cryptography (used by the PQC tests):
        classic  TLS 1.3 + X25519 (classical, harvestable)
        hybrid   TLS 1.3 + X25519MLKEM768 (quantum-resistant)
        rsa12    TLS 1.2 + RSA key transport (worst case)
        pqc_auth TLS 1.3 hybrid + ML-DSA signature offer
    """
    rng = jitter or random.Random(42)
    pkts: list = []
    cseq, sseq = 1000, 5000
    t = start

    pkts.append(_pkt(src, dst, sport, dport, "S", cseq, 0, t=t))
    t += 0.001
    pkts.append(_pkt(dst, src, dport, sport, "SA", sseq, cseq + 1, t=t))
    t += 0.001
    pkts.append(_pkt(src, dst, sport, dport, "A", cseq + 1, sseq + 1, t=t))

    if profile == "hybrid":
        ch = make_client_hello(sni=sni, groups=[0x11EC, 0x001D, 0x0017],
                               key_share_groups=[0x11EC, 0x001D])
        sh = make_server_hello(selected_cipher=0x1301, selected_group=0x11EC)
    elif profile == "rsa12":
        ch = make_client_hello(
            sni=sni, groups=[0x0017, 0x001D],
            ciphers=[0x009C, 0x009D, 0xC02F, 0xC030, 0x0033],
            include_key_share=False, include_supported_versions=False,
        )
        sh = make_server_hello(selected_cipher=0x009C, selected_group=None,
                               negotiated_version=None)
    elif profile == "pqc_auth":
        ch = make_client_hello(sni=sni, groups=[0x11EC, 0x001D],
                               key_share_groups=[0x11EC],
                               sigalgs=[0x0403, 0x0804, 0x0904, 0x0905])
        sh = make_server_hello(selected_cipher=0x1301, selected_group=0x11EC)
    else:  # classic
        ch = make_client_hello(sni=sni)
        sh = make_server_hello(selected_cipher=0x1301, selected_group=0x001D)

    t += 0.01 + rng.uniform(0, 0.005)
    pkts.append(_pkt(src, dst, sport, dport, "PA", cseq + 1, sseq + 1, ch, t=t))
    cseq += len(ch)

    t += 0.02 + rng.uniform(0, 0.01)
    pkts.append(_pkt(dst, src, dport, sport, "PA", sseq + 1, cseq + 1, sh, t=t))
    sseq += len(sh)

    for i in range(n_data):
        t += 0.05 + rng.uniform(0, 0.05)
        size = max(1, int(data_size * rng.uniform(0.7, 1.3)))
        pkts.append(_pkt(src, dst, sport, dport, "PA", cseq + 1, sseq + 1,
                         b"C" * size, t=t))
        cseq += size
        t += 0.03 + rng.uniform(0, 0.04)
        size = max(1, int(data_size * rng.uniform(0.7, 1.3)))
        pkts.append(_pkt(dst, src, dport, sport, "PA", sseq + 1, cseq + 1,
                         b"S" * size, t=t))
        sseq += size

    t += 0.05
    pkts.append(_pkt(src, dst, sport, dport, "FA", cseq + 1, sseq + 1, t=t))
    t += 0.01
    pkts.append(_pkt(dst, src, dport, sport, "FA", sseq + 1, cseq + 2, t=t))
    t += 0.01
    pkts.append(_pkt(src, dst, sport, dport, "A", cseq + 2, sseq + 2, t=t))
    return pkts


def quic_flow_packets(
    src: str = "10.0.0.5",
    dst: str = "93.184.216.34",
    sport: int = 40000,
    dport: int = 443,
    sni: str = "example.com",
    profile: str = "classic",
    start: float = BASE,
    jitter: random.Random | None = None,
    n_data: int = 4,
    data_size: int = 500,
) -> list:
    """A complete QUIC/HTTP3 session: protected Initial flight + 1-RTT data.

    The Initial packets are genuinely sealed (RFC 9001 keys derived from the
    DCID), so the passive parser recovers SNI/ALPN/cipher offers exactly as
    it would from a real capture. QUIC mandates TLS 1.3, so the `rsa12`
    profile falls back to `classic`.
    """
    rng = jitter or random.Random(42)
    dcid = bytes.fromhex("8394c8f03e515708")
    client_scid = b"\x11" * 8
    server_scid = b"\x22" * 8

    if profile == "hybrid":
        ch = make_client_hello(sni=sni, alpn="h3",
                               groups=[0x11EC, 0x001D, 0x0017],
                               key_share_groups=[0x11EC, 0x001D])
        sh = make_server_hello(selected_cipher=0x1301, alpn="h3",
                               selected_group=0x11EC)
    elif profile == "pqc_auth":
        ch = make_client_hello(sni=sni, alpn="h3", groups=[0x11EC, 0x001D],
                               key_share_groups=[0x11EC],
                               sigalgs=[0x0403, 0x0804, 0x0904, 0x0905])
        sh = make_server_hello(selected_cipher=0x1301, alpn="h3",
                               selected_group=0x11EC)
    else:  # classic (and rsa12, which QUIC cannot express)
        ch = make_client_hello(sni=sni, alpn="h3")
        sh = make_server_hello(selected_cipher=0x1301, alpn="h3",
                               selected_group=0x001D)

    client_initial = seal_initial(
        ch[5:], side="client", key_dcid=dcid, header_dcid=dcid,
        scid=client_scid, pn=0, min_size=1200,
    )
    server_initial = seal_initial(
        sh[5:], side="server", key_dcid=dcid, header_dcid=client_scid,
        scid=server_scid, pn=1, pn_len=2, min_size=1200,
    )

    def udp(a: str, b: str, sp: int, dp: int, payload: bytes, ts: float):
        p = IP(src=a, dst=b) / UDP(sport=sp, dport=dp) / Raw(load=payload)
        p.time = ts
        return p

    pkts: list = []
    t = start
    pkts.append(udp(src, dst, sport, dport, client_initial, t))
    t += 0.02 + rng.uniform(0, 0.01)
    pkts.append(udp(dst, src, dport, sport, server_initial, t))

    # Short-header (1-RTT) application packets: opaque to the Initial parser
    # (form bit clear), counted as ordinary UDP payload.
    for i in range(n_data):
        t += 0.05 + rng.uniform(0, 0.05)
        size = max(1, int(data_size * rng.uniform(0.7, 1.3)))
        pkts.append(udp(src, dst, sport, dport,
                        bytes([0x30 + (i % 3)]) + b"C" * size, t))
        t += 0.03 + rng.uniform(0, 0.04)
        size = max(1, int(data_size * rng.uniform(0.7, 1.3)))
        pkts.append(udp(dst, src, dport, sport,
                        bytes([0x30 + (i % 3)]) + b"S" * size, t))
    return pkts


def beacon_flow_packets(
    src: str = "10.0.0.66",
    dst: str = "198.51.100.7",
    sport: int = 41000,
    dport: int = 8443,
    n_beacons: int = 12,
    start: float = BASE,
) -> list:
    """C2-style beacon: fixed-interval tiny packets, no TLS handshake, RST end."""
    pkts: list = []
    cseq, sseq = 9000, 7000
    t = start
    pkts.append(_pkt(src, dst, sport, dport, "S", cseq, 0, t=t))
    t += 0.001
    pkts.append(_pkt(dst, src, dport, sport, "SA", sseq, cseq + 1, t=t))
    t += 0.001
    pkts.append(_pkt(src, dst, sport, dport, "A", cseq + 1, sseq + 1, t=t))
    cseq += 1
    sseq += 1

    for i in range(n_beacons):
        t += 1.0  # perfectly periodic - unnatural
        pkts.append(_pkt(src, dst, sport, dport, "PA", cseq + 1, sseq + 1,
                         b"\x00\x01\x02\x03", t=t))
        cseq += 4
        t += 0.002
        pkts.append(_pkt(dst, src, dport, sport, "PA", sseq + 1, cseq + 1,
                         b"\x00\x00", t=t))
        sseq += 2

    t += 0.5
    pkts.append(_pkt(src, dst, sport, dport, "RA", cseq + 1, sseq + 1, t=t))
    return pkts


def write_pcap(path: str, packets: list) -> str:
    """Write an Ethernet-framed PCAP (linktype 1) readable by every tool.

    Packets that already carry an Ether layer are written as-is.
    """
    from scapy.layers.l2 import Ether

    writer = PcapWriter(path, sync=True)
    try:
        for pkt in packets:
            ts = float(pkt.time)
            frame = pkt if pkt.haslayer(Ether) else (
                Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02") / pkt)
            frame.time = ts
            writer.write(frame)
    finally:
        writer.close()
    return path


def make_baseline_pcap(path: str, n_flows: int = 40, seed: int = 7) -> str:
    """Benign baseline: many TLS sessions plus HTTP/3 (QUIC) across hosts."""
    rng = random.Random(seed)
    pkts: list = []
    clients = ["10.0.0.5", "10.0.0.6", "10.0.0.7", "10.0.0.8"]
    snis = ["example.com", "api.bank.test", "portal.health.test", "cdn.city.test",
            "mail.example.org", "static.assets.io"]
    for i in range(n_flows):
        pkts += tls_flow_packets(
            src=clients[i % len(clients)],
            sport=40000 + i,
            sni=snis[i % len(snis)],
            n_data=rng.randint(3, 10),
            data_size=rng.randint(200, 900),
            start=BASE + i * 2.0 + rng.uniform(0, 0.5),
            jitter=rng,
        )
    # Genuinely sealed QUIC/HTTP3 sessions alongside the TCP flows.
    pkts += quic_flow_packets(
        src="10.0.0.7", sport=41500, sni="cdn.city.test", profile="classic",
        start=BASE + 6.0, jitter=rng,
    )
    pkts += quic_flow_packets(
        src="10.0.0.8", sport=41501, sni="static.assets.io", profile="hybrid",
        start=BASE + 9.0, jitter=rng,
    )
    pkts.sort(key=lambda p: float(p.time))
    return write_pcap(path, pkts)


def make_suspicious_pcap(path: str, n_benign: int = 8, n_beacons: int = 4,
                         seed: int = 11) -> str:
    """Mixed traffic: a little benign plus unmistakably odd beacon flows."""
    rng = random.Random(seed)
    pkts: list = []
    for i in range(n_benign):
        pkts += tls_flow_packets(
            src="10.0.0.5",
            sport=42000 + i,
            sni="example.com",
            n_data=rng.randint(3, 8),
            start=BASE + 1000 + i * 3.0,
            jitter=rng,
        )
    # One classic (harvestable) QUIC session among the TCP flows.
    pkts += quic_flow_packets(
        src="10.0.0.7", sport=44444, sni="quic.example", profile="classic",
        start=BASE + 1100.0, jitter=rng,
    )
    for i in range(n_beacons):
        pkts += beacon_flow_packets(
            src="10.0.0.66",
            sport=43000 + i,
            start=BASE + 2000 + i * 30.0,
        )
    pkts.sort(key=lambda p: float(p.time))
    return write_pcap(path, pkts)
