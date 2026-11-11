"""In-tree packet dissector (ADR-011): replaces scapy for everything Spectra reads.

Only what the pipeline needs is decoded - link layer (Ethernet + VLAN, 802.3/SNAP, raw IP, BSD loopback, Linux cooked), IPv4
(+options, fragments), IPv6 (+extension headers), IP-in-IP / 6in4 tunnels, TCP and UDP headers.  The rules follow what scapy
did on the same bytes (the differential test in ``tests/test_pcap_differential.py`` and ``docs/evidence/`` pins this): a layer
exists only when its fixed header is present inside the length the layer below declares; a non-first IPv4 fragment has no
transport layer; the transport payload runs to the end of the captured frame (so link-layer padding counts), and the size
accounted for a packet is the IP total length (IPv6: payload length + 40).

A :class:`Packet` keeps the captured frame bytes for the duration of the loop that handles it; nothing here stores or logs
payload content.
"""
from __future__ import annotations

import socket
import struct
from typing import Any

_U16 = struct.Struct(">H").unpack_from
_U32 = struct.Struct(">I").unpack_from
_ntoa = socket.inet_ntoa
_ntop = socket.inet_ntop
_AF6 = socket.AF_INET6

LINKTYPE_NULL, LINKTYPE_ETHERNET, LINKTYPE_RAW = 0, 1, 101
_RAW_LINKTYPES = frozenset({12, 14, 101})      # version nibble decides IPv4 / IPv6
_MAX_TUNNEL_DEPTH = 4


class Packet:
    """One captured frame plus the decoded header facts the pipeline uses."""

    __slots__ = ("time", "data", "wirelen", "linktype", "src", "dst", "ip_proto", "l4", "sport", "dport",
                 "flags", "poff", "size", "icmp")

    def __init__(self, data: bytes = b"", time: float = 0.0, wirelen: int | None = None, linktype: int = 1) -> None:
        self.time = time
        self.data = data
        self.wirelen = len(data) if wirelen is None else wirelen
        self.linktype = linktype
        self.src: str | None = None       # first IPv4 layer, else first IPv6 layer
        self.dst: str | None = None
        self.ip_proto: int | None = None  # that layer's protocol / first next-header (None: no IP at all)
        self.l4 = 0                       # 6 TCP, 17 UDP, 0 neither (first transport layer found)
        self.sport = 0
        self.dport = 0
        self.flags = 0                    # TCP flag byte
        self.poff = len(data)             # offset of the transport payload in ``data``
        self.size = len(data)             # IP total length (IPv6: payload length + 40) when an IP layer exists
        self.icmp = False                 # an ICMPv4 header is present

    @property
    def payload(self) -> bytes:
        """Transport payload (to the end of the frame, link-layer padding included)."""
        return self.data[self.poff:]

    @property
    def payload_len(self) -> int:
        return max(0, len(self.data) - self.poff)

    def __len__(self) -> int:
        return len(self.data)

    def __bytes__(self) -> bytes:
        return self.data

    def __repr__(self) -> str:
        return f"Packet({self.src}:{self.sport} > {self.dst}:{self.dport} proto={self.ip_proto} len={len(self.data)})"


def _l3_start(data: bytes, linktype: int) -> tuple[int, int]:
    """Return (offset, 4|6) of the network layer, or (0, 0) when there is none we read."""
    n = len(data)
    if linktype == LINKTYPE_ETHERNET:
        if n < 14:
            return 0, 0
        off, et = 14, _U16(data, 12)[0]
        while et in (0x8100, 0x88A8) and n >= off + 4:        # 802.1Q / 802.1ad tags
            et = _U16(data, off + 2)[0]
            off += 4
        if et <= 1500 and data[off:off + 3] == b"\xaa\xaa\x03" and n >= off + 8:   # 802.3 + LLC/SNAP
            et, off = _U16(data, off + 6)[0], off + 8
    elif linktype in _RAW_LINKTYPES and n:
        return (0, data[0] >> 4) if data[0] >> 4 in (4, 6) else (0, 0)
    elif linktype == 228:
        return (0, 4) if n else (0, 0)
    elif linktype == 229:
        return (0, 6) if n else (0, 0)
    elif linktype in (LINKTYPE_NULL, 108):
        if n < 4:
            return 0, 0
        fam = int.from_bytes(data[:4], "little")
        if fam > 255:
            fam = int.from_bytes(data[:4], "big")
        off, et = 4, 0x0800 if fam == 2 else 0x86DD if fam in (10, 24, 28, 30) else 0
    elif linktype == 113 and n >= 16:                          # Linux cooked v1
        off, et = 16, _U16(data, 14)[0]
    elif linktype == 276 and n >= 20:                          # Linux cooked v2
        off, et = 20, _U16(data, 0)[0]
    else:
        return 0, 0
    return (off, 4) if et == 0x0800 else (off, 6) if et == 0x86DD else (0, 0)


def dissect(data: bytes, linktype: int = LINKTYPE_ETHERNET, ts: float = 0.0, wirelen: int | None = None) -> Packet:
    """Decode ``data`` (one captured frame of link type ``linktype``).  Never raises on malformed input."""
    p = Packet(data, ts, wirelen, linktype)
    off, kind = _l3_start(data, linktype)
    if not kind:
        return p
    n = len(data)
    first4 = first6 = False
    end = n                                                    # the layer below bounds this layer
    for _depth in range(_MAX_TUNNEL_DEPTH):
        if kind == 4:
            if end - off < 20:
                break
            ihl = (data[off] & 15) * 4
            tlen = _U16(data, off + 2)[0]
            frag = _U16(data, off + 6)[0] & 0x1FFF
            proto = data[off + 9]
            if not first4:
                first4, p.src, p.dst, p.ip_proto, p.size = True, _ntoa(data[off + 12:off + 16]), _ntoa(
                    data[off + 16:off + 20]), proto, tlen
            l4 = off + max(ihl, 20)
            tail = tlen - ihl
            end = min(end, l4 + tail) if tail >= 0 else end
            if frag:
                break
            nxt = proto
        else:
            if end - off < 40:
                break
            plen, nxt = _U16(data, off + 4)[0], data[off + 6]
            if not first4 and not first6:
                first6, p.src, p.dst, p.ip_proto, p.size = True, _ntop(_AF6, data[off + 8:off + 24]), _ntop(
                    _AF6, data[off + 24:off + 40]), nxt, plen + 40
            l4 = off + 40
            end = min(end, l4 + plen)
            while nxt in (0, 43, 60, 44):                      # hop-by-hop, routing, destination options, fragment
                if end - l4 < 8:
                    nxt = -1
                    break
                if nxt == 44:
                    if _U16(data, l4 + 2)[0] >> 3:
                        nxt = -1
                        break
                    nxt, l4 = data[l4], l4 + 8
                else:
                    nxt, l4 = data[l4], l4 + (data[l4 + 1] + 1) * 8
            if nxt == -1:
                break
        if nxt == 6:
            if end - l4 >= 20:
                p.l4, p.sport, p.dport = 6, *struct.unpack_from(">HH", data, l4)
                p.flags = data[l4 + 13]
                p.poff = min(l4 + max((data[l4 + 12] >> 4) * 4, 20), end)
            break
        if nxt == 17:
            if end - l4 >= 8:
                p.l4, p.sport, p.dport = 17, *struct.unpack_from(">HH", data, l4)
                p.poff = l4 + 8
            break
        if nxt == 1:
            p.icmp = end - l4 >= 4
            break
        if nxt == 4:
            kind, off = 4, l4
        elif nxt == 41:
            kind, off = 6, l4
        else:
            break
    return p


def as_packet(obj: Any) -> Packet:
    """Accept a :class:`Packet`, or a foreign object that serialises to frame bytes (a scapy packet in tests / live capture)."""
    if isinstance(obj, Packet):
        return obj
    if hasattr(obj, "haslayer"):                               # scapy-like: decide link type by its layers
        lt = LINKTYPE_ETHERNET if obj.haslayer("Ether") else LINKTYPE_RAW
        return dissect(bytes(obj), lt, float(getattr(obj, "time", 0.0)))
    return dissect(bytes(obj), LINKTYPE_ETHERNET, float(getattr(obj, "time", 0.0)))
