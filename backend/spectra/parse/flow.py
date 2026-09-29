"""Bidirectional flow tracking with TLS metadata attachment.

A "flow" is one 5-tuple conversation (initiator -> responder over TCP/UDP).
The tracker maintains per-direction TLS stream parsers so handshake metadata
is attached to the flow it belongs to. QUIC/UDP flows are parsed via the
Initial-packet path (see quic.py); their CRYPTO frames feed the same TLS
metadata pipeline. Payload bytes are parsed only for handshake structure and
then discarded.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Iterator

from scapy.packet import Packet

from .tls import TlsMetadata, TlsStreamParser, parse_handshake

DEFAULT_IDLE_TIMEOUT = 120.0
DEFAULT_MAX_PACKETS = 10000
FLOW_TCP = 6
FLOW_UDP = 17

PROTO_NAMES = {FLOW_TCP: "TCP", FLOW_UDP: "UDP"}


@dataclass(slots=True)
class PacketRec:
    ts: float
    size: int          # wire length (IP total length when available)
    direction: int     # 0 = initiator->responder, 1 = responder->initiator
    syn: bool = False
    ack: bool = False
    fin: bool = False
    rst: bool = False
    psh: bool = False
    payload: int = 0   # transport payload bytes


@dataclass
class Flow:
    proto: int
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    start_ts: float
    last_ts: float = 0.0
    packets: list[PacketRec] = field(default_factory=list)
    truncated: bool = False
    bytes_fwd: int = 0
    bytes_bwd: int = 0
    packets_fwd: int = 0
    packets_bwd: int = 0
    client_tls: TlsMetadata | None = None
    server_tls: TlsMetadata | None = None
    client_hello_ts: float = 0.0
    server_hello_ts: float = 0.0
    quic: dict | None = None                # {"version", "version_name", "dcid", ...}
    _parsers: dict[int, TlsStreamParser] = field(default_factory=dict, repr=False)
    _quic: dict = field(default_factory=dict, repr=False)
    _fin_seen: set[int] = field(default_factory=set, repr=False)
    _max_packets: int = field(default=DEFAULT_MAX_PACKETS, repr=False)

    @property
    def key(self) -> tuple:
        return (self.proto, self.src_ip, self.src_port, self.dst_ip, self.dst_port)

    @property
    def is_tcp(self) -> bool:
        return self.proto == FLOW_TCP

    @property
    def duration(self) -> float:
        return max(0.0, self.last_ts - self.start_ts)

    @property
    def tls(self) -> TlsMetadata | None:
        """Prefer client hello metadata (richest), fall back to server."""
        return self.client_tls or self.server_tls

    @property
    def ports(self) -> tuple[int, int]:
        return self.src_port, self.dst_port

    def record(self) -> dict:
        tls = self.tls
        return {
            "proto": PROTO_NAMES.get(self.proto, str(self.proto)),
            "src": f"{self.src_ip}:{self.src_port}",
            "dst": f"{self.dst_ip}:{self.dst_port}",
            "start_ts": self.start_ts,
            "last_ts": self.last_ts,
            "duration": round(self.duration, 6),
            "packets": self.packets_fwd + self.packets_bwd,
            "bytes": self.bytes_fwd + self.bytes_bwd,
            "tls_version": tls.version_name if tls else None,
            "sni": tls.sni if tls else None,
            "alpn": tls.alpn if tls else None,
            "ja3": tls.ja3 if tls else None,
            "ja4": tls.ja4 if tls else None,
            "cipher_count": tls.cipher_count if tls else 0,
            "extension_count": tls.extension_count if tls else 0,
            "quic_version": self.quic.get("version_name") if self.quic else None,
        }


def _endpoints(pkt: Packet) -> tuple[str, int, str, int, int] | None:
    """Return (src_ip, src_port, dst_ip, dst_port, proto) or None."""
    from scapy.layers.inet import IP, TCP, UDP
    from scapy.layers.inet6 import IPv6

    if pkt.haslayer(IP):
        ip = pkt[IP]
    elif pkt.haslayer(IPv6):
        ip = pkt[IPv6]
    else:
        return None
    if pkt.haslayer(TCP):
        t = pkt[TCP]
        return ip.src, int(t.sport), ip.dst, int(t.dport), FLOW_TCP
    if pkt.haslayer(UDP):
        u = pkt[UDP]
        return ip.src, int(u.sport), ip.dst, int(u.dport), FLOW_UDP
    return None


class FlowTracker:
    """Turns a packet stream into flows, emitting them when they end."""

    def __init__(
        self,
        idle_timeout: float = DEFAULT_IDLE_TIMEOUT,
        max_packets: int = DEFAULT_MAX_PACKETS,
        on_complete: Callable[[Flow], None] | None = None,
    ):
        self.idle_timeout = idle_timeout
        self.max_packets = max_packets
        self.on_complete = on_complete
        # Recently completed 5-tuples: trailing ACKs / retransmitted FINs must
        # not spawn ghost flows after a connection is torn down.
        self._completed: dict[tuple, float] = {}
        self._completed_window = max(idle_timeout, 60.0)
        self._flows: dict[tuple, Flow] = {}
        self.completed = 0

    def __len__(self) -> int:
        return len(self._flows)

    def process(self, pkt: Packet, ts: float | None = None) -> Flow | None:
        """Feed one packet; returns the flow it belongs to (may be unfinished)."""
        eps = _endpoints(pkt)
        if eps is None:
            return None
        src, sport, dst, dport, proto = eps
        fwd_key = (proto, src, sport, dst, dport)
        rev_key = (proto, dst, dport, src, sport)

        if ts is None:
            ts = float(pkt.time)
        if self._drop_completed(fwd_key, rev_key, ts):
            return None

        from scapy.layers.inet import IP, TCP
        from scapy.layers.inet6 import IPv6

        if pkt.haslayer(IP) and pkt[IP].len is not None:
            size = int(pkt[IP].len)
        elif pkt.haslayer(IPv6) and pkt[IPv6].plen is not None:
            size = int(pkt[IPv6].plen) + 40
        else:
            size = len(pkt)
        payload_len = 0
        if pkt.haslayer(TCP):
            payload_len = len(bytes(pkt[TCP].payload)) if pkt[TCP].payload else 0
        elif pkt.haslayer("UDP"):
            payload_len = len(bytes(pkt["UDP"].payload)) if pkt["UDP"].payload else 0

        flow = self._flows.get(fwd_key)
        direction = 0
        if flow is None:
            flow = self._flows.get(rev_key)
            if flow is not None:
                direction = 1
        if flow is None:
            flow = Flow(
                proto=proto, src_ip=src, src_port=sport, dst_ip=dst, dst_port=dport,
                start_ts=ts, last_ts=ts, _max_packets=self.max_packets,
            )
            self._flows[fwd_key] = flow

        flow.last_ts = ts
        if direction == 0:
            flow.bytes_fwd += size
            flow.packets_fwd += 1
        else:
            flow.bytes_bwd += size
            flow.packets_bwd += 1

        syn = fin = rst = psh = ack = False
        if pkt.haslayer(TCP):
            flags = pkt[TCP].flags
            syn, fin, rst, psh, ack = bool(flags.S), bool(flags.F), bool(
                flags.R), bool(flags.P), bool(flags.A)

        rec = PacketRec(ts=ts, size=size, direction=direction, syn=syn, ack=ack,
                        fin=fin, rst=rst, psh=psh, payload=payload_len)
        if len(flow.packets) < flow._max_packets:
            flow.packets.append(rec)
        else:
            flow.truncated = True

        if proto == FLOW_TCP and payload_len:
            self._feed_tls(flow, direction, bytes(pkt[TCP].payload), ts)
        elif proto == FLOW_UDP and payload_len:
            self._feed_quic(flow, direction, bytes(pkt["UDP"].payload), ts)

        if proto == FLOW_TCP:
            if fin:
                flow._fin_seen.add(direction)
            # Both sides FIN'd, or a reset -> conversation is over.
            if rst or (fin and len(flow._fin_seen) >= 2):
                self._complete(flow)
                return flow

        return flow

    def _feed_tls(self, flow: Flow, direction: int, payload: bytes, ts: float) -> None:
        parser = flow._parsers.get(direction)
        if parser is None:
            parser = TlsStreamParser()
            flow._parsers[direction] = parser
        records = parser.feed(payload)
        if not records:
            return
        meta = TlsMetadata()
        if not parse_handshake(records, meta):
            return
        if meta.role == "client" and flow.client_tls is None:
            meta.hello_time = ts
            flow.client_tls = meta
            flow.client_hello_ts = ts
        elif meta.role == "server" and flow.server_tls is None:
            meta.hello_time = ts
            flow.server_tls = meta
            flow.server_hello_ts = ts

    def _feed_quic(self, flow: Flow, direction: int, payload: bytes, ts: float) -> None:
        """Parse a QUIC packet; Initial packets yield TLS handshake metadata.

        Initial keys are public (derived from the cleartext DCID), so this is
        passive metadata extraction just like TLS over TCP. Only claims a flow
        is QUIC when the evidence is solid: a successfully authenticated
        Initial, a known QUIC version on the cleartext header, or a
        structurally valid Version Negotiation packet.
        """
        from .quic import (
            CRYPTO_AVAILABLE,
            extract_crypto,
            handshake_metadata,
            initial_secrets,
            open_initial,
            parse_long_header,
            quic_version_name,
        )

        hdr = parse_long_header(payload)
        if hdr is None:
            return
        state = flow._quic
        if direction == 0:
            # Initiator's first packet carries the original DCID that all
            # Initial secrets are derived from (including server replies).
            state.setdefault("initial_dcid", hdr.get("dcid", b""))

        opened = None
        if hdr["type"] == "initial" and CRYPTO_AVAILABLE:
            key_dcid = hdr["dcid"] if direction == 0 else state.get(
                "initial_dcid", hdr["dcid"])
            secrets = initial_secrets(hdr["version"], key_dcid)
            if secrets is not None:
                opened = open_initial(
                    payload, secrets["client" if direction == 0 else "server"], hdr)

        known_version = hdr.get("version") in (0x00000001, 0x6B3343CF, 0xFF00001D)
        is_quic = (
            opened is not None
            or hdr["type"] == "version_negotiation"
            or (known_version and hdr["type"] in ("initial", "0rtt",
                                                  "handshake", "retry"))
        )
        if not is_quic:
            return  # structurally plausible but not authenticated: don't claim

        if flow.quic is None:
            flow.quic = {
                "version": hdr.get("version", 0),
                "version_name": ("version negotiation"
                                 if hdr["type"] == "version_negotiation"
                                 else quic_version_name(hdr["version"])),
                "dcid": hdr["dcid"].hex(),
                "scid": hdr["scid"].hex(),
            }
            if hdr["type"] == "version_negotiation":
                flow.quic["offered_versions"] = [
                    f"0x{v:08x}" for v in hdr.get("versions", [])[:8]
                ]

        if opened is None:
            return  # 0-RTT/Handshake packets: sizes counted, contents opaque
        crypto = extract_crypto(opened["plaintext"])
        if not crypto:
            return
        buf = state.setdefault("crypto", {0: bytearray(), 1: bytearray()})
        buf[direction].extend(crypto)
        meta = handshake_metadata(bytes(buf[direction]))
        if meta is None:
            return  # incomplete hello - wait for more packets
        if meta.role == "client" and flow.client_tls is None:
            meta.hello_time = ts
            flow.client_tls = meta
            flow.client_hello_ts = ts
        elif meta.role == "server" and flow.server_tls is None:
            meta.hello_time = ts
            flow.server_tls = meta
            flow.server_hello_ts = ts

    def flush_expired(self, now: float) -> Iterator[Flow]:
        """Yield and drop flows idle for longer than the timeout."""
        expired = [
            key for key, flow in self._flows.items()
            if now - flow.last_ts >= self.idle_timeout
        ]
        for key in expired:
            flow = self._flows.pop(key)
            yield from self._emit(flow)

    def flush_all(self) -> Iterator[Flow]:
        for key in list(self._flows):
            flow = self._flows.pop(key)
            yield from self._emit(flow)

    def _drop_completed(self, fwd_key: tuple, rev_key: tuple, ts: float) -> bool:
        """True when both tuple directions belong to a just-finished flow."""
        if not self._completed:
            return False
        now_deadline = ts - self._completed_window
        for key in (fwd_key, rev_key):
            done_at = self._completed.get(key)
            if done_at is not None:
                if done_at >= now_deadline:
                    return True
                del self._completed[key]
        return False

    def _remember_completed(self, flow: Flow) -> None:
        fwd = flow.key
        rev = (flow.proto, flow.dst_ip, flow.dst_port, flow.src_ip, flow.src_port)
        self._completed[fwd] = flow.last_ts
        self._completed[rev] = flow.last_ts
        if len(self._completed) > 8192:  # bound memory on busy captures
            cutoff = flow.last_ts - self._completed_window
            self._completed = {k: v for k, v in self._completed.items() if v >= cutoff}

    def _complete(self, flow: Flow) -> None:
        self._flows.pop(flow.key, None)
        self._remember_completed(flow)
        for _ in self._emit(flow):
            pass

    def _emit(self, flow: Flow) -> Iterator[Flow]:
        if flow.packets_fwd + flow.packets_bwd == 0:
            return
        self.completed += 1
        if self.on_complete is not None:
            self.on_complete(flow)
        yield flow
