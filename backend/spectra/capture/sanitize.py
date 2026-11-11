"""Metadata-only rewrite of an uploaded capture (owner decision 5, 2026-11-07).

An uploaded pcap carries application payload; Spectra's own parsers only ever read TLS handshake records and QUIC Initial
packets.  ``sanitize_pcap`` writes a classic pcap in which every packet keeps its headers, its timestamp, its original
length and the exact payload *length*, but whose payload bytes are zeroed except:

* TCP: the 5-byte header of every TLS record, and the whole body of records whose type is handshake (0x16), which is the
  ClientHello / ServerHello / certificate metadata the parsers read.  Application data, alerts and everything that is not a
  TLS record stream (HTTP, SMTP, DNS over TCP ...) become zeros.
* UDP: datagrams whose first packet is a QUIC Initial (the handshake the QUIC parser reads).  Everything else is zeros.

Lengths are preserved, so every feature derived from sizes, counts and timing is unchanged; only content-dependent parsing of
the dropped bytes is lost.  Unsure means zeros: a stream that does not begin with a valid TLS record header, or a record header
split across segments, is zeroed from that point.  IP and TCP/UDP checksums are NOT recomputed (the zeroed packets no longer
match them); Spectra does not validate checksums.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass

from ..parse.quic import parse_long_header
from .base import CaptureError
from .packet import Packet
from .pcap_file import PcapFileSource

_TLS_TYPES = (0x14, 0x15, 0x16, 0x17)       # change_cipher_spec, alert, handshake, application_data
_TLS_HANDSHAKE = 0x16


@dataclass
class _Dir:
    remaining: int = 0          # body bytes of the current TLS record still to come
    keep: bool = False          # that record is a handshake record
    dead: bool = False          # not a TLS stream (or lost sync): zero everything


def _tls_mask(payload: bytes, st: _Dir) -> bytearray:
    """Copy of ``payload`` with everything but TLS record headers and handshake bodies zeroed."""
    out = bytearray(len(payload))
    if st.dead:
        return out
    pos, n = 0, len(payload)
    while pos < n:
        if st.remaining:
            take = min(st.remaining, n - pos)
            if st.keep:
                out[pos:pos + take] = payload[pos:pos + take]
            st.remaining -= take
            pos += take
            continue
        if n - pos < 5 or payload[pos] not in _TLS_TYPES or payload[pos + 1] != 3:
            st.dead = True                  # not a record header we can trust: zero the rest of the stream
            break
        out[pos:pos + 5] = payload[pos:pos + 5]
        st.keep = payload[pos] == _TLS_HANDSHAKE
        st.remaining = int.from_bytes(payload[pos + 3:pos + 5], "big")
        pos += 5
    return out


def _is_quic_initial(payload: bytes) -> bool:
    hdr = parse_long_header(payload)
    return bool(hdr and hdr.get("type") == "initial")


def sanitize_packet(pkt: Packet, states: dict) -> tuple[bytes, bool]:
    """Return (new raw bytes, changed) for one packet."""
    raw = pkt.data
    if not pkt.l4:
        return raw, False
    payload = pkt.payload
    if not payload:
        return raw, False
    if pkt.l4 == 6:
        key = (pkt.src, pkt.dst, pkt.sport, pkt.dport)
        new = bytes(_tls_mask(payload, states.setdefault(key, _Dir())))
    else:
        new = payload if _is_quic_initial(payload) else bytes(len(payload))
    return raw[:pkt.poff] + new, new != payload


def sanitize_pcap(src: str, dst: str) -> dict:
    """Write the metadata-only copy of ``src`` (pcap/pcapng/gz) to ``dst`` (classic pcap); return counts."""
    states: dict = {}
    packets = changed = 0
    out = None
    linktype = 0
    try:
        for pkt in PcapFileSource(src).packets():
            new, did = sanitize_packet(pkt, states)
            if out is None:
                linktype = pkt.linktype
                out = open(dst, "wb")
                out.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, linktype))
            elif pkt.linktype != linktype:      # a classic pcap has one link type; keeping the raw frame is not an option
                raise CaptureError("the capture mixes link types and cannot be rewritten as a classic pcap")
            usec = round(pkt.time * 1_000_000)
            out.write(struct.pack("<IIII", usec // 1_000_000, usec % 1_000_000, len(new), pkt.wirelen) + new)
            packets += 1
            changed += did
    except CaptureError:
        raise
    except Exception as exc:  # noqa: BLE001 - fail closed: never keep the raw copy on a sanitising error
        raise CaptureError(f"could not sanitise the capture: {exc}") from exc
    finally:
        if out is not None:
            out.close()
    if packets == 0:
        raise CaptureError("the capture holds no packets to keep")
    return {"packets": packets, "packets_payload_zeroed_or_trimmed": changed}
