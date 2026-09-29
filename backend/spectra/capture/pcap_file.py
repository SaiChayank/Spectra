"""Offline PCAP/PCAPNG file source."""

from __future__ import annotations

import os
from typing import Iterator

from scapy.packet import Packet

# Register IP/TCP decoders with conf.l2types *before* any PCAP is read;
# otherwise linktype 228 (raw IP) packets decode as opaque Raw payloads.
import scapy.layers.inet  # noqa: F401
import scapy.layers.inet6  # noqa: F401

from ..filters import compile_filter
from .base import CaptureError, CaptureSource


class PcapFileSource(CaptureSource):
    name = "pcap-file"

    def __init__(self, path: str, bpf_filter: str = ""):
        if not os.path.isfile(path):
            raise CaptureError(f"PCAP file not found: {path}")
        self.path = path
        self.bpf_filter = bpf_filter
        try:
            self._predicate = compile_filter(bpf_filter) if bpf_filter else None
        except ValueError as exc:
            raise CaptureError(f"invalid filter {bpf_filter!r}: {exc}") from exc

    def packets(self) -> Iterator[Packet]:
        from scapy.utils import PcapReader

        try:
            reader = PcapReader(self.path)
        except Exception as exc:  # scapy raises various errors for bad files
            raise CaptureError(f"cannot read PCAP {self.path}: {exc}") from exc
        try:
            for pkt in reader:
                if self._predicate is None or self._predicate(pkt):
                    yield pkt
        finally:
            reader.close()

    def __repr__(self) -> str:
        return f"PcapFileSource({self.path!r})"
