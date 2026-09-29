"""Pluggable packet capture sources (live NIC or PCAP file)."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Iterator

from scapy.packet import Packet


class CaptureError(RuntimeError):
    """Raised when a capture source cannot be opened."""


class CaptureSource(ABC):
    """A source of packets. Implementations yield scapy packets."""

    name: str = "capture"

    @abstractmethod
    def packets(self) -> Iterator[Packet]:
        """Yield packets until the source is exhausted or stopped."""

    def close(self) -> None:  # pragma: no cover - default no-op
        """Release any resources held by the source."""


def open_source(mode: str, path: str | None = None, iface: str | None = None,
                bpf_filter: str = "") -> CaptureSource:
    """Factory: mode is 'pcap' (needs path) or 'live' (optional iface)."""
    if mode == "pcap":
        if not path:
            raise CaptureError("pcap mode requires a file path")
        from .pcap_file import PcapFileSource

        return PcapFileSource(path, bpf_filter=bpf_filter)
    if mode == "live":
        from .live import LiveSource

        return LiveSource(iface=iface, bpf_filter=bpf_filter)
    raise CaptureError(f"unknown capture mode: {mode!r}")
