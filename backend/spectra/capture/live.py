"""Live NIC capture.

Requires libpcap/Npcap on Windows (https://nmap.org/npcap/). Without it,
scapy cannot sniff and we raise a CaptureError with install guidance.
"""

from __future__ import annotations

import queue
import threading
from typing import Iterator

from scapy.packet import Packet

from ..filters import compile_filter
from .base import CaptureError, CaptureSource

_NPCAP_HINT = (
    "Live capture requires Npcap (Windows) or libpcap. "
    "Install Npcap from https://nmap.org/npcap/ with 'WinPcap API-compatible mode' "
    "enabled, then restart this process."
)


class LiveSource(CaptureSource):
    name = "live"

    def __init__(self, iface: str | None = None, bpf_filter: str = "",
                 max_packets: int | None = None, queue_size: int = 10000):
        self.iface = iface
        self.bpf_filter = bpf_filter
        self.max_packets = max_packets
        self._queue: queue.Queue[Packet | None] = queue.Queue(maxsize=queue_size)
        self._stop = threading.Event()
        self._error: BaseException | None = None
        try:
            self._predicate = compile_filter(bpf_filter) if bpf_filter else None
        except ValueError as exc:
            raise CaptureError(f"invalid filter {bpf_filter!r}: {exc}") from exc

    def packets(self) -> Iterator[Packet]:
        from scapy.all import conf, sniff

        if conf.use_pcap is False and not _npcap_installed():
            raise CaptureError(_NPCAP_HINT)

        def _sniff() -> None:
            try:
                # No libpcap `filter=`: we filter in pure Python instead, so
                # capture works on machines without Npcap's BPF engine.
                sniff(
                    iface=self.iface,
                    prn=self._on_packet,
                    store=False,
                    stop_filter=lambda _: self._stop.is_set(),
                    count=self.max_packets or 0,
                )
            except PermissionError as exc:
                self._error = CaptureError(
                    "permission denied opening the capture interface - "
                    "run with elevated privileges (Administrator on Windows)."
                )
            except Exception as exc:  # noqa: BLE001 - surface any sniff failure
                self._error = CaptureError(f"live capture failed: {exc}")
            finally:
                self._queue.put(None)

        thread = threading.Thread(target=_sniff, name="spectra-sniff", daemon=True)
        thread.start()

        try:
            while True:
                pkt = self._queue.get()
                if pkt is None:
                    break
                yield pkt
        finally:
            self._stop.set()

        if self._error is not None:
            raise self._error

    def _on_packet(self, pkt: Packet) -> None:
        if self._stop.is_set():
            return
        if self._predicate is not None and not self._predicate(pkt):
            return
        try:
            self._queue.put_nowait(pkt)
        except queue.Full:
            # Drop rather than stall the sniffer under backpressure.
            pass

    def close(self) -> None:
        self._stop.set()

    def __repr__(self) -> str:
        return f"LiveSource(iface={self.iface!r}, filter={self.bpf_filter!r})"


def _npcap_installed() -> bool:
    import os

    return os.path.exists(r"C:\Windows\System32\wpcap.dll")
