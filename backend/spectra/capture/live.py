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
        # Queue/backpressure telemetry (see stats()). Written by the sniffer
        # thread; plain int increments are GIL-atomic, so no lock is needed.
        self._packets_received = 0
        self._packets_queued = 0
        self._packets_dropped = 0
        self._max_queue_depth = 0
        try:
            self._predicate = compile_filter(bpf_filter) if bpf_filter else None
        except ValueError as exc:
            raise CaptureError(f"invalid filter {bpf_filter!r}: {exc}") from exc

    def packets(self) -> Iterator[Packet]:
        from scapy.all import conf, sniff

        if self._stop.is_set():
            return   # stopped before it ever started: do not open the sniffer
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
                self._put_sentinel()   # never block the sniffer on shutdown

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

    def _put_sentinel(self) -> None:
        """Wake a waiting consumer without ever blocking.

        Used on the shutdown path: if the queue is full one packet is shed
        (and counted) to make room for the end-of-stream marker, so a stop
        request is honoured immediately instead of waiting for the queue to
        drain.
        """
        try:
            self._queue.put_nowait(None)
            return
        except queue.Full:
            pass
        try:
            self._queue.get_nowait()
            self._packets_dropped += 1
        except queue.Empty:  # pragma: no cover - race with another producer
            pass
        try:
            self._queue.put_nowait(None)
        except queue.Full:  # pragma: no cover - fully contended
            pass

    def _on_packet(self, pkt: Packet) -> None:
        self._packets_received += 1
        if self._stop.is_set():
            return
        if self._predicate is not None and not self._predicate(pkt):
            return  # filtered out by policy: received but never queued
        try:
            self._queue.put_nowait(pkt)
            self._packets_queued += 1
            depth = self._queue.qsize()
            if depth > self._max_queue_depth:
                self._max_queue_depth = depth
        except queue.Full:
            # Never block the adapter under backpressure - drop, but count
            # the loss so it is measurable (status["queue"] + /api/metrics)
            # instead of silent.
            self._packets_dropped += 1

    def stats(self) -> dict:
        """Live queue telemetry: received/queued/dropped + depth high-water.

        ``packets_received`` counts adapter callbacks; packets rejected by
        the filter are received but never queued (received >= queued +
        dropped holds apart from packets arriving after close()).
        """
        return {
            "packets_received": self._packets_received,
            "packets_queued": self._packets_queued,
            "packets_dropped": self._packets_dropped,
            "queue_depth": self._queue.qsize(),
            "max_queue_depth": self._max_queue_depth,
        }

    def close(self) -> None:
        """Stop sniffing and wake a consumer blocked on the queue.

        Idempotent, never blocks, never raises - shutdown must stay cheap.
        """
        already_stopped = self._stop.is_set()
        self._stop.set()
        if not already_stopped:
            self._put_sentinel()

    def __repr__(self) -> str:
        return f"LiveSource(iface={self.iface!r}, filter={self.bpf_filter!r})"


def _npcap_installed() -> bool:
    import os

    return os.path.exists(r"C:\Windows\System32\wpcap.dll")
