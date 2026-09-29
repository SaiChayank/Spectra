"""Small offline-analysis tools shared by the CLI, engine and modules."""

from __future__ import annotations

from .capture import open_source
from .parse.flow import Flow, FlowTracker


def collect_flows(path: str, idle_timeout: float = 30.0, bucket: int = 5) -> list[Flow]:
    """Read a PCAP and return its completed flows (metadata only)."""
    source = open_source("pcap", path=path)
    flows: list[Flow] = []
    tracker = FlowTracker(idle_timeout=idle_timeout, on_complete=flows.append)
    last: float | None = None
    for pkt in source.packets():
        ts = float(pkt.time)
        tracker.process(pkt, ts)
        if last is None:
            last = ts
        elif ts - last >= bucket:
            for _ in tracker.flush_expired(ts):
                pass
            last = ts
    list(tracker.flush_all())  # generator must be consumed to emit flows
    return flows
