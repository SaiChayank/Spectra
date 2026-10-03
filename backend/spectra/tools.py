"""Small offline-analysis tools shared by the CLI, engine and modules."""

from __future__ import annotations

from .capture import open_source
from .parse.flow import Flow, FlowTracker

#: Upper bound for flows materialised from one offline PCAP.  A crafted
#: upload full of short-lived connections would otherwise grow the result
#: list (and the matrix built from it) until the process is killed; the cap
#: is far past what training or an analysis window legitimately needs, and
#: the excess is refused instead of buffered.
MAX_COLLECT_FLOWS = 250_000


class FlowBudgetError(ValueError):
    """The capture completed more flows than one run may buffer.

    A ``ValueError`` so existing ``except ValueError`` -> 400 handlers keep
    working; routers that would otherwise answer 500 catch it explicitly.
    """


def collect_flows(path: str, idle_timeout: float = 30.0, bucket: int = 5,
                  max_flows: int = MAX_COLLECT_FLOWS) -> list[Flow]:
    """Read a PCAP and return its completed flows (metadata only).

    Raises :class:`FlowBudgetError` when the capture completes more than
    ``max_flows`` flows - callers map that to HTTP 400 rather than letting
    an oversized file consume unbounded memory.
    """
    source = open_source("pcap", path=path)
    flows: list[Flow] = []

    def _collect(flow: Flow) -> None:
        if len(flows) >= max_flows:
            raise FlowBudgetError(
                f"capture holds more than {max_flows} complete flows - "
                "refusing to buffer it")
        flows.append(flow)

    tracker = FlowTracker(idle_timeout=idle_timeout, on_complete=_collect)
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
