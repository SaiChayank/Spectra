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


def stream_flows(path: str, on_flow, *, idle_timeout: float = 30.0,
                 bucket: int = 5, max_flows: int | None = None) -> dict:
    """Read a PCAP and hand each completed flow to ``on_flow`` as it ends.

    The bounded-memory reader: at any moment only the flow being delivered
    is alive - the callback decides what to keep (nothing, a ScoredFlow row,
    a record), so a multi-GB capture is processed in flat memory.  Delivery
    order is identical to :func:`collect_flows` (both are driven by the same
    tracker completion events).

    ``max_flows`` stops the read after that many deliveries; if a further
    flow then completes, ``truncated`` is set and the read unwinds - a
    capture holding *exactly* ``max_flows`` flows is therefore not
    truncated (the flag means flows were withheld).  Exceptions raised by
    ``on_flow`` propagate unchanged.

    Returns ``{"flows": <delivered>, "truncated": bool}``.
    """

    class _Stop(Exception):
        """Budget reached: unwind the packet loop (internal control flow)."""

    source = open_source("pcap", path=path)
    count = 0
    truncated = False

    def _deliver(flow: Flow) -> None:
        nonlocal count, truncated
        if max_flows is not None and count >= max_flows:
            truncated = True
            raise _Stop
        count += 1
        on_flow(flow)

    tracker = FlowTracker(idle_timeout=idle_timeout, on_complete=_deliver)
    last: float | None = None
    try:
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
    except _Stop:
        pass                      # partial read: reported as truncated
    return {"flows": count, "truncated": truncated}


def collect_flows(path: str, idle_timeout: float = 30.0, bucket: int = 5,
                  max_flows: int = MAX_COLLECT_FLOWS) -> list[Flow]:
    """Read a PCAP and return its completed flows (metadata only).

    Raises :class:`FlowBudgetError` when the capture completes more than
    ``max_flows`` flows - callers map that to HTTP 400 rather than letting
    an oversized file consume unbounded memory.
    """
    flows: list[Flow] = []

    def _collect(flow: Flow) -> None:
        flows.append(flow)

    info = stream_flows(path, _collect, idle_timeout=idle_timeout,
                        bucket=bucket, max_flows=max_flows)
    if info["truncated"]:
        raise FlowBudgetError(
            f"capture holds more than {max_flows} complete flows - "
            "refusing to buffer it")
    return flows
