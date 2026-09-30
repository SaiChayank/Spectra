"""In-process publish/subscribe bus for pipeline events."""

from __future__ import annotations

import threading
from typing import Callable

from ..domain import SystemEvent

Listener = Callable[[SystemEvent], None]


class EventBus:
    """Thread-safe fan-out of system events to subscribers.

    A failing listener is isolated: one bad subscriber (e.g. a disconnected
    WebSocket handler) must never stop capture or starve other listeners.
    """

    def __init__(self) -> None:
        self._listeners: list[Listener] = []
        self._lock = threading.Lock()

    def subscribe(self, listener: Listener) -> Callable[[], None]:
        """Register ``listener``; returns a callable that unsubscribes it."""
        with self._lock:
            self._listeners.append(listener)

        def unsubscribe() -> None:
            with self._lock:
                if listener in self._listeners:
                    self._listeners.remove(listener)

        return unsubscribe

    def emit(self, event: SystemEvent) -> None:
        """Deliver ``event`` to every subscriber; listener errors are swallowed."""
        with self._lock:
            listeners = list(self._listeners)
        for listener in listeners:
            try:
                listener(event)
            except Exception:  # noqa: BLE001 - a bad subscriber must not stop capture
                pass
