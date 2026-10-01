"""FastAPI application: router assembly, auth gate, WebSocket event bridge.

Route definitions live in ``spectra.api.routers``; the engine itself is
constructed once in ``spectra.api.runtime`` (re-exported here so tests and
tooling can keep importing ``spectra.api.app``).

Security layout:

* the **default-deny session gate** (:func:`spectra.api.security.auth_gate`)
  is registered before CORS, so CORS stays outermost (it answers preflights
  before the gate) while every ``/api/`` request still needs a session;
* per-route **permissions** come from ``require(...)`` inside each router;
* the **event WebSocket** authenticates at handshake time from the session
  cookie or ``?token=`` and revalidates while streaming, closing with 4401
  when the session ends;
* the first **admin account** is bootstrapped once per database at import
  (``SPECTRA_ADMIN_PASSWORD`` or a mode-restricted file - see
  :meth:`spectra.services.auth.AuthService.bootstrap`).
"""

from __future__ import annotations

import asyncio
import logging
import time

from fastapi import FastAPI, WebSocket
from fastapi.middleware.cors import CORSMiddleware

from .. import __version__
from .routers import (
    alerts,
    audit,
    auth,
    bio,
    captures,
    core,
    edge,
    graph,
    history,
    incidents,
    investigation,
    model,
    pqc,
    tee,
    twin,
    users,
)
from .middleware import RequestIdMiddleware
from .runtime import cfg, engine  # noqa: F401  (re-exported for tests/tools)
from .security import (
    auth_gate,
    resolve_ws_principal,
)

log = logging.getLogger("spectra.api")

app = FastAPI(title="Spectra API", version=__version__)

# Registered before CORSMiddleware below: add_middleware prepends, so CORS
# ends up outermost (preflights answered without hitting the gate) while the
# gate still wraps routing for every /api/ request.
app.middleware("http")(auth_gate)

app.add_middleware(
    CORSMiddleware,
    allow_origins=cfg.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["X-Request-ID"],  # browsers may read the correlation id
)

# Outermost last: request id + structured access log wrap CORS and the gate
# (see spectra.api.middleware - query strings are never logged).
app.add_middleware(RequestIdMiddleware)

for _router in (core.router, captures.router, model.router, history.router,
                graph.router, pqc.router, audit.router, twin.router,
                bio.router, tee.router, edge.router, auth.router,
                users.router, incidents.router, alerts.router,
                investigation.router):
    app.include_router(_router)

try:
    engine.auth.bootstrap()  # first admin, once per database (see service)
except Exception:  # noqa: BLE001 - a bootstrap failure must not block serving
    log.exception("auth bootstrap failed; logins will be unavailable")


@app.websocket("/ws/events")
async def ws_events(ws: WebSocket) -> None:
    """Authenticated event stream (cookie or ``?token=``; any role with read).

    Rejected *before* the handshake when there is no valid session, and
    revalidated while streaming so logout/expiry closes the socket with 4401
    instead of letting a revoked session keep reading events.
    """
    cookies = dict(ws.cookies)
    query = dict(ws.query_params)
    principal = resolve_ws_principal(cookies, query)
    if principal is None or "read" not in principal["permissions"]:
        await ws.close(code=4401)  # pre-accept close = handshake rejected
        return
    expires_at = principal["session"]["expires_at"]
    await ws.accept()
    loop = asyncio.get_running_loop()
    queue: asyncio.Queue[dict] = asyncio.Queue(maxsize=500)
    ws_status = engine.status["websocket"]
    ws_status["clients"] += 1
    log.info("websocket client connected", extra={
        "event": "ws_open", "clients": ws_status["clients"]})

    def _put(event: dict) -> None:
        try:
            queue.put_nowait(event)
        except asyncio.QueueFull:  # slow client: drop oldest to keep stream fresh
            ws_status["slow_client_drops"] += 1
            try:
                queue.get_nowait()
                queue.put_nowait(event)
            except (asyncio.QueueEmpty, asyncio.QueueFull):
                pass

    unsubscribe = engine.subscribe(lambda e: loop.call_soon_threadsafe(_put, e))
    await ws.send_json({"type": "status", "data": engine.status})

    async def _reader() -> None:
        while True:
            await ws.receive_text()  # client messages are ignored (keepalive/ping)

    async def _writer() -> None:
        while True:
            # Wait for the next event, but never longer than until the session
            # should be re-checked (logout, expiry) - then close with 4401.
            wait = max(1.0, min(30.0, expires_at - time.time()))
            try:
                event = await asyncio.wait_for(queue.get(), timeout=wait)
            except asyncio.TimeoutError:
                if resolve_ws_principal(cookies, query) is None:
                    await ws.close(code=4401)
                    return
                continue
            await ws.send_json(event)

    reader_task = asyncio.create_task(_reader())
    writer_task = asyncio.create_task(_writer())
    try:
        await asyncio.wait({reader_task, writer_task},
                           return_when=asyncio.FIRST_COMPLETED)
    finally:
        for task in (reader_task, writer_task):
            task.cancel()
        unsubscribe()
        ws_status["clients"] = max(0, ws_status["clients"] - 1)
        log.info("websocket client disconnected", extra={
            "event": "ws_close", "clients": ws_status["clients"]})
        try:
            await ws.close()
        except RuntimeError:  # already closed by the client
            pass
