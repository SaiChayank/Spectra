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
from contextlib import asynccontextmanager
from urllib.parse import urlsplit

from fastapi import FastAPI, Request, WebSocket
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

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


@asynccontextmanager
async def lifespan(_app: FastAPI):
    """Graceful shutdown: end the capture session, then make the store durable.

    Startup deliberately does nothing - the engine is built at import time
    (see ``spectra.api.runtime``), and running work during lifespan startup
    would make importing the app have side effects.  The shutdown half is
    what was missing: without it, stopping the server left the capture
    supervisor thread draining on its own and the batch writer's staged rows
    uncommitted until process death.
    """
    yield
    try:
        if engine.capture.running:
            engine.capture.stop()
    except Exception:  # noqa: BLE001 - shutdown must never raise
        log.exception("capture stop failed during shutdown")
    try:
        store = getattr(engine, "store", None)
        if store is not None:
            store.close()          # flushes staged rows, then closes the DB
    except Exception:  # noqa: BLE001
        log.exception("store close failed during shutdown")


app = FastAPI(title="Spectra API", version=__version__, lifespan=lifespan)

#: The event WebSocket revalidates its session against the store at least
#: this often while streaming - even when events never stop flowing - so a
#: logout/revocation cannot be outrun by a busy event stream.  Module-level
#: so tests can lower it.
REVALIDATE_INTERVAL = 30.0

#: Upper bound for a JSON request body on the /api/ routes.  Generous for
#: every legitimate payload (the biggest JSON routes are simulation actions
#: and audit verify certificates) yet finite, so an oversized or maliciously
#: chunked body cannot buffer unbounded data in memory.  The capture import
#: gets its own larger allowance (multipart overhead over the store cap).
JSON_BODY_LIMIT = 4 * 1024 * 1024
_CAPTURE_BODY_LIMIT = cfg.capture_max_bytes + 1024 * 1024


class BodyTooLarge(Exception):
    """Raised while streaming a request body past the route's size cap.

    Handled by :class:`_BodyLimit` itself: the raise happens while the route
    reads the body, and the middleware converts it to a 413 before any of
    the oversized payload is retained.
    """


class _BodyLimit:
    """413 for oversized bodies **before** the gate or any handler runs.

    ``Content-Length`` is checked up front (the common case - one header
    compare, no body read); a chunked body without a declared length is
    counted as it streams and aborted via :class:`BodyTooLarge` the moment
    it passes the cap, so neither encoding can buffer an unbounded payload.
    Registered between CORS and the gate: CORS headers land on the 413, and
    unauthenticated requests (login) are covered too.
    """

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if (scope["type"] != "http"
                or scope["method"] not in ("POST", "PUT", "PATCH")
                or not scope["path"].startswith("/api/")):
            await self.app(scope, receive, send)
            return
        limit = (_CAPTURE_BODY_LIMIT if scope["path"] == "/api/captures"
                 else JSON_BODY_LIMIT)
        declared = dict(scope.get("headers") or {}).get(b"content-length")
        if declared is not None:
            try:
                if int(declared) > limit:
                    await self._send_413(send)
                    return
            except ValueError:  # pragma: no cover - malformed header
                pass
        total = 0

        async def counting_receive() -> dict:
            nonlocal total
            message = await receive()
            if message.get("type") == "http.request":
                total += len(message.get("body", b""))
                if total > limit:
                    raise BodyTooLarge(limit)
            return message

        try:
            await self.app(scope, counting_receive, send)
        except BodyTooLarge:
            # The route's body read raised before any response started.
            await self._send_413(send)

    @staticmethod
    async def _send_413(send) -> None:
        body = b'{"detail":"request body too large"}'
        await send({
            "type": "http.response.start",
            "status": 413,
            "headers": [
                (b"content-type", b"application/json"),
                (b"content-length", str(len(body)).encode("ascii")),
            ],
        })
        await send({"type": "http.response.body", "body": body})


@app.exception_handler(BodyTooLarge)
async def _body_too_large(request: Request,
                          exc: BodyTooLarge) -> JSONResponse:
    """Chunked-body cap: raised while the route reads the stream, answered
    as 413 by the exception middleware (CORS headers still applied)."""
    return JSONResponse(status_code=413,
                        content={"detail": "request body too large"})


# Registered before CORSMiddleware below: add_middleware prepends, so CORS
# ends up outermost (preflights answered without hitting the gate) while the
# gate still wraps routing for every /api/ request.
app.middleware("http")(auth_gate)

# Between CORS and the gate (registered after the gate, before CORS): 413
# responses still get CORS headers, and the body cap covers public routes
# (login) before any session work happens.
app.add_middleware(_BodyLimit)

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

# Model registry adoption (Prompt 14): an empty registry with a trained
# deployed model registers that artifact as the first ACTIVE row - explicit,
# audited lineage for models that predate the registry. Never blocks serving.
try:
    engine.adopt_model()
except Exception:  # noqa: BLE001 - adoption is opportunistic
    log.exception("model registry adoption failed")


def _origin_allowed(origin: str, host: str | None) -> bool:
    """True when a browser may open the event WebSocket from ``origin``.

    Allowed: the configured CORS origins (the dashboard at :5173) and the
    API's own host (same-origin, e.g. the docs page).  Anything else - a
    foreign site attempting a cross-site WebSocket hijack - is refused.
    """
    if origin in cfg.cors_origins:
        return True
    try:
        netloc = urlsplit(origin).netloc
    except ValueError:  # pragma: no cover - urlsplit is tolerant
        return False
    return bool(host) and netloc == host


@app.websocket("/ws/events")
async def ws_events(ws: WebSocket) -> None:
    """Authenticated event stream (cookie or ``?token=``; any role with read).

    Rejected *before* the handshake when there is no valid session, and
    revalidated while streaming so logout/expiry closes the socket with 4401
    instead of letting a revoked session keep reading events.  A browser
    Origin that is neither same-host nor in the CORS allowlist is rejected
    with 4403 (cross-site WebSocket hijacking); non-browser clients send no
    Origin and are unaffected.
    """
    origin = ws.headers.get("origin")
    if origin is not None and not _origin_allowed(origin, ws.headers.get("host")):
        await ws.close(code=4403)
        return
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
        last_check = time.time()
        while True:
            # Session liveness is enforced on every pass: expiry needs no
            # I/O, and the store is re-read on a fixed cadence (not only
            # when the queue goes quiet) so neither a busy event stream nor
            # an expired TTL can keep a revoked session reading events.
            if time.time() >= expires_at:
                await ws.close(code=4401)
                return
            now = time.time()
            if now - last_check >= REVALIDATE_INTERVAL:
                last_check = now
                if resolve_ws_principal(cookies, query) is None:
                    await ws.close(code=4401)
                    return
            # Wake at least each REVALIDATE_INTERVAL, and never past expiry.
            wait = max(0.2, min(REVALIDATE_INTERVAL, expires_at - now))
            try:
                event = await asyncio.wait_for(queue.get(), timeout=wait)
            except asyncio.TimeoutError:
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


@app.exception_handler(RequestValidationError)
async def _validation_detail(request: Request,
                             exc: RequestValidationError) -> JSONResponse:
    """422 responses carry loc/msg/type/ctx only - never the rejected input.

    FastAPI's default serializer echoes the offending value back, which on
    the login/user routes would mean reflecting passwords (or other secrets)
    in an error response and any intermediary log that captures it.
    """
    errors = [
        {key: err[key] for key in ("loc", "msg", "type", "ctx")
         if key in err}
        for err in exc.errors()
    ]
    return JSONResponse(status_code=422,
                        content={"detail": jsonable_encoder(errors)})


@app.exception_handler(OverflowError)
async def _overflow(request: Request, exc: OverflowError) -> JSONResponse:
    """Huge numeric ids/params answer 422, not a 500 from the SQLite bind.

    Path/query values parse as unbounded Python ints but SQLite integers
    are 64-bit; without this a probe like ``/api/incidents/10**30`` produced
    a server error (and a stack trace in the logs).
    """
    log.warning("numeric parameter out of range", extra={
        "event": "request_overflow", "path": request.url.path})
    return JSONResponse(status_code=422,
                        content={"detail": "numeric parameter out of range"})
