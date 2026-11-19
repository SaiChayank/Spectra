"""Request correlation + structured access logging for the HTTP layer.

``RequestIdMiddleware`` is registered outermost (after CORS, so
``add_middleware``'s prepend ordering wraps both CORS and the auth gate):

* an inbound ``X-Request-ID`` is honoured when it is a short safe token,
  otherwise one is generated - either way it is bound to the request
  context (:data:`spectra.observability.REQUEST_ID`), echoed on the
  response (exposed through CORS), and stamped onto every log record the
  request produces;
* each completed request logs one JSON line (``event="http_request"``)
  with method, **path only** (never the query string, so a ``?token=``
  WebSocket handshake URL cannot leak into logs), status and duration.

WebSocket scopes pass through untouched - BaseHTTPMiddleware only sees
``http`` requests, and the socket's own open/close lines are logged by
the bridge in ``spectra.api.app``.
"""

from __future__ import annotations

import json
import logging
import re
import time
import uuid

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

from ..observability import REQUEST_ID, current_request_id

log = logging.getLogger("spectra.api")

#: Client-supplied ids must look like a token, not arbitrary text.
_SAFE_ID = re.compile(r"^[A-Za-z0-9._-]{1,64}$")


class RequestIdMiddleware(BaseHTTPMiddleware):
    """Assign, propagate and log the per-request correlation id."""

    async def dispatch(self, request: Request, call_next) -> Response:
        incoming = request.headers.get("x-request-id", "")
        request_id = incoming if _SAFE_ID.match(incoming) \
            else uuid.uuid4().hex[:16]
        token = REQUEST_ID.set(request_id)
        started = time.perf_counter()
        status = 500
        try:
            response = await call_next(request)
            status = response.status_code
        except BaseException:
            self._log(request, status, started, request_id, failed=True)
            raise
        finally:
            REQUEST_ID.reset(token)
        response.headers["X-Request-ID"] = request_id
        if request.url.path.startswith("/api/"):
            # API bodies are data, never rendered: a browser must not sniff a
            # JSON or text body into HTML (Cache-Control stays per route)
            response.headers["X-Content-Type-Options"] = "nosniff"
        self._log(request, status, started, request_id, failed=False)
        return response

    @staticmethod
    def _log(request: Request, status: int, started: float,
             request_id: str, *, failed: bool) -> None:
        duration_ms = round((time.perf_counter() - started) * 1000.0, 2)
        # Path only: the query string can carry a session token.
        fields = {
            "event": "http_request",
            "method": request.method,
            "path": request.url.path,
            "status": 500 if failed else status,
            "duration_ms": duration_ms,
            "request_id": request_id,
        }
        if failed or fields["status"] >= 500:
            log.error("http request failed", extra=fields)
        elif fields["status"] >= 400:
            log.warning("http request", extra=fields)
        else:
            log.info("http request", extra=fields)


class UnhandledErrorMiddleware:
    """Last-resort handler: an exception no route or handler mapped becomes a
    fixed JSON 500 that names the request id, and the full traceback goes to
    the server log under that id.

    Registered inside CORS (so the dashboard can read the 500 instead of
    reporting the server as unreachable) and inside :class:`RequestIdMiddleware`
    (so the id is bound and echoed). Without it Starlette answered a plain-text
    ``Internal Server Error`` with neither. Nothing from the exception reaches
    the client.
    """

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        started = False

        async def tracking_send(message):
            nonlocal started
            if message["type"] == "http.response.start":
                started = True
            await send(message)

        try:
            await self.app(scope, receive, tracking_send)
        except Exception:
            request_id = current_request_id()
            log.error("unhandled error", exc_info=True, extra={
                "event": "unhandled_error", "path": scope.get("path", ""),
                "request_id": request_id})
            if started:  # headers already sent: nothing safe left to answer
                raise
            body = json.dumps({"detail": "internal server error",
                               "request_id": request_id}).encode()
            await send({"type": "http.response.start", "status": 500, "headers": [
                (b"content-type", b"application/json"),
                (b"content-length", str(len(body)).encode("ascii"))]})
            await send({"type": "http.response.body", "body": body})
