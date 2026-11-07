"""Serve the built dashboard from the API process (Phase 11 packaging).

``spectra serve`` is then one process on one origin: the REST API, the event
WebSocket and the React app.  Registered *last* so every real route wins, and
deliberately small - this is the only code that maps a URL to a file on disk,
so the rules are strict:

* only ``GET`` (a catch-all ``GET`` route; other methods get 405);
* ``api/`` and ``ws/`` paths are never answered with HTML (a mistyped API call
  must be a JSON 404, not a 200 page);
* every candidate is resolved and must stay inside the web root - symlinks that
  point out of it, ``..`` segments, backslashes, NUL bytes and dotfiles are all
  a 404;
* an unknown path *with a file extension* is a 404 (never HTML posing as a
  script); an unknown extension-less path is a client-side route and gets the
  index (single-page-app fallback);
* no directory listings.
"""

from __future__ import annotations

import logging
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse

log = logging.getLogger("spectra.api")

#: The dashboard loads only same-origin script/style/images and talks to the
#: same origin (REST + WebSocket); nothing may frame it or load plugins.
#: ``style-src 'unsafe-inline'`` is there for the charts' inline style
#: attributes; scripts stay strictly ``'self'`` (no inline, no eval).
CONTENT_SECURITY_POLICY = (
    "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
    "img-src 'self' data:; font-src 'self'; connect-src 'self'; object-src 'none'; "
    "base-uri 'self'; frame-ancestors 'none'; form-action 'self'"
)

_SECURITY_HEADERS = {
    "Content-Security-Policy": CONTENT_SECURITY_POLICY,
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    # ZAP baseline 2026-11-07: the dashboard needs none of these browser features and shares nothing cross-origin.
    "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=(), usb=(), interest-cohort=()",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
}
_IMMUTABLE = "public, max-age=31536000, immutable"   # Vite emits content-hashed asset names
_REVALIDATE = "no-cache"


def _inside(path: Path, base: Path) -> bool:
    try:
        path.relative_to(base)
        return True
    except ValueError:
        return False


def mount_webui(app: FastAPI, root: str) -> bool:
    """Register the dashboard routes for the build in ``root``; False if there is none."""
    if not root:
        return False
    try:
        base = Path(root).resolve(strict=True)
        index = (base / "index.html").resolve(strict=True)
    except (OSError, RuntimeError):
        return False
    if not base.is_dir() or not index.is_file() or not _inside(index, base):
        return False

    def reply(path: Path, cache: str) -> FileResponse:
        return FileResponse(path, headers={"Cache-Control": cache, **_SECURITY_HEADERS})

    @app.get("/{path:path}", include_in_schema=False)
    def serve_dashboard(path: str) -> FileResponse:
        first = path.split("/", 1)[0]
        if first in ("api", "ws"):
            raise HTTPException(status_code=404)
        if "\x00" in path or "\\" in path:
            raise HTTPException(status_code=404)
        parts = [p for p in path.split("/") if p != ""]
        if any(p.startswith(".") for p in parts):          # '..', dotfiles, .git, .env
            raise HTTPException(status_code=404)
        if not parts:
            return reply(index, _REVALIDATE)
        try:
            candidate = (base.joinpath(*parts)).resolve()
        except (OSError, RuntimeError, ValueError):
            raise HTTPException(status_code=404) from None
        if not _inside(candidate, base):                    # symlink or traversal out of the root
            raise HTTPException(status_code=404)
        if candidate.is_file():
            return reply(candidate, _IMMUTABLE if parts[0] == "assets" else _REVALIDATE)
        if "." in parts[-1]:                                # a missing file, not a page
            raise HTTPException(status_code=404)
        return reply(index, _REVALIDATE)                    # client-side route

    log.info("dashboard served from %s", base)
    return True
