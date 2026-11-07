"""Serving the built dashboard from the API process (Phase 11 packaging).

``spectra.api.webui.mount_webui`` is exercised on a fresh FastAPI app so the
tests control the directory.  The properties that matter: nothing outside the
web root is ever readable, API/WebSocket paths are never answered with HTML,
a missing asset is a 404 (not an HTML page pretending to be JavaScript), and
responses carry the security headers a browser-facing page needs.
"""

from __future__ import annotations

import os

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from spectra.api.webui import mount_webui

INDEX = "<!doctype html><html><body><div id=root></div><script type=module src=/assets/app.abc123.js></script></body></html>"
JS = "console.log('app');"
SECRET = "TOP-SECRET-OUTSIDE-THE-WEB-ROOT"


@pytest.fixture
def site(tmp_path):
    outer = tmp_path / "outer"
    root = outer / "webui"
    (root / "assets").mkdir(parents=True)
    (root / "index.html").write_text(INDEX)
    (root / "assets" / "app.abc123.js").write_text(JS)
    (root / "assets" / "style.def456.css").write_text("body{color:#000}")
    (root / "favicon.svg").write_text("<svg xmlns='http://www.w3.org/2000/svg'/>")
    (root / ".hidden").write_text("dotfile")
    (outer / "secret.txt").write_text(SECRET)
    (root / "escape").symlink_to(outer)                    # a symlink out of the root
    app = FastAPI()

    @app.get("/api/ping")
    def ping():
        return {"ok": True}

    assert mount_webui(app, str(root)) is True
    return TestClient(app), root


def test_index_and_security_headers(site):
    client, _ = site
    res = client.get("/")
    assert res.status_code == 200 and res.text == INDEX
    assert res.headers["content-type"].startswith("text/html")
    assert res.headers["cache-control"] == "no-cache"
    assert res.headers["x-content-type-options"] == "nosniff"
    assert res.headers["x-frame-options"] == "DENY"
    assert res.headers["referrer-policy"] == "no-referrer"
    assert "camera=()" in res.headers["permissions-policy"] and "microphone=()" in res.headers["permissions-policy"]
    assert res.headers["cross-origin-opener-policy"] == "same-origin"
    assert res.headers["cross-origin-resource-policy"] == "same-origin"
    csp = res.headers["content-security-policy"]
    for part in ("default-src 'self'", "frame-ancestors 'none'", "object-src 'none'",
                 "base-uri 'self'", "connect-src 'self'"):
        assert part in csp, csp
    assert "unsafe-eval" not in csp and "script-src 'unsafe-inline'" not in csp


def test_hashed_assets_are_cacheable_forever_with_the_right_type(site):
    client, _ = site
    js = client.get("/assets/app.abc123.js")
    assert js.status_code == 200 and js.text == JS
    assert js.headers["cache-control"] == "public, max-age=31536000, immutable"
    assert "javascript" in js.headers["content-type"]
    assert client.get("/assets/style.def456.css").headers["content-type"].startswith("text/css")
    assert js.headers["x-content-type-options"] == "nosniff"
    fav = client.get("/favicon.svg")
    assert fav.status_code == 200 and fav.headers["cache-control"] == "no-cache"


@pytest.mark.parametrize("path", ["/network", "/incidents/42", "/some/deep/client/route", "/assets"])
def test_client_side_routes_fall_back_to_the_index(site, path):
    client, _ = site
    res = client.get(path)
    assert res.status_code == 200 and res.text == INDEX


def test_api_and_websocket_paths_are_never_answered_with_html(site):
    client, _ = site
    assert client.get("/api/ping").json() == {"ok": True}          # real routes win
    for path in ("/api/does-not-exist", "/api/", "/ws/events", "/ws/anything"):
        res = client.get(path)
        assert res.status_code == 404, path
        assert "<html" not in res.text.lower()
        assert res.headers["content-type"].startswith("application/json")


def test_a_missing_file_is_a_404_not_html_posing_as_the_asset(site):
    client, _ = site
    for path in ("/assets/missing.js", "/missing.css", "/robots.txt", "/x.png"):
        res = client.get(path)
        assert res.status_code == 404, path
        assert INDEX not in res.text


@pytest.mark.parametrize("path", [
    "/..%2f..%2fsecret.txt", "/%2e%2e/%2e%2e/secret.txt", "/assets/../../secret.txt",
    "/assets/%2e%2e/%2e%2e/secret.txt", "//secret.txt", "/..\\..\\secret.txt",
    "/%2e%2e%5csecret.txt", "/assets/..%252f..%252fsecret.txt", "/escape/secret.txt",
    "/assets/app.abc123.js%00.txt", "/%ff%fe",
])
def test_nothing_outside_the_web_root_is_readable(site, path):
    client, _ = site
    res = client.get(path)
    assert SECRET not in res.text, path
    assert res.status_code in (200, 404), (path, res.status_code)
    if res.status_code == 200:
        assert res.text == INDEX            # the SPA fallback, never a file


def test_dotfiles_and_directory_listings_are_not_served(site):
    client, _ = site
    assert client.get("/.hidden").status_code == 404
    assert client.get("/.git/config").status_code == 404
    res = client.get("/assets/")
    assert "app.abc123.js" not in res.text.replace(INDEX, "")      # no listing


def test_only_get_is_accepted_on_static_paths(site):
    client, _ = site
    assert client.post("/", content=b"x").status_code == 405
    assert client.put("/assets/app.abc123.js", content=b"x").status_code == 405
    assert client.delete("/network").status_code == 405


def test_without_a_build_nothing_is_mounted(tmp_path):
    app = FastAPI()
    assert mount_webui(app, str(tmp_path / "nope")) is False
    empty = tmp_path / "empty"
    empty.mkdir()
    assert mount_webui(app, str(empty)) is False                   # no index.html
    assert mount_webui(app, "") is False
    assert TestClient(app).get("/").status_code == 404


def test_symlinked_index_outside_the_root_is_refused(tmp_path):
    outer = tmp_path / "o"
    root = outer / "w"
    root.mkdir(parents=True)
    (outer / "real.html").write_text(SECRET)
    (root / "index.html").symlink_to(outer / "real.html")
    app = FastAPI()
    assert mount_webui(app, str(root)) is False
    assert os.path.islink(root / "index.html")
