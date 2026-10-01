"""Live check: a real WebSocket handshake with ?token= must not leak the
session token into the server log (cmd_serve log_config=None routes the
uvicorn.error handshake line through the redacting formatter)."""
from __future__ import annotations

import json
import os
import re
import sys
import time
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

BASE = "http://127.0.0.1:8787"

from spectra.api.security import SESSION_COOKIE  # noqa: E402

PASSWORD = os.environ["SPECTRA_ADMIN_PASSWORD"]


def login() -> str:
    req = urllib.request.Request(
        BASE + "/api/auth/login",
        data=json.dumps({"username": "admin",
                         "password": PASSWORD}).encode(),
        headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(req, timeout=10) as res:
        set_cookie = res.headers.get("Set-Cookie", "")
    match = re.search(rf"{re.escape(SESSION_COOKIE)}=([^;]+)", set_cookie)
    assert match, f"no session cookie in {set_cookie!r}"
    return match.group(1)


def main() -> None:
    token = login()
    from websockets.sync.client import connect  # stdlib-adjacent, installed

    for attempt in range(20):
        try:
            with connect(f"ws://127.0.0.1:8787/ws/events?token={token}",
                         open_timeout=3) as ws:
                ws.recv(timeout=5)
            break
        except OSError:
            time.sleep(0.5)          # server still booting
    else:
        raise SystemExit("could not open the websocket")
    print("WS_OPENED_AND_CLOSED")


if __name__ == "__main__":
    main()
