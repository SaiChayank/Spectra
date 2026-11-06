"""Escalating login backoff (Phase 10 §6).

The pre-existing throttle was a fixed-rate limiter (N failures per window per
ip+username, plus a per-ip cap).  This adds escalation: each time a source
hits the limit its block doubles (window, 2x, 4x ... up to a cap), strikes
decay after a quiet period, and a success clears them.  Properties pinned:

* blocks are per source (ip+username) and time-limited, so an attacker can
  neither lock the admin out of other networks nor lock anyone out forever;
* decisions never depend on whether the username exists (no enumeration);
* memory stays bounded under key spraying.
"""

from __future__ import annotations

import os

import pytest
from fastapi.testclient import TestClient

from spectra.api.app import app
from spectra.api.runtime import engine
from spectra.services.auth import LoginThrottle


class Clock:
    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        return self.t

    def advance(self, s):
        self.t += s


def _fail(th, n, ip="198.51.100.7", user="admin"):
    for _ in range(n):
        th.record_failure(ip, user)


def _throttle(clock, **kw):
    kw = {"limit": 3, "ip_limit": 1000, "window": 60.0, "max_block": 600.0,
          "strike_ttl": 3600.0, **kw}
    return LoginThrottle(clock=clock, **kw)


def test_block_doubles_with_each_episode_up_to_the_cap():
    clock = Clock()
    th = _throttle(clock)
    assert th.retry_after("198.51.100.7", "admin") is None
    waits = []
    for _ in range(7):
        _fail(th, 3)
        wait = th.retry_after("198.51.100.7", "admin")
        waits.append(round(wait))
        clock.advance(wait + 1)                           # wait it out
        assert th.retry_after("198.51.100.7", "admin") is None
    assert waits == [60, 120, 240, 480, 600, 600, 600]    # doubled, then capped


def test_a_success_clears_the_escalation():
    clock = Clock()
    th = _throttle(clock)
    _fail(th, 3)
    clock.advance(th.retry_after("198.51.100.7", "admin") + 1)
    _fail(th, 2)
    th.record_success("198.51.100.7", "admin")
    _fail(th, 3)
    assert round(th.retry_after("198.51.100.7", "admin")) == 60     # back to the base block


def test_strikes_decay_after_a_quiet_period():
    clock = Clock()
    th = _throttle(clock)
    _fail(th, 3)
    clock.advance(th.retry_after("198.51.100.7", "admin") + 1)
    _fail(th, 3)                                          # second strike -> 120
    assert round(th.retry_after("198.51.100.7", "admin")) == 120
    clock.advance(3600 + 130)                             # quiet for longer than strike_ttl
    _fail(th, 3)
    assert round(th.retry_after("198.51.100.7", "admin")) == 60


def test_blocks_are_per_source_so_the_victim_is_not_locked_out():
    clock = Clock()
    th = _throttle(clock)
    _fail(th, 3, ip="198.51.100.7")                       # the attacker
    assert th.retry_after("198.51.100.7", "admin") is not None
    assert th.retry_after("203.0.113.9", "admin") is None  # the real admin elsewhere
    assert th.retry_after("198.51.100.7", "someone-else") is None


def test_no_state_can_outlive_the_cap_so_nobody_is_locked_out_permanently():
    clock = Clock()
    th = _throttle(clock)
    for _ in range(60):                                   # sustained attack
        _fail(th, 3)
        wait = th.retry_after("198.51.100.7", "admin")
        assert wait is not None and wait <= 600 + 1
        clock.advance(wait + 1)
    assert th.retry_after("198.51.100.7", "admin") is None
    th.reset()                                            # what a restart does
    assert th.retry_after("198.51.100.7", "admin") is None


def test_the_per_ip_cap_escalates_too():
    clock = Clock()
    th = _throttle(clock, limit=100, ip_limit=5)
    for i in range(5):
        th.record_failure("198.51.100.7", f"user{i}")     # a spray across usernames
    first = th.retry_after("198.51.100.7", "anyone")
    assert round(first) == 60
    clock.advance(first + 1)
    for i in range(5):
        th.record_failure("198.51.100.7", f"u{i}")
    assert round(th.retry_after("198.51.100.7", "anyone")) == 120


def test_key_spraying_keeps_memory_bounded():
    clock = Clock()
    th = _throttle(clock, limit=2, ip_limit=10**9)
    for i in range(30_000):
        th.record_failure("198.51.100.7", f"spray-{i}")
        th.record_failure("198.51.100.7", f"spray-{i}")   # reach the per-key limit -> a block
        if i % 500 == 0:
            clock.advance(1)
    assert len(th._pair.blocks) <= 10_000 and len(th._pair.events) <= 10_000


# -- through the API -----------------------------------------------------------------

ADMIN_PW = os.environ.get("SPECTRA_ADMIN_PASSWORD", "")


def _client(ip):
    return TestClient(app, client=(ip, 50000))


def _login(c, user, pw):
    return c.post("/api/auth/login", json={"username": user, "password": pw})


@pytest.fixture
def small_throttle(monkeypatch):
    clock = Clock()
    th = LoginThrottle(limit=2, ip_limit=1000, window=60.0, max_block=600.0, clock=clock)
    monkeypatch.setattr(engine.auth, "throttle", th)
    return th, clock


def test_api_blocks_the_guessing_source_but_not_the_admin_elsewhere(small_throttle):
    th, clock = small_throttle
    attacker = _client("198.51.100.7")
    codes = [_login(attacker, "admin", "wrong-password").status_code for _ in range(3)]
    assert codes == [401, 401, 429]
    blocked = _login(attacker, "admin", "wrong-password")
    assert blocked.status_code == 429 and int(blocked.headers["Retry-After"]) >= 1
    # even the correct password is refused while this source is blocked
    assert _login(attacker, "admin", ADMIN_PW).status_code == 429
    # the legitimate admin on another network is unaffected
    assert _login(_client("203.0.113.9"), "admin", ADMIN_PW).status_code == 200
    # and the attacker gets back in once the (escalated) block has elapsed
    clock.advance(int(blocked.headers["Retry-After"]) + 1)
    assert _login(attacker, "admin", ADMIN_PW).status_code == 200


def test_api_does_not_reveal_whether_a_username_exists(small_throttle):
    th, clock = small_throttle
    seen = {}
    for name, user in (("real", "admin"), ("ghost", "no-such-user-4f2a")):
        c = _client("198.51.100.20" if name == "real" else "198.51.100.21")
        rows = []
        for _ in range(4):
            r = _login(c, user, "wrong-password")
            rows.append((r.status_code, r.json().get("detail"),
                         r.headers.get("Retry-After")))
        seen[name] = rows
    assert [s for s, *_ in seen["real"]] == [s for s, *_ in seen["ghost"]] == [401, 401, 429, 429]
    assert [d for _, d, _ in seen["real"]] == [d for _, d, _ in seen["ghost"]]
    assert [h for _, _, h in seen["real"]][2:] == [h for _, _, h in seen["ghost"]][2:]
