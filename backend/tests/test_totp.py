"""TOTP second factor (Phase 10 §6) - optional, per account, self-service.

Primitives are checked against published vectors (RFC 4226 Appendix D and
RFC 6238 Appendix B, re-derived with pyotp as an independent implementation
before being hard-coded here).  The service/API tests pin the security
properties the plan names: no account enumeration, a code is single-use,
wrong codes feed the login throttle, the shared secret is encrypted at rest,
and a locked-out account (lost key file / lost device) has a tested recovery
path that does not need the second factor.
"""

from __future__ import annotations

import base64
import json
import os
import secrets
import sqlite3
import stat

import pytest
from fastapi.testclient import TestClient

import spectra.services.auth as auth_mod
from spectra.api.app import app
from spectra.api.runtime import engine
from spectra.auth import totp as T
from spectra.cli import main as cli_main

RFC_SECRET = b"12345678901234567890"
HOTP_6 = ["755224", "287082", "359152", "969429", "338314",
          "254676", "287922", "162583", "399871", "520489"]
TOTP_8 = [(59, "94287082"), (1111111109, "07081804"), (1111111111, "14050471"),
          (1234567890, "89005924"), (2000000000, "69279037"), (20000000000, "65353130")]
NOW = 1_800_000_000.0                       # fixed clock: counter 60 000 000


# -- primitives -------------------------------------------------------------------------

def test_hotp_matches_rfc4226_appendix_d():
    assert [T.hotp(RFC_SECRET, c) for c in range(10)] == HOTP_6


@pytest.mark.parametrize("ts,expected", TOTP_8)
def test_totp_matches_rfc6238_appendix_b_sha1(ts, expected):
    assert T.hotp(RFC_SECRET, T.counter_at(ts), digits=8) == expected


def test_verify_window_replay_and_shape():
    secret = RFC_SECRET
    c = T.counter_at(NOW)
    now_code = T.hotp(secret, c)
    assert T.verify(secret, now_code, NOW, last_counter=-1) == c
    assert T.verify(secret, T.hotp(secret, c - 1), NOW, last_counter=-1) == c - 1   # one step late
    assert T.verify(secret, T.hotp(secret, c + 1), NOW, last_counter=-1) == c + 1   # one step early
    assert T.verify(secret, T.hotp(secret, c - 2), NOW, last_counter=-1) is None    # too old
    assert T.verify(secret, T.hotp(secret, c + 2), NOW, last_counter=-1) is None    # too new
    assert T.verify(secret, now_code, NOW, last_counter=c) is None                  # replay
    assert T.verify(secret, T.hotp(secret, c - 1), NOW, last_counter=c) is None     # older than last use
    for bad in ("", "12345", "1234567", "12345a", "١٢٣٤٥٦", None, " "):
        assert T.verify(secret, bad, NOW, last_counter=-1) is None
    assert T.verify(secret, f" {now_code[:3]} {now_code[3:]} ", NOW, last_counter=-1) == c   # spaces ok


def test_secret_and_uri_formats():
    s = T.new_secret()
    assert len(s) == 20 and s != T.new_secret()
    b32 = T.to_base32(s)
    assert T.from_base32(b32) == s and "=" not in b32 and b32 == b32.upper()
    uri = T.provisioning_uri(b32, "alice@example", "Spectra")
    assert uri == f"otpauth://totp/Spectra:alice%40example?secret={b32}&issuer=Spectra"
    # the reference format from pyotp for the same inputs
    assert T.provisioning_uri("JBSWY3DPEHPK3PXP", "alice", "Spectra") == \
        "otpauth://totp/Spectra:alice?secret=JBSWY3DPEHPK3PXP&issuer=Spectra"


def test_recovery_codes_are_unique_normalised_and_hashed():
    codes = T.new_recovery_codes(8)
    assert len(codes) == len(set(codes)) == 8
    for c in codes:
        assert len(c) == 14 and c.count("-") == 2          # xxxx-xxxx-xxxx
        assert T.normalize_recovery(c.upper()) == T.normalize_recovery(c) == c.replace("-", "")
    h = T.hash_recovery(codes[0])
    assert h == T.hash_recovery(codes[0].upper()) != T.hash_recovery(codes[1])
    assert codes[0].replace("-", "") not in h


# -- the vault: secrets encrypted at rest -----------------------------------------------------

def test_vault_round_trip_aad_binding_tamper_and_key_file(tmp_path):
    key_path = tmp_path / "totp.key"
    vault = T.TotpVault(str(key_path))
    assert not key_path.exists()                          # no key until something is encrypted
    blob = vault.encrypt(RFC_SECRET, user_id=7)
    assert key_path.exists() and stat.S_IMODE(os.stat(key_path).st_mode) == 0o600
    assert RFC_SECRET not in blob.encode() and base64.b32encode(RFC_SECRET).decode() not in blob
    assert vault.decrypt(blob, user_id=7) == RFC_SECRET
    assert blob != vault.encrypt(RFC_SECRET, user_id=7)   # fresh nonce each time
    with pytest.raises(T.TotpVaultError):
        vault.decrypt(blob, user_id=8)                    # bound to the account
    raw = base64.b64decode(blob.split(":", 1)[1])
    flipped = blob.split(":", 1)[0] + ":" + base64.b64encode(raw[:-1] + bytes([raw[-1] ^ 1])).decode()
    with pytest.raises(T.TotpVaultError):
        vault.decrypt(flipped, user_id=7)
    with pytest.raises(T.TotpVaultError):
        vault.decrypt("garbage", user_id=7)
    key_path.unlink()
    with pytest.raises(T.TotpVaultError):
        T.TotpVault(str(key_path)).decrypt(blob, user_id=7)   # lost key: undecryptable, no new key invented
    assert not key_path.exists()


# -- service / API ------------------------------------------------------------------------------

PW = "correct-horse-battery-1"


@pytest.fixture(autouse=True)
def _fixed_clock(monkeypatch):
    monkeypatch.setattr(auth_mod, "_totp_now", lambda: NOW)
    engine.auth.throttle.reset()
    yield
    engine.auth.throttle.reset()


@pytest.fixture
def admin():
    c = TestClient(app, client=("203.0.113.200", 50000))   # carries the admin session
    return c


_ip_counter = iter(range(1, 250))


def _mk_user(admin, role="ANALYST"):
    name = f"totp_{secrets.token_hex(4)}"
    res = admin.post("/api/users", json={"username": name, "password": PW, "role": role})
    assert res.status_code == 200, res.text
    return name, res.json()["id"]


def _anon():
    c = TestClient(app, client=(f"198.51.100.{next(_ip_counter)}", 50000))
    c.cookies.clear()
    return c


def _login(c, name, pw=PW, code=None):
    body = {"username": name, "password": pw}
    if code is not None:
        body["totp_code"] = code
    return c.post("/api/auth/login", json=body)


def _enrol(name):
    """Log in, set up, confirm; returns (session client, secret bytes, recovery codes)."""
    c = _anon()
    assert _login(c, name).status_code == 200
    setup = c.post("/api/auth/totp/setup", json={"password": PW})
    assert setup.status_code == 200, setup.text
    secret = T.from_base32(setup.json()["secret"])
    code = T.hotp(secret, T.counter_at(NOW))
    enable = c.post("/api/auth/totp/enable", json={"code": code})
    assert enable.status_code == 200, enable.text
    return c, secret, enable.json()["recovery_codes"]


def _code(secret, offset=0):
    return T.hotp(secret, T.counter_at(NOW) + offset)


def test_setup_needs_the_password_and_never_echoes_it(admin):
    name, _ = _mk_user(admin)
    c = _anon()
    assert _login(c, name).status_code == 200
    assert c.post("/api/auth/totp/setup", json={"password": "wrong-password-1"}).status_code == 401
    assert _anon().post("/api/auth/totp/setup", json={"password": PW}).status_code == 401   # no session
    ok = c.post("/api/auth/totp/setup", json={"password": PW})
    assert ok.status_code == 200
    body = ok.json()
    assert set(body) == {"secret", "otpauth_uri", "issuer"} and PW not in ok.text
    assert body["otpauth_uri"].startswith("otpauth://totp/Spectra:") and body["secret"] in body["otpauth_uri"]
    assert c.get("/api/auth/me").json()["user"]["totp_enabled"] is False        # pending is not enabled


def test_enable_requires_a_valid_code_and_returns_recovery_codes_once(admin):
    name, _ = _mk_user(admin)
    c = _anon()
    _login(c, name)
    secret = T.from_base32(c.post("/api/auth/totp/setup", json={"password": PW}).json()["secret"])
    assert c.post("/api/auth/totp/enable", json={"code": "000000"}).status_code == 401
    assert c.post("/api/auth/totp/enable", json={"code": _code(secret, 5)}).status_code == 401
    good = c.post("/api/auth/totp/enable", json={"code": _code(secret)})
    assert good.status_code == 200
    codes = good.json()["recovery_codes"]
    assert len(codes) == 8 and len(set(codes)) == 8
    assert c.get("/api/auth/me").json()["user"]["totp_enabled"] is True
    # already enabled: setup is refused rather than silently replacing the secret
    assert c.post("/api/auth/totp/setup", json={"password": PW}).status_code == 409
    assert c.post("/api/auth/totp/enable", json={"code": _code(secret)}).status_code in (401, 409)


def test_login_with_totp_requires_a_valid_single_use_code(admin):
    name, _ = _mk_user(admin)
    _, secret, _codes = _enrol(name)                 # enrolment consumed the code at offset 0
    assert _login(_anon(), name, code=_code(secret, 0)).status_code == 401   # already used
    assert _login(_anon(), name, code=_code(secret, 1)).status_code == 200   # next step is fine
    assert _login(_anon(), name, code=_code(secret, 1)).status_code == 401   # replay of a used code
    assert _login(_anon(), name, code=_code(secret, 0)).status_code == 401   # older than the last used
    assert _login(_anon(), name).status_code == 401                          # no code at all
    assert _login(_anon(), name, code="abcdef").status_code == 401


def test_no_oracle_for_missing_or_wrong_second_factor(admin):
    name, _ = _mk_user(admin)
    _, secret, _ = _enrol(name)
    plain, _ = _mk_user(admin)
    answers = {
        "wrong password": _login(_anon(), name, pw="not-the-password-1"),
        "right password, no code": _login(_anon(), name),
        "right password, wrong code": _login(_anon(), name, code="000000"),
        "unknown user": _login(_anon(), "no-such-user-" + secrets.token_hex(3), code="000000"),
        "wrong password, plain account": _login(_anon(), plain, pw="not-the-password-1"),
    }
    shapes = {(r.status_code, r.json()["detail"]) for r in answers.values()}
    assert shapes == {(401, auth_mod.INVALID_CREDENTIALS)}, answers
    # an account without TOTP is unaffected by an unneeded code
    assert _login(_anon(), plain).status_code == 200


def test_wrong_codes_feed_the_login_throttle(admin, monkeypatch):
    monkeypatch.setattr(engine.auth, "throttle", auth_mod.LoginThrottle(limit=3, ip_limit=100, window=60.0))
    name, _ = _mk_user(admin)
    _, secret, _ = _enrol(name)
    attacker = _anon()
    codes = [_login(attacker, name, code=f"{i:06d}").status_code for i in range(4)]
    assert codes == [401, 401, 401, 429]
    assert _login(attacker, name, code=_code(secret, 1)).status_code == 429   # even the right code, while blocked


def test_recovery_codes_work_once_each(admin):
    name, _ = _mk_user(admin)
    _, secret, codes = _enrol(name)
    assert _login(_anon(), name, code=codes[0]).status_code == 200
    assert _login(_anon(), name, code=codes[0]).status_code == 401           # spent
    assert _login(_anon(), name, code=codes[1].upper()).status_code == 200    # case-insensitive
    assert _login(_anon(), name, code="aaaa-bbbb-cccc").status_code == 401   # a code that was never issued


def test_secret_is_encrypted_at_rest_and_absent_from_every_other_response(admin):
    name, uid = _mk_user(admin)
    c = _anon()
    _login(c, name)
    setup = c.post("/api/auth/totp/setup", json={"password": PW}).json()
    secret_b32 = setup["secret"]
    conn = sqlite3.connect(engine.store.path)
    try:
        rows = conn.execute("SELECT secret_enc FROM user_totp WHERE user_id = ?", (uid,)).fetchall()
        dump = b"".join(chunk.encode() for chunk in conn.iterdump())
    finally:
        conn.close()
    assert rows and secret_b32 not in rows[0][0] and secret_b32.encode() not in dump
    assert T.from_base32(secret_b32) not in dump
    for path in ("/api/auth/me", f"/api/users/{uid}", "/api/users"):
        assert secret_b32 not in admin.get(path).text and secret_b32 not in c.get(path).text
    kinds = engine.audit_service.entries(limit=50, kind="auth.totp_enabled")["items"]
    assert secret_b32 not in json.dumps(kinds)


def test_disable_needs_password_and_a_code_and_audits(admin):
    name, uid = _mk_user(admin)
    c, secret, codes = _enrol(name)
    assert c.post("/api/auth/totp/disable", json={"password": "wrong-password-1", "code": _code(secret, 1)}).status_code == 401
    assert c.post("/api/auth/totp/disable", json={"password": PW, "code": "000000"}).status_code == 401
    assert c.post("/api/auth/totp/disable", json={"password": PW, "code": codes[0]}).status_code == 200   # a recovery code will do
    assert c.get("/api/auth/me").json()["user"]["totp_enabled"] is False
    assert _login(_anon(), name).status_code == 200                          # back to password-only
    ev = [e for e in engine.audit_service.entries(limit=100)["items"] if e["kind"] == "auth.totp_disabled"]
    assert ev and ev[0]["actor"] == name and ev[0]["payload"]["username"] == name
    assert engine.audit_service.verify()["ok"] is True


def test_admin_reset_is_admin_only_and_restores_password_login(admin, viewer_client, analyst_client):
    name, uid = _mk_user(admin)
    _enrol(name)
    for rc in (viewer_client, analyst_client):
        assert rc.delete(f"/api/users/{uid}/totp").status_code == 403
    assert _login(_anon(), name).status_code == 401                          # still protected
    res = admin.delete(f"/api/users/{uid}/totp")
    assert res.status_code == 200 and res.json()["totp_enabled"] is False
    assert _login(_anon(), name).status_code == 200
    assert admin.delete("/api/users/999999/totp").status_code == 404
    ev = [e for e in engine.audit_service.entries(limit=100)["items"] if e["kind"] == "auth.totp_reset"]
    assert ev and ev[0]["payload"]["username"] == name


def test_lost_key_file_locks_out_the_totp_user_and_the_cli_recovers_them(admin, capsys):
    """The 'only admin cannot be locked out forever' requirement, end to end."""
    name, uid = _mk_user(admin)
    _, secret, _ = _enrol(name)
    key_path = engine.auth.config.totp_key_path
    saved = open(key_path, "rb").read()
    os.unlink(key_path)                                                      # the key file is lost
    try:
        assert _login(_anon(), name, code=_code(secret, 1)).status_code == 401   # undecryptable -> generic 401
        assert not os.path.exists(key_path)                                      # and no replacement key invented
        assert cli_main(["auth", "totp-reset", name]) == 0
        assert "reset" in capsys.readouterr().out
        assert _login(_anon(), name).status_code == 200                      # recovered, password only
        assert cli_main(["auth", "totp-reset", "no-such-user-xyz"]) != 0
    finally:
        with open(key_path, "wb") as fh:
            fh.write(saved)
        os.chmod(key_path, 0o600)


def test_upgrade_from_v12_database_with_existing_users(tmp_path):
    from spectra.store import Store
    store = Store(str(tmp_path / "up.db"))
    uid = store.create_user("legacy_user", "scrypt$x", "ADMIN")["id"]
    store._db.execute("DROP TABLE user_recovery_codes")
    store._db.execute("DROP TABLE user_totp")
    store._db.execute("DELETE FROM schema_migrations WHERE version = 13")
    store._db.commit()
    store.close()
    reopened = Store(str(tmp_path / "up.db"))
    assert reopened.schema_version >= 13
    assert reopened.find_user_credentials("legacy_user")["id"] == uid     # users survive
    assert reopened.totp_get(uid) is None                                  # no TOTP rows yet
    reopened.close()


def test_a_code_cannot_be_used_twice_even_by_concurrent_requests(admin):
    """Two logins that both read the row before either wrote must not both succeed."""
    name, uid = _mk_user(admin)
    _, secret, _ = _enrol(name)
    stale = dict(engine.store.totp_get(uid))              # what both requests read
    code = _code(secret, 1)
    assert engine.auth._accept_code(uid, stale, code) is True
    assert engine.auth._accept_code(uid, stale, code) is False      # same stale snapshot, same code
    assert engine.store.totp_advance(uid, T.counter_at(NOW) + 1) is False
    assert engine.store.totp_advance(uid, T.counter_at(NOW) + 2) is True


def test_a_recovery_code_cannot_be_spent_twice_concurrently(admin):
    name, uid = _mk_user(admin)
    _, _, codes = _enrol(name)
    row = dict(engine.store.totp_get(uid))
    assert engine.auth._accept_code(uid, row, codes[0]) is True
    assert engine.auth._accept_code(uid, row, codes[0]) is False
    assert engine.store.totp_unused_recovery(uid) == 7
