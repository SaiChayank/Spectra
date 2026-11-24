"""Password changes must not race session handling.

The HTTP behaviour of ``POST /api/auth/password`` is pinned by
``test_change_password.py``; this module pins the storage-level guarantees
found missing in the backend review:

B-5: a login that verified the *old* password could still open a session
after an admin had reset the password and revoked every session (the session
insert did not check that the hash it verified was still current).
B-6: a password change and the session revocation it implies were two
separate commits, so a failure between them left a new password with every
old session still alive.
Two self-service changes racing each other could both "win" (the second
overwrote a hash it had never verified).
"""

from __future__ import annotations

import pytest

import spectra.services.auth as auth_mod
from spectra.auth.passwords import verify_password
from spectra.services.auth import AuthService, CredentialsError
from spectra.store import Store

PW = "old-password-123"
NEW_PW = "new-password-456"


@pytest.fixture
def svc(tmp_path):
    store = Store(str(tmp_path / "pw.db"))
    service = AuthService(store)
    yield service, store
    store.close()


def _hash_of(store: Store, username: str) -> str:
    return store.find_user_credentials(username)["password_hash"]


def _sessions_of(store: Store, user_id: int) -> int:
    return int(store._db.query(
        "SELECT COUNT(*) AS n FROM sessions WHERE user_id = ?", (user_id,))[0]["n"])


def _during_verify(monkeypatch, action):
    """Run ``action`` once, right after the first successful password check."""
    real = auth_mod.verify_password
    fired = []

    def verify(password, encoded):
        ok = real(password, encoded)
        if ok and not fired:
            fired.append(True)
            action()
        return ok

    monkeypatch.setattr(auth_mod, "verify_password", verify)


def test_login_racing_a_password_reset_opens_no_session(svc, monkeypatch):
    service, store = svc
    user = service.create_user("racer", PW, "ANALYST")
    # the admin resets the password while the attacker's login is mid-scrypt
    _during_verify(monkeypatch, lambda: service.update_user(user["id"], password=NEW_PW))
    with pytest.raises(CredentialsError):
        service.login("racer", PW)
    assert _sessions_of(store, user["id"]) == 0


def test_login_still_works_after_an_in_place_rehash(svc, monkeypatch):
    # the conditional session insert must compare against the hash login just wrote
    service, _ = svc
    user = service.create_user("rehash", PW, "VIEWER")
    monkeypatch.setattr(auth_mod, "password_needs_rehash", lambda encoded: True)
    _, token, _ = service.login("rehash", PW)
    assert service.validate(token)["user_id"] == user["id"]


def _fail_session_delete(store, monkeypatch):
    real = store._db.execute

    def failing(sql, params=()):
        if sql.lstrip().upper().startswith("DELETE FROM SESSIONS"):
            raise RuntimeError("disk went away")
        return real(sql, params)

    monkeypatch.setattr(store._db, "execute", failing)
    return real


def test_admin_reset_and_revocation_are_one_transaction(svc, monkeypatch):
    service, store = svc
    user = service.create_user("atomic", PW, "VIEWER")
    _, token, _ = service.login("atomic", PW)
    before = _hash_of(store, "atomic")
    real = _fail_session_delete(store, monkeypatch)
    with pytest.raises(RuntimeError):
        service.update_user(user["id"], password=NEW_PW)
    monkeypatch.setattr(store._db, "execute", real)
    # neither half landed: old password, old session
    assert _hash_of(store, "atomic") == before
    assert service.validate(token) is not None


def test_own_change_and_revocation_are_one_transaction(svc, monkeypatch):
    service, store = svc
    user = service.create_user("atomic2", PW, "VIEWER")
    _, token, _ = service.login("atomic2", PW)
    before = _hash_of(store, "atomic2")
    real = _fail_session_delete(store, monkeypatch)
    with pytest.raises(RuntimeError):
        service.change_own_password(user["id"], PW, NEW_PW)
    monkeypatch.setattr(store._db, "execute", real)
    assert _hash_of(store, "atomic2") == before
    assert service.validate(token) is not None


def test_own_change_revokes_every_session(svc):
    service, store = svc
    user = service.create_user("self", PW, "ANALYST")
    _, one, _ = service.login("self", PW)
    _, two, _ = service.login("self", PW)
    service.change_own_password(user["id"], PW, NEW_PW)
    assert service.validate(one) is None and service.validate(two) is None
    assert verify_password(NEW_PW, _hash_of(store, "self"))


def test_two_racing_self_changes_cannot_both_win(svc, monkeypatch):
    service, store = svc
    user = service.create_user("twice", PW, "VIEWER")
    # a second tab changes the password between this request's check and write
    _during_verify(
        monkeypatch,
        lambda: store.update_user(user["id"],
                                  password_hash=auth_mod.hash_password("tab-two-pw-789")))
    with pytest.raises(CredentialsError):
        service.change_own_password(user["id"], PW, NEW_PW)
    assert verify_password("tab-two-pw-789", _hash_of(store, "twice"))
