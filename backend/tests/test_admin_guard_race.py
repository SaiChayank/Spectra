"""The last-ADMIN guard must hold even when two requests race.

The guard used to read the ADMIN count, then write in a separate statement.
Two admins demoting (or deleting) each other at the same moment could both
read "2 admins", both pass, and leave the database with no ADMIN at all.
These tests replay that interleaving deterministically: the count read is
pinned to the value both racers saw *before* either wrote.
"""

from __future__ import annotations

import pytest

from spectra.services.auth import AuthService, UserGuardError
from spectra.store import Store


@pytest.fixture
def two_admins(tmp_path):
    store = Store(str(tmp_path / "guard.db"))
    svc = AuthService(store)
    a = svc.create_user("admin_a", "admin-a-pass-123", "ADMIN")
    b = svc.create_user("admin_b", "admin-b-pass-123", "ADMIN")
    # Both racers read the count before either write lands.
    store.count_admin_users = lambda: 2
    yield svc, store, a["id"], b["id"]
    store.close()


def _admins(store: Store) -> int:
    return sum(1 for u in store.list_users() if u["role"] == "ADMIN")


def test_racing_demotions_keep_one_admin(two_admins):
    svc, store, a, b = two_admins
    svc.update_user(a, role="VIEWER")
    with pytest.raises(UserGuardError, match="last ADMIN"):
        svc.update_user(b, role="VIEWER")
    assert _admins(store) == 1


def test_racing_deletions_keep_one_admin(two_admins):
    svc, store, a, b = two_admins
    svc.delete_user(a)
    with pytest.raises(UserGuardError, match="last ADMIN"):
        svc.delete_user(b)
    assert _admins(store) == 1


def test_demote_and_delete_race_keeps_one_admin(two_admins):
    svc, store, a, b = two_admins
    svc.update_user(a, role="ANALYST")
    with pytest.raises(UserGuardError, match="last ADMIN"):
        svc.delete_user(b)
    assert _admins(store) == 1


def test_guard_does_not_block_ordinary_changes(two_admins):
    svc, store, a, b = two_admins
    viewer = svc.create_user("plain_viewer", "viewer-pass-123", "VIEWER")
    assert svc.update_user(viewer["id"], role="ANALYST")["role"] == "ANALYST"
    svc.delete_user(viewer["id"])
    assert svc.update_user(a, password="new-admin-pass-456")["role"] == "ADMIN"
    assert _admins(store) == 2
