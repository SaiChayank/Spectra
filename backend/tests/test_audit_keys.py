"""Phase 9F: audit signing-key epochs, a swappable key provider, rotation.

The hash chain is unkeyed; the signing key signs *checkpoints* (and
certificates).  Rotation registers a new key epoch whose validity window is a
range of chain sequence numbers, bound to an ``audit.key_rotated`` entry in
the chain.  A checkpoint is valid only if its epoch's key signed it AND its
covered range falls inside that epoch's window - so a stolen *current* key
cannot forge checkpoints over old entries, and a stolen *old* key cannot sign
anything after the rotation.  What rotation cannot do: an old key stolen
before it was rotated can still forge old-range checkpoints.
"""

from __future__ import annotations

import os
import stat
import time


from spectra.config import Config
from spectra.modules.audit import AuditLog, build_certificate, verify_certificate
from spectra.modules.audit.curve import schnorr_keypair, schnorr_sign
from spectra.modules.audit.keys import FileKeyProvider
from spectra.modules.audit.merkle import canonical_json
from spectra.store import Store


def _store(tmp_path, name="s"):
    return Store(str(tmp_path / f"{name}.db"))


def _log(tmp_path, name="s"):
    store = _store(tmp_path, name)
    return AuditLog(store=store), store


def _fill(log, n=3):
    for i in range(n):
        log.append("event", {"i": i})


# -- the provider seam ------------------------------------------------------------

def test_file_provider_signs_rotates_and_keeps_the_key_private(tmp_path):
    path = tmp_path / "k.key"
    p = FileKeyProvider(str(path))
    pub1 = p.public_key()
    sig = p.sign(b"m")
    from spectra.modules.audit.curve import schnorr_verify
    assert schnorr_verify(pub1, b"m", sig)
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600

    pub2 = p.rotate()
    assert pub2 != pub1 and p.public_key() == pub2
    assert not schnorr_verify(pub1, b"m", p.sign(b"m"))      # old key no longer signs
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
    assert FileKeyProvider(str(path)).public_key() == pub2    # rotation persisted
    assert not any(f.name.endswith((".tmp", ".next")) for f in tmp_path.iterdir())

    eph = FileKeyProvider(None)                               # ephemeral, no file
    assert eph.public_key() != eph.rotate()


class _FakeKms:
    """A non-file provider: the secret never exists in Spectra's process."""
    def __init__(self):
        self._secret, self._pub = schnorr_keypair()
        self.calls = []

    def public_key(self):
        return self._pub

    def sign(self, msg: bytes) -> str:
        self.calls.append("sign")
        return schnorr_sign(self._secret, msg)

    def rotate(self) -> str:
        self.calls.append("rotate")
        self._secret, self._pub = schnorr_keypair()
        return self._pub


def test_provider_swap_is_one_class(tmp_path):
    kms = _FakeKms()
    log = AuditLog(store=_store(tmp_path), provider=kms)
    _fill(log)
    ck = log.checkpoint()
    assert ck["pubkey"] == kms.public_key() and "sign" in kms.calls
    assert log.verify_checkpoint(ck)["ok"]
    log.rotate_key(actor="admin")
    assert "rotate" in kms.calls
    _fill(log, 1)
    ck2 = log.checkpoint()
    assert log.verify_checkpoint(ck)["ok"] and log.verify_checkpoint(ck2)["ok"]
    assert not hasattr(log, "secret")                          # log never holds the secret


# -- epochs -------------------------------------------------------------------------

def test_first_epoch_is_registered_once(tmp_path):
    log, store = _log(tmp_path)
    eps = log.epochs()
    assert [(e["epoch"], e["start_seq"]) for e in eps] == [(1, 0)]
    assert eps[0]["pubkey"] == log.pubkey
    assert log.current_epoch() == 1
    again = AuditLog(store=store)                              # same key file
    assert [e["epoch"] for e in again.epochs()] == [1]
    assert again.head()["seq"] == 0                            # no entry for epoch 1


def test_verification_passes_across_a_rotation(tmp_path):
    log, store = _log(tmp_path)
    _fill(log, 3)
    ck1 = log.checkpoint()
    old_pub = log.pubkey
    res = log.rotate_key(actor="alice")
    assert res["epoch"] == 2 and res["pubkey"] == log.pubkey != old_pub
    rot = log.get(res["entry_seq"])
    assert rot["kind"] == "audit.key_rotated" and rot["actor"] == "alice"
    assert rot["payload"]["pubkey"] == log.pubkey and res["start_seq"] == rot["seq"]
    _fill(log, 2)
    ck2 = log.checkpoint()

    assert ck1["epoch"] == 1 and ck2["epoch"] == 2
    assert ck1["pubkey"] == old_pub and ck2["pubkey"] == log.pubkey
    for ck in (ck1, ck2):
        rep = log.verify_checkpoint(ck)
        assert rep["ok"], rep
    assert log.verify_checkpoint(seq=ck1["seq"])["ok"]         # log-sourced (no signature)
    chain = log.verify()
    assert chain["ok"] and chain["epoch"] == 2
    assert [e["epoch"] for e in chain["epochs"]] == [1, 2]
    assert all("secret" not in e for e in chain["epochs"])
    # a restarted process sees the same history
    assert [e["pubkey"] for e in AuditLog(store=store).epochs()] == [old_pub, log.pubkey]


def _forged(log, secret_hex, epoch, covered_from, covered_to, drop_epoch=False):
    """A checkpoint someone with ``secret_hex`` builds for a range of their choosing."""
    body = {"covered_from": covered_from, "covered_to": covered_to, "entries": covered_to - covered_from + 1,
            "root": "0" * 64}
    if not drop_epoch:
        body["epoch"] = epoch
    from spectra.modules.audit.curve import compress, pt_mul, G
    pub = compress(pt_mul(int(secret_hex, 16), G))
    return {**body, "seq": 99, "pubkey": pub,
            "signature": schnorr_sign(secret_hex, canonical_json(body).encode())}


def _failed(report):
    return {c["name"] for c in report["checks"] if not c["ok"]}


def test_old_entry_forgery_with_the_current_key_fails(tmp_path):
    key_path = tmp_path / "audit_signing.key"
    log, store = _log(tmp_path)
    _fill(log, 5)
    log.checkpoint()
    old_secret = key_path.read_text().strip()
    log.rotate_key(actor="admin")
    cur_secret = key_path.read_text().strip()
    assert cur_secret != old_secret
    _fill(log, 2)

    # (a) current key, claims the current epoch, but covers entries from before it began
    a = log.verify_checkpoint(_forged(log, cur_secret, 2, 1, 5))
    assert not a["ok"] and "epoch_window" in _failed(a)
    # (b) current key, claims the old epoch: wrong key for that epoch
    b = log.verify_checkpoint(_forged(log, cur_secret, 1, 1, 5))
    assert not b["ok"] and "signature" in _failed(b)
    # (c) OLD key (stolen earlier) signing after the rotation: outside its window
    c = log.verify_checkpoint(_forged(log, old_secret, 1, 6, log.head()["seq"]))
    assert not c["ok"] and "epoch_window" in _failed(c)
    # (d) epoch label stripped to look like a legacy checkpoint: epoch 1 key mismatch
    d = log.verify_checkpoint(_forged(log, cur_secret, 1, 1, 5, drop_epoch=True))
    assert not d["ok"]
    # (e) relabelling a genuine checkpoint's epoch breaks the signed message
    genuine = log.checkpoint()
    relabelled = {**genuine, "epoch": 1}
    assert not log.verify_checkpoint(relabelled)["ok"]
    assert log.verify_checkpoint(genuine)["ok"]


def test_legacy_checkpoint_without_epoch_still_verifies(tmp_path):
    log, _ = _log(tmp_path)
    _fill(log, 3)
    secret = (tmp_path / "audit_signing.key").read_text().strip()
    body = {"covered_from": 1, "covered_to": 3, "entries": 3}
    from spectra.modules.audit.merkle import merkle_root
    body["root"] = merkle_root([e["entry_hash"] for e in sorted(log.all_entries(), key=lambda e: e["seq"])][:3])
    legacy = {**body, "seq": 4, "pubkey": log.pubkey,
              "signature": schnorr_sign(secret, canonical_json(body).encode())}
    assert log.verify_checkpoint(legacy)["ok"]                 # treated as epoch 1


def test_a_key_replaced_outside_rotate_is_registered_loudly(tmp_path):
    log, store = _log(tmp_path)
    _fill(log, 2)
    ck = log.checkpoint()
    (tmp_path / "audit_signing.key").unlink()                  # key file lost
    revived = AuditLog(store=store)
    assert revived.pubkey != log.pubkey
    assert revived.current_epoch() == 2
    rot = [e for e in revived.entries(limit=10) if e["kind"] == "audit.key_rotated"]
    assert len(rot) == 1 and "outside" in rot[0]["payload"]["reason"]
    assert revived.verify()["ok"] and revived.verify_checkpoint(ck)["ok"]


def test_a_rotation_that_crashed_before_registration_is_recovered(tmp_path):
    log, store = _log(tmp_path)
    _fill(log, 2)
    log.provider.rotate()                                      # key replaced, epoch never recorded
    revived = AuditLog(store=store)
    assert revived.current_epoch() == 2 and revived.verify()["ok"]


def test_verify_catches_a_rogue_or_edited_epoch_row(tmp_path):
    log, store = _log(tmp_path)
    _fill(log, 3)
    log.rotate_key(actor="admin")
    assert log.verify()["ok"]
    # an epoch row that is not backed by a key_rotated entry in the chain
    store.audit_epoch_add(3, "02" + "ab" * 32, log.head()["seq"] + 1, time.time())
    rep = log.verify()
    assert not rep["ok"] and any("epoch 3" in e["reason"] for e in rep["errors"])

    log2, store2 = _log(tmp_path, "t")
    _fill(log2, 3)
    log2.rotate_key(actor="admin")
    store2._conn.execute("UPDATE audit_key_epochs SET pubkey = ? WHERE epoch = 2",
                         ("02" + "cd" * 32,))
    store2._conn.commit()
    assert not log2.verify()["ok"]


def test_in_memory_log_has_epochs_too():
    log = AuditLog()
    log.append("event", {"i": 1})
    ck = log.checkpoint()
    log.rotate_key(actor="admin")
    log.append("event", {"i": 2})
    ck2 = log.checkpoint()
    assert log.verify()["ok"] and log.verify_checkpoint(ck)["ok"]
    assert log.verify_checkpoint(ck2)["ok"] and ck2["epoch"] == 2


# -- certificates ---------------------------------------------------------------------

def test_certificates_survive_a_rotation_but_not_an_unknown_key(tmp_path):
    from tests.test_audit import _seed_store
    store = _seed_store(tmp_path, flows=12)
    log = AuditLog(store=store)
    _fill(log, 2)
    old = build_certificate(store, log, profile="hipaa", min_flows=5, disclose=1, bits=16)
    assert verify_certificate(old, log=log)["ok"]
    log.rotate_key(actor="admin")
    assert verify_certificate(old, log=log)["ok"]             # signed in epoch 1, head in epoch 1
    new = build_certificate(store, log, profile="hipaa", min_flows=5, disclose=1, bits=16)
    assert verify_certificate(new, log=log)["ok"]

    secret, pub = schnorr_keypair()                            # a key the log never had
    bundle = {k: v for k, v in new.items() if k not in ("signature", "pubkey")}
    bundle["issuer"] = {**bundle["issuer"], "pubkey": pub}
    forged = {**bundle, "pubkey": pub,
              "signature": schnorr_sign(secret, canonical_json(bundle).encode())}
    assert not verify_certificate(forged, log=log)["ok"]


# -- schema -----------------------------------------------------------------------------

def test_upgrade_from_v11_with_audit_data(tmp_path):
    log, store = _log(tmp_path, "up")
    _fill(log, 4)
    before = [e["entry_hash"] for e in sorted(log.all_entries(), key=lambda e: e["seq"])]
    pub = log.pubkey
    store._conn.execute("DROP TABLE audit_key_epochs")        # what a v11 database looks like
    store._conn.execute("DELETE FROM schema_migrations WHERE version = 12")
    store._conn.commit()
    store.close()

    reopened = Store(str(tmp_path / "up.db"))
    assert reopened.schema_version == 12
    upgraded = AuditLog(store=reopened)
    assert [e["entry_hash"] for e in sorted(upgraded.all_entries(), key=lambda e: e["seq"])] == before
    assert upgraded.verify()["ok"] and upgraded.pubkey == pub
    assert [(e["epoch"], e["start_seq"]) for e in upgraded.epochs()] == [(1, 0)]


# -- API -------------------------------------------------------------------------------

def test_api_rotate_key_is_admin_only_and_never_returns_a_secret(client, viewer_client,
                                                                analyst_client):
    for rc in (viewer_client, analyst_client):
        assert rc.post("/api/audit/rotate-key").status_code == 403
    before = client.get("/api/audit/verify").json()
    res = client.post("/api/audit/rotate-key")
    assert res.status_code == 200, res.text
    body = res.json()
    assert set(body) == {"epoch", "pubkey", "start_seq", "entry_seq", "previous_pubkey"}
    assert body["epoch"] == before["epoch"] + 1 and body["pubkey"] != body["previous_pubkey"]

    after = client.get("/api/audit/verify").json()
    assert after["ok"] is True and after["signing_key"] == body["pubkey"]
    assert after["epochs"][-1]["pubkey"] == body["pubkey"]

    ck = client.post("/api/audit/checkpoint").json()
    assert ck["epoch"] == body["epoch"]
    assert client.get("/api/audit/checkpoint/verify").json()["ok"] is True

    entries = client.get("/api/audit/entries?kind=audit.key_rotated").json()["items"]
    assert entries and entries[0]["actor"] == "admin"
    secret = (os.path.join(Config.from_env().data_dir, "audit_signing.key"))
    if os.path.isfile(secret):
        text = open(secret).read().strip()
        assert text not in res.text and text not in client.get("/api/audit/entries").text
