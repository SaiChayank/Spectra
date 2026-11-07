"""Backup and restore (Phase 11).

The properties that matter in a disaster, each pinned here:

* a snapshot of a database that is open and being written to is consistent;
* the archive leaves private keys, captures and the bootstrap password out unless asked,
  and describes its own contents so corruption or tampering is detected before anything
  on disk is touched;
* a restore never deletes what it replaces (it moves it aside), refuses a database that is
  in use, a backup from a newer Spectra, and a damaged archive, and the restored audit chain
  verifies;
* key material is never printed.
"""

from __future__ import annotations

import io
import json
import os
import sqlite3
import stat
import tarfile
import time

import pytest

from spectra import backup as bk
from spectra.auth import totp
from spectra.config import Config
from spectra.demo import make_baseline_pcap, make_suspicious_pcap
from spectra.pipeline import SpectraEngine
from spectra.store import Store

PW = "correct-horse-battery-1"


def _cfg(root, name="a"):
    cfg = Config(persist=True)
    cfg.data_dir = str(root / name / "data")
    cfg.db_path = str(root / name / "data" / "spectra.db")
    cfg.capture_store_dir = str(root / name / "data" / "captures")
    cfg.model_path = str(root / name / "models" / "spectra_model.joblib")
    cfg.totp_key_path = str(root / name / "data" / "totp.key")
    cfg.ensure_dirs()
    return cfg


@pytest.fixture(scope="module")
def source(tmp_path_factory):
    """A used instance: trained model, a processed capture, an audit checkpoint, a TOTP user, an upload."""
    root = tmp_path_factory.mktemp("bk")
    cfg = _cfg(root)
    e = SpectraEngine(config=cfg)
    e.train_from_pcap(make_baseline_pcap(str(root / "b.pcap"), n_flows=50), contamination=0.05)
    e.start("pcap", path=make_suspicious_pcap(str(root / "s.pcap")))
    deadline = time.time() + 30
    while e.running and time.time() < deadline:
        time.sleep(0.05)
    e.audit_service.checkpoint()
    user = e.auth.create_user("alice", PW, "ANALYST")
    secret = totp.from_base32(e.auth.totp_begin("alice", PW)["secret"])
    e.auth.totp_confirm(user["id"], totp.hotp(secret, totp.counter_at(time.time())))
    with open(make_baseline_pcap(str(root / "up.pcap"), n_flows=6, seed=3), "rb") as fh:
        e.capture_resources.import_file("up.pcap", [fh.read()])
    e.store.flush()
    return e, cfg, root, secret


def _names(path):
    with tarfile.open(path) as tf:
        return sorted(m.name for m in tf.getmembers())


def _count(db, table):
    c = sqlite3.connect(db)
    try:
        return c.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]  # noqa: S608 - fixed names
    finally:
        c.close()


# -- create -----------------------------------------------------------------------------

def test_snapshot_of_a_live_database_is_consistent_and_described(source, tmp_path):
    e, cfg, _, _ = source
    out = str(tmp_path / "b.tar.gz")
    res = bk.create_backup(cfg, out)
    assert os.path.getsize(out) > 0 and stat.S_IMODE(os.stat(out).st_mode) == 0o600
    m = res["manifest"]
    assert m["manifest_version"] == 1 and m["schema_version"] == e.store.schema_version
    assert m["db"]["integrity"] == "ok"
    assert m["db"]["rows"]["audit_log"] == _count(cfg.db_path, "audit_log") > 0
    assert m["db"]["rows"]["flows"] == _count(cfg.db_path, "flows") > 0
    assert res["sha256"] and res["bytes"] == os.path.getsize(out)
    assert bk.verify_backup(out)["ok"] is True


def test_backup_while_the_database_is_being_written(source, tmp_path):
    e, cfg, _, _ = source
    import threading
    stop = threading.Event()

    def writer():
        while not stop.is_set():
            e.audit_service.append("event", {"noise": 1})
            time.sleep(0.002)

    t = threading.Thread(target=writer)
    t.start()
    try:
        out = str(tmp_path / "live.tar.gz")
        res = bk.create_backup(cfg, out)
    finally:
        stop.set()
        t.join()
    assert res["manifest"]["db"]["integrity"] == "ok"
    assert bk.verify_backup(out)["ok"] is True


def test_secrets_and_captures_are_left_out_by_default(source, tmp_path):
    _, cfg, _, _ = source
    out = str(tmp_path / "d.tar.gz")
    bk.create_backup(cfg, out)
    names = _names(out)
    assert "manifest.json" in names and "db/spectra.db" in names
    assert not [n for n in names if n.startswith("keys/") or n.startswith("captures/")]
    assert not [n for n in names if "bootstrap" in n or n.endswith(".key")]
    assert any(n.startswith("models/") for n in names) and any(n.startswith("model_artifacts/") for n in names)
    m = bk.verify_backup(out)["manifest"]
    assert m["includes"] == {"keys": False, "captures": False}


def test_keys_and_captures_only_when_asked_and_with_owner_only_modes(source, tmp_path, capsys):
    _, cfg, _, _ = source
    out = str(tmp_path / "full.tar.gz")
    res = bk.create_backup(cfg, out, include_keys=True, include_captures=True)
    names = _names(out)
    assert {"keys/audit_signing.key", "keys/totp.key", "keys/tee_attestation.key"} <= set(names)
    assert any(n.startswith("captures/cap_") for n in names)
    assert res["manifest"]["includes"] == {"keys": True, "captures": True}
    with tarfile.open(out) as tf:
        assert all(stat.S_IMODE(m.mode) == 0o600 for m in tf.getmembers() if m.isfile())
        assert all(m.uname == "" and m.uid == 0 for m in tf.getmembers())      # no local user names leak
    assert "BEGIN" not in capsys.readouterr().out


def test_will_not_overwrite_an_existing_archive(source, tmp_path):
    _, cfg, _, _ = source
    out = tmp_path / "x.tar.gz"
    out.write_bytes(b"precious")
    with pytest.raises(bk.BackupError, match="exists"):
        bk.create_backup(cfg, str(out))
    assert out.read_bytes() == b"precious"


# -- verify ----------------------------------------------------------------------------------

def _rewrite(src, dst, mutate):
    """Copy an archive member by member, letting ``mutate(name, data) -> (name, data) | None``."""
    with tarfile.open(src) as tin, tarfile.open(dst, "w:gz") as tout:
        for m in tin.getmembers():
            data = tin.extractfile(m).read()
            res = mutate(m.name, data)
            if res is None:
                continue
            info = tarfile.TarInfo(res[0])
            info.size, info.mode = len(res[1]), 0o600
            tout.addfile(info, io.BytesIO(res[1]))
        return tout


def test_verify_detects_tampering_missing_and_extra_members(source, tmp_path):
    _, cfg, _, _ = source
    good = str(tmp_path / "g.tar.gz")
    bk.create_backup(cfg, good)

    flipped = str(tmp_path / "flip.tar.gz")
    _rewrite(good, flipped, lambda n, d: (n, d[:-1] + bytes([d[-1] ^ 1])) if n == "db/spectra.db" else (n, d))
    rep = bk.verify_backup(flipped)
    assert not rep["ok"] and any("sha256" in p and "db/spectra.db" in p for p in rep["problems"])

    missing = str(tmp_path / "miss.tar.gz")
    _rewrite(good, missing, lambda n, d: None if n.startswith("models/") else (n, d))
    assert any("missing" in p for p in bk.verify_backup(missing)["problems"])

    extra = str(tmp_path / "extra.tar.gz")
    with tarfile.open(good) as tin, tarfile.open(extra, "w:gz") as tout:
        for m in tin.getmembers():
            tout.addfile(m, tin.extractfile(m))
        info = tarfile.TarInfo("keys/evil.key")
        info.size = 4
        tout.addfile(info, io.BytesIO(b"evil"))
    assert any("not listed" in p for p in bk.verify_backup(extra)["problems"])


@pytest.mark.parametrize("evil", ["../escape.txt", "/etc/passwd", "db/../../x", "db/sub/x", "weird/x"])
def test_verify_and_restore_refuse_dangerous_member_names(source, tmp_path, evil):
    _, cfg, _, _ = source
    good = str(tmp_path / "g.tar.gz")
    bk.create_backup(cfg, good)
    bad = str(tmp_path / "bad.tar.gz")
    with tarfile.open(good) as tin, tarfile.open(bad, "w:gz") as tout:
        for m in tin.getmembers():
            tout.addfile(m, tin.extractfile(m))
        info = tarfile.TarInfo(evil)
        info.size = 1
        tout.addfile(info, io.BytesIO(b"x"))
    assert not bk.verify_backup(bad)["ok"]
    with pytest.raises(bk.BackupError):
        bk.restore_backup(bad, _cfg(tmp_path, "t"))
    assert not (tmp_path / "escape.txt").exists()


def test_symlink_members_are_refused(source, tmp_path):
    _, cfg, _, _ = source
    good = str(tmp_path / "g.tar.gz")
    bk.create_backup(cfg, good)
    bad = str(tmp_path / "sym.tar.gz")
    with tarfile.open(good) as tin, tarfile.open(bad, "w:gz") as tout:
        for m in tin.getmembers():
            tout.addfile(m, tin.extractfile(m))
        link = tarfile.TarInfo("models/link")
        link.type, link.linkname = tarfile.SYMTYPE, "/etc/passwd"
        tout.addfile(link)
    assert not bk.verify_backup(bad)["ok"]


def test_a_garbage_file_is_not_an_archive(tmp_path):
    junk = tmp_path / "junk.tar.gz"
    junk.write_bytes(b"not a tarball")
    rep = bk.verify_backup(str(junk))
    assert rep["ok"] is False and rep["problems"]


# -- restore -----------------------------------------------------------------------------------

def test_restore_into_an_empty_directory_reproduces_the_instance(source, tmp_path):
    e, cfg, root, secret = source
    out = str(tmp_path / "r.tar.gz")
    snap = bk.create_backup(cfg, out, include_keys=True)
    target = _cfg(tmp_path, "restored")
    res = bk.restore_backup(out, target)
    assert res["audit_chain_ok"] is True and res["pre_restore_dir"] is None
    assert res["elapsed_s"] >= 0
    for table in ("flows", "audit_log", "users", "captures", "model_registry"):
        assert _count(target.db_path, table) == snap["manifest"]["db"]["rows"][table], table

    r = SpectraEngine(config=target)
    try:
        assert r.audit_service.verify()["ok"] is True
        assert r.model.detector.is_trained
        sample = [0.0] * 39
        assert float(e.model.detector.score(__import__("numpy").array([sample]))[0]) == \
            float(r.model.detector.score(__import__("numpy").array([sample]))[0])
        # the TOTP user still needs, and accepts, their second factor (key restored with --include-keys)
        for code, ok in (("000000", False), (totp.hotp(secret, totp.counter_at(time.time()) + 1), True)):
            try:
                r.auth.login("alice", PW, code)
                assert ok
            except Exception:  # noqa: BLE001
                assert not ok
        assert stat.S_IMODE(os.stat(target.totp_key_path).st_mode) == 0o600
    finally:
        r.store.close()


def test_restore_refuses_a_populated_target_and_force_moves_it_aside(source, tmp_path):
    _, cfg, _, _ = source
    out = str(tmp_path / "r.tar.gz")
    bk.create_backup(cfg, out)
    target = _cfg(tmp_path, "pop")
    s = Store(target.db_path)
    s.save_flow({"proto": "TCP", "src": "10.0.0.1:1", "dst": "10.0.0.2:2", "start_ts": 1.0, "last_ts": 1.0,
                 "duration": 1.0, "packets": 1, "bytes": 1}, score=1.0, anomaly=False)
    s.close()
    marker = open(target.db_path, "rb").read()
    with pytest.raises(bk.BackupError, match="--force"):
        bk.restore_backup(out, target)
    assert open(target.db_path, "rb").read() == marker                 # untouched

    res = bk.restore_backup(out, target, force=True)
    aside = res["pre_restore_dir"]
    assert aside and os.path.isfile(os.path.join(aside, "db", "spectra.db"))      # never deleted
    assert open(os.path.join(aside, "db", "spectra.db"), "rb").read() == marker
    assert not os.path.exists(target.db_path + "-wal")
    assert _count(target.db_path, "audit_log") > 0


def test_restore_refuses_a_database_that_is_in_use(source, tmp_path):
    _, cfg, _, _ = source
    out = str(tmp_path / "r.tar.gz")
    bk.create_backup(cfg, out)
    target = _cfg(tmp_path, "busy")
    Store(target.db_path).close()
    holder = sqlite3.connect(target.db_path, timeout=0)
    holder.execute("BEGIN EXCLUSIVE")
    try:
        with pytest.raises(bk.BackupError, match="in use"):
            bk.restore_backup(out, target, force=True)
    finally:
        holder.rollback()
        holder.close()


def test_restore_refuses_a_backup_from_a_newer_spectra(source, tmp_path):
    _, cfg, _, _ = source
    out = str(tmp_path / "r.tar.gz")
    bk.create_backup(cfg, out)

    def bump(name, data):
        if name == "manifest.json":
            m = json.loads(data)
            m["schema_version"] = 999
            return name, json.dumps(m).encode()
        return name, data

    newer = str(tmp_path / "newer.tar.gz")
    _rewrite(out, newer, bump)
    target = _cfg(tmp_path, "new")
    with pytest.raises(bk.BackupError, match="newer"):
        bk.restore_backup(newer, target)
    assert not os.path.exists(target.db_path)


def test_a_damaged_archive_never_touches_the_target(source, tmp_path):
    _, cfg, _, _ = source
    out = str(tmp_path / "r.tar.gz")
    bk.create_backup(cfg, out)
    bad = str(tmp_path / "bad.tar.gz")
    _rewrite(out, bad, lambda n, d: (n, d[:-1] + bytes([d[-1] ^ 1])) if n == "db/spectra.db" else (n, d))
    target = _cfg(tmp_path, "safe")
    Store(target.db_path).close()
    before = open(target.db_path, "rb").read()
    with pytest.raises(bk.BackupError, match="sha256"):
        bk.restore_backup(bad, target, force=True)
    assert open(target.db_path, "rb").read() == before
    assert not [p for p in os.listdir(target.data_dir) if p.startswith(".restore")]     # staging cleaned


def test_a_backup_from_an_older_schema_restores_and_migrates(source, tmp_path):
    _, cfg, _, _ = source
    out = str(tmp_path / "r.tar.gz")
    bk.create_backup(cfg, out)
    # rebuild the archive's database as a v12 one (no TOTP tables), exactly what an older release wrote
    work = tmp_path / "old.db"
    with tarfile.open(out) as tf:
        work.write_bytes(tf.extractfile("db/spectra.db").read())
    c = sqlite3.connect(work)
    c.execute("DROP TABLE user_recovery_codes")
    c.execute("DROP TABLE user_totp")
    c.execute("DELETE FROM schema_migrations WHERE version = 13")
    c.commit()
    c.close()

    def swap(name, data):
        if name == "db/spectra.db":
            return name, work.read_bytes()
        if name == "manifest.json":
            m = json.loads(data)
            m["schema_version"] = 12
            for f in m["files"]:
                if f["path"] == "db/spectra.db":
                    import hashlib
                    f["sha256"], f["size"] = hashlib.sha256(work.read_bytes()).hexdigest(), work.stat().st_size
            return name, json.dumps(m).encode()
        return name, data

    old = str(tmp_path / "old.tar.gz")
    _rewrite(out, old, swap)
    target = _cfg(tmp_path, "mig")
    res = bk.restore_backup(old, target)
    assert res["audit_chain_ok"] is True
    s = Store(target.db_path)
    try:
        assert s.schema_version >= 13 and s.totp_get(1) is None
    finally:
        s.close()


def test_restore_without_keys_registers_a_new_audit_key_epoch_and_the_chain_still_verifies(source, tmp_path):
    _, cfg, _, _ = source
    out = str(tmp_path / "nokeys.tar.gz")
    bk.create_backup(cfg, out)                       # keys excluded (the default)
    target = _cfg(tmp_path, "nokeys")
    bk.restore_backup(out, target)
    assert not os.path.exists(os.path.join(os.path.dirname(target.db_path), "audit_signing.key"))
    r = SpectraEngine(config=target)
    try:
        v = r.audit_service.verify()
        assert v["ok"] is True and v["epoch"] >= 2             # a fresh key started a new epoch
        kinds = [x["kind"] for x in r.audit_service.entries(limit=500)["items"]]
        assert "audit.key_rotated" in kinds
        assert r.audit_service.verify_checkpoint()["ok"] is True      # old checkpoint still valid
    finally:
        r.store.close()


def test_the_first_start_after_a_restore_records_it_in_the_audit_chain(source, tmp_path):
    _, cfg, _, _ = source
    out = str(tmp_path / "r.tar.gz")
    snap = bk.create_backup(cfg, out)
    target = _cfg(tmp_path, "mark")
    bk.restore_backup(out, target)
    marker = os.path.join(target.data_dir, bk.PENDING_MARKER)
    assert os.path.isfile(marker)
    r = SpectraEngine(config=target)
    try:
        rows = [x for x in r.audit_service.entries(limit=500)["items"] if x["kind"] == "backup.restore"]
        assert len(rows) == 1
        p = rows[0]["payload"]
        assert p["archive_sha256"] == snap["sha256"] and p["backup_created_at"] == snap["manifest"]["created_at"]
        assert "key" not in json.dumps(p).lower() or "include" in json.dumps(p).lower()
        assert not os.path.exists(marker)                           # consumed
        assert r.audit_service.verify()["ok"] is True
    finally:
        r.store.close()
    r2 = SpectraEngine(config=target)                                # a second start adds nothing
    try:
        assert len([x for x in r2.audit_service.entries(limit=500)["items"] if x["kind"] == "backup.restore"]) == 1
    finally:
        r2.store.close()


# -- CLI --------------------------------------------------------------------------------------

def test_cli_create_verify_restore_round_trip(source, tmp_path, monkeypatch, capsys):
    from spectra import cli
    _, cfg, _, _ = source
    monkeypatch.setattr("spectra.config.get_config", lambda: cfg)
    out = str(tmp_path / "cli.tar.gz")
    assert cli.main(["backup", "create", "--out", out]) == 0
    assert "sha256" in capsys.readouterr().out
    assert cli.main(["backup", "verify", out]) == 0
    target = _cfg(tmp_path, "clirestore")
    monkeypatch.setattr("spectra.config.get_config", lambda: target)
    assert cli.main(["backup", "restore", out]) == 0
    assert cli.main(["backup", "restore", out]) == 1                      # populated now: refused without --force
    assert "--force" in capsys.readouterr().err
    assert cli.main(["backup", "verify", str(tmp_path / "nope.tar.gz")]) == 1


def test_restoring_over_a_corrupt_database_works_and_keeps_the_wreck_aside(source, tmp_path):
    """The disaster case: the live database is damaged. It is not 'in use'; it is moved aside, never deleted."""
    _, cfg, _, _ = source
    out = str(tmp_path / "r.tar.gz")
    snap = bk.create_backup(cfg, out)
    target = _cfg(tmp_path, "corrupt")
    with open(target.db_path, "wb") as fh:
        fh.write(b"this is not a sqlite database " * 200)
    wreck = open(target.db_path, "rb").read()
    res = bk.restore_backup(out, target, force=True)
    assert open(os.path.join(res["pre_restore_dir"], "db", "spectra.db"), "rb").read() == wreck
    assert _count(target.db_path, "audit_log") == snap["manifest"]["db"]["rows"]["audit_log"]


def test_committed_frames_in_a_leftover_wal_do_not_leak_into_the_restored_database(source, tmp_path):
    """A crash leaves ``spectra.db`` + ``spectra.db-wal`` with committed but un-checkpointed rows."""
    import shutil
    _, cfg, _, _ = source
    out = str(tmp_path / "r.tar.gz")
    snap = bk.create_backup(cfg, out)
    target = _cfg(tmp_path, "crashed")
    s = Store(target.db_path)
    for i in range(5):
        s.save_flow({"proto": "TCP", "src": f"10.9.9.{i}:1", "dst": "10.8.8.8:443", "start_ts": 1.0 + i,
                     "last_ts": 1.0 + i, "duration": 1.0, "packets": 1, "bytes": 1}, score=1.0, anomaly=False)
    s.flush()
    crash = tmp_path / "crash_state"
    crash.mkdir()
    shutil.copy(target.db_path, crash / "spectra.db")
    shutil.copy(target.db_path + "-wal", crash / "spectra.db-wal")        # copied while the writer is still open
    s.close()
    for name in ("spectra.db", "spectra.db-wal", "spectra.db-shm"):
        if os.path.exists(target.db_path.replace("spectra.db", name)):
            os.unlink(target.db_path.replace("spectra.db", name))
    shutil.copy(crash / "spectra.db", target.db_path)
    shutil.copy(crash / "spectra.db-wal", target.db_path + "-wal")
    res = bk.restore_backup(out, target, force=True)
    assert _count(target.db_path, "flows") == snap["manifest"]["db"]["rows"]["flows"]   # the backup's, not the crash's
    assert not os.path.exists(target.db_path + "-wal") and not os.path.exists(target.db_path + "-shm")
    aside = sqlite3.connect(os.path.join(res["pre_restore_dir"], "db", "spectra.db"))
    try:
        assert aside.execute("SELECT COUNT(*) FROM flows WHERE dst = '10.8.8.8:443'").fetchone()[0] == 5   # nothing lost
    finally:
        aside.close()
