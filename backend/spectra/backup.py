"""Backup and restore of a Spectra instance (Phase 11).

``create_backup`` writes one ``.tar.gz``: a consistent snapshot of the SQLite database
(taken with SQLite's online-backup API, so it is safe while the server is writing), the
model artifacts, and a ``manifest.json`` that lists every member with its SHA-256 and
records row counts and the schema version.  What is *left out* by default is deliberate:

* **private keys** (audit signing key, TOTP encryption key, TEE attestation key) - ask for
  them with ``include_keys``; without them a restore is still safe by design: a missing audit
  key starts a new key epoch (old checkpoints keep verifying from the public keys in the
  database) and users with a second factor are reset by an admin;
* **uploaded captures** - large and payload-bearing; ``include_captures`` adds them;
* the bootstrap password file and anything else not named below.

``restore_backup`` verifies the archive *before* it touches anything, refuses a backup from
a newer Spectra, a database that is in use and a populated target (without ``force``), stages
and checks the restored database (integrity + audit hash chain), and **moves** whatever it
replaces into ``pre-restore-<time>/`` - it never deletes.  The first start afterwards records
the restore in the audit chain.
"""

from __future__ import annotations

import hashlib
import io
import json
import os
import shutil
import sqlite3
import stat
import tarfile
import tempfile
import time
from contextlib import closing
from datetime import datetime, timezone

from . import __version__
from .config import Config
from .db.migrations import MIGRATIONS

MANIFEST = "manifest.json"
MANIFEST_VERSION = 1
PENDING_MARKER = "restore_pending.json"
_MAX_MANIFEST = 4 * 1024 * 1024
_COUNTED_TABLES = ("flows", "audit_log", "alerts", "incidents", "captures", "users",
                   "model_registry", "audit_key_epochs", "model_runs", "events")
_KEY_FILES = ("audit_signing.key", "totp.key", "tee_attestation.key")


class BackupError(RuntimeError):
    """Anything that makes a backup or restore refuse to proceed (message is user-safe)."""


# -- paths -----------------------------------------------------------------------------------

def _key_paths(config: Config) -> dict[str, str]:
    return {
        "audit_signing.key": os.path.join(os.path.dirname(os.path.abspath(config.db_path)), "audit_signing.key"),
        "totp.key": config.totp_key_path,
        "tee_attestation.key": os.path.join(os.path.dirname(os.path.abspath(config.model_path)), "tee_attestation.key"),
    }


def _safe_leaf(name: str) -> bool:
    return bool(name) and name not in (".", "..") and "/" not in name and "\\" not in name and "\x00" not in name


def _target_for(arcname: str, config: Config) -> str:
    """Where an archive member goes on disk - derived from fixed rules, never from the archive's path."""
    head, _, leaf = arcname.partition("/")
    if arcname == "db/spectra.db":
        return config.db_path
    if not _safe_leaf(leaf):
        raise BackupError(f"unsafe or unknown member name in the archive: {arcname!r}")
    if head == "models":
        return os.path.join(os.path.dirname(os.path.abspath(config.model_path)), leaf)
    if head == "model_artifacts":
        return os.path.join(config.data_dir, "model_artifacts", leaf)
    if head == "captures":
        return os.path.join(config.capture_store_dir, leaf)
    if head == "keys" and leaf in _KEY_FILES:
        return _key_paths(config)[leaf]
    raise BackupError(f"unsafe or unknown member name in the archive: {arcname!r}")


def _sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


# -- create ------------------------------------------------------------------------------------

def _snapshot_database(src: str, dst: str) -> dict:
    """Consistent copy of a (possibly busy) database + integrity result, schema version, row counts."""
    if not os.path.isfile(src):
        raise BackupError("there is no database to back up")
    with closing(sqlite3.connect(src, timeout=30)) as s, closing(sqlite3.connect(dst)) as d:
        s.backup(d)
        d.execute("PRAGMA journal_mode=DELETE")            # one self-contained file, no -wal sidecar
    with closing(sqlite3.connect(dst)) as c:
        integrity = c.execute("PRAGMA integrity_check").fetchall()
        version = c.execute("SELECT COALESCE(MAX(version), 0) FROM schema_migrations").fetchone()[0]
        have = {r[0] for r in c.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}
        rows = {t: c.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0]  # noqa: S608 - fixed table names
                for t in _COUNTED_TABLES if t in have}
    return {"integrity": "ok" if integrity == [("ok",)] else "FAILED", "schema_version": int(version), "rows": rows}


def _plan(config: Config, include_keys: bool, include_captures: bool) -> list[tuple[str, str]]:
    plan: list[tuple[str, str]] = []
    stem = os.path.basename(os.path.splitext(config.model_path)[0])
    model_dir = os.path.dirname(os.path.abspath(config.model_path))
    if os.path.isdir(model_dir):
        for name in sorted(os.listdir(model_dir)):
            if name.startswith(stem) and name.endswith(".joblib"):
                plan.append((f"models/{name}", os.path.join(model_dir, name)))
    art = os.path.join(config.data_dir, "model_artifacts")
    if os.path.isdir(art):
        plan += [(f"model_artifacts/{n}", os.path.join(art, n)) for n in sorted(os.listdir(art))
                 if os.path.isfile(os.path.join(art, n))]
    if include_keys:
        plan += [(f"keys/{n}", p) for n, p in _key_paths(config).items() if os.path.isfile(p)]
    if include_captures and os.path.isdir(config.capture_store_dir):
        plan += [(f"captures/{n}", os.path.join(config.capture_store_dir, n))
                 for n in sorted(os.listdir(config.capture_store_dir))
                 if n.startswith("cap_") and os.path.isfile(os.path.join(config.capture_store_dir, n))]
    return plan


def create_backup(config: Config, out_path: str, *, include_keys: bool = False,
                  include_captures: bool = False) -> dict:
    """Write a verified archive to ``out_path`` (refuses to overwrite). Returns path, sha256, size, manifest."""
    out_path = os.path.abspath(out_path)
    if os.path.exists(out_path):
        raise BackupError(f"{os.path.basename(out_path)} already exists; refusing to overwrite a backup")
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="spectra-backup-") as tmp:
        snap = os.path.join(tmp, "spectra.db")
        info = _snapshot_database(config.db_path, snap)
        members = [("db/spectra.db", snap)] + _plan(config, include_keys, include_captures)
        files = [{"path": arc, "size": os.path.getsize(p), "sha256": _sha256(p)} for arc, p in members]
        manifest = {
            "manifest_version": MANIFEST_VERSION,
            "created_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "spectra_version": __version__,
            "schema_version": info["schema_version"],
            "includes": {"keys": include_keys, "captures": include_captures},
            "db": {"integrity": info["integrity"], "rows": info["rows"]},
            "files": files,
        }
        if info["integrity"] != "ok":
            raise BackupError("the live database failed its integrity check; not writing a backup of it")
        data = json.dumps(manifest, indent=2, sort_keys=True).encode()
        tmp_out = out_path + ".part"
        fd = os.open(tmp_out, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            with os.fdopen(fd, "wb") as raw, tarfile.open(fileobj=raw, mode="w:gz", format=tarfile.PAX_FORMAT) as tf:
                def add(name: str, size: int, fileobj) -> None:
                    ti = tarfile.TarInfo(name)
                    ti.size, ti.mode, ti.mtime = size, 0o600, int(time.time())
                    ti.uid = ti.gid = 0
                    ti.uname = ti.gname = ""
                    tf.addfile(ti, fileobj)
                add(MANIFEST, len(data), io.BytesIO(data))
                for arc, p in members:
                    with open(p, "rb") as fh:
                        add(arc, os.path.getsize(p), fh)
            os.replace(tmp_out, out_path)
        except BaseException:
            if os.path.exists(tmp_out):
                os.unlink(tmp_out)
            raise
    return {"path": out_path, "sha256": _sha256(out_path), "bytes": os.path.getsize(out_path), "manifest": manifest}


# -- verify ------------------------------------------------------------------------------------

def verify_backup(path: str) -> dict:
    """Check an archive against its own manifest. Never writes anything."""
    problems: list[str] = []
    manifest: dict = {}
    try:
        with tarfile.open(path) as tf:
            members = {m.name: m for m in tf.getmembers()}
            for m in members.values():
                if not (m.isfile() or m.isdir()):
                    problems.append(f"{m.name}: not a regular file (links and devices are refused)")
            if MANIFEST not in members or not members[MANIFEST].isfile():
                return {"ok": False, "problems": ["no manifest.json"], "manifest": {}}
            if members[MANIFEST].size > _MAX_MANIFEST:
                return {"ok": False, "problems": ["manifest.json is implausibly large"], "manifest": {}}
            try:
                manifest = json.loads(tf.extractfile(members[MANIFEST]).read())
                listed = {f["path"]: f for f in manifest["files"]}
            except (ValueError, KeyError, TypeError):
                return {"ok": False, "problems": ["manifest.json is not valid"], "manifest": {}}
            if manifest.get("manifest_version") != MANIFEST_VERSION:
                problems.append(f"unsupported manifest version {manifest.get('manifest_version')!r}")
            for name in sorted(set(members) - set(listed) - {MANIFEST}):
                if members[name].isfile() or not members[name].isdir():
                    problems.append(f"{name}: member is not listed in the manifest")
            for name, entry in sorted(listed.items()):
                if name not in members:
                    problems.append(f"{name}: missing from the archive")
                    continue
                try:
                    _target_for(name, Config(persist=False))        # name rules only
                except BackupError as exc:
                    problems.append(str(exc))
                    continue
                h, n = hashlib.sha256(), 0
                src = tf.extractfile(members[name])
                for chunk in iter(lambda s=src: s.read(1 << 20), b""):
                    h.update(chunk)
                    n += len(chunk)
                if n != entry.get("size"):
                    problems.append(f"{name}: size {n} does not match the manifest ({entry.get('size')})")
                if h.hexdigest() != entry.get("sha256"):
                    problems.append(f"{name}: sha256 does not match the manifest")
    except (tarfile.TarError, OSError, EOFError) as exc:
        return {"ok": False, "problems": [f"not a readable archive: {type(exc).__name__}"], "manifest": {}}
    return {"ok": not problems, "problems": problems, "manifest": manifest}


# -- restore -----------------------------------------------------------------------------------

class _ReadOnlyKey:
    """Stand-in key provider for verifying a restored audit chain without minting or touching a key."""

    def __init__(self, pubkey: str) -> None:
        self._pub = pubkey

    def public_key(self) -> str:
        return self._pub

    def sign(self, msg: bytes) -> str:             # pragma: no cover - verification never signs
        raise BackupError("verification must not sign")

    def rotate(self) -> str:                       # pragma: no cover
        raise BackupError("verification must not rotate keys")


def _check_staged_database(path: str) -> bool:
    """Open the staged database (applying migrations to the *staged copy*) and verify the audit chain."""
    from .modules.audit import AuditLog
    from .store import Store

    store = Store(path)
    try:
        epochs = store.audit_epochs()
        pub = epochs[-1]["pubkey"] if epochs else ""
        if not pub:
            return True                      # a database that never had an audit key has an empty chain
        return bool(AuditLog(store=store, provider=_ReadOnlyKey(pub)).verify()["ok"])
    finally:
        store.close()


def _database_in_use(path: str) -> bool:
    if not os.path.isfile(path):
        return False
    try:
        with closing(sqlite3.connect(path, timeout=0.2)) as c:
            c.execute("BEGIN EXCLUSIVE")
            c.rollback()
        return False
    except sqlite3.OperationalError:
        return True                  # locked/busy (or cannot be opened): refuse rather than guess
    except sqlite3.DatabaseError:
        return False                 # "file is not a database": damaged, so nothing is using it


def restore_backup(archive: str, config: Config, *, force: bool = False) -> dict:
    """Restore ``archive`` into ``config``'s locations. See the module docstring for the guarantees."""
    t0 = time.monotonic()
    report = verify_backup(archive)
    if not report["ok"]:
        raise BackupError("the archive failed verification: " + "; ".join(report["problems"][:3]))
    manifest = report["manifest"]
    latest = max(m.version for m in MIGRATIONS)
    if int(manifest["schema_version"]) > latest:
        raise BackupError(
            f"the backup has database schema v{manifest['schema_version']} but this Spectra knows up to "
            f"v{latest}: it is from a newer release - upgrade Spectra before restoring it")
    if manifest["db"].get("integrity") != "ok":
        raise BackupError("the backup records a failed database integrity check")
    targets = {f["path"]: _target_for(f["path"], config) for f in manifest["files"]}
    populated = os.path.exists(config.db_path)
    if populated and not force:
        raise BackupError("the target already holds a Spectra database; use --force to restore over it "
                          "(the existing files are moved aside, not deleted)")
    if _database_in_use(config.db_path):
        raise BackupError("the target database is in use: stop Spectra before restoring")

    os.makedirs(config.data_dir, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    staging = os.path.join(config.data_dir, f".restore-{stamp}-{os.getpid()}")
    os.makedirs(staging)
    aside: str | None = None
    try:
        with tarfile.open(archive) as tf:
            for f in manifest["files"]:
                dest = os.path.join(staging, *f["path"].split("/"))
                os.makedirs(os.path.dirname(dest), exist_ok=True)
                src = tf.extractfile(f["path"])
                fd = os.open(dest, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(fd, "wb") as out:
                    shutil.copyfileobj(src, out, 1 << 20)
        chain_ok = _check_staged_database(os.path.join(staging, "db", "spectra.db"))
        if not chain_ok:
            raise BackupError("the restored audit chain does not verify; nothing was changed")

        if populated:
            aside = os.path.join(config.data_dir, f"pre-restore-{stamp}")
            os.makedirs(aside)
            for arc, target in targets.items():
                for suffix in ("", "-wal", "-shm") if arc == "db/spectra.db" else ("",):
                    if os.path.exists(target + suffix):
                        dest = os.path.join(aside, *arc.split("/")) + suffix
                        os.makedirs(os.path.dirname(dest), exist_ok=True)
                        shutil.move(target + suffix, dest)
        else:
            for suffix in ("-wal", "-shm"):                     # a stray sidecar must not meet the new file
                if os.path.exists(config.db_path + suffix):
                    os.unlink(config.db_path + suffix)
        for arc, target in targets.items():
            os.makedirs(os.path.dirname(target), exist_ok=True)
            shutil.move(os.path.join(staging, *arc.split("/")), target)
            if arc.startswith("keys/") or arc.endswith(".joblib"):
                os.chmod(target, stat.S_IRUSR | stat.S_IWUSR)
    finally:
        shutil.rmtree(staging, ignore_errors=True)

    pending = {"archive_sha256": _sha256(archive), "backup_created_at": manifest["created_at"],
               "backup_spectra_version": manifest["spectra_version"],
               "restored_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
               "included_keys": bool(manifest["includes"]["keys"]),
               "included_captures": bool(manifest["includes"]["captures"]),
               "rows": manifest["db"]["rows"]}
    with open(os.path.join(config.data_dir, PENDING_MARKER), "w", encoding="utf-8") as fh:
        json.dump(pending, fh)
    return {"restored": sorted(targets), "pre_restore_dir": aside, "audit_chain_ok": True,
            "rows": manifest["db"]["rows"], "manifest": manifest,
            "elapsed_s": round(time.monotonic() - t0, 3)}


def consume_pending_restore(config: Config, audit) -> bool:
    """On engine start: record a just-completed restore in the audit chain, once."""
    marker = os.path.join(config.data_dir, PENDING_MARKER)
    if not os.path.isfile(marker):
        return False
    try:
        with open(marker, encoding="utf-8") as fh:
            payload = json.load(fh)
        entry = audit.append("backup.restore", payload, actor="restore")
        if entry is not None:
            os.unlink(marker)
            return True
    except (OSError, ValueError):
        pass
    return False
