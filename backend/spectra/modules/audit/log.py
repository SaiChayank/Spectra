"""Module 5: hash-chained, append-only audit log with Merkle checkpoints.

Every entry commits to its predecessor (``entry_hash = sha256(canonical
entry including prev_hash)``), so any retro-edit breaks verification from that
point on. Entries can carry a set of leaves (one per processed flow record) so
the log doubles as a commitment the auditor can query with inclusion proofs.

Checkpoints Merkle-root the entry hashes covered since the previous checkpoint
and are Schnorr-signed with the log's key: a third party can verify "entries
1..N existed, unmodified, at checkpoint time" without the database.
"""

from __future__ import annotations

import hashlib
import json
import os
import threading
import time

from .curve import G, N as N_ORDER, compress, pt_mul
from .merkle import canonical_json, leaf_hash, merkle_proof, merkle_root, verify_merkle_proof
from .zkp import schnorr_keypair, schnorr_sign, schnorr_verify

GENESIS = "0" * 64
KEY_FILE = "audit_signing.key"
MAX_LEAVES = 5000  # per-entry cap: keeps rows bounded on long captures


class AuditError(RuntimeError):
    pass


def _entry_hash(entry: dict) -> str:
    body = canonical_json({
        "seq": entry["seq"],
        "ts": entry["ts"],
        "kind": entry["kind"],
        "actor": entry["actor"],
        "payload": entry["payload"],
        "leaves": entry.get("leaves"),
        "prev": entry["prev_hash"],
    })
    return hashlib.sha256(body.encode()).hexdigest()


class AuditLog:
    """Append-only log; persists through :class:`~spectra.store.Store` when
    available, otherwise keeps entries in memory (persistence-disabled mode)."""

    def __init__(self, store=None, key_path: str | None = None):
        self.store = store
        self._lock = threading.RLock()
        self._mem: list[dict] = []
        self.secret, self.pubkey = self._load_key(key_path)

    # -- signing key ---------------------------------------------------------

    def _default_key_path(self) -> str | None:
        if self.store is None:
            return None
        path = getattr(self.store, "path", None)
        if not path or path == ":memory:":
            return None
        return os.path.join(os.path.dirname(os.path.abspath(path)), KEY_FILE)

    def _load_key(self, key_path: str | None) -> tuple[str, str]:
        path = key_path if key_path is not None else self._default_key_path()
        if path and os.path.isfile(path):
            try:
                with open(path, "r", encoding="utf-8") as fh:
                    secret = fh.read().strip()
                if secret:
                    pub = self._pub_from_secret(secret)
                    return secret, pub
            except (OSError, ValueError):
                pass  # fall through to a fresh key
        secret, pub = schnorr_keypair()
        if path:
            try:
                os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
                with open(path, "w", encoding="utf-8") as fh:
                    fh.write(secret + "\n")
                try:
                    os.chmod(path, 0o600)
                except OSError:  # pragma: no cover - platform dependent
                    pass
            except OSError:  # pragma: no cover - read-only dirs: ephemeral key
                pass
        return secret, pub

    @staticmethod
    def _pub_from_secret(secret_hex: str) -> str:
        x = int(secret_hex, 16)
        if not (0 < x < N_ORDER):
            raise AuditError("stored signing key is out of range")
        return compress(pt_mul(x, G))

    def sign(self, msg: bytes) -> str:
        return schnorr_sign(self.secret, msg)

    def verify_signature(self, msg: bytes, sig: str) -> bool:
        return schnorr_verify(self.pubkey, msg, sig)

    # -- append --------------------------------------------------------------

    def append(self, kind: str, payload: dict | None = None, leaves=None,
               actor: str = "spectra") -> dict:
        """Append one entry; returns the stored entry (including its hash)."""
        items = list(leaves or [])
        if len(items) > MAX_LEAVES:
            items = items[:MAX_LEAVES]
        leaf_hashes = [leaf_hash(it) for it in items]
        root = merkle_root(leaf_hashes) if leaf_hashes else None

        with self._lock:
            entry = None
            for attempt in range(3):  # seq conflicts only across processes
                seq, prev = self._head_locked()
                candidate = {
                    "seq": seq + 1,
                    "ts": time.time(),
                    "kind": kind,
                    "actor": actor,
                    "payload": payload or {},
                    "merkle_root": root,
                    "leaves": leaf_hashes or None,
                    "prev_hash": prev,
                }
                candidate["entry_hash"] = _entry_hash(candidate)
                try:
                    self._store_insert(candidate)
                except Exception:  # noqa: BLE001 - retry on concurrent insert
                    if attempt == 2:
                        raise
                    time.sleep(0.01)
                    continue
                entry = candidate
                break
            if entry is None:  # pragma: no cover
                raise AuditError("failed to append audit entry")
            return entry

    def _store_insert(self, entry: dict) -> None:
        if self.store is None:
            dup = any(e["seq"] == entry["seq"] for e in self._mem)
            if dup:
                raise AuditError(f"sequence {entry['seq']} already used")
            self._mem.append(entry)
            return
        self.store.audit_insert(
            seq=entry["seq"],
            ts=entry["ts"],
            kind=entry["kind"],
            actor=entry["actor"],
            payload_json=canonical_json(entry["payload"]),
            leaves_json=canonical_json(entry["leaves"]) if entry["leaves"] else None,
            prev_hash=entry["prev_hash"],
            entry_hash=entry["entry_hash"],
        )

    def _head_locked(self) -> tuple[int, str]:
        if self.store is None:
            if not self._mem:
                return 0, GENESIS
            last = self._mem[-1]
            return last["seq"], last["entry_hash"]
        head = self.store.audit_head()
        if head is None:
            return 0, GENESIS
        return int(head["seq"]), head["entry_hash"]

    # -- reads ---------------------------------------------------------------

    @staticmethod
    def _hydrate(row: dict) -> dict:
        payload = row["payload"]
        if isinstance(payload, str):
            payload = json.loads(payload)
        leaves = row.get("leaves")
        if isinstance(leaves, str):
            leaves = json.loads(leaves)
        return {
            "seq": int(row["seq"]),
            "ts": row["ts"],
            "kind": row["kind"],
            "actor": row["actor"],
            "payload": payload,
            "leaves": leaves,
            "merkle_root": (leaves and merkle_root(leaves)) or None,
            "prev_hash": row["prev_hash"],
            "entry_hash": row["entry_hash"],
        }

    def count(self, kind: str | None = None, *, kind_prefix: str | None = None,
              since: float | None = None, until: float | None = None,
              actor: str | None = None) -> int:
        with self._lock:
            if self.store is None:
                return len(self._filtered(self._mem, kind,
                                          kind_prefix=kind_prefix,
                                          since=since, until=until,
                                          actor=actor))
            return self.store.audit_count(kind, kind_prefix=kind_prefix,
                                          since=since, until=until,
                                          actor=actor)

    def head(self) -> dict:
        with self._lock:
            if self.store is None:
                last = self._mem[-1] if self._mem else None
            else:
                last = self.store.audit_head()
        if last is None:
            return {"seq": 0, "entry_hash": GENESIS, "ts": None, "kind": None}
        return {
            "seq": int(last["seq"]),
            "entry_hash": last["entry_hash"],
            "ts": last["ts"],
            "kind": last["kind"],
        }

    @staticmethod
    def _filtered(rows, kind: str | None = None, *,
                  kind_prefix: str | None = None, since: float | None = None,
                  until: float | None = None,
                  actor: str | None = None) -> list[dict]:
        """In-memory twin of the SQL filters (same semantics, same order)."""
        if kind:
            rows = [r for r in rows if r["kind"] == kind]
        if kind_prefix:
            rows = [r for r in rows if str(r["kind"]).startswith(kind_prefix)]
        if since is not None:
            rows = [r for r in rows if (r.get("ts") or 0.0) >= since]
        if until is not None:
            rows = [r for r in rows if (r.get("ts") or 0.0) <= until]
        if actor:
            rows = [r for r in rows if r.get("actor") == actor]
        return list(rows)

    def entries(self, limit: int = 50, offset: int = 0,
                kind: str | None = None, *, kind_prefix: str | None = None,
                since: float | None = None, until: float | None = None,
                actor: str | None = None) -> list[dict]:
        with self._lock:
            if self.store is None:
                rows = self._filtered(self._mem, kind, kind_prefix=kind_prefix,
                                      since=since, until=until, actor=actor)
                rows = sorted(rows, key=lambda r: -r["seq"])
                return rows[offset:offset + limit]
            return [self._hydrate(r) for r in
                    self.store.audit_entries(limit=limit, offset=offset,
                                             kind=kind,
                                             kind_prefix=kind_prefix,
                                             since=since, until=until,
                                             actor=actor)]

    def get(self, seq: int) -> dict | None:
        with self._lock:
            if self.store is None:
                for r in self._mem:
                    if r["seq"] == seq:
                        return r
                return None
            row = self.store.audit_get(seq)
            return self._hydrate(row) if row else None

    def all_entries(self) -> list[dict]:
        with self._lock:
            if self.store is None:
                return list(self._mem)
            return [self._hydrate(r) for r in self.store.audit_all()]

    # -- verification --------------------------------------------------------

    def verify(self, max_errors: int = 5) -> dict:
        """Full chain verification: seq continuity, prev links, entry hashes."""
        entries = self.all_entries()
        errors: list[dict] = []
        prev_hash = GENESIS
        expected_seq = 1
        for entry in entries:
            if entry["seq"] != expected_seq:
                errors.append({"seq": entry["seq"],
                               "reason": f"sequence gap: expected {expected_seq}"})
            if entry["prev_hash"] != prev_hash:
                errors.append({"seq": entry["seq"],
                               "reason": "prev_hash does not match predecessor"})
            recomputed = _entry_hash(entry)
            if recomputed != entry["entry_hash"]:
                errors.append({"seq": entry["seq"],
                               "reason": "entry_hash mismatch (entry was modified)"})
                # keep verifying the rest against the *stored* chain
            if len(errors) >= max_errors:
                break
            prev_hash = entry["entry_hash"]
            expected_seq += 1
        return {
            "ok": not errors,
            "entries": len(entries),
            "head": self.head(),
            "signing_key": self.pubkey,
            "errors": errors,
        }

    def inclusion_proof(self, seq: int, leaf_index: int) -> dict | None:
        """Merkle proof that a disclosed item is committed by entry ``seq``."""
        entry = self.get(seq)
        if entry is None or not entry.get("leaves"):
            return None
        leaves = entry["leaves"]
        if leaf_index < 0 or leaf_index >= len(leaves):
            return None
        siblings = merkle_proof(leaves, leaf_index)
        return {
            "seq": seq,
            "entry_hash": entry["entry_hash"],
            "merkle_root": merkle_root(leaves),
            "index": leaf_index,
            "leaf": leaves[leaf_index],
            "siblings": siblings,
            "count": len(leaves),
        }

    def verify_inclusion(self, proof: dict, item=None) -> bool:
        """Check a proof against the log's stored entry (and a disclosed item)."""
        entry = self.get(int(proof["seq"]))
        if entry is None or not entry.get("leaves"):
            return False
        leaf = leaf_hash(item) if item is not None else proof.get("leaf")
        if leaf is None:
            return False
        root = merkle_root(entry["leaves"])
        return verify_merkle_proof(
            leaf, int(proof["index"]), list(proof["siblings"]), root,
            count=len(entry["leaves"]),
        )

    # -- checkpoints ---------------------------------------------------------

    def checkpoint(self) -> dict:
        """Merkle-root + sign every entry since the previous checkpoint."""
        with self._lock:
            entries = self.all_entries()
            if not entries:
                raise AuditError("audit log is empty - nothing to checkpoint")
            last_ckpt = None
            if self.store is not None:
                row = self.store.audit_last_checkpoint()
                if row is not None:
                    last_ckpt = self._hydrate(row)
            else:
                ckpts = [e for e in entries if e["kind"] == "checkpoint"]
                last_ckpt = ckpts[-1] if ckpts else None
            # continue where the previous checkpoint stopped so every entry
            # (including earlier checkpoint entries) is eventually covered
            if last_ckpt is not None:
                prev_payload = last_ckpt.get("payload") or {}
                start_seq = int(prev_payload.get("covered_to",
                                                 last_ckpt["seq"])) + 1
                # entries appended after the previous checkpoint are the "new"
                # content; its own entry is re-covered for completeness but is
                # not worth signing again on its own
                if not any(e["seq"] > last_ckpt["seq"] for e in entries):
                    raise AuditError("no new entries since the last checkpoint")
            else:
                start_seq = 1
            covered = [e for e in entries if start_seq <= e["seq"]]
            if not covered:
                raise AuditError("no new entries since the last checkpoint")
            hashes = [e["entry_hash"] for e in covered]
            root = merkle_root(hashes)
            payload = {
                "covered_from": covered[0]["seq"],
                "covered_to": covered[-1]["seq"],
                "entries": len(covered),
                "root": root,
            }
            entry = self.append("checkpoint", payload, actor="audit")
            sig = schnorr_sign(self.secret, canonical_json(payload).encode())
            return {
                "seq": entry["seq"],
                "entry_hash": entry["entry_hash"],
                "signature": sig,
                "pubkey": self.pubkey,
                **payload,
            }

    def _latest_checkpoint(self, seq: int | None = None) -> dict | None:
        if seq is not None:
            entry = self.get(seq)
            if entry is None or entry["kind"] != "checkpoint":
                return None
            rows = [entry]
        elif self.store is not None:
            row = self.store.audit_last_checkpoint()
            rows = [self._hydrate(row)] if row else []
        else:
            rows = [e for e in self._mem if e["kind"] == "checkpoint"][-1:]
        if not rows:
            return None
        entry = rows[-1]
        ck = dict(entry["payload"])
        ck["seq"] = entry["seq"]
        ck["entry_hash"] = entry["entry_hash"]
        return ck

    def verify_checkpoint(self, ckpt: dict | None = None,
                          seq: int | None = None) -> dict:
        """Re-verify a checkpoint: covered range, Merkle root, signature."""
        if ckpt is None:
            ckpt = self._latest_checkpoint(seq)
            if ckpt is None:
                raise AuditError("no checkpoint has been created yet")

        checks: list[dict] = []

        def check(name: str, ok: bool, detail: str = "") -> None:
            checks.append({"name": name, "ok": bool(ok), "detail": detail})

        try:
            start = int(ckpt["covered_from"])
            end = int(ckpt["covered_to"])
            declared = int(ckpt["entries"])
            declared_root = str(ckpt["root"])
        except (KeyError, TypeError, ValueError):
            return {"ok": False, "seq": None, "root": None,
                    "checks": [{"name": "shape", "ok": False,
                                "detail": "checkpoint lacks coverage fields"}]}
        entries = [e for e in self.all_entries() if start <= e["seq"] <= end]
        check("range_complete",
              len(entries) == declared == end - start + 1,
              f"{len(entries)} entries in [{start}, {end}], declared {declared}")
        root = merkle_root([e["entry_hash"] for e in entries])
        check("merkle_root", root == declared_root, "recomputed covered-root")
        chain_ok = all(
            cur["prev_hash"] == prev["entry_hash"]
            for prev, cur in zip(entries, entries[1:])
        )
        check("chain_links", chain_ok, "prev_hash links across covered range")
        # stored entry hashes must still match their payloads (tamper check)
        integrity_ok = all(_entry_hash(e) == e["entry_hash"] for e in entries)
        check("entry_integrity", integrity_ok,
              "every covered entry still hashes to its stored entry_hash")
        if "signature" in ckpt:
            msg = canonical_json({
                k: ckpt[k] for k in
                ("covered_from", "covered_to", "entries", "root")
            }).encode()
            ok = ckpt.get("pubkey") == self.pubkey and schnorr_verify(
                str(ckpt.get("pubkey", "")), msg, str(ckpt.get("signature", "")))
            check("signature", ok, "Schnorr signature over the covered root")
        return {"ok": all(c["ok"] for c in checks), "checks": checks,
                "seq": ckpt.get("seq"), "root": declared_root}


__all__ = ["AuditLog", "AuditError", "GENESIS", "MAX_LEAVES"]
