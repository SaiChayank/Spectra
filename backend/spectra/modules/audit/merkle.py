"""Merkle trees for selective disclosure (Module 5).

Leaves are SHA-256 hashes of canonical JSON, so a certificate can hand the
auditor a handful of flow records (metadata only) plus inclusion proofs while
every other record stays hidden - yet still committed to by the same root.

Pairing rule: duplicate the last node when a level has an odd count (the
verifier derives sibling sides from the leaf index, so both sides must agree
on exactly this rule).
"""

from __future__ import annotations

import hashlib
import json

LEAF_DST = b"spectra/merkle/leaf/v1"
NODE_DST = b"spectra/merkle/node/v1"


class MerkleError(ValueError):
    pass


def canonical_json(obj) -> str:
    """Deterministic JSON: sorted keys, no whitespace, stable across runs."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, default=str)


def leaf_hash(item) -> str:
    """Hash one disclosed item (dict/str/...) into a Merkle leaf."""
    if isinstance(item, str) and _looks_like_hash(item):
        return item  # already a hex digest: hash items and leaves interoperate
    payload = item if isinstance(item, (bytes, bytearray)) else canonical_json(item).encode()
    return hashlib.sha256(LEAF_DST + payload).hexdigest()


def _looks_like_hash(s: str) -> bool:
    if len(s) != 64:
        return False
    try:
        int(s, 16)
        return True
    except ValueError:
        return False


def node_hash(left: str, right: str) -> str:
    return hashlib.sha256(
        NODE_DST + bytes.fromhex(left) + bytes.fromhex(right)
    ).hexdigest()


def merkle_root(leaves: list[str]) -> str:
    """Root of the tree; empty list hashes to a defined empty root."""
    if not leaves:
        return hashlib.sha256(LEAF_DST + b"<empty>").hexdigest()
    level = list(leaves)
    while len(level) > 1:
        nxt = []
        for i in range(0, len(level), 2):
            left = level[i]
            right = level[i + 1] if i + 1 < len(level) else left
            nxt.append(node_hash(left, right))
        level = nxt
    return level[0]


def tree_depth(count: int) -> int:
    """Number of pairing levels for ``count`` leaves."""
    depth = 0
    n = count
    while n > 1:
        n = (n + 1) // 2
        depth += 1
    return depth


def merkle_proof(leaves: list[str], index: int) -> list[str]:
    """Sibling hash at each level for ``leaves[index]``."""
    if not leaves:
        raise MerkleError("cannot prove membership of an empty tree")
    if index < 0 or index >= len(leaves):
        raise MerkleError(f"leaf index {index} out of range (n={len(leaves)})")
    proof: list[str] = []
    level = list(leaves)
    idx = index
    while len(level) > 1:
        sibling = idx + 1 if idx % 2 == 0 else idx - 1
        if sibling >= len(level):
            sibling = idx  # duplicated last node pairs with itself
        proof.append(level[sibling])
        nxt = []
        for i in range(0, len(level), 2):
            left = level[i]
            right = level[i + 1] if i + 1 < len(level) else left
            nxt.append(node_hash(left, right))
        level = nxt
        idx //= 2
    return proof


def verify_merkle_proof(leaf: str, index: int, siblings: list[str], root: str,
                        count: int | None = None) -> bool:
    """Recompute the path from ``leaf`` to ``root`` using index-derived sides."""
    try:
        if not _looks_like_hash(leaf) or not _looks_like_hash(root):
            return False
        if index < 0:
            return False
        if count is not None:
            if index >= count:
                return False
            if len(siblings) != tree_depth(count):
                return False
        h = leaf
        idx = index
        for sib in siblings:
            if not _looks_like_hash(sib):
                return False
            if idx % 2 == 0:
                h = node_hash(h, sib)  # we are the left child (or duplicated tail)
            else:
                h = node_hash(sib, h)
            idx //= 2
        if idx != 0:
            return False  # index deeper than the supplied path
        return h.lower() == root.lower()
    except (ValueError, MerkleError):
        return False


def build(leaves: list[str]) -> dict:
    """Bundle a tree: root + every leaf's proof (used for exports)."""
    return {
        "root": merkle_root(leaves),
        "count": len(leaves),
        "proofs": [merkle_proof(leaves, i) for i in range(len(leaves))],
    }


__all__ = [
    "MerkleError",
    "canonical_json",
    "leaf_hash",
    "node_hash",
    "merkle_root",
    "merkle_proof",
    "verify_merkle_proof",
    "tree_depth",
    "build",
]
