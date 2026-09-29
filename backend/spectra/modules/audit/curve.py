"""Module 5 crypto core: NIST P-256 group arithmetic, hash-to-curve, Schnorr.

Hand-rolled (pure hashlib + int math) so the zero-knowledge audit trail adds
no dependencies. Everything else in ``audit`` is built on this file:

    * ``pt_add`` / ``pt_double`` / ``pt_mul``  - affine + Jacobian point math
    * ``compress`` / ``decompress``            - SEC1 compressed encoding
    * ``hash_to_curve``                        - try-and-increment, no known log
    * ``schnorr_sign`` / ``schnorr_verify``    - authenticity of certificates
    * ``prove_dlog`` / ``verify_dlog``         - Sigma protocol used by the ZKPs

``hash_to_curve`` matters for soundness: the Pedersen second generator H must
have an *unknown* discrete log base G, otherwise a prover could open a
commitment to any value it liked and every proof below would be vacuous.
Try-and-increment with SHA-256 gives nobody (including us) a relation between
G and H.
"""

from __future__ import annotations

import hashlib
import secrets

# -- NIST P-256 parameters ---------------------------------------------------

P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
A = P - 3  # curve is y^2 = x^3 - 3x + b
B = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
GX = 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296
GY = 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5

G: tuple[int, int] = (GX, GY)

Point = tuple[int, int] | None  # None == point at infinity

DLOG_DST = b"SPECTRA/zkp/dlog/v1"
SIG_DST = b"SPECTRA/zkp/schnorr/v1"
H2C_DST = b"SPECTRA/zkp/hash-to-curve/v1"


class CurveError(ValueError):
    pass


# -- helpers -----------------------------------------------------------------


def _inv(x: int) -> int:
    return pow(x % P, P - 2, P)


def _hex64(v: int) -> str:
    return f"{v % N:064x}"


def is_on_curve(pt: Point) -> bool:
    if pt is None:
        return True
    x, y = pt
    return (y * y - (x * x * x + A * x + B)) % P == 0


def rand_scalar() -> int:
    """Uniform random scalar in [1, N-1]."""
    return secrets.randbelow(N - 1) + 1


# -- affine arithmetic (reference implementation, used by tests) -------------


def pt_neg(p: Point) -> Point:
    if p is None:
        return None
    return (p[0], (-p[1]) % P)


def pt_double(p: Point) -> Point:
    if p is None:
        return None
    x, y = p
    if y == 0:
        return None
    slope = (3 * x * x + A) * _inv(2 * y) % P
    x3 = (slope * slope - 2 * x) % P
    y3 = (slope * (x - x3) - y) % P
    return (x3, y3)


def pt_add(p1: Point, p2: Point) -> Point:
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    x1, y1 = p1
    x2, y2 = p2
    if x1 == x2:
        if (y1 + y2) % P == 0:
            return None
        return pt_double(p1)
    slope = (y2 - y1) * _inv(x2 - x1) % P
    x3 = (slope * slope - x1 - x2) % P
    y3 = (slope * (x1 - x3) - y1) % P
    return (x3, y3)


def pt_mul_affine(k: int, p: Point) -> Point:
    """Double-and-add over affine coordinates (slow: one inverse per add)."""
    if p is None:
        return None
    k %= N
    if k == 0:
        return None
    acc: Point = None
    addend = p
    while k:
        if k & 1:
            acc = pt_add(acc, addend)
        addend = pt_double(addend)
        k >>= 1
    return acc


# -- Jacobian arithmetic (hot path) ------------------------------------------

_J_INF = (1, 1, 0)  # Z == 0


def _to_j(p: Point) -> tuple[int, int, int]:
    if p is None:
        return _J_INF
    return (p[0], p[1], 1)


def _from_j(j: tuple[int, int, int]) -> Point:
    x, y, z = j
    if z == 0:
        return None
    zi = _inv(z)
    zi2 = zi * zi % P
    return (x * zi2 % P, y * zi2 * zi % P)


def _j_double(j: tuple[int, int, int]) -> tuple[int, int, int]:
    """dbl-2001-b with a = -3."""
    x1, y1, z1 = j
    if z1 == 0 or y1 == 0:
        return _J_INF
    delta = z1 * z1 % P
    gamma = y1 * y1 % P
    beta = x1 * gamma % P
    alpha = 3 * (x1 - delta) * (x1 + delta) % P
    x3 = (alpha * alpha - 8 * beta) % P
    z3 = ((y1 + z1) * (y1 + z1) - gamma - delta) % P
    y3 = (alpha * (4 * beta - x3) - 8 * gamma * gamma) % P
    return (x3, y3, z3)


def _j_add(j1: tuple[int, int, int], j2: tuple[int, int, int]) -> tuple[int, int, int]:
    """add-2007-bl."""
    x1, y1, z1 = j1
    x2, y2, z2 = j2
    if z1 == 0:
        return j2
    if z2 == 0:
        return j1
    z1z1 = z1 * z1 % P
    z2z2 = z2 * z2 % P
    u1 = x1 * z2z2 % P
    u2 = x2 * z1z1 % P
    s1 = y1 * z2 % P * z2z2 % P
    s2 = y2 * z1 % P * z1z1 % P
    h = (u2 - u1) % P
    r = (2 * (s2 - s1)) % P
    if h == 0:
        if r == 0:
            return _j_double(j1)
        return _J_INF
    i = (2 * h) * (2 * h) % P
    jj = h * i % P
    v = u1 * i % P
    x3 = (r * r - jj - 2 * v) % P
    y3 = (r * (v - x3) - 2 * s1 * jj) % P
    z3 = ((z1 + z2) * (z1 + z2) - z1z1 - z2z2) % P * h % P
    return (x3, y3, z3)


def pt_mul(k: int, p: Point) -> Point:
    """Scalar multiplication (Jacobian inner loop, one field inverse)."""
    if p is None:
        return None
    k %= N
    if k == 0:
        return None
    addend = _to_j(p)
    acc = _J_INF
    while k:
        if k & 1:
            acc = _j_add(acc, addend)
        addend = _j_double(addend)
        k >>= 1
    return _from_j(acc)


# -- encoding ----------------------------------------------------------------


def compress(p: Point) -> str:
    """SEC1 compressed point as hex ('00' for infinity)."""
    if p is None:
        return "00"
    x, y = p
    prefix = "02" if y % 2 == 0 else "03"
    return prefix + f"{x:064x}"


def decompress(data: str) -> Point:
    """Inverse of :func:`compress`; raises CurveError on malformed input."""
    if not isinstance(data, str):
        raise CurveError("point must be a hex string")
    raw = data.strip().lower()
    if raw == "00":
        return None
    if len(raw) != 66 or raw[:2] not in ("02", "03"):
        raise CurveError(f"malformed compressed point: {data!r}")
    x = int(raw[2:], 16)
    if x >= P:
        raise CurveError("point x out of range")
    rhs = (x * x * x + A * x + B) % P
    y = pow(rhs, (P + 1) // 4, P)  # P % 4 == 3, so this is the candidate sqrt
    if y * y % P != rhs:
        raise CurveError("point is not on the curve")
    if (y % 2 == 0) != (raw[:2] == "02"):
        y = P - y
    pt = (x, y)
    if not is_on_curve(pt):
        raise CurveError("point failed on-curve check")
    return pt


def hash_to_curve(msg: bytes, dst: bytes = H2C_DST) -> tuple[int, int]:
    """Deterministic hash-to-curve (try-and-increment).

    The resulting point's discrete log base G is unknown to everyone, which is
    exactly the property Pedersen commitments need for their second generator.
    """
    if P % 4 != 3:  # pragma: no cover - P-256 is fixed
        raise CurveError("sqrt-by-exponentiation requires p == 3 (mod 4)")
    ctr = 0
    while ctr < 1024:
        x = int.from_bytes(
            hashlib.sha256(dst + b"|x|" + ctr.to_bytes(2, "big") + msg).digest(), "big"
        ) % P
        rhs = (x * x * x + A * x + B) % P
        y = pow(rhs, (P + 1) // 4, P)
        if y * y % P == rhs:
            parity = hashlib.sha256(
                dst + b"|y|" + ctr.to_bytes(2, "big") + msg
            ).digest()[0] & 1
            if (y & 1) != parity:
                y = P - y
            pt = (x, y)
            if not is_on_curve(pt):  # pragma: no cover
                raise CurveError("hash-to-curve produced an invalid point")
            return pt
        ctr += 1
    raise CurveError("hash-to-curve failed to find a curve point")  # pragma: no cover


def challenge(dst: bytes, *chunks: bytes) -> int:
    """Fiat-Shamir challenge: length-prefixed, domain separated, mod N."""
    h = hashlib.sha256()
    h.update(len(dst).to_bytes(2, "big"))
    h.update(dst)
    for c in chunks:
        if isinstance(c, str):
            c = c.encode()
        h.update(len(c).to_bytes(4, "big"))
        h.update(c)
    return int.from_bytes(h.digest(), "big") % N


# -- Schnorr signatures / discrete-log proofs --------------------------------


def schnorr_keypair() -> tuple[str, str]:
    """(secret_hex, public_hex) - public key is the compressed x*G."""
    x = rand_scalar()
    return _hex64(x), compress(pt_mul(x, G))


def prove_dlog(statement: Point, witness: int, msg: bytes = b"",
               dst: bytes = DLOG_DST) -> dict:
    """Sigma proof of knowledge of ``witness`` with ``witness * G == statement``.

    Also serves as the signature primitive (statement = public key, msg bound
    into the challenge).
    """
    if statement is None:
        raise CurveError("statement point is the identity")
    k = rand_scalar()
    r_pt = pt_mul(k, G)
    e = challenge(dst, compress(statement), compress(r_pt), msg)
    s = (k + e * (witness % N)) % N
    return {"R": compress(r_pt), "s": _hex64(s), "e": _hex64(e)}


def verify_dlog(statement: Point, proof: dict, msg: bytes = b"",
                dst: bytes = DLOG_DST) -> bool:
    try:
        if not proof:
            return False
        r_pt = decompress(proof["R"])
        if r_pt is None or statement is None:
            return False
        s = int(proof["s"], 16)
        e = challenge(dst, compress(statement), compress(r_pt), msg)
        if int(proof.get("e", _hex64(e)), 16) != e:
            return False
        if not (0 <= s < N) or not (0 <= e < N):
            return False
        lhs = pt_mul(s, G)
        rhs = pt_add(r_pt, pt_mul(e, statement))
        return lhs is not None and lhs == rhs or (lhs is None and rhs is None)
    except (CurveError, ValueError, KeyError, TypeError):
        return False


def schnorr_sign(secret_hex: str, msg: bytes) -> str:
    """Deterministic Schnorr signature: compressed R (33B) || s (32B)."""
    x = int(secret_hex, 16)
    if not (0 < x < N):
        raise CurveError("secret scalar out of range")
    pub = pt_mul(x, G)
    # deterministic nonce: unique per (key, message)
    seed = hashlib.sha256(
        b"SPECTRA/zkp/nonce/v1" + x.to_bytes(32, "big") + msg
    ).digest()
    k = int.from_bytes(seed, "big") % N
    if k == 0:  # pragma: no cover - astronomically unlikely
        k = 1
    r_pt = pt_mul(k, G)
    e = challenge(SIG_DST, compress(pub), compress(r_pt), msg)
    s = (k + e * x) % N
    return compress(r_pt) + _hex64(s)


def schnorr_verify(pub_hex: str, msg: bytes, sig: str) -> bool:
    try:
        if not isinstance(sig, str) or len(sig) != 130:
            return False
        pub = decompress(pub_hex)
        r_pt = decompress(sig[:66])
        s = int(sig[66:], 16)
        if pub is None or r_pt is None:
            return False
        if not (0 <= s < N):
            return False
        e = challenge(SIG_DST, compress(pub), compress(r_pt), msg)
        lhs = pt_mul(s, G)
        rhs = pt_add(r_pt, pt_mul(e, pub))
        return lhs == rhs
    except (CurveError, ValueError):
        return False
