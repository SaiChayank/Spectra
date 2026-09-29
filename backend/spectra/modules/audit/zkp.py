"""Zero-knowledge primitives for Module 5 (ZK-verified privacy).

Three statements the auditor can check without learning anything else:

1. ``prove_zero``      - "the committed counter is 0" (payload bytes read,
                          PHI fields touched: both must be zero, always).
2. ``prove_threshold`` - "the committed value is >= T" via a bit-decomposed
                          range proof: each bit gets a Camenisch-Majtor
                          OR-proof (bit = 0 OR bit = 1) and a closing Schnorr
                          proof ties the bits back to the commitment. The
                          exact value is never revealed.
3. ``schnorr_sign``     - authenticity of certificates (re-exported).

Every proof is a Fiat-Shamir Sigma protocol: special-sound (a fabricated
proof for a false statement lets you extract the witness, which is a discrete
log nobody knows) and honest-verifier zero-knowledge (simulatable from the
challenge alone).
"""

from __future__ import annotations

import secrets

from .curve import (
    DLOG_DST,
    G,
    N,
    CurveError,
    challenge,
    compress,
    decompress,
    hash_to_curve,
    pt_add,
    pt_mul,
    pt_neg,
    rand_scalar,
    schnorr_keypair,
    schnorr_sign,
    schnorr_verify,
    verify_dlog,
    prove_dlog,
)

PEDERSEN_DST = b"SPECTRA/zkp/pedersen/v1"
OR_DST = b"SPECTRA/zkp/bit-or/v1"
CLOSE_DST = b"SPECTRA/zkp/range-close/v1"

ZERO_DST = b"SPECTRA/zkp/zero/v1"

_MAX_BITS = 64  # counters/quantities committed by the audit trail


class ZKPError(ValueError):
    pass


_H: tuple[int, int] | None = None


def pedersen_base() -> tuple[int, int]:
    """Second generator H = hash_to_curve(...) - discrete log unknown."""
    global _H
    if _H is None:
        _H = hash_to_curve(PEDERSEN_DST)
    return _H


def commit(value: int, rand: int, h: tuple[int, int] | None = None) -> tuple[int, int]:
    """Pedersen commitment C = rand*G + value*H (perfectly hiding)."""
    base = h or pedersen_base()
    return pt_add(pt_mul(rand % N, G), pt_mul(value % N, base))


def verify_opening(c: tuple[int, int], value: int, rand: int,
                   h: tuple[int, int] | None = None) -> bool:
    return commit(value, rand, h) == c


def rand_blinding() -> int:
    return secrets.randbelow(N - 1) + 1


# -- statement 1: "committed value is zero" ---------------------------------


def prove_zero(c: tuple[int, int], rand: int, msg: bytes = b"") -> dict:
    """Prove C opens to 0: i.e. prove knowledge of rho with C = rho*G.

    Sound because the prover does not know log_G(H): if the committed value
    were non-zero, rewriting C as a pure multiple of G would require that log.
    """
    return prove_dlog(c, rand, msg=msg, dst=ZERO_DST)


def verify_zero(c: tuple[int, int] | str, proof: dict, msg: bytes = b"") -> bool:
    try:
        point = decompress(c) if isinstance(c, str) else c
        return verify_dlog(point, proof, msg=msg, dst=ZERO_DST)
    except CurveError:
        return False


# -- bit OR-proof (Camenisch-Majtor) ----------------------------------------


def _or_challenge(p0, p1, r0, r1, index: int) -> int:
    return challenge(
        OR_DST,
        compress(p0).encode(), compress(p1).encode(),
        compress(r0).encode(), compress(r1).encode(),
        index.to_bytes(4, "big"),
    )


def prove_bit(c_i, h, bit: int, rand: int, index: int) -> dict:
    """Prove C_i opens to 0 OR opens to 1, without revealing which."""
    if bit not in (0, 1):
        raise ZKPError(f"bit must be 0 or 1, got {bit}")
    p0 = c_i                     # claim: C = r*G          (bit 0)
    p1 = pt_add(c_i, pt_neg(h))  # claim: C - H = r*G      (bit 1)
    real, fake = (0, 1) if bit == 0 else (1, 0)
    witnesses = {real: rand}

    a = rand_scalar()
    r_real = pt_mul(a, G)
    # simulate the branch that is NOT true: pick challenge + response first
    e_fake = rand_scalar()
    s_fake = rand_scalar()
    p_fake = (p0, p1)[fake]
    r_fake = pt_add(pt_mul(s_fake, G), pt_neg(pt_mul(e_fake, p_fake)))

    r_pts = [None, None]
    r_pts[real] = r_real
    r_pts[fake] = r_fake
    e = _or_challenge(p0, p1, r_pts[0], r_pts[1], index)

    e_vec = [None, None]
    s_vec = [None, None]
    e_vec[fake] = e_fake
    s_vec[fake] = s_fake
    e_vec[real] = (e - e_fake) % N
    s_vec[real] = (a + e_vec[real] * witnesses[real]) % N

    return {
        "R0": compress(r_pts[0]),
        "R1": compress(r_pts[1]),
        "e0": f"{e_vec[0]:064x}",
        "e1": f"{e_vec[1]:064x}",
        "s0": f"{s_vec[0]:064x}",
        "s1": f"{s_vec[1]:064x}",
    }


def verify_bit(c_i, h, proof: dict, index: int) -> bool:
    try:
        p0 = decompress(c_i) if isinstance(c_i, str) else c_i
        if p0 is None:
            return False
        p1 = pt_add(p0, pt_neg(h))
        r0 = decompress(proof["R0"])
        r1 = decompress(proof["R1"])
        e0 = int(proof["e0"], 16)
        e1 = int(proof["e1"], 16)
        s0 = int(proof["s0"], 16)
        s1 = int(proof["s1"], 16)
        if r0 is None or r1 is None:
            return False
        if not all(0 <= v < N for v in (e0, e1, s0, s1)):
            return False
        e = _or_challenge(p0, p1, r0, r1, index)
        if (e0 + e1) % N != e:
            return False
        if pt_mul(s0, G) != pt_add(r0, pt_mul(e0, p0)):
            return False
        if pt_mul(s1, G) != pt_add(r1, pt_mul(e1, p1)):
            return False
        return True
    except (CurveError, ValueError, KeyError, TypeError):
        return False


# -- statement 2: "committed value >= threshold" -----------------------------


def prove_threshold(value: int, rand: int, threshold: int, bits: int = 32) -> dict:
    """Range proof that a Pedersen commitment opens to a value >= threshold.

    The exact value never leaves the prover: the verifier only learns that
    ``value - threshold`` fits in ``bits`` bits (i.e. >= 0).
    """
    if bits < 1 or bits > _MAX_BITS:
        raise ZKPError(f"bits must be in [1, {_MAX_BITS}]")
    delta = int(value) - int(threshold)
    if delta < 0:
        raise ZKPError(f"cannot prove {value} >= {threshold}: claim is false")
    if delta >= (1 << bits):
        raise ZKPError(f"{value} - {threshold} does not fit in {bits} bits")

    c = commit(value, rand)
    h = pedersen_base()
    # D is a commitment to delta with the same blinding as C
    d = pt_add(c, pt_neg(pt_mul(threshold % N, h)))

    for _ in range(4):  # degenerate blinding collision is ~2^-256; retry anyway
        bit_rands = [rand_blinding() for _ in range(bits)]
        bit_commits = [commit((delta >> i) & 1, bit_rands[i], h) for i in range(bits)]
        closing = d
        r_sum = 0
        for i, bc in enumerate(bit_commits):
            closing = pt_add(closing, pt_neg(pt_mul((1 << i) % N, bc)))
            r_sum = (r_sum + ((1 << i) % N) * bit_rands[i]) % N
        rho = (rand - r_sum) % N
        if closing is not None and rho != 0:
            break
    else:  # pragma: no cover
        raise ZKPError("degenerate blinding factors; retry")

    close = prove_dlog(closing, rho,
                       msg=f"{compress(c)}|{threshold}|{bits}".encode(),
                       dst=CLOSE_DST)
    return {
        "bits": bits,
        "threshold": int(threshold),
        "commitment": compress(c),
        "bit_commitments": [compress(b) for b in bit_commits],
        "bit_proofs": [
            prove_bit(bit_commits[i], h, (delta >> i) & 1, bit_rands[i], i)
            for i in range(bits)
        ],
        "close": close,
    }


def verify_threshold(proof: dict, commitment: str | None = None,
                     threshold: int | None = None) -> bool:
    """Verify a threshold proof; returns False on ANY inconsistency."""
    try:
        if not proof:
            return False
        bits = int(proof["bits"])
        thr = int(proof.get("threshold", -1) if threshold is None else threshold)
        if bits < 1 or bits > _MAX_BITS or thr < 0:
            return False
        c_hex = proof.get("commitment") if commitment is None else commitment
        c = decompress(c_hex)
        if c is None:
            return False
        if commitment is not None and proof.get("commitment") not in (None, c_hex):
            return False
        if threshold is not None and int(proof.get("threshold", -1)) != thr:
            return False

        h = pedersen_base()
        bit_commits = proof.get("bit_commitments") or []
        bit_proofs = proof.get("bit_proofs") or []
        if len(bit_commits) != bits or len(bit_proofs) != bits:
            return False
        for i in range(bits):
            if not verify_bit(bit_commits[i], h, bit_proofs[i], i):
                return False

        d = pt_add(c, pt_neg(pt_mul(thr % N, h)))
        closing = d
        for i, bc_hex in enumerate(bit_commits):
            bc = decompress(bc_hex)
            if bc is None:
                return False
            closing = pt_add(closing, pt_neg(pt_mul((1 << i) % N, bc)))
        if closing is None:
            return False
        return verify_dlog(closing, proof.get("close") or {},
                           msg=f"{compress(c)}|{thr}|{bits}".encode(),
                           dst=CLOSE_DST)
    except (CurveError, ValueError, KeyError, TypeError):
        return False


__all__ = [
    "ZKPError",
    "commit",
    "verify_opening",
    "rand_blinding",
    "pedersen_base",
    "prove_zero",
    "verify_zero",
    "prove_bit",
    "verify_bit",
    "prove_threshold",
    "verify_threshold",
    "schnorr_keypair",
    "schnorr_sign",
    "schnorr_verify",
]
