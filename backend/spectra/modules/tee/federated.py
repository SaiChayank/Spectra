"""Module 2: secure multi-party (federated) training via secret sharing.

Each party's model update (a feature-space delta) is quantized to integers
and split across the shareholder enclaves.  Two schemes:

* **additive k-of-k** (the default, ``threshold=None``): all shareholders must
  recombine; k-1 shares are information-theoretically independent of the
  secret;
* **Shamir t-of-n** (``threshold=t``, Phase 9G): a degree t-1 polynomial over
  the prime field GF(2^127 - 1); any t shareholders recombine, so up to n-t
  shareholders may drop out mid-session, and t-1 shares reveal nothing.  A
  party that drops out *before dealing* is excluded from every shareholder's
  aggregate consistently.

Properties this buys us, and honestly documents:

  * a single shareholder learns nothing about any party's data;
  * the coordinator only ever needs the per-shareholder *aggregate*, so it
    learns the sum of all updates, never any party's contribution (Shamir
    shares are additively homomorphic, so aggregating shares of the same x
    gives a share of the sum);
  * raw data never leaves the enclaves - only fixed-size integer shares
    cross the wire;
  * Shamir shares carry hiding SHA-256 commitments (per party share and per
    aggregate share, with a secret nonce); a tampered share fails its
    commitment and is rejected, and shares that commit fine but do not lie on
    one polynomial are detected when more than t are supplied.

What it does NOT do: it is not verifiable secret sharing - a malicious
*dealer* that commits to inconsistent shares is only caught by the
polynomial-consistency check when surplus shares exist.  (Feldman VSS would
publish g^secret, which for quantized updates is brute-forceable, i.e. it
would leak every party's delta; Pedersen VSS would fix that and is the
documented upgrade.)  Seeded randomness is reproducible, not a production
CSPRNG.  The capability stays SIMULATED: parties and shareholders are
in-process.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import random
import uuid

import numpy as np

QUANT = 1_000_000          # float -> int scale (micro-units)

#: Shamir field: the Mersenne prime 2^127 - 1.  Shares live in [0, P); signed
#: quantized values map in and out with ``to_field`` / ``from_field``.
FIELD_PRIME = (1 << 127) - 1
#: quantized |value| bound (same int64 headroom as the additive path)
MAX_ABS_QUANT = 1 << 62
COMMIT_DST = b"SPECTRA/federated/share-commitment/v1"


class FederatedError(ValueError):
    pass


def _share(secret: int, k: int, rng: np.random.Generator) -> list[int]:
    """Additive shares of one integer: k values summing exactly to secret.

    The random range is bounded (±2^50) so that aggregating shares over many
    parties still stays far inside int64 when recombination hits numpy.
    """
    if k < 2:
        raise FederatedError("need at least 2 shareholders")
    cuts = rng.integers(-(1 << 50), 1 << 50, size=k - 1, dtype=np.int64)
    last = int(secret) - int(cuts.sum())
    return [int(c) for c in cuts] + [last]


def recombine(shares: list, k: int | None = None) -> list[int]:
    """Sum aligned integer share vectors back into the secret vector.

    ``k`` is the shareholder count the round was created with; when given, a
    partial set of shares is rejected (additive sharing is k-of-k - k-1
    shares reveal nothing, so they must not reconstruct anything either).
    """
    if not shares:
        raise FederatedError("no shares to recombine")
    if k is not None and len(shares) != int(k):
        raise FederatedError(
            f"need exactly {k} shares to recombine, got {len(shares)} "
            f"(k-of-k: partial shares reveal nothing)")
    arrays = [np.asarray(s, dtype=np.int64) for s in shares]
    dim = arrays[0].shape[0]
    if any(a.shape[0] != dim for a in arrays):
        raise FederatedError("share vectors have mismatched dimensions")
    return [int(v) for v in np.sum(arrays, axis=0)]


# -- Shamir over GF(2^127 - 1) --------------------------------------------------------


def to_field(value: int, prime: int = FIELD_PRIME) -> int:
    """Signed integer -> field element (negatives wrap to prime - |v|)."""
    return int(value) % prime


def from_field(value: int, prime: int = FIELD_PRIME) -> int:
    """Field element -> signed integer in (-prime/2, prime/2]."""
    v = int(value) % prime
    return v - prime if v > prime // 2 else v


def shamir_shares(secret: int, coeffs, xs, prime: int = FIELD_PRIME) -> list[tuple[int, int]]:
    """Evaluate f(x) = secret + c1*x + c2*x^2 + ... (mod prime) at each x.

    ``coeffs`` are the t-1 non-constant coefficients (random in real use; an
    argument here so the arithmetic can be checked against fixed vectors).
    """
    poly = [int(c) % prime for c in coeffs]
    poly.insert(0, int(secret) % prime)
    out = []
    for x in xs:
        x = int(x)
        if x % prime == 0:
            raise FederatedError("x = 0 would reveal the secret")
        acc = 0
        for c in reversed(poly):                 # Horner
            acc = (acc * x + c) % prime
        out.append((x, acc))
    return out


def _interpolate(points, x0: int, prime: int) -> int:
    """Lagrange interpolation of the unique degree < len(points) polynomial at x0."""
    xs = [int(x) % prime for x, _ in points]
    if len(set(xs)) != len(xs):
        raise FederatedError("duplicate x coordinates")
    if any(x == 0 for x in xs):
        raise FederatedError("x = 0 is reserved for the secret")
    total = 0
    for i, (xi, yi) in enumerate(points):
        num, den = 1, 1
        for j, (xj, _) in enumerate(points):
            if i != j:
                num = num * (x0 - int(xj)) % prime
                den = den * (int(xi) - int(xj)) % prime
        total = (total + int(yi) * num * pow(den, -1, prime)) % prime
    return total


def shamir_secret(points, prime: int = FIELD_PRIME) -> int:
    """Recover the secret f(0) from >= t shares ``[(x, y), ...]`` (in [0, prime))."""
    if not points:
        raise FederatedError("no shares to recombine")
    return _interpolate(points, 0, prime)


def commit_share(round_id: str, owner, x: int, values, nonce: str) -> str:
    """Hiding, binding commitment to one share vector (SHA-256, secret nonce)."""
    body = json.dumps([str(round_id), str(owner), int(x),
                       [int(v) for v in values], str(nonce)],
                      separators=(",", ":")).encode()
    return hashlib.sha256(COMMIT_DST + body).hexdigest()


def verify_share_commitment(commitment: str, round_id: str, owner, x: int,
                            values, nonce: str) -> bool:
    try:
        return hmac.compare_digest(
            commit_share(round_id, owner, x, values, nonce), str(commitment))
    except (TypeError, ValueError):
        return False


def combine_submissions(submissions, commitments, threshold: int, round_id: str,
                        prime: int = FIELD_PRIME) -> dict:
    """Coordinator side: verify each submitted aggregate share, then recombine.

    Each submission is ``{"x", "values", "nonce"}``.  A share whose
    commitment does not match the published one (tampered values, wrong
    nonce, someone else's slot) is rejected and reported; fewer than
    ``threshold`` valid shares is an error, never a guess.  When more than
    ``threshold`` valid shares arrive, the surplus must lie on the same
    polynomial or the dealing is rejected as inconsistent.
    """
    used: list[tuple[int, list[int]]] = []
    rejected: list[dict] = []
    for sub in submissions:
        try:
            x = int(sub["x"])
            vals = [int(v) for v in sub["values"]]
            nonce = str(sub["nonce"])
        except (KeyError, TypeError, ValueError):
            rejected.append({"x": None, "reason": "malformed submission"})
            continue
        if not 1 <= x <= len(commitments):
            rejected.append({"x": x, "reason": "unknown shareholder slot"})
        elif any(u == x for u, _ in used):
            rejected.append({"x": x, "reason": "duplicate submission"})
        elif not verify_share_commitment(commitments[x - 1], round_id,
                                         "aggregate", x, vals, nonce):
            rejected.append({"x": x, "reason": "commitment mismatch"})
        else:
            used.append((x, vals))
    if len(used) < threshold:
        raise FederatedError(
            f"only {len(used)} valid shares, need {threshold} "
            f"({len(rejected)} rejected)")
    dim = len(used[0][1])
    if any(len(v) != dim for _, v in used):
        raise FederatedError("share vectors have mismatched dimensions")
    base = used[:threshold]
    values = [from_field(shamir_secret([(x, v[e]) for x, v in base], prime), prime)
              for e in range(dim)]
    for x, v in used[threshold:]:
        for e in range(dim):
            if _interpolate([(bx, bv[e]) for bx, bv in base], x, prime) != v[e] % prime:
                raise FederatedError(
                    "shares do not lie on one polynomial (inconsistent dealing)")
    return {"values": values, "used": [x for x, _ in used], "rejected": rejected}


def _indices(values, bound: int, what: str) -> list[int]:
    try:
        items = list(values or [])
    except TypeError:
        raise FederatedError(f"dropped {what}s must be a list of indexes") from None
    if any(isinstance(i, bool) or not isinstance(i, int) for i in items):
        raise FederatedError(f"dropped {what}s must be integer indexes")
    if any(not 0 <= i < bound for i in items):
        raise FederatedError(f"dropped {what} index out of range [0, {bound})")
    if len(set(items)) != len(items):
        raise FederatedError(f"duplicate dropped {what} index")
    return sorted(items)


def federated_round(deltas, shareholders: int = 3, seed: int = 7,
                    threshold: int | None = None, dropped_parties=(),
                    dropped_shareholders=()) -> dict:
    """Split every party's delta across shareholders and prove recombination.

    ``deltas`` is a list of equal-length numeric vectors (one per party).
    Returns the share bundles, the per-shareholder aggregate shares, and a
    verification that recombination reproduces sum(deltas) exactly.

    ``threshold=None`` (default) is the additive k-of-k scheme.  With
    ``threshold=t`` the shares are Shamir t-of-n: ``dropped_shareholders``
    (indexes, failing after dealing) and ``dropped_parties`` (indexes, failing
    before dealing) are tolerated while >= t shareholders respond and >= 2
    parties remain.
    """
    if not isinstance(deltas, (list, tuple)) or len(deltas) < 2:
        raise FederatedError("need >= 2 parties to federate")
    vecs = [np.asarray(d, dtype=np.float64).reshape(-1) for d in deltas]
    dim = vecs[0].shape[0]
    if dim == 0:
        raise FederatedError("deltas are empty")
    if any(v.shape[0] != dim for v in vecs):
        raise FederatedError("all parties must have equal-length deltas")
    if any(not np.all(np.isfinite(v)) for v in vecs):
        raise FederatedError("deltas contain non-finite values")
    if shareholders < 2:
        raise FederatedError("need at least 2 shareholders")

    if threshold is not None:
        return _shamir_round(vecs, shareholders, seed, threshold,
                             dropped_parties, dropped_shareholders)
    if dropped_parties or dropped_shareholders:
        raise FederatedError(
            "dropout needs a threshold: additive k-of-k sharing needs every "
            "shareholder (pass threshold=t for Shamir t-of-n)")

    rng = np.random.default_rng(seed)
    parties = len(vecs)

    # quantize -> integer shares per party
    party_shares: list[list[list[int]]] = []
    for v in vecs:
        q = np.rint(v * QUANT).astype(np.int64)
        per_party: list[list[int]] = []
        for element in q:
            per_party.append(_share(int(element), shareholders, rng))
        # per_party[element] = list of k shares -> transpose to k vectors
        k_shares = [[per_party[e][j] for e in range(dim)]
                    for j in range(shareholders)]
        party_shares.append(k_shares)

    # per-shareholder aggregate (what the coordinator collects): each
    # shareholder sums its share over all parties
    agg_shares = [
        [int(sum(party_shares[p][j][e] for p in range(parties)))
         for e in range(dim)]
        for j in range(shareholders)
    ]

    # verification: full recombination must equal the sum of the *quantized*
    # party deltas exactly (quantization happens per party before sharing)
    got = np.asarray(recombine(agg_shares, k=shareholders), dtype=np.int64)
    want = sum(np.rint(v * QUANT).astype(np.int64) for v in vecs)
    exact = bool(np.array_equal(got, want))
    aggregate = [float(v) / QUANT for v in got.tolist()]

    # per-party recombination also works (all k shares of one party)
    party_ok = all(
        np.array_equal(
            np.asarray(recombine(party_shares[p], k=shareholders),
                       dtype=np.int64),
            np.rint(vecs[p] * QUANT).astype(np.int64))
        for p in range(parties)
    )

    digest = hashlib.sha256(
        np.asarray(got, dtype=np.int64).tobytes()
    ).hexdigest()

    return {
        "round_id": uuid.uuid4().hex,
        "parties": parties,
        "shareholders": shareholders,
        "dim": dim,
        "quantize": QUANT,
        "seed": int(seed),
        "scheme": "additive",
        "threshold": shareholders,
        "responded": shareholders,
        "dropped": {"parties": [], "shareholders": []},
        "exact": exact and party_ok,
        "aggregate": aggregate,
        "aggregate_digest": digest,
        "aggregate_shares": agg_shares,
        "party_shares": party_shares,      # [party][shareholder] -> vector
        "claims": {
            "raw_data_egress": 0,
            "learned_by_coordinator": "sum of updates only",
            "single_shareholder_leaks": 0,
            "caveat": f"privacy holds while < {shareholders} shareholders "
                      "collude (k-of-k additive sharing)",
        },
    }


def _shamir_round(vecs, n: int, seed: int, threshold, dropped_parties,
                  dropped_shareholders) -> dict:
    """Shamir t-of-n round with dropout; see :func:`federated_round`."""
    if isinstance(threshold, bool) or not isinstance(threshold, int) \
            or not 2 <= threshold <= n:
        raise FederatedError(f"threshold must be an integer in [2, {n}]")
    t = threshold
    parties_total = len(vecs)
    dp = _indices(dropped_parties, parties_total, "party")
    ds = _indices(dropped_shareholders, n, "shareholder")
    active = [p for p in range(parties_total) if p not in dp]
    if len(active) < 2:
        raise FederatedError(
            "at least 2 parties must remain (a lone party's update would be "
            "revealed by its own sum)")
    responders = [j for j in range(n) if j not in ds]
    if len(responders) < t:
        raise FederatedError(
            f"only {len(responders)} of {n} shareholders responded; need {t}")

    quant = []
    for p in active:
        q = np.rint(vecs[p] * QUANT).astype(np.int64)
        if int(np.max(np.abs(q))) >= MAX_ABS_QUANT:
            raise FederatedError("delta too large to share exactly")
        quant.append(q)
    dim = len(quant[0])

    rng = random.Random(f"spectra/federated/shamir/{int(seed)}")
    round_id = uuid.uuid4().hex
    xs = list(range(1, n + 1))

    party_shares: list[list[list[int]]] = []     # [party][shareholder] -> vector
    for q in quant:
        per_elem = []
        for element in q:
            coeffs = [rng.randrange(FIELD_PRIME) for _ in range(t - 1)]
            per_elem.append(shamir_shares(to_field(int(element)), coeffs, xs))
        party_shares.append([[per_elem[e][j][1] for e in range(dim)]
                             for j in range(n)])

    def nonce() -> str:
        return f"{rng.getrandbits(128):032x}"

    party_nonces = [[nonce() for _ in range(n)] for _ in active]
    party_commits = [
        [commit_share(round_id, f"party:{p}", j + 1, party_shares[i][j],
                      party_nonces[i][j]) for j in range(n)]
        for i, p in enumerate(active)
    ]
    agg_shares = [[sum(party_shares[i][j][e] for i in range(len(active))) % FIELD_PRIME
                   for e in range(dim)] for j in range(n)]
    agg_nonces = [nonce() for _ in range(n)]
    agg_commits = [commit_share(round_id, "aggregate", j + 1, agg_shares[j],
                                agg_nonces[j]) for j in range(n)]

    # coordinator: collect from the shareholders that responded, verify, recombine
    submissions = [{"x": j + 1, "values": agg_shares[j], "nonce": agg_nonces[j]}
                   for j in responders]
    combined = combine_submissions(submissions, agg_commits, t, round_id)
    got = np.asarray(combined["values"], dtype=np.int64)
    want = sum(quant)
    # each active party's own secret must also recombine from its shares
    party_ok = all(
        [from_field(shamir_secret([(j + 1, party_shares[i][j][e]) for j in range(t)]))
         for e in range(dim)] == [int(v) for v in quant[i]]
        for i in range(len(active))
    )
    exact = bool(np.array_equal(got, want)) and party_ok
    digest = hashlib.sha256(np.asarray(got, dtype=np.int64).tobytes()).hexdigest()

    return {
        "round_id": round_id,
        "parties": len(active),
        "parties_requested": parties_total,
        "shareholders": n,
        "dim": dim,
        "quantize": QUANT,
        "seed": int(seed),
        "scheme": "shamir",
        "threshold": t,
        "responded": len(responders),
        "dropped": {"parties": dp, "shareholders": ds},
        "exact": exact,
        "aggregate": [float(v) / QUANT for v in got.tolist()],
        "aggregate_digest": digest,
        "aggregate_shares": agg_shares,
        "aggregate_submissions": submissions,
        "party_shares": party_shares,
        "party_nonces": party_nonces,
        "commitments": {"parties": party_commits, "aggregate": agg_commits},
        "claims": {
            "raw_data_egress": 0,
            "learned_by_coordinator": "sum of updates only",
            "single_shareholder_leaks": 0,
            "caveat": f"privacy holds while fewer than {t} of {n} shareholders "
                      f"collude; any {t} recombine. Shares are checked against "
                      "hash commitments, but this is not verifiable secret "
                      "sharing: a malicious dealer is only caught by the "
                      "polynomial-consistency check when surplus shares exist",
        },
    }


def public_report(report: dict) -> dict:
    """Safe, externally shareable summary of a round (API/CLI surface).

    Strips every detail that could help reconstruct a party's model update:
    the per-party share bundles, the per-shareholder aggregates, and the
    round seed and the commitment nonces (k-1 shares are derivable from the
    seed, so it must not leave the process). Consumers get round identity, participant and
    threshold counts, verification status, the aggregate digest, and the
    summed aggregate itself - the coordinator's intended output.

    Detailed shares remain available to the internal simulation/testing
    layer (``federated_round`` / ``recombine``).
    """
    out = {
        "round_id": report["round_id"],
        "parties": report["parties"],
        "shareholders": report["shareholders"],
        "threshold": report.get("threshold", report["shareholders"]),
        "scheme": report.get("scheme", "additive"),
        "responded": report.get("responded", report["shareholders"]),
        "dropped": report.get("dropped", {"parties": [], "shareholders": []}),
        "dim": report["dim"],
        "quantize": report["quantize"],
        "exact": report["exact"],
        "verified": report["exact"],              # aggregate verification status
        "aggregate": report["aggregate"],
        "aggregate_digest": report["aggregate_digest"],
        "capability": "SIMULATED",                # matches /api/capabilities
        "claims": report["claims"],
    }
    if "commitments" in report:                   # digests only: no nonces, no shares
        out["commitments"] = report["commitments"]
    return out
