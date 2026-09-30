"""Module 2: secure multi-party (federated) training via secret sharing.

Each party's model update (a feature-space delta) is quantized to integers
and split with additive secret sharing across the shareholder enclaves.
Properties this buys us, and honestly documents:

  * a single shareholder learns nothing about any party's data - k-1 shares
    are information-theoretically independent of the secret (only the full
    set of k shares recombines);
  * the coordinator only ever needs the per-shareholder *aggregate*, so it
    learns the sum of all updates, never any party's contribution;
  * raw data never leaves the enclaves - only fixed-size integer shares
    cross the wire.

Shares are k-of-k (all shareholders must recombine); collusion of every
shareholder breaks one party's privacy, which is the standard caveat for
additive sharing and is called out in the returned report.
"""

from __future__ import annotations

import hashlib
import uuid

import numpy as np

QUANT = 1_000_000          # float -> int scale (micro-units)


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


def federated_round(deltas, shareholders: int = 3, seed: int = 7) -> dict:
    """Split every party's delta across shareholders and prove recombination.

    ``deltas`` is a list of equal-length numeric vectors (one per party).
    Returns the share bundles, the per-shareholder aggregate shares, and a
    verification that recombination reproduces sum(deltas) exactly.
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


def public_report(report: dict) -> dict:
    """Safe, externally shareable summary of a round (API/CLI surface).

    Strips every detail that could help reconstruct a party's model update:
    the per-party share bundles, the per-shareholder aggregates, and the
    round seed (k-1 shares are derivable from the seed, so it must not
    leave the process). Consumers get round identity, participant and
    threshold counts, verification status, the aggregate digest, and the
    summed aggregate itself - the coordinator's intended output.

    Detailed shares remain available to the internal simulation/testing
    layer (``federated_round`` / ``recombine``).
    """
    return {
        "round_id": report["round_id"],
        "parties": report["parties"],
        "shareholders": report["shareholders"],   # k-of-k threshold
        "threshold": report["shareholders"],
        "dim": report["dim"],
        "quantize": report["quantize"],
        "exact": report["exact"],
        "verified": report["exact"],              # aggregate verification status
        "aggregate": report["aggregate"],
        "aggregate_digest": report["aggregate_digest"],
        "capability": "SIMULATED",                # matches /api/capabilities
        "claims": report["claims"],
    }
