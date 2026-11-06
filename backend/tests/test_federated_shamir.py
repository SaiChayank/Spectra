"""Phase 9G: k-of-n Shamir sharing, share commitments, dropout tolerance.

Finite-field arithmetic is checked against vectors produced by an
INDEPENDENT implementation (sympy 1.14: ``galoistools.gf_eval`` for the
shares, exact rational Lagrange for the secret) and by the well-known worked
example from the Shamir's-secret-sharing literature (prime 1613, secret 1234).
The literals below are hard-coded on purpose: they are not recomputed with the
code under test.  The default (``threshold=None``) additive path is the
pre-9G behaviour and is covered by test_tee.py / test_integrity.py unchanged.
"""

from __future__ import annotations

import json

import numpy as np
import pytest

from spectra.modules.tee.federated import (
    FIELD_PRIME,
    FederatedError,
    combine_submissions,
    commit_share,
    federated_round,
    from_field,
    public_report,
    shamir_secret,
    shamir_shares,
    to_field,
    verify_share_commitment,
)

P = FIELD_PRIME

# -- independent vectors ------------------------------------------------------------

# Wikipedia "Shamir's Secret Sharing" worked example: p=1613, secret 1234,
# f(x) = 1234 + 166x + 94x^2
WIKI = [(1, 1494), (2, 329), (3, 965), (4, 176), (5, 1188), (6, 775)]

S2 = 123456789012345678901234567890
C2 = [98765432109876543210987654321098765, 170141183460469231731687303715884105000]
V2 = [
    (1, 98765555566665555556666555555665928),
    (2, 197530987676542098767654209876762512),
    (3, 296296419786418641978641864197857642),
    (4, 395061851896295185189629518518951318),
    (5, 493827284006171728400617172840043540),
]

# two parties, secrets -123456 and 7000000 (negative maps to P-123456)
SA, SB = -123456, 7000000
CA = [111111111111111111111111111111, 222222222222222222222222222222]
CB = [333333333333333333333333333333, 4444444444444444444444444444]
V3_A = [(1, 333333333333333333333333209877), (2, 1111111111111111111111110987654),
        (3, 2333333333333333333333333209875), (4, 3999999999999999999999999876540),
        (5, 6111111111111111111111110987649)]
V3_B = [(1, 337777777777777777777784777777), (2, 684444444444444444444451444442),
        (3, 1040000000000000000000006999995), (4, 1404444444444444444444451444436),
        (5, 1777777777777777777777784777765)]
V3_AGG = [(1, 671111111111111111111117987654), (2, 1795555555555555555555562432096),
          (3, 3373333333333333333333340209870), (4, 5404444444444444444444451320976),
          (5, 7888888888888888888888895765414)]


def test_field_prime_is_the_mersenne_prime_2_127_minus_1():
    assert FIELD_PRIME == 2**127 - 1


def test_wikipedia_worked_example():
    assert shamir_shares(1234, [166, 94], range(1, 7), prime=1613) == WIKI
    for subset in ([1, 3, 4], [0, 2, 5], [1, 4, 5], [0, 1, 2]):
        assert shamir_secret([WIKI[i] for i in subset], prime=1613) == 1234


def test_vectors_from_an_independent_implementation():
    assert shamir_shares(S2, C2, range(1, 6), prime=P) == V2
    for subset in ([0, 2, 4], [1, 2, 3], [0, 1, 4]):
        assert shamir_secret([V2[i] for i in subset], prime=P) == S2

    assert shamir_shares(to_field(SA, P), CA, range(1, 6), prime=P) == V3_A
    assert shamir_shares(to_field(SB, P), CB, range(1, 6), prime=P) == V3_B
    assert to_field(SA, P) == P - 123456 and from_field(to_field(SA, P), P) == SA


def test_shares_are_additively_homomorphic():
    agg = [(x, (ya + yb) % P) for (x, ya), (_, yb) in zip(V3_A, V3_B, strict=True)]
    assert agg == V3_AGG
    for subset in ([0, 2, 3], [1, 3, 4]):
        assert from_field(shamir_secret([V3_AGG[i] for i in subset], prime=P), P) == SA + SB


def test_fewer_than_threshold_shares_reveal_nothing_exhaustive():
    """p=101, t=3: for each secret, the share at x=1 takes every value equally often."""
    p = 101
    for secret in (0, 1, 57):
        counts = [0] * p
        for a1 in range(p):
            for a2 in range(p):
                counts[shamir_shares(secret, [a1, a2], [1], prime=p)[0][1]] += 1
        assert set(counts) == {p}                     # perfectly uniform, independent of secret


def test_combine_rejects_duplicate_or_zero_x():
    with pytest.raises(FederatedError):
        shamir_secret([(1, 5), (1, 7)], prime=P)
    with pytest.raises(FederatedError):
        shamir_secret([(0, 5), (1, 7)], prime=P)


# -- the round: k-of-n, dropout --------------------------------------------------------

DELTAS = [[0.5, -1.25, 3.0, 0.001], [1.5, 0.75, -2.0, 0.002], [-0.25, 0.1, 0.4, 0.003]]


def _want(deltas):
    return np.sum(np.asarray(deltas), axis=0)


def test_shamir_round_exact_and_scheme_labelled():
    r = federated_round(DELTAS, shareholders=5, seed=3, threshold=3)
    assert r["scheme"] == "shamir" and r["threshold"] == 3 and r["shareholders"] == 5
    assert r["parties"] == 3 and r["responded"] == 5 and r["exact"] is True
    assert np.allclose(r["aggregate"], _want(DELTAS), atol=1e-5)
    again = federated_round(DELTAS, shareholders=5, seed=3, threshold=3)   # same seed
    assert again["round_id"] != r["round_id"]                    # rounds stay distinct
    assert again["aggregate_digest"] == r["aggregate_digest"]
    assert [(s["values"], s["nonce"]) for s in again["aggregate_submissions"]] == \
        [(s["values"], s["nonce"]) for s in r["aggregate_submissions"]]


def test_recombination_succeeds_with_n_minus_1_of_n_shares():
    r = federated_round(DELTAS, shareholders=4, seed=5, threshold=3,
                        dropped_shareholders=[1])
    assert r["responded"] == 3 and r["dropped"] == {"parties": [], "shareholders": [1]}
    assert r["exact"] is True
    assert np.allclose(r["aggregate"], _want(DELTAS), atol=1e-5)


def test_dropped_participant_mid_session_aggregate_still_reconstructed():
    # a shareholder fails after dealing; a party fails before dealing
    r = federated_round(DELTAS, shareholders=5, seed=9, threshold=3,
                        dropped_shareholders=[0, 4], dropped_parties=[2])
    assert r["parties"] == 2 and r["responded"] == 3
    assert r["dropped"] == {"parties": [2], "shareholders": [0, 4]}
    assert r["exact"] is True
    assert np.allclose(r["aggregate"], _want(DELTAS[:2]), atol=1e-5)   # excludes the dropout


def test_too_few_responders_or_survivors_is_an_error_not_a_guess():
    with pytest.raises(FederatedError, match="responded"):
        federated_round(DELTAS, shareholders=5, seed=1, threshold=3,
                        dropped_shareholders=[0, 1, 2])
    with pytest.raises(FederatedError, match="at least 2"):
        federated_round(DELTAS, shareholders=3, seed=1, threshold=2,
                        dropped_parties=[0, 1])             # one survivor = no privacy


def test_parameter_validation():
    for bad in (
        dict(threshold=1), dict(threshold=6), dict(threshold=True),
        dict(threshold=3, dropped_shareholders=[7]),
        dict(threshold=3, dropped_shareholders=[0, 0]),
        dict(threshold=3, dropped_parties=[-1]),
        dict(threshold=3, dropped_parties=["a"]),
    ):
        with pytest.raises(FederatedError):
            federated_round(DELTAS, shareholders=5, seed=1, **bad)
    # dropout without a threshold cannot be tolerated by k-of-k sharing
    with pytest.raises(FederatedError):
        federated_round(DELTAS, shareholders=3, seed=1, dropped_shareholders=[0])


def test_default_path_is_still_additive_k_of_k():
    r = federated_round(DELTAS, shareholders=3, seed=7)
    assert r["scheme"] == "additive" and r["threshold"] == 3 and r["exact"] is True


# -- commitments: tampered shares are rejected ------------------------------------------

def _round():
    return federated_round(DELTAS, shareholders=5, seed=11, threshold=3)


def _combine(r, subs, **kw):
    return combine_submissions(subs, r["commitments"]["aggregate"], r["threshold"],
                               r["round_id"], **kw)


def test_untampered_submissions_combine_and_match_the_published_aggregate():
    r = _round()
    out = _combine(r, r["aggregate_submissions"])
    assert out["rejected"] == [] and len(out["used"]) == 5
    got = np.asarray(out["values"], dtype=np.int64) / r["quantize"]
    assert np.allclose(got, _want(DELTAS), atol=1e-5)


def test_tampered_share_is_rejected_and_the_rest_still_reconstruct():
    r = _round()
    subs = [dict(s) for s in r["aggregate_submissions"]]
    vals = list(subs[1]["values"])
    vals[0] = (vals[0] + 1) % P
    subs[1]["values"] = vals
    out = _combine(r, subs)
    assert [x["x"] for x in out["rejected"]] == [subs[1]["x"]]
    assert "commitment" in out["rejected"][0]["reason"]
    got = np.asarray(out["values"], dtype=np.int64) / r["quantize"]
    assert np.allclose(got, _want(DELTAS), atol=1e-5)          # 4 valid shares >= t


def test_tamper_with_only_t_shares_cannot_reconstruct():
    r = _round()
    subs = [dict(s) for s in r["aggregate_submissions"][:3]]
    subs[0] = {**subs[0], "values": [(v + 1) % P for v in subs[0]["values"]]}
    with pytest.raises(FederatedError, match="valid shares"):
        _combine(r, subs)


@pytest.mark.parametrize("mutate", [
    lambda s: {**s, "nonce": "00" * 16},                       # wrong blinding nonce
    lambda s: {**s, "x": s["x"] % 5 + 1},                      # claims another shareholder's slot
])
def test_nonce_and_slot_swaps_are_rejected(mutate):
    r = _round()
    subs = [dict(s) for s in r["aggregate_submissions"]]
    subs[2] = mutate(subs[2])
    out = _combine(r, subs)
    assert subs[2]["x"] in {x["x"] for x in out["rejected"]} or len(out["used"]) == 4


def test_a_commitment_from_another_round_does_not_verify():
    a, b = _round(), federated_round(DELTAS, shareholders=5, seed=12, threshold=3)
    s = a["aggregate_submissions"][0]
    assert verify_share_commitment(a["commitments"]["aggregate"][0], a["round_id"],
                                   "aggregate", s["x"], s["values"], s["nonce"])
    assert not verify_share_commitment(b["commitments"]["aggregate"][0], a["round_id"],
                                       "aggregate", s["x"], s["values"], s["nonce"])
    assert commit_share("r", "aggregate", 1, [1, 2], "aa") != commit_share("r", "aggregate", 1, [1, 3], "aa")


def test_shares_that_commit_but_do_not_lie_on_one_polynomial_are_detected():
    """A dealer that hands out inconsistent shares (each matching its own commitment)."""
    r = _round()
    subs = [dict(s) for s in r["aggregate_submissions"]]
    bad = (subs[4]["values"][0] + 5) % P
    subs[4]["values"] = [bad] + subs[4]["values"][1:]
    commits = list(r["commitments"]["aggregate"])
    commits[4] = commit_share(r["round_id"], "aggregate", subs[4]["x"],
                              subs[4]["values"], subs[4]["nonce"])
    with pytest.raises(FederatedError, match="polynomial"):
        combine_submissions(subs, commits, r["threshold"], r["round_id"])


# -- the public surface -----------------------------------------------------------------

def test_public_report_hides_shares_nonces_and_seed():
    r = federated_round(DELTAS, shareholders=5, seed=21, threshold=3,
                        dropped_shareholders=[2])
    safe = public_report(r)
    for secret in ("party_shares", "aggregate_shares", "aggregate_submissions",
                   "seed", "nonces"):
        assert secret not in safe
    assert safe["scheme"] == "shamir" and safe["threshold"] == 3
    assert safe["responded"] == 4 and safe["dropped"]["shareholders"] == [2]
    com = safe["commitments"]
    assert len(com["aggregate"]) == 5 and all(len(c) == 64 for c in com["aggregate"])
    assert len(com["parties"]) == 3
    blob = json.dumps(safe)
    for sub in r["aggregate_submissions"]:
        assert sub["nonce"] not in blob
        assert not any(str(v) in blob for v in sub["values"] if v > 10**9)


# -- API -----------------------------------------------------------------------------------

def test_api_federate_tolerates_dropout(client):
    body = {"deltas": DELTAS, "shareholders": 5, "threshold": 3,
            "dropped_shareholders": [0], "dropped_parties": [2]}
    res = client.post("/api/tee/federate", json=body)
    assert res.status_code == 200, res.text
    out = res.json()
    assert out["scheme"] == "shamir" and out["threshold"] == 3 and out["responded"] == 4
    assert out["parties"] == 2 and out["exact"] is True and out["verified"] is True
    assert np.allclose(out["aggregate"], _want(DELTAS[:2]), atol=1e-5)
    for secret in ("party_shares", "aggregate_shares", "aggregate_submissions", "seed"):
        assert secret not in out

    too_many = client.post("/api/tee/federate", json={
        **body, "dropped_shareholders": [0, 1, 2]})
    assert too_many.status_code == 400
    assert client.post("/api/tee/federate", json={
        "deltas": DELTAS, "shareholders": 3, "threshold": 9}).status_code in (400, 422)


def test_api_defaults_unchanged(client):
    out = client.post("/api/tee/federate", json={"deltas": DELTAS, "shareholders": 3}).json()
    assert out["scheme"] == "additive" and out["threshold"] == out["shareholders"] == 3


def test_cli_exposes_the_dropout_flags():
    from spectra.cli import build_parser
    ns = build_parser().parse_args(["tee", "federate", "--shareholders", "5",
                                    "--threshold", "3", "--drop-shareholders", "0,1"])
    assert ns.threshold == 3 and ns.drop_shareholders == "0,1"
