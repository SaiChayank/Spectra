"""Module 5: zero-knowledge audit trail - crypto, log, certificates, API."""

from __future__ import annotations

import json
import random

import pytest

from spectra.modules.audit import (
    AuditError,
    AuditLog,
    CertificateError,
    PROFILES,
    build_certificate,
    canonical_json,
    commit,
    leaf_hash,
    merkle_proof,
    merkle_root,
    prove_threshold,
    prove_zero,
    sanitize,
    schnorr_keypair,
    schnorr_sign,
    schnorr_verify,
    verify_certificate,
    verify_merkle_proof,
    verify_threshold,
    verify_zero,
)
from spectra.modules.audit.curve import (
    G,
    N,
    P,
    decompress,
    hash_to_curve,
    is_on_curve,
    pt_add,
    pt_double,
    pt_mul,
    pt_mul_affine,
    pt_neg,
    compress,
)
from spectra.modules.audit.zkp import ZKPError, rand_blinding
from spectra.store import Store


# -- group arithmetic ---------------------------------------------------------


def test_point_arithmetic_jacobian_matches_affine():
    rng = random.Random(1234)
    for _ in range(4):
        a = rng.randrange(1, N)
        b = rng.randrange(1, N)
        assert pt_mul(a + b, G) == pt_add(pt_mul_affine(a, G), pt_mul_affine(b, G))
        assert pt_mul(a, G) == pt_mul_affine(a, G)
        assert pt_mul(a * b % N, G) == pt_mul(a, pt_mul(b, G))
    assert pt_mul(N, G) is None
    assert pt_mul(0, G) is None
    assert pt_mul(-1, G) == pt_neg(G)


def test_affine_identity_and_doubling():
    assert pt_add(G, None) == G
    assert pt_add(None, None) is None
    assert pt_add(G, pt_neg(G)) is None
    assert pt_double(G) == pt_add(G, G)
    assert is_on_curve(pt_double(G))
    assert pt_add(G, G) == pt_mul(2, G)


def test_compress_roundtrip_and_rejections():
    for k in (1, 2, 3, 7, 1234567, N - 1):
        pt = pt_mul(k, G)
        assert decompress(compress(pt)) == pt
    assert decompress("00") is None
    for bad in ("", "02", "04" + "11" * 32, "02" + "ff" * 32, 12345):
        with pytest.raises(ValueError):
            decompress(bad)


def test_hash_to_curve_deterministic_and_on_curve():
    h1 = hash_to_curve(b"spectra test")
    h2 = hash_to_curve(b"spectra test")
    h3 = hash_to_curve(b"spectra other")
    assert h1 == h2 != h3
    assert is_on_curve(h1) and is_on_curve(h3)
    # unknown discrete log: cannot be a small multiple of G
    for k in range(1, 50):
        assert pt_mul(k, G) != h1


def test_schnorr_signature_verify_and_tampering():
    secret, pub = schnorr_keypair()
    msg = b"checkpoint 42"
    sig = schnorr_sign(secret, msg)
    assert schnorr_verify(pub, msg, sig)
    assert not schnorr_verify(pub, b"checkpoint 43", sig)
    _, other_pub = schnorr_keypair()
    assert not schnorr_verify(other_pub, msg, sig)
    assert not schnorr_verify(pub, msg, sig[:-1] + ("0" if sig[-1] != "0" else "1"))
    assert not schnorr_verify(pub, msg, "garbage")
    assert not schnorr_verify(pub, msg, sig[:64])


# -- merkle ------------------------------------------------------------------


@pytest.mark.parametrize("count", [1, 2, 3, 5, 8, 16])
def test_merkle_proofs_verify_for_every_leaf(count):
    leaves = [leaf_hash({"i": i, "pad": "x" * (i % 4)}) for i in range(count)]
    root = merkle_root(leaves)
    for i in range(count):
        siblings = merkle_proof(leaves, i)
        assert verify_merkle_proof(leaves[i], i, siblings, root, count=count)
        if count > 1:
            # wrong leaf / wrong index must fail
            assert not verify_merkle_proof(leaves[(i + 1) % count], i, siblings,
                                           root, count=count)
            j = (i + 1) % count
            assert not verify_merkle_proof(leaves[i], j, siblings, root, count=count)


def test_merkle_tampering_and_shape_failures():
    leaves = [leaf_hash(f"item-{i}") for i in range(7)]
    root = merkle_root(leaves)
    siblings = merkle_proof(leaves, 3)
    bad_root = root[:-1] + ("0" if root[-1] != "0" else "1")
    assert not verify_merkle_proof(leaves[3], 3, siblings, bad_root, count=7)
    assert not verify_merkle_proof(leaves[3], 3, siblings[:1], root, count=7)
    assert not verify_merkle_proof(leaves[3], 3, siblings, root, count=9)
    assert not verify_merkle_proof(leaves[3], -1, siblings, root, count=7)
    assert not verify_merkle_proof("not-a-hash", 3, siblings, root, count=7)
    with pytest.raises(ValueError):
        merkle_proof([], 0)
    with pytest.raises(ValueError):
        merkle_proof(leaves, 99)


def test_canonical_json_is_stable():
    assert canonical_json({"b": 1, "a": [1, 2]}) == '{"a":[1,2],"b":1}'
    assert canonical_json({"a": 1, "b": 2}) == canonical_json({"b": 2, "a": 1})


# -- zero-knowledge proofs ---------------------------------------------------


def test_zero_proof_true_and_false():
    r = rand_blinding()
    c0 = commit(0, r)
    assert verify_zero(c0, prove_zero(c0, r, msg=b"x"), msg=b"x")
    assert not verify_zero(c0, prove_zero(c0, r, msg=b"x"), msg=b"y")
    # a commitment to a non-zero counter cannot pass, even with its opening
    r2 = rand_blinding()
    c5 = commit(5, r2)
    assert not verify_zero(c5, prove_zero(c5, r2, msg=b"x"), msg=b"x")
    # wrong opening also fails
    assert not verify_zero(c0, prove_zero(c0, r + 1, msg=b"x"), msg=b"x")


def test_commitment_binding_and_hiding_openings():
    r = rand_blinding()
    c = commit(42, r)
    assert commit(42, r) == c                 # deterministic opening check
    assert commit(42, r + 1) != c             # different blinding -> different C
    assert commit(43, r) != c                 # different value -> different C


def test_threshold_proof_proves_and_hides():
    r = rand_blinding()
    proof = prove_threshold(12_345, r, 1000, bits=32)
    assert verify_threshold(proof, threshold=1000)
    # the proof is bound to the exact threshold it was created for
    assert not verify_threshold(proof, threshold=999)
    assert not verify_threshold(proof, threshold=1001)
    # stronger threshold the value cannot satisfy must NOT verify
    assert not verify_threshold(proof, threshold=20_000)
    # the proof reveals nothing about the exact value: no plaintext field
    assert "value" not in proof and "12345" not in canonical_json(proof)


def test_threshold_proof_rejects_tampering():
    r = rand_blinding()
    proof = prove_threshold(500, r, 100, bits=16)
    assert verify_threshold(proof, threshold=100)

    tampered = json.loads(canonical_json(proof))
    tampered["bit_proofs"][2]["s0"] = f"{(int(tampered['bit_proofs'][2]['s0'], 16) + 1) % N:064x}"
    assert not verify_threshold(tampered, threshold=100)

    tampered = json.loads(canonical_json(proof))
    tampered["bit_commitments"][0] = compress(pt_mul(99, G))
    assert not verify_threshold(tampered, threshold=100)

    tampered = json.loads(canonical_json(proof))
    tampered["threshold"] = 1
    assert not verify_threshold(tampered, threshold=100)


def test_false_threshold_claim_cannot_be_proven():
    with pytest.raises(ZKPError):
        prove_threshold(10, rand_blinding(), 100, bits=16)
    with pytest.raises(ZKPError):
        prove_threshold(70_000, rand_blinding(), 1, bits=16)  # does not fit


def test_zero_bit_threshold_is_provable_and_verifies():
    proof = prove_threshold(7, rand_blinding(), 7, bits=8)  # value - threshold = 0
    assert verify_threshold(proof, threshold=7)
    assert not verify_threshold(proof, threshold=8)


# -- audit log ---------------------------------------------------------------


def _seed_store(tmp_path, flows=20) -> Store:
    store = Store(str(tmp_path / "audit.db"))
    import time as _t

    now = _t.time()
    for i in range(flows):
        store.save_flow(
            {
                "ts": now - i, "last_ts": now - i, "proto": "TLSv1.3",
                "src": f"10.0.0.{i % 250}:40000", "dst": "93.184.216.34:443",
                "duration": 1.2, "packets": 8, "bytes": 1500,
                "tls_version": "TLSv1.3", "sni": "example.com", "alpn": ["h2"],
                "ja3": "deadbeef", "ja4": "t13d", "score": 5.0 + i,
                "anomaly": i % 5 == 0,
            },
            score=5.0 + i, anomaly=(i % 5 == 0), reasons=None,
        )
    return store


def test_log_chain_and_persistence(tmp_path):
    store = _seed_store(tmp_path, flows=5)
    log = AuditLog(store=store)
    e1 = log.append("capture.start", {"mode": "pcap"})
    e2 = log.append("window", {"flows": 5}, leaves=[{"i": i} for i in range(5)])
    e3 = log.append("capture.stop", {"packets": 40})

    assert [e["seq"] for e in (e1, e2, e3)] == [1, 2, 3]
    assert e2["prev_hash"] == e1["entry_hash"]
    assert e3["prev_hash"] == e2["entry_hash"]
    assert e1["prev_hash"] == "0" * 64
    assert e2["merkle_root"] == merkle_root([leaf_hash({"i": i}) for i in range(5)])

    report = log.verify()
    assert report["ok"] and report["entries"] == 3

    # a fresh instance continues the same chain with the same signing key
    log2 = AuditLog(store=store)
    assert log2.pubkey == log.pubkey
    e4 = log2.append("alert", {"alert_type": "drift"})
    assert e4["prev_hash"] == e3["entry_hash"]
    assert log2.verify()["ok"]


def test_log_detects_tampering(tmp_path):
    store = _seed_store(tmp_path, flows=3)
    log = AuditLog(store=store)
    log.append("capture.start", {"mode": "live"})
    log.append("window", {"flows": 3}, leaves=[{"a": 1}, {"b": 2}])
    log.append("capture.stop", {"packets": 9})

    store._conn.execute(
        "UPDATE audit_log SET payload = ? WHERE seq = 2",
        (canonical_json({"flows": 999_999}),),
    )
    store._conn.commit()

    report = log.verify()
    assert not report["ok"]
    assert any(e["seq"] == 2 and "mismatch" in e["reason"] for e in report["errors"])
    # entries read back are the tampered ones
    assert log.get(2)["payload"]["flows"] == 999_999


def test_log_seq_gap_is_detected(tmp_path):
    store = _seed_store(tmp_path, flows=1)
    log = AuditLog(store=store)
    log.append("a", {})
    log.append("b", {})
    store._conn.execute("DELETE FROM audit_log WHERE seq = 1")
    store._conn.commit()
    report = log.verify()
    assert not report["ok"]
    assert any("gap" in e["reason"] or "prev" in e["reason"] for e in report["errors"])


def test_inclusion_proofs(tmp_path):
    store = _seed_store(tmp_path, flows=4)
    log = AuditLog(store=store)
    records = [{"src": f"10.0.0.{i}"} for i in range(6)]
    entry = log.append("window", {"flows": 6}, leaves=records)
    assert entry["merkle_root"] == merkle_root([leaf_hash(r) for r in records])

    for i, rec in enumerate(records):
        proof = log.inclusion_proof(entry["seq"], i)
        assert proof is not None
        assert log.verify_inclusion(proof, rec)
        assert not log.verify_inclusion(proof, {"src": "forged"})

    assert log.inclusion_proof(entry["seq"], 99) is None
    assert log.inclusion_proof(999, 0) is None
    no_leaves = log.append("plain", {"x": 1})
    assert log.inclusion_proof(no_leaves["seq"], 0) is None


def test_memory_log_without_store():
    log = AuditLog(store=None)
    log.append("capture.start", {"mode": "pcap"})
    log.append("window", {"flows": 1}, leaves=[{"s": 1}])
    assert log.count() == 2
    assert log.verify()["ok"]
    head = log.head()
    assert head["seq"] == 2 and head["entry_hash"] != "0" * 64
    # memory key is ephemeral (no key file for :memory:)
    assert log.pubkey


def test_checkpoint_signs_and_verifies(tmp_path):
    store = _seed_store(tmp_path, flows=6)
    log = AuditLog(store=store)
    for i in range(4):
        log.append("event", {"i": i})

    ck = log.checkpoint()
    assert ck["covered_from"] == 1 and ck["covered_to"] == 4
    assert ck["entries"] == 4
    assert len(ck["signature"]) == 130 and ck["pubkey"] == log.pubkey

    report = log.verify_checkpoint()
    assert report["ok"], report

    # appending more and checkpointing again continues where the previous
    # checkpoint stopped, so checkpoint entries themselves are covered too
    log.append("event", {"i": 4})
    ck2 = log.checkpoint()
    assert ck2["covered_from"] == 5 and ck2["covered_to"] == 6
    assert ck2["entries"] == 2
    assert log.verify_checkpoint(seq=ck2["seq"])["ok"]

    # nothing new -> error
    with pytest.raises(AuditError):
        log.checkpoint()


def test_checkpoint_detects_covered_entry_tampering(tmp_path):
    store = _seed_store(tmp_path, flows=3)
    log = AuditLog(store=store)
    log.append("event", {"i": 1})
    log.append("event", {"i": 2})
    ck = log.checkpoint()
    assert log.verify_checkpoint(seq=ck["seq"])["ok"]

    store._conn.execute(
        "UPDATE audit_log SET payload = ? WHERE seq = 2",
        (canonical_json({"i": 999}),),
    )
    store._conn.commit()
    report = log.verify_checkpoint(seq=ck["seq"])
    assert not report["ok"]
    # payload tampering breaks the entry's own hash (merkle root of stored
    # hashes still matches, but the entry no longer matches its hash)
    assert any(c["name"] == "entry_integrity" and not c["ok"]
               for c in report["checks"])


def test_checkpoint_requires_entries(tmp_path):
    store = _seed_store(tmp_path, flows=1)
    log = AuditLog(store=store)
    with pytest.raises(AuditError):
        log.checkpoint()


# -- certificates ------------------------------------------------------------


def _prepared(tmp_path, flows=25):
    store = _seed_store(tmp_path, flows=flows)
    log = AuditLog(store=store)
    log.append("capture.start", {"mode": "pcap"})
    log.append("window", {"flows": flows},
               leaves=[{"idx": i} for i in range(flows)])
    store.add_model_run("baseline.pcap", 100, 0.02, {"n_train": 100})
    return store, log


@pytest.mark.parametrize("profile", sorted(PROFILES))
def test_certificate_roundtrip_all_profiles(tmp_path, profile):
    store, log = _prepared(tmp_path)
    bundle = build_certificate(store, log, profile=profile, min_flows=10,
                               disclose=3, bits=32)
    assert bundle["type"] == "spectra.compliance.certificate"
    assert [c["id"] for c in bundle["claims"]] == PROFILES[profile]
    assert bundle["signature"] and bundle["pubkey"] == log.pubkey

    result = verify_certificate(bundle, log=log)
    assert result["ok"], json.dumps(result, indent=2)
    assert len(result["checks"]) >= len(PROFILES[profile]) + 2
    assert all(c["ok"] for c in result["checks"])

    # also verifiable with no database at all (signature + proofs only)
    standalone = verify_certificate(bundle)
    assert standalone["ok"], json.dumps(standalone, indent=2)


def test_certificate_disclosure_is_metadata_only(tmp_path):
    store, log = _prepared(tmp_path, flows=15)
    bundle = build_certificate(store, log, profile="hipaa", min_flows=5,
                               disclose=4)
    claim = next(c for c in bundle["claims"] if c["id"] == "detection_continuity")
    assert claim["evidence_count"] == 15
    assert len(claim["disclosed"]) == 4
    assert claim["redacted"] == 11
    for row in claim["disclosed"]:
        item = row["item"]
        assert "reasons" not in item          # detection methods stay private
        assert "record" not in item
        assert set(item) <= set(
            {"ts", "proto", "src", "dst", "duration", "packets", "bytes",
             "tls_version", "sni", "alpn", "ja3", "ja4", "quic_version",
             "score", "anomaly"})
    assert verify_certificate(bundle, log=log)["ok"]


def test_certificate_coverage_claim_hides_count_but_proves_threshold(tmp_path):
    store, log = _prepared(tmp_path, flows=25)
    bundle = build_certificate(store, log, profile="hipaa", min_flows=10,
                               disclose=0, bits=32)
    claim = next(c for c in bundle["claims"] if c["id"] == "min_coverage")
    assert claim["threshold"] == 10
    # the exact count (25) is not a field anywhere in the claim
    assert "value" not in claim and "count" not in claim and "exact" not in claim
    proof = claim["proof"]
    # proof is bound to its threshold: only the proven one verifies
    assert verify_threshold(proof, threshold=10)
    assert not verify_threshold(proof, threshold=9)
    assert not verify_threshold(proof, threshold=25)
    assert verify_certificate(bundle, log=log)["ok"]


def test_certificate_unmet_claim_refuses_to_issue(tmp_path):
    store, log = _prepared(tmp_path, flows=5)
    with pytest.raises(CertificateError):
        build_certificate(store, log, profile="hipaa", min_flows=100)
    # unknown profile
    with pytest.raises(CertificateError):
        build_certificate(store, log, profile="sox", min_flows=1)
    # no persistence -> cannot certify
    with pytest.raises(CertificateError):
        build_certificate(None, log, profile="hipaa")


def test_certificate_empty_log_refuses_to_issue(tmp_path):
    store = _seed_store(tmp_path, flows=5)
    log = AuditLog(store=store)  # never appended to
    with pytest.raises(CertificateError):
        build_certificate(store, log, profile="hipaa", min_flows=1)


def test_certificate_tampering_is_caught(tmp_path):
    store, log = _prepared(tmp_path, flows=12)

    # 1. swapped commitment (breaks signature AND the zero proof)
    bundle = build_certificate(store, log, profile="hipaa", min_flows=5,
                               disclose=2)
    bundle["claims"][0]["commitment"] = compress(pt_mul(12345, G))
    res = verify_certificate(bundle, log=log)
    assert not res["ok"]

    # 2. forged disclosed record (breaks Merkle inclusion)
    bundle = build_certificate(store, log, profile="hipaa", min_flows=5,
                               disclose=2)
    disc = next(c for c in bundle["claims"] if c["id"] == "detection_continuity")
    disc["disclosed"][0]["item"]["sni"] = "attacker.example"
    res = verify_certificate(bundle, log=log)
    assert not res["ok"]
    assert any(c["name"].startswith("claim:detection") and not c["ok"]
               for c in res["checks"])

    # 3. claim set downgraded (dropped a required claim)
    bundle = build_certificate(store, log, profile="hipaa", min_flows=5,
                               disclose=1)
    bundle["claims"] = [c for c in bundle["claims"] if c["id"] != "no_phi"]
    res = verify_certificate(bundle, log=log)
    assert not res["ok"]
    assert any(c["name"] == "claim_set" and not c["ok"] for c in res["checks"])

    # 4. raised coverage threshold with an unchanged proof
    bundle = build_certificate(store, log, profile="hipaa", min_flows=5,
                               disclose=1)
    cov = next(c for c in bundle["claims"] if c["id"] == "min_coverage")
    cov["threshold"] = 5000  # proof still says >= 5
    res = verify_certificate(bundle, log=log)
    assert not res["ok"]


def test_certificate_binds_to_log_head(tmp_path):
    store, log = _prepared(tmp_path, flows=10)
    bundle = build_certificate(store, log, profile="hipaa", min_flows=5,
                               disclose=1)
    seq = bundle["chain_head"]["seq"]
    # the signed head must be a real, unmodified entry
    entry = log.get(seq)
    assert entry is not None and entry["entry_hash"] == bundle["chain_head"]["entry_hash"]
    assert verify_certificate(bundle, log=log)["ok"]

    store._conn.execute("UPDATE audit_log SET payload = ? WHERE seq = 1",
                        (canonical_json({"i": 666}),))
    store._conn.commit()
    res = verify_certificate(bundle, log=log)
    assert not res["ok"]
    assert any(c["name"] == "claim:chain_integrity" and not c["ok"]
               for c in res["checks"])


def test_certificate_gdpr_retention_bound(tmp_path):
    store, log = _prepared(tmp_path, flows=8)
    import time as _t

    now = _t.time()
    # window inside the retention policy
    ok = build_certificate(store, log, profile="gdpr", since=now - 86400,
                           until=now, min_flows=1, disclose=1)
    assert verify_certificate(ok, log=log)["ok"]
    # window beyond 90 days must be refused
    with pytest.raises(CertificateError):
        build_certificate(store, log, profile="gdpr", since=now - 400 * 86400,
                          until=now, min_flows=1)


def test_sanitize_projects_only_disclosable_keys():
    rec = {"src": "a", "sni": "x", "reasons": [{"feature": "f"}],
           "payload": "SECRET", "record": {"inner": 1}}
    out = sanitize(rec)
    assert out == {"src": "a", "sni": "x"}
    assert "reasons" not in out and "payload" not in out


# -- engine + API integration ------------------------------------------------


def test_engine_capture_writes_audit_evidence(tmp_path):
    from fastapi.testclient import TestClient

    from spectra.api.app import app, engine
    from spectra.demo import make_suspicious_pcap

    client = TestClient(app)
    pcap = make_suspicious_pcap(str(tmp_path / "s.pcap"))
    before = engine.audit.count()

    res = client.post("/api/capture/start", json={"mode": "pcap", "path": pcap})
    assert res.status_code == 200, res.text

    import time as _t

    deadline = _t.time() + 30
    while engine.running and _t.time() < deadline:
        _t.sleep(0.05)
    assert not engine.running
    client.post("/api/capture/stop")

    assert engine.audit.count() > before
    entries = engine.audit.entries(limit=50)
    kinds = [e["kind"] for e in entries]
    assert "capture.start" in kinds and "capture.stop" in kinds
    stop = next(e for e in entries if e["kind"] == "capture.stop")
    assert stop["payload"]["flows"] >= 1
    assert stop["leaves"] and stop["merkle_root"]
    assert engine.audit.verify()["ok"]

    # inclusion proof through the API for the first leaf of that entry
    res = client.get(f"/api/audit/proof?seq={stop['seq']}&leaf=0")
    assert res.status_code == 200, res.text
    proof = res.json()
    assert proof["merkle_root"] == stop["merkle_root"]
    assert engine.audit.verify_inclusion(proof)


def test_audit_api_endpoints(tmp_path):
    from fastapi.testclient import TestClient

    from spectra.api.app import app, engine

    client = TestClient(app)
    if engine.store is None:
        pytest.skip("persistence disabled")

    # guarantee a non-empty log regardless of test ordering
    engine.audit.append("test.ping", {"ok": True})

    res = client.get("/api/audit/entries?limit=5")
    assert res.status_code == 200
    body = res.json()
    assert body["count"] >= 1 and len(body["items"]) <= 5
    assert body["signing_key"]

    res = client.get("/api/audit/head")
    assert res.status_code == 200
    assert res.json()["seq"] >= 1

    res = client.get("/api/audit/verify")
    assert res.status_code == 200
    assert res.json()["ok"] is True

    res = client.post("/api/audit/checkpoint")
    assert res.status_code == 200, res.text
    ck = res.json()
    assert ck["entries"] >= 1 and ck["signature"]

    res = client.get("/api/audit/checkpoint/verify")
    assert res.status_code == 200
    assert res.json()["ok"] is True

    # proof for a missing leaf -> 404
    res = client.get("/api/audit/proof?seq=1&leaf=9999")
    assert res.status_code == 404

    # certificate round trip through the API
    if engine.store.query_flows(limit=1)["count"] == 0:
        engine.store.save_flow(
            {"ts": 1.0, "last_ts": 1.0, "proto": "TLSv1.3", "src": "10.0.0.1:1",
             "dst": "1.2.3.4:443", "sni": "api.test.example",
             "tls_version": "TLSv1.3", "score": 3.0, "anomaly": False,
             "packets": 1, "bytes": 60},
            score=3.0, anomaly=False, reasons=None)
    res = client.post("/api/audit/certificate",
                      json={"profile": "hipaa", "min_flows": 1, "disclose": 2})
    assert res.status_code == 200, res.text
    bundle = res.json()

    res = client.post("/api/audit/certificate/verify",
                      json={"certificate": bundle})
    assert res.status_code == 200, res.text
    assert res.json()["ok"] is True, res.json()

    # unmet coverage -> 409
    res = client.post("/api/audit/certificate",
                      json={"profile": "hipaa", "min_flows": 10 ** 9})
    assert res.status_code == 409

    # garbage certificate -> not ok
    res = client.post("/api/audit/certificate/verify",
                      json={"certificate": {"type": "nope"}})
    assert res.status_code == 200
    assert res.json()["ok"] is False
