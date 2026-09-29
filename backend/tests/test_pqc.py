"""Module 1 tests: PQC readiness scanning, inventory, HNDL, roadmap."""

import time

from scapy.utils import PcapWriter

from spectra.demo import tls_flow_packets
from spectra.modules.pqc import (
    PQCInventory,
    assess_flow,
    assess_hndl,
    generate_roadmap,
    group_info,
    cipher_info,
    signature_info,
    risk_from_score,
    screen_flows,
)
from spectra.modules.pqc.scan import scan_pcap
from spectra.pipeline import SpectraEngine
from spectra.tools import collect_flows


def _write_pcap(path, flows):
    writer = PcapWriter(str(path), sync=True)
    for pkts in flows:
        for p in pkts:
            writer.write(p)
    writer.close()
    return str(path)


# -- registry ----------------------------------------------------------------

def test_group_registry():
    assert group_info(0x11EC) == {
        "code": 0x11EC, "name": "X25519MLKEM768",
        "kx_class": "hybrid", "quantum": "resistant",
    }
    assert group_info(0x11EB)["kx_class"] == "hybrid"
    assert group_info(0x0201)["kx_class"] == "pqc"
    assert group_info(0x001D) == {
        "code": 0x001D, "name": "x25519",
        "kx_class": "classical", "quantum": "vulnerable",
    }
    assert group_info(0x0100)["quantum"] == "vulnerable"   # ffdhe2048
    assert group_info(0xFFFF)["kx_class"] == "unknown"
    assert group_info(0)["name"] == "none"


def test_cipher_and_signature_registry():
    assert cipher_info(0x009C)["scheme"] == "rsa_transport"
    assert cipher_info(0xC02F)["scheme"] == "ecdhe"
    assert cipher_info(0x1301)["scheme"] == "tls13"
    assert signature_info(0x0905)["quantum"] == "resistant"
    assert signature_info(0x0401)["quantum"] == "vulnerable"


def test_risk_bands():
    assert risk_from_score(None) == "unknown"
    assert risk_from_score(95) == "quantum_ready"
    assert risk_from_score(80) == "quantum_ready"
    assert risk_from_score(70) == "low"
    assert risk_from_score(40) == "moderate"
    assert risk_from_score(20) == "high"
    assert risk_from_score(0) == "critical"


# -- per-flow assessment -----------------------------------------------------

def _assess(profile: str, tmp_path, i: int) -> dict:
    pcap = _write_pcap(
        tmp_path / f"{profile}_{i}.pcap",
        [tls_flow_packets(sport=40000 + i, sni="example.com", profile=profile)],
    )
    flows = collect_flows(pcap)
    assert len(flows) == 1
    return assess_flow(flows[0])


def test_classical_tls13_is_harvestable(tmp_path):
    a = _assess("classic", tmp_path, 1)
    assert a["applicable"]
    assert a["version"] == "TLS 1.3"
    assert a["kx"]["name"] == "x25519"
    assert a["kx"]["source"] == "negotiated"
    assert a["risk"] == "moderate"
    assert a["quantum_vulnerable"] is True
    assert a["score"] < 55
    assert any("harvestable" in r for r in a["reasons"])
    assert any("X25519MLKEM768" in act for act in a["actions"])


def test_hybrid_tls13_is_quantum_ready(tmp_path):
    a = _assess("hybrid", tmp_path, 2)
    assert a["kx"]["name"] == "X25519MLKEM768"
    assert a["kx"]["kx_class"] == "hybrid"
    assert a["risk"] == "quantum_ready"
    assert a["score"] >= 80
    assert a["quantum_vulnerable"] is False
    assert "X25519MLKEM768" in a["kx"]["offered"]


def test_rsa_tls12_is_critical(tmp_path):
    a = _assess("rsa12", tmp_path, 3)
    assert a["kx_scheme"] == "rsa_transport"
    assert a["version"] == "TLS 1.2"
    assert a["risk"] in ("critical", "high")
    assert a["quantum_vulnerable"] is True
    assert any("RSA key transport" in r for r in a["reasons"])
    assert any("disable RSA key transport" in act for act in a["actions"])


def test_pq_signature_offer_raises_score(tmp_path):
    a = _assess("pqc_auth", tmp_path, 4)
    assert a["auth"]["pq_signatures_offered"] == ["mldsa44", "mldsa65"]
    assert a["score"] >= 80
    assert a["risk"] == "quantum_ready"


def test_plaintext_flow_not_applicable(tmp_path):
    # beacon-style UDP flow with no TLS handshake
    from scapy.all import IP, UDP, Raw

    pkt = IP(src="10.0.0.9", dst="198.51.100.7") / UDP(sport=5555, dport=4444) / Raw(b"\x01" * 32)
    pkt.time = 1_700_000_000.0
    pcap = tmp_path / "plain.pcap"
    w = PcapWriter(str(pcap), sync=True)
    w.write(pkt)
    w.close()
    flows = collect_flows(str(pcap))
    a = assess_flow(flows[0])
    assert a["applicable"] is False
    assert a["risk"] == "unknown"
    assert a["score"] is None


# -- inventory ---------------------------------------------------------------

def test_inventory_aggregation():
    inv = PQCInventory()

    def rec(sni, dst="93.184.216.34:443", b=1000, ts=1_700_000_000.0):
        return {"sni": sni, "dst": dst, "src": "10.0.0.5:40000",
                "bytes": b, "start_ts": ts, "last_ts": ts + 1}

    vulnerable = {"applicable": True, "risk": "high", "score": 20,
                  "quantum_vulnerable": True,
                  "kx": {"name": "x25519", "kx_class": "classical"},
                  "cipher": {"name": "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"},
                  "version": "TLS 1.2", "actions": ["upgrade endpoint to TLS 1.3"]}
    ready = {"applicable": True, "risk": "quantum_ready", "score": 90,
             "quantum_vulnerable": False,
             "kx": {"name": "X25519MLKEM768", "kx_class": "hybrid"},
             "cipher": {"name": "TLS_AES_128_GCM_SHA256"},
             "version": "TLS 1.3", "actions": []}

    inv.observe(rec("portal.hospital.example", b=5000), vulnerable)
    inv.observe(rec("portal.hospital.example", b=7000), vulnerable)
    inv.observe(rec("pay.bank.example", b=100), ready)
    inv.observe({"sni": None, "dst": "203.0.113.9:443", "bytes": 10,
                 "start_ts": 1, "last_ts": 2}, vulnerable)

    summary = inv.summary()
    assert summary["endpoints"] == 3
    assert summary["flows"] == 4
    assert summary["vulnerable_endpoints"] == 2
    assert summary["quantum_ready_endpoints"] == 1
    assert summary["risk_distribution"]["high"] == 3
    assert summary["by_sector"]["healthcare"] == 1
    assert summary["by_sector"]["fintech"] == 1

    eps = inv.endpoints()
    # worst posture first
    assert eps[0]["min_score"] == 20
    assert eps[0]["endpoint"] == "portal.hospital.example"
    assert eps[0]["vulnerable_flows"] == 2
    assert eps[0]["bytes"] == 12000
    ready_ep = [e for e in eps if e["min_score"] == 90][0]
    assert ready_ep["endpoint"] == "pay.bank.example"

    only_health = inv.endpoints(sector="healthcare")
    assert [e["endpoint"] for e in only_health] == ["portal.hospital.example"]


# -- HNDL --------------------------------------------------------------------

def _vuln_assessment(score=20):
    return {"applicable": True, "risk": "high", "score": score,
            "quantum_vulnerable": True,
            "kx": {"name": "x25519", "kx_class": "classical"}}


def _ready_assessment(score=90):
    return {"applicable": True, "risk": "quantum_ready", "score": score,
            "quantum_vulnerable": False,
            "kx": {"name": "X25519MLKEM768", "kx_class": "hybrid"}}


def test_hndl_flags_bulk_vulnerable_transfer():
    record = {"sni": "archive.hospital.example", "dst": "203.0.113.9:443",
              "src": "10.0.0.5:40000", "bytes": 500_000_000,
              "duration": 1800.0, "last_ts": 1_700_000_000.0}
    finding = assess_hndl(record, _vuln_assessment())
    assert finding is not None
    assert finding["level"] in ("high", "medium")
    assert finding["sector"] == "healthcare"
    assert finding["score"] > 0
    assert any("quantum-vulnerable" in r for r in finding["reasons"])
    assert finding["bytes"] == 500_000_000


def test_hndl_ignores_quantum_ready_and_small_flows():
    big = {"sni": "cdn.example", "dst": "1.2.3.4:443", "bytes": 500_000_000,
           "duration": 1800.0, "last_ts": 0}
    assert assess_hndl(big, _ready_assessment()) is None

    tiny = {"sni": "cdn.example", "dst": "1.2.3.4:443", "bytes": 4096,
            "duration": 0.5, "last_ts": 0}
    assert assess_hndl(tiny, _vuln_assessment()) is None


def test_hndl_custom_thresholds():
    rec = {"sni": "x.example", "dst": "1.2.3.4:443", "bytes": 5_000,
           "duration": 5.0, "last_ts": 0}
    assert assess_hndl(rec, _vuln_assessment(), min_bytes=1_000) is not None
    assert assess_hndl(rec, _vuln_assessment(), min_bytes=100_000_000) is None


def test_screen_flows_orders_by_score():
    pairs = [
        ({"sni": "a.example", "dst": "1.1.1.1:443", "bytes": 100_000_000,
          "duration": 600, "last_ts": 0}, _vuln_assessment(score=10)),
        ({"sni": "b.example", "dst": "2.2.2.2:443", "bytes": 100_000_000,
          "duration": 600, "last_ts": 0}, _vuln_assessment(score=50)),
    ]
    findings = screen_flows(pairs)
    assert len(findings) == 2
    assert findings[0]["score"] >= findings[1]["score"]


# -- roadmap -----------------------------------------------------------------

def test_roadmap_structure_and_drivers():
    summary = {"endpoints": 10, "flows": 40, "vulnerable_endpoints": 7,
               "quantum_ready_endpoints": 2,
               "risk_distribution": {"high": 30, "quantum_ready": 10},
               "by_sector": {"fintech": 6, "general": 4}}
    endpoints = [
        {"endpoint": "old.bank.example", "sector": "fintech", "min_score": 5,
         "algorithms": ["x25519 (classical)"],
         "actions": ["disable RSA key transport suites; require ECDHE/TLS 1.3",
                     "disable TLS 1.0; enforce TLS 1.2+"]},
        {"endpoint": "new.bank.example", "sector": "fintech", "min_score": 85,
         "algorithms": ["X25519MLKEM768 (hybrid)"], "actions": []},
    ]
    hndl = [{"endpoint": "old.bank.example", "sector": "fintech",
             "bytes": 900_000_000, "duration": 3600, "level": "high", "score": 82}]

    plan = generate_roadmap(summary, endpoints, hndl)
    assert [p["phase"] for p in plan["phases"]] == [1, 2, 3]
    assert plan["generated_from"]["hndl_findings"] == 1

    p1_ids = [i["id"] for i in plan["phases"][0]["items"]]
    assert "hndl-contain" in p1_ids
    assert "kill-rsa-transport" in p1_ids
    assert "retire-legacy-tls" in p1_ids

    p2_ids = [i["id"] for i in plan["phases"][1]["items"]]
    assert "roll-out-hybrid-kx" in p2_ids
    assert "pq-auth-pilot" in p2_ids

    # sector filter restricts findings
    gen = generate_roadmap(summary, endpoints, hndl, sector="healthcare")
    assert gen["sector"] == "healthcare"
    gen_p1 = [i["id"] for i in gen["phases"][0]["items"]]
    assert "hndl-contain" not in gen_p1  # finding was fintech


def test_roadmap_clean_environment():
    plan = generate_roadmap({"endpoints": 0, "flows": 0,
                             "vulnerable_endpoints": 0,
                             "quantum_ready_endpoints": 0}, [], [])
    p1 = [i["id"] for i in plan["phases"][0]["items"]]
    assert p1 == ["baseline-ok"]


# -- offline scan ------------------------------------------------------------

def test_scan_pcap_report(tmp_path):
    pcap = _write_pcap(tmp_path / "mixed.pcap", [
        tls_flow_packets(sport=40001, sni="portal.hospital.example",
                         profile="classic"),
        tls_flow_packets(sport=40002, sni="pay.bank.example", profile="hybrid"),
        tls_flow_packets(sport=40003, sni="legacy.corp.example", profile="rsa12"),
        tls_flow_packets(sport=40004, sni="research.lab.example",
                         profile="pqc_auth"),
    ])
    report = scan_pcap(pcap)
    assert report["flows"] == 4
    assert report["assessed"] == 4
    assert report["summary"]["endpoints"] == 4
    # classic + rsa12 are vulnerable; hybrid + pqc_auth are ready
    assert report["summary"]["vulnerable_endpoints"] == 2
    assert report["summary"]["quantum_ready_endpoints"] == 2  # hybrid + pqc_auth

    by_sni = {a["sni"]: a for a in report["assessments"]}
    assert by_sni["pay.bank.example"]["kx"] == "X25519MLKEM768"
    assert by_sni["legacy.corp.example"]["risk"] in ("high", "critical")
    assert by_sni["research.lab.example"]["risk"] == "quantum_ready"

    assert [p["phase"] for p in report["roadmap"]["phases"]] == [1, 2, 3]
    assert report["roadmap"]["generated_from"]["endpoints"] == 4

    # sector filter on the endpoint list
    fin = scan_pcap(pcap, sector="fintech")
    assert {e["endpoint"] for e in fin["endpoints"]} == {"pay.bank.example"}


# -- engine + API integration ------------------------------------------------

def test_engine_tracks_pqc_and_serves_api(tmp_path):
    from fastapi.testclient import TestClient
    from spectra.api.app import engine as api_engine

    baseline = _write_pcap(tmp_path / "b.pcap", [
        tls_flow_packets(sport=40100 + i, sni=f"site{i}.example",
                         profile="classic", start=1_700_000_000.0 + i * 2)
        for i in range(12)
    ])
    mixed = _write_pcap(tmp_path / "m.pcap", [
        tls_flow_packets(sport=40200, sni="pay.bank.example", profile="hybrid"),
        tls_flow_packets(sport=40201, sni="legacy.example", profile="rsa12"),
        tls_flow_packets(sport=40202, sni="corp.example", profile="classic"),
    ])

    engine = SpectraEngine(model_path=str(tmp_path / "m.joblib"))
    engine.train_from_pcap(baseline, contamination=0.05)
    engine.start("pcap", path=mixed)
    deadline = time.time() + 30
    while engine.running and time.time() < deadline:
        time.sleep(0.05)
    assert not engine.running

    snap = engine.pqc_snapshot()
    assert snap["summary"]["endpoints"] == 3
    assert snap["summary"]["quantum_ready_endpoints"] == 1
    assert len(snap["hndl"]) == 0  # flows are tiny - no HNDL candidates
    assert [p["phase"] for p in snap["roadmap"]["phases"]] == [1, 2, 3]
    # every in-memory flow carries a PQC verdict
    assert all("pqc" in r for r in engine.flows)
    assert all(r["pqc"]["applicable"] for r in engine.flows)

    # API surface (same engine instance is shared with the app)
    api_engine.store = engine.store
    api_engine.pqc = engine.pqc
    api_engine.flows = engine.flows
    client = TestClient(__import__("spectra.api.app", fromlist=["app"]).app)

    res = client.get("/api/pqc")
    assert res.status_code == 200
    body = res.json()
    assert body["summary"]["endpoints"] == 3
    assert body["roadmap"]["phases"]

    res = client.get("/api/pqc/inventory")
    assert res.status_code == 200
    assert res.json()["summary"]["flows"] == 3

    res = client.get(f"/api/pqc/scan?pcap={mixed}")
    assert res.status_code == 200
    assert res.json()["assessed"] == 3

    res = client.get("/api/pqc/scan?pcap=/does/not/exist.pcap")
    assert res.status_code == 400
