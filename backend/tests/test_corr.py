"""Module 7 tests: correlation graph, cascade scoring, API surface."""

import time

from fastapi.testclient import TestClient
from scapy.utils import PcapWriter

from spectra.demo import tls_flow_packets
from spectra.modules.corr import NODE_DOMAIN, NODE_HOST, NODE_IP, NODE_SECTOR, cascade
from spectra.modules.corr.graph import CorrelationGraph
from spectra.pipeline import SpectraEngine


def rec(src="10.0.0.5:40000", dst="93.184.216.34:443", sni="example.com",
        b=1000, ts=1_700_000_000.0, anomaly=False):
    return {"src": src, "dst": dst, "sni": sni, "bytes": b,
            "start_ts": ts, "last_ts": ts + 1, "anomaly": anomaly}


def test_graph_builds_expected_topology():
    g = CorrelationGraph()
    g.observe(rec(sni="pay.bank.example", dst="10.1.0.10:443", b=500))
    g.observe(rec(sni="billing.bank.example", dst="10.1.0.10:443", b=700))
    g.observe(rec(sni="portal.hospital.example", dst="10.2.0.20:443",
                  src="10.0.0.6:41000", b=900, anomaly=True))

    assert g.nodes["host:10.0.0.5"]["type"] == NODE_HOST
    assert g.nodes["ip:10.1.0.10"]["type"] == NODE_IP
    assert g.nodes["domain:pay.bank.example"]["type"] == NODE_DOMAIN
    assert g.nodes["sector:fintech"]["type"] == NODE_SECTOR

    # domains classified by sector
    assert g.nodes["domain:pay.bank.example"]["sector"] == "fintech"
    assert g.nodes["domain:portal.hospital.example"]["sector"] == "healthcare"

    # shared infrastructure: two domains served by one IP
    summary = g.summary()
    assert summary["shared_infrastructure"] == 1
    assert "ip:10.1.0.10" in summary["shared_ip_nodes"]
    assert summary["by_type"][NODE_DOMAIN] == 3
    assert summary["by_sector"]["fintech"] >= 1


def test_neighbors_and_path():
    g = CorrelationGraph()
    g.observe(rec(sni="pay.bank.example", dst="10.1.0.10:443"))
    g.observe(rec(sni="portal.hospital.example", dst="10.2.0.20:443",
                  src="10.0.0.6:41000"))

    nb = g.neighbors("host:10.0.0.5")
    assert nb["node"]["type"] == NODE_HOST
    assert any(o["target"] == "ip:10.1.0.10" for o in nb["out"])
    # ip node has incoming edges
    nb_ip = g.neighbors("ip:10.1.0.10")
    assert nb_ip["in"]

    path = g.shortest_path("host:10.0.0.5", "sector:fintech")
    assert path == ["host:10.0.0.5", "ip:10.1.0.10",
                    "domain:pay.bank.example", "sector:fintech"]
    assert g.shortest_path("host:10.0.0.5", "sector:general") is None
    assert g.shortest_path("nope", "sector:fintech") is None


def test_cascade_scoring():
    g = CorrelationGraph()
    # noisy host talking to shared infra across two sectors
    for i in range(6):
        g.observe(rec(sni="pay.bank.example", dst="10.1.0.10:443",
                      b=1000 * (i + 1), anomaly=(i % 2 == 0)))
    g.observe(rec(sni="cdn.shared.example", dst="10.1.0.10:443", b=500))
    g.observe(rec(sni="portal.hospital.example", dst="10.1.0.10:443",
                  b=800, anomaly=True))

    result = cascade(g, "host:10.0.0.5")
    assert result["found"] is True
    assert 0 <= result["score"] <= 100
    assert result["level"] in ("low", "medium", "high")
    assert result["detections"] >= 3
    assert set(result["sectors"]) & {"fintech", "healthcare"}
    assert result["affected_counts"][NODE_HOST] == 1
    assert result["affected_counts"][NODE_DOMAIN] == 3
    assert len(result["kill_chain"]) >= 3
    assert result["kill_chain"][0]["node"] == "host:10.0.0.5"
    assert any("cross-sector" in r for r in result["reasons"])

    missing = cascade(g, "host:9.9.9.9")
    assert missing["found"] is False and missing["score"] == 0


def test_graph_hydrate_from_store(tmp_path):
    from spectra.store import Store

    store = Store(str(tmp_path / "g.db"))
    for i in range(10):
        store.save_flow(rec(dst=f"93.184.216.{i}:443", sni=f"site{i}.example"),
                        score=None, anomaly=False)
    g = CorrelationGraph()
    n = g.hydrate(store)
    store.close()
    assert n == 10
    assert g.summary()["nodes"] > 10
    assert g.summary()["by_type"][NODE_DOMAIN] == 10


def test_graph_survives_capture_start(tmp_path):
    """Starting a capture must not wipe history-backed graph nodes."""
    from spectra.store import Store

    store = Store(str(tmp_path / "h.db"))
    for i in range(4):
        store.save_flow(rec(dst=f"93.184.216.9{i}:443", sni=f"old{i}.example"),
                        score=None, anomaly=False)

    pcap = str(tmp_path / "fresh.pcap")
    w = PcapWriter(pcap, sync=True)
    for p in tls_flow_packets(sport=40700, sni="fresh.example"):
        w.write(p)
    w.close()

    engine = SpectraEngine(model_path=str(tmp_path / "m.joblib"), store=store)
    engine.start("pcap", path=pcap)
    deadline = time.time() + 30
    while engine.running and time.time() < deadline:
        time.sleep(0.05)
    assert not engine.running

    snap = engine.graph_snapshot()
    ids = {n["id"] for n in snap["nodes"]}
    assert "domain:old0.example" in ids      # replayed history survived start()
    assert "domain:fresh.example" in ids     # live capture still observed
    assert snap["summary"]["nodes"] >= 6
    store.close()


def test_engine_graph_and_api(tmp_path):
    def write(path, flows):
        w = PcapWriter(str(path), sync=True)
        for pkts in flows:
            for p in pkts:
                w.write(p)
        w.close()
        return str(path)

    baseline = write(tmp_path / "b.pcap", [
        tls_flow_packets(sport=40500 + i, sni=f"site{i}.example",
                         start=1_700_000_000.0 + i * 2)
        for i in range(12)
    ])
    mixed = write(tmp_path / "m.pcap", [
        tls_flow_packets(sport=40600, sni="pay.bank.example", dst="10.1.0.10"),
        tls_flow_packets(sport=40601, sni="billing.bank.example", dst="10.1.0.10"),
        tls_flow_packets(sport=40602, sni="portal.hospital.example",
                         dst="10.2.0.20", src="10.0.0.7"),
    ])

    engine = SpectraEngine(model_path=str(tmp_path / "m.joblib"))
    engine.train_from_pcap(baseline, contamination=0.05)
    engine.start("pcap", path=mixed)
    deadline = time.time() + 30
    while engine.running and time.time() < deadline:
        time.sleep(0.05)
    assert not engine.running

    snap = engine.graph_snapshot()
    assert snap["summary"]["nodes"] >= 6
    assert any(n["type"] == NODE_DOMAIN for n in snap["nodes"])
    assert snap["edges"]

    cas = engine.graph_cascade("host:10.0.0.5")
    assert cas["found"] is True

    # ---- API (share state with the app instance) ----
    import spectra.api.app as app_module

    app_module.engine.store = engine.store
    app_module.engine.graph = engine.graph
    client = TestClient(app_module.app)

    res = client.get("/api/graph")
    assert res.status_code == 200
    body = res.json()
    assert body["summary"]["nodes"] >= 6
    assert body["nodes"] and body["edges"]

    res = client.get("/api/graph/summary")
    assert res.status_code == 200
    assert res.json()["nodes"] >= 6

    res = client.get("/api/graph/node?id=host:10.0.0.5")
    assert res.status_code == 200
    assert res.json()["node"]["type"] == NODE_HOST

    res = client.get("/api/graph/node?id=nope")
    assert res.status_code == 404

    res = client.get("/api/graph/cascade?id=host:10.0.0.5")
    assert res.status_code == 200
    assert res.json()["found"] is True

    res = client.get("/api/graph/path?src=host:10.0.0.5&dst=sector:fintech")
    assert res.status_code == 200
    assert res.json()["hops"] >= 2

    res = client.get("/api/graph/path?src=host:10.0.0.5&dst=sector:zzz")
    assert res.status_code == 404
