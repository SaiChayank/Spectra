"""Module 7 tests: correlation graph, cascade scoring, API surface."""

import time

from fastapi.testclient import TestClient

from spectra.demo import tls_flow_packets, write_pcap
from spectra.modules.corr import NODE_DOMAIN, NODE_HOST, NODE_IP, NODE_SECTOR, cascade
from spectra.modules.corr.graph import CorrelationGraph, cadence_stats
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
    write_pcap(pcap, tls_flow_packets(sport=40700, sni="fresh.example"))

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
        return write_pcap(str(path), [p for pkts in flows for p in pkts])

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


# ---- 9A: time-windowed edges (FR-2.2) --------------------------------------

DAY = 86_400.0
NOW = 1_700_000_000.0


def _two_sector_graph():
    """One host: fintech contact 3 days ago, healthcare contact just now."""
    g = CorrelationGraph()
    g.observe({**rec(sni="pay.bank.example", dst="10.1.0.10:443", ts=NOW - 3 * DAY),
               "id": 1})
    g.observe({**rec(sni="portal.hospital.example", dst="10.2.0.20:443", ts=NOW),
               "id": 2})
    return g


def test_edges_carry_contact_window_and_flow_ids():
    g = CorrelationGraph()
    g.observe({**rec(ts=NOW - 2 * DAY), "id": 7})
    g.observe({**rec(ts=NOW), "id": 9})
    edge = next(e for e in g.edges_list()
                if e["source"] == "host:10.0.0.5" and e["type"] == "talks_to")
    assert edge["first_ts"] == NOW - 2 * DAY
    assert edge["last_ts"] == NOW + 1
    assert edge["last_ts"] - edge["first_ts"] > 2 * DAY      # multi-day, distinguishable
    assert edge["flow_ids"] == [7, 9]


def test_wide_window_links_two_sectors_narrow_does_not():
    g = _two_sector_graph()
    wide = cascade(g, "host:10.0.0.5", window_s=7 * DAY)
    narrow = cascade(g, "host:10.0.0.5", window_s=3600)
    unwindowed = cascade(g, "host:10.0.0.5")

    assert set(wide["sectors"]) == {"fintech", "healthcare"}
    assert set(narrow["sectors"]) == {"healthcare"}
    assert set(unwindowed["sectors"]) == {"fintech", "healthcare"}  # default unchanged
    assert wide["window_s"] == 7 * DAY and narrow["window_s"] == 3600
    assert unwindowed["window_s"] is None
    assert not any(r.startswith("cross-sector") for r in narrow["reasons"])
    # the kill chain must not step over an out-of-window edge either
    assert all("fintech" not in s["label"] for s in narrow["kill_chain"])


def test_shortest_path_respects_window():
    g = _two_sector_graph()
    assert g.shortest_path("host:10.0.0.5", "sector:fintech") is not None
    assert g.shortest_path("host:10.0.0.5", "sector:fintech", window_s=7 * DAY)
    assert g.shortest_path("host:10.0.0.5", "sector:fintech", window_s=3600) is None


def test_hydrate_reproduces_windows_from_stored_flows(tmp_path):
    from spectra.store import Store

    store = Store(str(tmp_path / "w.db"))
    store.save_flow(rec(sni="pay.bank.example", dst="10.1.0.10:443", ts=NOW - 3 * DAY),
                    score=None, anomaly=False)
    store.save_flow(rec(sni="portal.hospital.example", dst="10.2.0.20:443", ts=NOW),
                    score=None, anomaly=False)
    g = CorrelationGraph()
    g.hydrate(store)
    store.close()
    assert set(cascade(g, "host:10.0.0.5", window_s=3600)["sectors"]) == {"healthcare"}
    edge = next(e for e in g.edges_list() if e["type"] == "talks_to")
    assert edge["flow_ids"]                                   # stored row ids carried over


def test_api_window_param(tmp_path):
    import spectra.api.app as app_module

    app_module.engine.graph = _two_sector_graph()
    app_module.engine.correlation.graph = app_module.engine.graph
    client = TestClient(app_module.app)

    ok = client.get("/api/graph/cascade?id=host:10.0.0.5&window_s=3600")
    assert ok.status_code == 200
    assert ok.json()["window_s"] == 3600
    assert ok.json()["sectors"] == ["healthcare"]
    assert client.get("/api/graph/cascade?id=host:10.0.0.5").json()["window_s"] is None
    for bad in ("0", "-5"):
        assert client.get(f"/api/graph/cascade?id=host:10.0.0.5&window_s={bad}"
                          ).status_code == 400
        assert client.get(f"/api/graph/path?src=host:10.0.0.5&dst=sector:fintech"
                          f"&window_s={bad}").status_code == 400
    assert client.get("/api/graph/path?src=host:10.0.0.5&dst=sector:fintech"
                      "&window_s=3600").status_code == 404


# -- 9D: per-host-pair cadence ------------------------------------------------

def _beacons(g, gaps, sni="c2.example", src="10.0.0.5:40000", dst="203.0.113.9:443"):
    t = 1_700_000_000.0
    for gap in gaps:
        t += gap
        g.observe(rec(src=src, dst=dst, sni=sni, ts=t))
    return t


def _talks(g):
    return next(e for e in g.edges_list() if e["type"] == "talks_to")


def test_pair_cadence_regular_vs_irregular_edge_weight():
    reg, irr = CorrelationGraph(), CorrelationGraph()
    _beacons(reg, [0, 10.2, 9.7, 10.1, 9.9])            # jittered 10 s beacon
    _beacons(irr, [0, 1.0, 30.0, 4.0, 90.0])            # organic
    assert _talks(reg)["regularity"] > 0.9
    assert _talks(irr)["regularity"] < 0.3
    assert _talks(reg)["regularity"] > _talks(irr)["regularity"]
    assert _talks(reg)["weight"] == _talks(irr)["weight"]   # byte weight unchanged

    stats = cadence_stats(next(iter(reg.pair_times.values())))
    assert stats["n"] == 5 and 9.5 < stats["mean_s"] < 10.5 and stats["cv"] < 0.05


def test_pair_cadence_needs_four_flows_and_includes_the_current_one():
    g = CorrelationGraph()
    last = _beacons(g, [0, 10, 10])                       # 3 observed starts
    assert cadence_stats(next(iter(g.pair_times.values()))) is None
    assert _talks(g)["regularity"] is None
    # peek: the 4th (current) flow counts although it is not observed yet
    now = rec(sni="c2.example", dst="203.0.113.9:443", ts=last + 10)
    assert g.pair_cadence(now)["n"] == 4
    assert _talks(g)["regularity"] is None                # peeking changed nothing


def test_pair_window_is_configurable_and_bounded():
    gaps = [0, 1, 50, 2, 70, 10, 10, 10, 10, 10]        # irregular, then regular tail
    wide, narrow = CorrelationGraph(pair_window=32), CorrelationGraph(pair_window=5)
    _beacons(wide, gaps)
    _beacons(narrow, gaps)
    assert _talks(narrow)["regularity"] > 0.95            # last 5 starts only
    assert _talks(wide)["regularity"] < 0.5
    (times,) = narrow.pair_times.values()
    assert len(times) == 5                                # bounded history

    from spectra.config import Config
    assert Config().pair_window_flows == 32
    cfg = Config(pair_window_flows=7)
    assert SpectraEngine(config=cfg, persist=False).correlation.graph.pair_window == 7


def test_pair_window_env_override(monkeypatch):
    from spectra.config import Config
    monkeypatch.setenv("SPECTRA_PAIR_WINDOW_FLOWS", "9")
    assert Config.from_env().pair_window_flows == 9


def test_tracked_pairs_are_capped(monkeypatch):
    import spectra.modules.corr.graph as graph_mod
    monkeypatch.setattr(graph_mod, "PAIR_CAP", 3)
    g = CorrelationGraph()
    for i in range(10):
        g.observe(rec(dst=f"203.0.113.{i}:443", sni=f"h{i}.example"))
    assert len(g.pair_times) == 3


def test_pair_cadence_keeps_only_timestamps_and_endpoints():
    """Metadata-only: pair state holds start times, never anything payload-like."""
    import json
    g = CorrelationGraph()
    secret = "TOP-SECRET-PAYLOAD"
    t = 1_700_000_000.0
    for i in range(5):
        r = rec(sni="c2.example", dst="203.0.113.9:443", ts=t + 10 * i)
        r.update(payload=secret.encode(), client_hello=secret, raw=secret)
        g.observe(r)
    stats = g.pair_cadence(rec(sni="c2.example", dst="203.0.113.9:443", ts=t + 60))
    assert set(stats) == {"n", "mean_s", "cv", "regularity"}
    blob = json.dumps(stats) + repr(g.pair_times) + json.dumps(g.edges_list())
    assert secret not in blob
    for times in g.pair_times.values():
        assert all(isinstance(v, float) for v in times)


def test_detection_passes_pair_cadence_to_bio(tmp_path):
    from spectra.demo import make_baseline_pcap, make_suspicious_pcap
    import time as _t
    engine = SpectraEngine(model_path=str(tmp_path / "m.joblib"), persist=False)
    engine.train_from_pcap(make_baseline_pcap(str(tmp_path / "b.pcap"), n_flows=30),
                           contamination=0.05)
    seen = []
    real = engine.bio.assess

    def spy(x, **kw):
        seen.append(kw)
        return real(x, **kw)

    engine.bio.assess = spy
    engine.start("pcap", path=make_suspicious_pcap(str(tmp_path / "s.pcap")))
    deadline = _t.time() + 30
    while engine.running and _t.time() < deadline:
        _t.sleep(0.05)
    assert seen and all("pair_cadence" in kw for kw in seen)
