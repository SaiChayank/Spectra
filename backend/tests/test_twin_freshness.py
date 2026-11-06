"""Phase 9H: the twin/correlation graph says how stale it is.

The twin is built from the correlation graph, which is only rebuilt from the
persisted flows at hydrate time (API start, capture start).  ``flow_lag`` is
the newest persisted flow time minus the newest flow time the graph has seen,
so it grows when flows are persisted behind the graph's back and returns to
zero on re-hydrate.  (JA4S/JA4L, the other half of 9H, are NOT built: JA4+ is
under FoxIO License 1.1 - see HANDOFF_FINDINGS.md.)
"""

from __future__ import annotations

from spectra.config import Config
from spectra.modules.corr import CorrelationGraph
from spectra.pipeline import SpectraEngine
from spectra.services.correlation import STALE_FLOW_LAG_S

T0 = 1_700_000_000.0


def _rec(ts, dst="93.184.216.34:443"):
    return {"src": "10.0.0.5:40000", "dst": dst, "sni": "example.com", "bytes": 100,
            "start_ts": ts, "last_ts": ts, "proto": "TLSv1.3", "packets": 5,
            "duration": 1.0, "tls_version": "TLSv1.3"}


def _engine(tmp_path):
    cfg = Config(persist=True)
    cfg.data_dir = str(tmp_path / "d")
    cfg.db_path = str(tmp_path / "d" / "spectra.db")     # db_path is resolved at construction
    cfg.capture_store_dir = str(tmp_path / "d" / "c")
    cfg.model_path = str(tmp_path / "d" / "m.joblib")
    cfg.ensure_dirs()
    return SpectraEngine(config=cfg)


def _persist(engine, ts):
    engine.store.save_flow(_rec(ts), score=1.0, anomaly=False)


def test_graph_tracks_its_hydrate_time_and_newest_flow_seen(tmp_path):
    g = CorrelationGraph()
    assert g.hydrated_at is None and g.cursor_ts is None
    g.observe(_rec(T0 + 5))
    g.observe(_rec(T0 + 2))
    assert g.cursor_ts == T0 + 5 and g.hydrated_at is None     # live flows are not a hydrate
    g.reset()
    assert g.cursor_ts is None and g.hydrated_at is None


def test_flow_lag_grows_without_rehydrate_and_resets_on_rehydrate(tmp_path):
    e = _engine(tmp_path)
    _persist(e, T0)
    e.correlation.hydrate()
    f = e.correlation.freshness()
    assert f["hydrated_at"] is not None and f["flow_lag"] == 0 and f["stale"] is False

    _persist(e, T0 + 60)                    # persisted behind the graph's back
    lag1 = e.correlation.freshness()["flow_lag"]
    _persist(e, T0 + 600)
    f2 = e.correlation.freshness()
    assert lag1 == 60 and f2["flow_lag"] == 600 > lag1          # grows, no re-hydrate
    assert f2["hydrated_at"] == f["hydrated_at"]                 # still the old hydrate
    assert f2["stale"] is True and 600 > STALE_FLOW_LAG_S

    e.correlation.hydrate()
    f3 = e.correlation.freshness()
    assert f3["flow_lag"] == 0 and f3["stale"] is False
    assert f3["hydrated_at"] >= f["hydrated_at"]


def test_live_flows_keep_the_cursor_current(tmp_path):
    e = _engine(tmp_path)
    _persist(e, T0)
    e.correlation.hydrate()
    for ts in (T0 + 30, T0 + 90):           # flows the graph sees as they happen
        _persist(e, ts)
        e.correlation.observe(_rec(ts))
    assert e.correlation.freshness()["flow_lag"] == 0


def test_freshness_is_unknown_without_persistence():
    e = SpectraEngine(persist=False)
    f = e.correlation.freshness()
    assert f["hydrated_at"] is None and f["flow_lag"] is None and f["stale"] is False


def test_api_topology_and_graph_report_freshness(client):
    topo = client.get("/api/twin/topology").json()
    assert {"hydrated_at", "flow_lag", "stale"} <= set(topo)
    assert "nodes" in topo and "summary" in topo                  # payload unchanged
    graph = client.get("/api/graph").json()
    assert {"hydrated_at", "flow_lag", "stale"} <= set(graph["freshness"])


def test_topology_itself_stays_deterministic():
    from spectra.modules.twin import build_topology
    g = CorrelationGraph()
    for i in range(3):
        g.observe(_rec(T0 + i, dst=f"10.9.0.{i}:443"))
    assert build_topology(g) == build_topology(g)
