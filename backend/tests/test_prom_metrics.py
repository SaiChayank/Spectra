"""Prometheus exposition (Phase 11): parsed by the official client's parser.

The previous metrics tests only grepped for substrings.  Here the whole body is
fed to ``prometheus_client.parser`` (an independent implementation of the text
format), histograms are checked for the invariants Prometheus relies on, the
scrape is proven side-effect free, and the optional metrics-only bearer token
is pinned to exactly one route.
"""

from __future__ import annotations

import secrets
import time

import pytest
from fastapi.testclient import TestClient
from prometheus_client.parser import text_string_to_metric_families

from spectra.api.app import app
from spectra.api.runtime import engine as api_engine
from spectra.config import Config
from spectra.demo import make_baseline_pcap, make_suspicious_pcap
from spectra.pipeline import SpectraEngine

CT = "text/plain; version=0.0.4; charset=utf-8"


def parse(text):
    return {f.name: f for f in text_string_to_metric_families(text)}


def samples(text):
    return [(s.name, dict(s.labels), s.value)
            for f in text_string_to_metric_families(text) for s in f.samples]


@pytest.fixture(scope="module")
def ran(tmp_path_factory):
    """A local engine that trained, processed a capture and computed drift."""
    tmp = tmp_path_factory.mktemp("prom")
    cfg = Config(persist=True)
    cfg.data_dir = str(tmp / "d")
    cfg.db_path = str(tmp / "d" / "spectra.db")
    cfg.capture_store_dir = str(tmp / "d" / "c")
    cfg.model_path = str(tmp / "d" / "m.joblib")
    cfg.ensure_dirs()
    e = SpectraEngine(config=cfg)
    e.train_from_pcap(make_baseline_pcap(str(tmp / "b.pcap"), n_flows=60), contamination=0.05)
    e.start("pcap", path=make_suspicious_pcap(str(tmp / "s.pcap")))
    deadline = time.time() + 30
    while e.running and time.time() < deadline:
        time.sleep(0.05)
    assert not e.running
    e.model.drift_report()          # a drift check populates the cached numbers the scrape reads
    return e


def test_idle_engine_exposition_is_valid_and_typed():
    e = SpectraEngine(persist=False)
    text = e.system.metrics()
    fams = parse(text)                                  # raises on any malformed line
    assert "spectra_build_info" in fams and "spectra_packets" in fams
    untyped = [n for n, f in fams.items() if f.type == "unknown"]
    assert not untyped, f"series without a TYPE line: {untyped}"
    assert text.endswith("\n")
    # series that only exist once measured are absent, not faked as zero
    names = {n for n, _, _ in samples(text)}
    assert "spectra_drift_psi" not in names


def test_required_operational_series_after_a_run(ran):
    text = ran.system.metrics()
    names = {n for n, _, _ in samples(text)}
    for must in ("spectra_queue_depth", "spectra_packet_queue_dropped_total",
                 "spectra_flow_queue_depth", "spectra_publish_queue_depth",
                 "spectra_build_info", "spectra_audit_head_seq",
                 "spectra_inference_duration_seconds_count",
                 "spectra_db_write_duration_seconds_count",
                 "spectra_drift_psi", "spectra_drift_level"):
        assert must in names, f"missing series {must}"
    drift = {s[1]["baseline"]: s[2] for s in samples(text) if s[0] == "spectra_drift_psi"}
    assert "train" in drift and drift["train"] >= 0.0


def test_histograms_satisfy_prometheus_invariants(ran):
    fams = parse(ran.system.metrics())
    for name in ("spectra_inference_duration_seconds", "spectra_db_write_duration_seconds"):
        fam = fams[name]
        assert fam.type == "histogram"
        buckets = [(s.labels["le"], s.value) for s in fam.samples if s.name.endswith("_bucket")]
        bounds = [float("inf") if le == "+Inf" else float(le) for le, _ in buckets]
        counts = [v for _, v in buckets]
        assert bounds == sorted(bounds) and bounds[-1] == float("inf")
        assert counts == sorted(counts), "buckets must be cumulative"
        count = next(s.value for s in fam.samples if s.name.endswith("_count"))
        total = next(s.value for s in fam.samples if s.name.endswith("_sum"))
        assert counts[-1] == count and total >= 0
    assert next(s.value for s in fams["spectra_inference_duration_seconds"].samples
                if s.name.endswith("_count")) > 0


def test_bio_verdict_counts_cover_every_response_and_sum_to_assessed(ran):
    s = [x for x in samples(ran.system.metrics()) if x[0] == "spectra_bio_assessments_total"]
    assert {x[1]["response"] for x in s} == {"ignore", "monitor", "alert", "isolate"}
    assert sum(x[2] for x in s) == ran.bio.n_assessed > 0


def test_label_values_are_escaped():
    e = SpectraEngine(persist=False)
    e.status["failures"]['we"ird\\comp\nonent'] = 3
    fams = parse(e.system.metrics())                    # a bad escape would raise here
    labels = [s.labels["component"] for s in fams["spectra_pipeline_failures"].samples]
    assert 'we"ird\\comp\nonent' in labels


def test_a_scrape_has_no_side_effects(ran, monkeypatch):
    def boom(*a, **k):
        raise AssertionError("a metrics scrape must not recompute drift")
    monkeypatch.setattr(ran.model, "drift_report", boom)
    before = ran.audit_service.head()["seq"]
    first, second = ran.system.metrics(), ran.system.metrics()
    assert ran.audit_service.head()["seq"] == before
    assert [n for n, _, _ in samples(first)] == [n for n, _, _ in samples(second)]


# -- HTTP surface -----------------------------------------------------------------------------

def test_endpoint_headers_and_roles(client, raw_client, viewer_client):
    res = client.get("/api/metrics")
    assert res.status_code == 200 and res.headers["content-type"] == CT
    assert parse(res.text)
    assert viewer_client.get("/api/metrics").status_code == 200
    assert raw_client.get("/api/metrics").status_code == 401


# -- the optional metrics-only bearer token ------------------------------------------------------

@pytest.fixture
def token(monkeypatch):
    t = secrets.token_urlsafe(32)
    monkeypatch.setattr(api_engine.config, "metrics_token", t)
    return t


def _anon():
    c = TestClient(app)
    c.cookies.clear()
    return c


def test_token_is_off_by_default(raw_client):
    assert Config().metrics_token == ""
    assert raw_client.get("/api/metrics", headers={"Authorization": "Bearer "}).status_code == 401
    assert raw_client.get("/api/metrics", headers={"Authorization": "Bearer anything"}).status_code == 401


def test_token_opens_the_metrics_route_and_nothing_else(token):
    ok = _anon().get("/api/metrics", headers={"Authorization": f"Bearer {token}"})
    assert ok.status_code == 200 and ok.headers["content-type"] == CT and parse(ok.text)
    assert token not in ok.text
    for path in ("/api/flows", "/api/auth/me", "/api/model", "/api/users", "/api/audit/entries"):
        assert _anon().get(path, headers={"Authorization": f"Bearer {token}"}).status_code == 401, path
    assert _anon().post("/api/capture/stop", headers={"Authorization": f"Bearer {token}"}).status_code == 401
    assert _anon().get("/api/metrics", headers={"Authorization": f"Bearer {token}x"}).status_code == 401
    assert _anon().get("/api/metrics", headers={"Authorization": f"Bearer {token[:-1]}"}).status_code == 401
    assert _anon().get("/api/metrics").status_code == 401


def test_sessions_still_work_when_a_token_is_configured(token, client):
    assert client.get("/api/metrics").status_code == 200
    assert client.get("/api/auth/me").status_code == 200


def test_token_grants_no_role_beyond_scraping(token):
    # the synthetic scraper principal must not leak into other dependencies
    res = _anon().get("/api/metrics", headers={"Authorization": f"Bearer {token}"})
    assert res.status_code == 200
    me = _anon().get("/api/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert me.status_code == 401


def test_a_short_token_is_refused_at_startup(monkeypatch):
    with pytest.raises(ValueError, match="at least 32"):
        Config(metrics_token="too-short")
    monkeypatch.setenv("SPECTRA_METRICS_TOKEN", "x" * 31)
    with pytest.raises(ValueError):
        Config.from_env()
    monkeypatch.setenv("SPECTRA_METRICS_TOKEN", "x" * 32)
    assert Config.from_env().metrics_token == "x" * 32
