"""Pair beaconing scorer v2 (spectra.modules.corr.beacon): hand-computed cases, allow-list, bounds, alert path."""

from __future__ import annotations

import pytest

from spectra.config import Config
from spectra.modules.corr import beacon
from spectra.modules.corr.beacon import BeaconTracker, as_threat, is_allowed, parse_allowlist

H = 3600.0


def rec(t, src="10.0.0.5:40000", dst="203.0.113.9:443", b=1000, sni=None, dur=1.0):
    return {"src": src, "dst": dst, "start_ts": float(t), "last_ts": t + dur, "duration": dur,
            "bytes": b * 2, "bytes_fwd": b, "sni": sni}


def run(starts, **kw):
    """Feed flows at ``starts`` (seconds) to a fresh tracker; return (tracker, verdicts in order)."""
    tr = BeaconTracker(threshold=kw.pop("threshold", 0.8))
    return tr, [tr.observe(rec(t, **kw)) for t in starts]


def steady(period, hours):
    return [i * period for i in range(int(hours * H / period) + 1)]


def jittered_starts():
    # gaps alternate 150, 450 (mean 300 s, +-50 % jitter): flows at 600k and 600k+150, then one at 4 h
    return [600 * k + o for k in range(24) for o in (0, 150)] + [14400]


# -- hand-computed scores -----------------------------------------------------------------

def test_steady_beacon_over_four_hours_alerts_with_full_score():
    # every 300 s for 4 h = 49 flows; hour bins 0..4 hold 12,12,12,12,1 flows.
    # G: Q1=Q2=Q3 -> bowley 0, MAD 0 -> 1.  S the same.  D = 5/5.  H: median 12, MAD 0 -> 1.  mean = 1.0
    _, out = run(steady(300, 4))
    v = out[-1]
    assert v["score"] == 1.0 and v["components"] == {"G": 1.0, "S": 1.0, "D": 1.0, "H": 1.0}
    assert v["pair"] == ("10.0.0.5", "203.0.113.9") and v["n"] == 49 and v["span_h"] == 4.0
    assert v["median_gap_s"] == 300.0 and v["dst_ips"] == ["203.0.113.9"] and v["sni"] is None


def test_fifty_percent_jitter_scores_as_documented():
    # 48 gaps, 24 of 150 and 24 of 450.  Inclusive quartiles of the sorted gaps: Q1 = 150, Q2 = (150 + 450)/2 = 300,
    # Q3 = 450 -> bowley = (450 + 150 - 600)/300 = 0 -> 1;  |g - 300| = 150 for all -> MAD/median = 0.5 -> 0.5;  G = 0.75.
    # S = 1 (constant sizes), D = 5/5 = 1, H = 1 (counts 12,12,12,12,1 -> MAD 0).   score = (0.75 + 1 + 1 + 1)/4 = 0.9375
    _, out = run(jittered_starts())
    v = out[-1]
    assert v["components"] == {"G": 0.75, "S": 1.0, "D": 1.0, "H": 1.0} and v["score"] == 0.9375


def test_bursty_benign_pair_does_not_alert():
    # 100 flows 20 s apart in hour 0, silence, one flow at 4 h.  G = S = 1 (the burst is perfectly regular), but
    # D = 2 active of 5 bins = 0.4 and H = 0 (median count 0):  (1 + 1 + 0.4 + 0)/4 = 0.6 < 0.8
    tr, out = run([20 * i for i in range(100)] + [4 * H])
    assert all(v is None for v in out[:-1])      # span < 3 h until the last flow
    assert out[-1] is None
    s = beacon.score_pair(sorted(tr.pairs[("10.0.0.5", "203.0.113.9")]["flows"]),
                          tr.pairs[("10.0.0.5", "203.0.113.9")]["hours"], 0.0, 4 * H)
    assert s["components"] == {"G": 1.0, "S": 1.0, "D": 0.4, "H": 0.0} and s["score"] == 0.6


def test_long_lived_single_session_has_no_verdict_but_fills_its_hour_bins():
    tr = BeaconTracker(threshold=0.0)
    assert tr.observe(rec(0, dur=6 * H)) is None     # "now" = its end (6 h): D and H exist, but G does not -> no verdict
    st = tr.pairs[("10.0.0.5", "203.0.113.9")]
    assert sorted(st["hours"]) == list(range(7))                 # hours 0..6 inclusive each count it once
    assert tr.now == 6 * H
    assert tr.observe(rec(6 * H, dur=1)) is None                 # a second session: still no timing evidence


def test_one_flow_per_hour_does_not_alert():
    # persistence and a flat histogram (D = H = 1) but only 4 unique seconds: no G, so no verdict
    _, out = run([i * H for i in range(5)], threshold=0.0)
    assert not any(out)


def test_inbound_and_internal_pairs_are_ignored():
    starts = steady(300, 4)
    tr = BeaconTracker(threshold=0.0)
    assert not any(tr.observe(rec(t, src="203.0.113.9:40000", dst="10.0.0.5:443")) for t in starts)   # external -> internal
    assert not any(tr.observe(rec(t, dst="10.9.9.9:443")) for t in starts)                          # internal -> internal
    assert not tr.pairs
    tr = BeaconTracker(internal_nets=["203.0.113.0/24"])        # the inside is configurable
    assert [tr.observe(rec(t, src="203.0.113.9:1", dst="198.51.100.1:443")) for t in starts][-1]["score"] == 1.0
    with pytest.raises(ValueError):
        BeaconTracker(internal_nets=["not-a-net"])


def test_gap_timestamps_are_unique_whole_seconds():
    # two flows per beat (0.0 and 0.5 s): unique seconds give the same G as one flow per beat; S sees every flow
    _, out = run([t + o for t in steady(300, 4) for o in (0.0, 0.5)])
    assert out[-1]["components"]["G"] == 1.0 and out[-1]["n"] == 98 and out[-1]["unique_seconds"] == 49


def test_nothing_alerts_before_three_hours_of_span():
    _, out = run(steady(60, 2.9))
    assert all(v is None for v in out)
    _, out = run(steady(60, 3))
    first = next(i for i, v in enumerate(out) if v)
    assert first == 180 and out[first]["span_h"] == 3.0          # flow 180 starts at 3 h; flow 179 ends at 10741 s < 3 h


def test_g_needs_twelve_unique_seconds_and_s_twelve_flows():
    # 3 h span, 11 flows: D and H exist but G does not -> no verdict
    starts = [0, 600, 1200, 2000, 3000, 4000, 5000, 6000, 8000, 9000, 10800]
    assert not any(run(starts, threshold=0.0)[1])
    # 12 flows -> G, S, D, H all exist
    starts = [0, 600, 1200, 2000, 3000, 4000, 5000, 6000, 8000, 9000, 10000, 10800]
    assert set(run(starts, threshold=0.0)[1][-1]["components"]) == {"G", "S", "D", "H"}
    # many flows but only 6 unique seconds: no G, no verdict
    assert not any(run([i // 10 for i in range(60)] + [3 * H], threshold=0.0)[1])


def test_sni_aggregates_destination_ips_into_one_pair():
    tr = BeaconTracker()
    out = [tr.observe(rec(t, dst=f"203.0.113.{1 + i % 2}:443", sni="C2.Example.com.")) for i, t in enumerate(steady(300, 4))]
    assert len(tr.pairs) == 1
    v = out[-1]
    assert v["sni"] == "c2.example.com" and v["pair"] == ("10.0.0.5", "c2.example.com")
    assert v["dst_ips"] == ["203.0.113.1", "203.0.113.2"] and v["n"] == 49 and v["score"] == 1.0
    assert "c2.example.com" in as_threat(v)["supporting"][0]["detail"]


def test_threshold_is_the_boundary():
    def last(threshold):
        return run(jittered_starts(), threshold=threshold)[1][-1]
    assert last(0.9375)["score"] == 0.9375        # score >= threshold alerts
    assert last(0.9376) is None


def test_random_arrivals_do_not_alert():
    starts = [0, 3, 4, 40, 41, 90, 200, 201, 900, 5000, 5001, 5100, 7000, 9000, 9001, 11000, 11500, 12000]
    assert not any(run(starts)[1])


# -- allow-list ---------------------------------------------------------------------------

# -- allow-list ---------------------------------------------------------------------------

def test_allowlist_matching():
    allow = parse_allowlist(["10.9.0.0/16", "192.0.2.7", "*.update.example.com", "NTP.example.org"])
    assert is_allowed(allow, "10.9.4.4", None)
    assert is_allowed(allow, "192.0.2.7", None)
    assert not is_allowed(allow, "192.0.2.8", None)
    assert is_allowed(allow, "8.8.8.8", "a.update.example.com")
    assert is_allowed(allow, "8.8.8.8", "ntp.example.org.")
    assert not is_allowed(allow, "8.8.8.8", "evil-update.example.com")      # suffix needs a label boundary
    assert not is_allowed(allow, "2001:db8::1", None)                        # IPv6 vs IPv4 nets: no crash, no match


# -- streaming tracker --------------------------------------------------------------------

def test_tracker_ignores_other_pairs_and_bad_records():
    tr = BeaconTracker()
    # a regular beacon that moves to a new destination every hour never builds a pair with 3 h of span
    assert not any(tr.observe(rec(t, dst=f"203.0.113.{i // 12}:443")) for i, t in enumerate(steady(300, 4)))
    assert tr.observe({"src": "10.0.0.5:1", "dst": "", "start_ts": 1.0}) is None
    assert tr.observe({"src": "10.0.0.5:1", "dst": "1.2.3.4:5"}) is None


def test_tracker_allowlist_suppresses_alert():
    tr = BeaconTracker(allowlist=["203.0.113.0/24"])
    assert not any(tr.observe(rec(t)) for t in steady(300, 4))
    tr = BeaconTracker(allowlist=["time.example.com"])
    assert not any(tr.observe(rec(t, sni="eu.time.example.com")) for t in steady(300, 4))


def test_tracker_handles_out_of_order_replay():
    _, out = run(list(reversed(steady(300, 4))))
    assert out[-1]["score"] == 1.0 and out[-1]["n"] == 49


def test_state_is_bounded(monkeypatch):
    tr = BeaconTracker()
    for i in range(1200):                                   # one pair, a flow every 60 s for 20 h
        tr.observe(rec(60 * i))
    st = tr.pairs[("10.0.0.5", "203.0.113.9")]
    assert len(st["flows"]) == beacon.KEEP == 512
    assert len(st["hours"]) <= beacon.BINS                  # old hour bins are dropped
    for i in range(40):                                     # one SNI, many destination IPs
        tr.observe(rec(i, dst=f"198.51.100.{i}:443", sni="many.example.com"))
    assert len(tr.pairs[("10.0.0.5", "many.example.com")]["ips"]) == beacon.MAX_IPS
    monkeypatch.setattr(beacon, "PAIR_CAP", 5)
    for i in range(20):
        tr.observe(rec(i, src=f"10.1.0.{i}:1"))
    assert len(tr.pairs) == 5
    tr.reset()
    assert not tr.pairs and tr.now == float("-inf")


def test_metadata_only_no_payload_is_kept_or_reported():
    def walk(o):
        if isinstance(o, dict):
            for k, x in o.items():
                yield k
                yield from walk(x)
        elif isinstance(o, (list, tuple, set, frozenset)) or hasattr(o, "maxlen"):
            for x in o:
                yield from walk(x)
        else:
            yield o
    tr = BeaconTracker()
    r = rec(0)
    r.update(payload=b"SECRET-PAYLOAD", raw=bytearray(b"xx"), ja3="abc")
    v = [tr.observe({**r, "start_ts": float(t)}) for t in steady(300, 4)][-1]
    for obj in (tr.pairs, v, as_threat(v)):
        leaves = list(walk(obj))
        assert not any(isinstance(x, (bytes, bytearray)) for x in leaves)
        assert not any("SECRET" in str(x) or x in ("payload", "raw", "ja3") for x in leaves)
    assert set(tr.pairs[("10.0.0.5", "203.0.113.9")]) == {"flows", "first", "hours", "ips"}
    assert all(isinstance(x, float | int) for f in tr.pairs[("10.0.0.5", "203.0.113.9")]["flows"] for x in f)
    assert set(v) == {"score", "components", "n", "unique_seconds", "span_h", "median_gap_s", "median_duration_s", "pair", "sni", "dst_ips"}


def test_threat_dict_shows_available_components_and_feeds_the_evidence_summary():
    from spectra.evidence import build_evidence
    v = run(steady(300, 4))[1][-1]
    threat = as_threat(v)
    assert threat["threat_type"] == "C2_BEACONING" and 0.0 < threat["confidence"] <= 0.95
    assert "G 1.00, S 1.00, D 1.00, H 1.00" in threat["supporting"][1]["detail"]
    assert "300 seconds" in build_evidence(rec(0), threat)["summary"]


# -- the alert path: flag off by default, flag on raises one grouped C2_BEACONING alert --------

def test_config_default_is_off_and_env_override(monkeypatch):
    assert Config().beaconing_enabled is False
    monkeypatch.setenv("SPECTRA_BEACONING_ENABLED", "true")
    monkeypatch.setenv("SPECTRA_BEACONING_ALLOWLIST", "10.0.0.0/8, time.example.com")
    cfg = Config.from_env()
    assert cfg.beaconing_enabled and cfg.beaconing_allowlist == ["10.0.0.0/8", "time.example.com"]


@pytest.mark.parametrize("enabled", [False, True])
def test_engine_raises_beaconing_alert_only_when_enabled(tmp_path, monkeypatch, enabled):
    from spectra.pipeline import SpectraEngine
    cfg = Config(persist=False, beaconing_enabled=enabled)
    eng = SpectraEngine(model_path=str(tmp_path / "m.joblib"), config=cfg)
    records = []
    for i in range(300):
        r = rec(60 * i)
        records.append(r)
        r.update(proto="TCP", tls_version=None, alpn=None, ja3=None, ja4=None, cipher_count=0,
                 extension_count=0, quic_version=None, packets=6, score=None, anomaly=False)
        eng.detection.publish_flow({"record": r, "score": None, "anomaly": False, "reasons": [], "feats": None})
    stamped = [r.get("alert_id") for r in records]
    alerts = [a for a in eng.threat_alerts._open.values() if a["threat_type"] == "C2_BEACONING"]
    if not enabled:
        assert alerts == [] and not any(stamped)
    else:
        assert len(alerts) == 1                      # grouped, not one alert per flow
        a = alerts[0]
        first = next(i for i, x in enumerate(stamped) if x)
        assert first == 180                          # the flow starting at 3 h: the earliest a verdict can exist
        assert stamped[first:] == [a["alert_id"]] * (300 - first)   # flow rows link back to the alert
        assert a["occurrences"] == 300 - first
        assert a["source"] == "10.0.0.5:40000" and a["severity"] in ("HIGH", "CRITICAL")
        assert "60 seconds" in a["evidence"]["summary"]
