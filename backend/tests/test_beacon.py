"""Pair beaconing scorer (spectra.modules.corr.beacon): hand-computed cases, allow-list, alert path."""

from __future__ import annotations

import pytest

from spectra.config import Config
from spectra.modules.corr.beacon import (
    BeaconTracker,
    as_threat,
    is_allowed,
    parse_allowlist,
    score_pair,
)


def flows(starts, size=1000, dur=1.0):
    sizes = size if isinstance(size, list) else [size] * len(starts)
    return [(float(t), b, dur) for t, b in zip(starts, sizes, strict=True)]


def rec(t, src="10.0.0.5:40000", dst="203.0.113.9:443", b=1000, sni=None):
    return {"src": src, "dst": dst, "start_ts": float(t), "last_ts": t + 1.0, "duration": 1.0,
            "bytes": b, "sni": sni}


# -- hand-computed scores -----------------------------------------------------------------

def test_metronome_scores_one():
    s = score_pair(flows(range(0, 80, 10)))               # 8 flows, every 10 s, same size
    assert s["score"] == 1.0
    assert (s["n"], s["median_gap_s"], s["regularity"], s["jitter_ratio"], s["size_cv"]) == (8, 10.0, 1.0, 0.0, 0.0)


def test_one_outage_hurts_cv_but_not_the_robust_part():
    # gaps 10 x6 then 30: mean 90/7, pstdev sqrt(16800/343)=6.9985, cv 0.5443 -> regularity 0.4557
    # median gap 10, MAD 0 -> robust part 1, sizes equal -> 1;  (0.4557 + 1 + 1) / 3 = 0.8186
    s = score_pair(flows([0, 10, 20, 30, 40, 50, 60, 90]))
    assert s["regularity"] == 0.4557
    assert s["score"] == 0.8186


def test_jitter_ratio_is_mad_over_median():
    # gaps 9,10,11,10,9,11,10: mean 10, var 4/7 -> cv 0.0756 -> regularity 0.9244;
    # |gap - 10| = 1,0,1,0,1,1,0 -> MAD 1 -> jitter 0.1 -> robust part 0.9;  (0.9244 + 0.9 + 1) / 3 = 0.9415
    s = score_pair(flows([0, 9, 19, 30, 40, 49, 60, 70]))
    assert s["jitter_ratio"] == 0.1
    assert s["score"] == 0.9415


def test_size_consistency_part():
    # sizes alternate 1000/3000: mean 2000, pstdev 1000, cv 0.5 -> part 0.5;  (1 + 1 + 0.5) / 3 = 0.8333
    s = score_pair(flows(range(0, 80, 10), size=[1000, 3000] * 4))
    assert s["size_cv"] == 0.5
    assert s["score"] == 0.8333


def test_not_scorable_cases():
    assert score_pair(flows(range(0, 70, 10))) is None                  # 7 flows < 8
    assert score_pair(flows([i * 0.5 for i in range(8)])) is None       # median gap 0.5 s: a burst, not a beacon
    assert score_pair(flows([5.0] * 8)) is None                         # all at one instant (mean gap 0)


def test_random_arrivals_score_low():
    starts = [0, 3, 4, 40, 41, 90, 200, 201]
    assert score_pair(flows(starts))["score"] < 0.5


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

def test_tracker_alerts_at_eighth_regular_flow_only():
    tr = BeaconTracker(threshold=0.8)
    out = [tr.observe(rec(10 * i)) for i in range(8)]
    assert out[:7] == [None] * 7
    v = out[7]
    assert v["pair"] == ("10.0.0.5", "203.0.113.9") and v["score"] == 1.0 and v["n"] == 8


def test_tracker_threshold_is_the_boundary():
    starts = [0, 10, 20, 30, 40, 50, 60, 90]                 # scores 0.8186 (see above)
    def last(threshold):
        tr = BeaconTracker(threshold=threshold)
        return [tr.observe(rec(t)) for t in starts][-1]
    assert last(0.82) is None
    assert last(0.81)["score"] == 0.8186


def test_tracker_ignores_irregular_and_other_pairs():
    tr = BeaconTracker(threshold=0.8)
    assert all(tr.observe(rec(t)) is None for t in [0, 3, 4, 40, 41, 90, 200, 201, 500])
    # eight regular flows spread over eight different destinations never form a pair
    assert all(tr.observe(rec(10 * i, dst=f"203.0.113.{i}:443")) is None for i in range(8))


def test_tracker_allowlist_suppresses_alert():
    tr = BeaconTracker(threshold=0.8, allowlist=["203.0.113.0/24"])
    assert all(tr.observe(rec(10 * i)) is None for i in range(12))
    tr = BeaconTracker(threshold=0.8, allowlist=["time.example.com"])
    assert all(tr.observe(rec(10 * i, sni="eu.time.example.com")) is None for i in range(12))


def test_tracker_handles_out_of_order_replay_and_is_bounded():
    tr = BeaconTracker(threshold=0.8, window=16)
    for i in reversed(range(12)):
        last = tr.observe(rec(10 * i))
    assert last is not None and last["n"] == 12
    for i in range(100):
        tr.observe(rec(10 * i))
    assert len(tr.pairs[("10.0.0.5", "203.0.113.9")]) == 16
    tr.reset()
    assert not tr.pairs


def test_threat_dict_is_metadata_only_and_feeds_the_evidence_summary():
    from spectra.evidence import build_evidence
    tr = BeaconTracker(threshold=0.8)
    v = [tr.observe(rec(30 * i)) for i in range(8)][-1]
    threat = as_threat(v)
    assert threat["threat_type"] == "C2_BEACONING" and 0.0 < threat["confidence"] <= 0.95
    ev = build_evidence(rec(0), threat)
    assert "30 seconds" in ev["summary"]
    assert set(v) <= {"score", "n", "median_gap_s", "regularity", "jitter_ratio", "size_cv",
                      "median_duration_s", "pair", "sni"}          # numbers, addresses, SNI: no payload field


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
    for i in range(10):
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
        assert stamped[:7] == [None] * 7 and stamped[7:] == [a["alert_id"]] * 3   # flow rows link back to the alert
        assert a["occurrences"] == 3                 # flows 8, 9, 10
        assert a["source"] == "10.0.0.5:40000" and a["severity"] in ("HIGH", "CRITICAL")
        assert "60 seconds" in a["evidence"]["summary"]
