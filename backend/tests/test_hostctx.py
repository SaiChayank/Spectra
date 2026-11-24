"""Host/destination context and corroborated beaconing (v3, ci/prereg/e22.json).

Synthetic flow records only; they test the rules as preregistered, not detection quality.
"""

from __future__ import annotations

import pickle

import pytest

from spectra.modules.corr import hostctx as hc
from spectra.modules.corr.hostctx import CorroboratedBeacon, HostContext, PeriodicityLearner

T0 = 1_700_000_000.0
L = T0 + 3600.0          # learning window = first hour


def rec(src, dst, t, *, sni=None, ja4=None, ja3=None, fwd=300, dur=0.5, **extra):
    return {"src": f"{src}:50000", "dst": f"{dst}:443", "start_ts": t, "duration": dur, "bytes_fwd": fwd,
            "sni": sni, "ja4": ja4, "ja3": ja3, **extra}


def beacon(src, dst, start, end, every=60.0, **kw):
    t = start
    while t < end:
        yield rec(src, dst, t, **kw)
        t += every


# -- P: learned periodicity ---------------------------------------------------------------------------------------------

def test_learner_learns_regular_destinations_only():
    lr = PeriodicityLearner(L)
    for r in beacon("10.0.0.5", "93.184.216.34", T0, L, every=64, sni="time.example"):
        lr.observe("10.0.0.5", "time.example", r["start_ts"])
    for t in [T0 + x for x in (1, 2, 40, 41, 300, 900, 901, 902, 1500, 2000, 2500, 3000, 3100, 3500)]:
        lr.observe("10.0.0.5", "browse.example", t)
    lr.finalize()
    assert lr.expected("time.example", L + 10)
    assert not lr.expected("browse.example", L + 10)          # irregular gaps
    assert not lr.expected("never.example", L + 10)


def test_learner_needs_enough_unique_seconds_and_ignores_flows_after_window():
    lr = PeriodicityLearner(L)
    for i in range(11):                                       # 11 < 12 unique seconds
        lr.observe("10.0.0.5", "few.example", T0 + 60 * i)
    for i in range(50):                                       # after the window: never learned
        lr.observe("10.0.0.5", "late.example", L + 60 * i)
    lr.finalize()
    assert lr.learned == {}


def test_learned_entries_expire_and_are_capped():
    lr = PeriodicityLearner(L, cap=2, expiry_s=100.0)
    for name in ("a", "b", "c"):
        for i in range(20):
            lr.observe("10.0.0.5", name, T0 + 60 * i)
    lr.finalize()
    assert list(lr.learned) == ["b", "c"]                     # cap: oldest learned dropped
    assert lr.expected("c", L + 99) and not lr.expected("c", L + 100)


# -- R and F: rarity relative to the window -----------------------------------------------------------------------------

def test_destination_novelty_and_prevalence_across_hosts():
    ctx = HostContext(L)
    ctx.observe(rec("10.0.0.1", "1.1.1.1", T0 + 5, sni="known.example"))
    for h in range(1, 21):                                    # 20 hosts after the window
        ctx.observe(rec(f"10.0.0.{h}", "2.2.2.2", L + h, sni="popular.example"))
    ctx.observe(rec("10.0.0.3", "3.3.3.3", L + 50, sni="rare.example"))
    ctx.observe(rec("10.0.0.1", "1.1.1.1", L + 60, sni="known.example"))
    assert ctx.rare_destination("rare.example")["fires"]
    pop = ctx.rare_destination("popular.example")
    assert pop["novel"] and pop["prevalence"] == 20 and pop["limit"] == 2 and not pop["fires"]
    known = ctx.rare_destination("known.example")
    assert not known["novel"] and not known["fires"]
    assert known["prevalence_measurable"]


def test_single_host_data_reports_prevalence_as_unmeasurable():
    ctx = HostContext(L)
    ctx.observe(rec("10.0.0.1", "3.3.3.3", L + 5, sni="new.example"))
    r = ctx.rare_destination("new.example")
    assert r["fires"] and r["novel"] and not r["prevalence_measurable"]


def test_fingerprint_rarity_prefers_ja4_and_ignores_learned_ones():
    ctx = HostContext(L)
    ctx.observe(rec("10.0.0.1", "1.1.1.1", T0 + 1, ja4="t13d_common", ja3="x"))
    for h in range(1, 11):
        ctx.observe(rec(f"10.0.0.{h}", "1.1.1.1", L + h, ja4="t13d_common"))
    ctx.observe(rec("10.0.0.9", "4.4.4.4", L + 30, ja4="t12d_odd", ja3="ignored"))
    ctx.observe(rec("10.0.0.9", "5.5.5.5", L + 31, ja3="only_ja3"))
    assert not ctx.rare_fingerprint(("10.0.0.1", "1.1.1.1"))["fires"]
    assert ctx.rare_fingerprint(("10.0.0.9", "4.4.4.4"))["fires"]
    assert ctx.rare_fingerprint(("10.0.0.9", "5.5.5.5"))["fires"]       # JA3 when there is no JA4
    assert not ctx.rare_fingerprint(("10.0.0.9", "6.6.6.6"))["has_fingerprint"]


def test_isolation_forest_share_per_pair_after_window():
    ctx = HostContext(L)
    ctx.observe(rec("10.0.0.1", "7.7.7.7", T0 + 1), if_flag=True)       # inside the window: not counted
    for k in range(10):
        ctx.observe(rec("10.0.0.1", "7.7.7.7", L + k), if_flag=k < 3)
    assert ctx.if_share(("10.0.0.1", "7.7.7.7")) == pytest.approx(0.3)
    assert ctx.if_share(("10.0.0.1", "8.8.8.8")) is None


def test_inbound_and_internal_destinations_are_not_pairs():
    ctx = HostContext(L)
    assert ctx.observe(rec("8.8.8.8", "10.0.0.1", L + 1)) is None           # external source
    assert ctx.observe(rec("10.0.0.1", "10.0.0.2", L + 1)) is None          # internal -> internal
    assert ctx.observe(rec("10.0.0.1", "8.8.8.8", L + 1)) == ("10.0.0.1", "8.8.8.8")


def test_host_window_statistics():
    ctx = HostContext(T0, window_s=3600)
    for i in range(6):
        ctx.observe(rec("10.0.0.1", f"9.9.9.{i % 3}", T0 + i, sni=f"s{i % 2}.example" if i % 3 else None))
    ctx.observe(rec("10.0.0.1", "9.9.9.0", T0 + 3700))
    first, second = ctx.host_windows("10.0.0.1")
    assert first["flows"] == 6 and first["distinct_snis"] == 2 and first["new_destinations"] == 3
    assert second["flows"] == 1 and second["new_destinations"] == 0


# -- fusion -------------------------------------------------------------------------------------------------------------

def _run(cb, records, flags=None):
    out = []
    for r in sorted(records, key=lambda r: r["start_ts"]):
        ev = cb.observe(r, None if flags is None else flags(r))
        if ev is not None:
            out.append(ev)
    return out


def test_beacon_to_a_known_destination_needs_corroboration():
    cb = CorroboratedBeacon(L, tau_i=None)
    pre = [rec("10.0.0.5", "203.0.0.9", T0 + 5, sni="c2.example")]          # seen once in the window, not periodic there
    recs = pre + list(beacon("10.0.0.5", "203.0.0.9", L + 10, L + 5 * 3600, sni="c2.example"))
    assert _run(cb, recs) == []                               # B fires, but nothing corroborates it
    ev = cb.evaluate(("10.0.0.5", "c2.example"))
    assert ev["B"] and not ev["P"] and not ev["R"]["fires"] and not ev["corroborated"] and not ev["alert"]


def test_beacon_to_a_novel_destination_alerts():
    cb = CorroboratedBeacon(L, tau_i=None)
    recs = list(beacon("10.0.0.5", "203.0.0.9", L + 10, L + 5 * 3600, sni="c2.example"))
    alerts = _run(cb, recs)
    assert alerts and alerts[0]["R"]["fires"] and alerts[0]["B"]
    threat = hc.as_threat(alerts[0])
    assert threat["threat_type"] == "C2_BEACONING"
    assert "rare destination" in threat["supporting"][-1]["detail"]


def test_learned_periodic_destination_is_suppressed_even_when_corroborated():
    cb = CorroboratedBeacon(L, tau_i=0.1)
    recs = list(beacon("10.0.0.5", "203.0.0.9", T0, T0 + 6 * 3600, every=64, sni="telemetry.example"))
    alerts = _run(cb, recs, flags=lambda r: True)              # every flow flagged: I fires
    ev = cb.evaluate(("10.0.0.5", "telemetry.example"))
    assert ev["P"] and ev["I"]["fires"] and ev["B"] and not ev["alert"] and alerts == []


def test_isolation_forest_share_can_corroborate():
    cb = CorroboratedBeacon(L, tau_i=0.5)
    pre = [rec("10.0.0.5", "203.0.0.9", T0 + 5, sni="c2.example")]          # known destination, irregular in the window
    recs = pre + list(beacon("10.0.0.5", "203.0.0.9", L + 10, L + 5 * 3600, sni="c2.example"))
    alerts = _run(cb, recs, flags=lambda r: r["start_ts"] >= L)
    assert alerts and alerts[0]["I"]["fires"] and not alerts[0]["R"]["fires"]


def test_results_need_twenty_flows_after_the_window():
    cb = CorroboratedBeacon(L, tau_i=None)
    _run(cb, [rec("10.0.0.5", "1.2.3.4", L + i) for i in range(19)] + [rec("10.0.0.5", "5.6.7.8", L + i) for i in range(20)])
    assert [e["pair"] for e in cb.results(20)] == [("10.0.0.5", "5.6.7.8")]


# -- invariants ---------------------------------------------------------------------------------------------------------

def test_no_payload_bytes_reach_the_state():
    marker = b"PAYLOAD-MARKER-9f1c"
    cb = CorroboratedBeacon(L, tau_i=0.5)
    recs = [rec("10.0.0.5", "203.0.0.9", t, sni="c2.example", ja4="t13d", payload=marker, raw=marker.decode())
            for t in (T0 + 1, L + 1, L + 61)]
    _run(cb, recs, flags=lambda r: True)
    blob = pickle.dumps(cb.__dict__) + pickle.dumps(cb.ctx.__dict__) + pickle.dumps(cb.learner.__dict__)
    assert marker not in blob and marker.decode().encode("utf-8") not in blob


def test_state_is_bounded(monkeypatch):
    monkeypatch.setattr(hc, "CAP_KEYS", 50)
    monkeypatch.setattr(hc, "CAP_MEMBERS", 3)
    ctx = HostContext(L)
    for i in range(500):
        ctx.observe(rec(f"10.0.{i // 250}.{i % 250}", f"8.{i // 250}.{i % 250}.1", L + i, sni=f"d{i}.example",
                        ja4=f"fp{i}"), if_flag=False)
    for i in range(10):
        ctx.observe(rec(f"10.1.0.{i}", "1.1.1.1", L + 1000 + i, sni="shared.example"))
    for d in (ctx.dest_first, ctx.dest_users, ctx.fp_users, ctx.pair_fps, ctx.pair_if):
        assert len(d) <= 50
    assert len(ctx.dest_users["shared.example"]) == 3


def test_capture_clock_only():
    import inspect

    from spectra.modules.corr import beacon as bc
    for mod in (hc, bc):
        src = inspect.getsource(mod)
        assert "import time" not in src and "datetime" not in src      # timestamps come from the flows only


# -- live wiring: off by default; with it on, a lone beacon never alerts ------------------------------------------------

def _engine(tmp_path, **cfg):
    from spectra.config import Config
    from spectra.pipeline import SpectraEngine
    return SpectraEngine(model_path=str(tmp_path / "m.joblib"), config=Config(persist=False, **cfg))


def _publish(eng, records):
    for r in records:
        r.update(proto="TCP", tls_version=None, alpn=None, cipher_count=0, extension_count=0, quic_version=None,
                 packets=6, bytes=r["bytes_fwd"] * 2, last_ts=r["start_ts"] + r["duration"], score=None, anomaly=False)
        eng.detection.publish_flow({"record": r, "score": None, "anomaly": False, "reasons": [], "feats": None})
    return [a for a in eng.threat_alerts._open.values() if a["threat_type"] == "C2_BEACONING"]


def test_corroboration_flag_defaults_off():
    from spectra.config import Config
    c = Config()
    assert c.corroboration_enabled is False and c.beaconing_enabled is False and c.corroboration_tau_i < 0


@pytest.mark.parametrize("novel", [False, True])
def test_live_engine_alerts_only_when_corroborated(tmp_path, novel):
    eng = _engine(tmp_path, beaconing_enabled=True, corroboration_enabled=True, corroboration_learn_hours=1.0)
    first = [] if novel else [rec("10.0.0.5", "203.0.0.9", T0, sni="c2.example")]
    noise = [rec("10.0.0.5", "198.51.100.7", T0 + 1, sni="other.example")]       # starts the learning window
    alerts = _publish(eng, sorted(noise + first + list(beacon("10.0.0.5", "203.0.0.9", L + 10, L + 5 * 3600,
                                                           sni="c2.example")), key=lambda r: r["start_ts"]))
    assert (len(alerts) == 1) is novel
    ev = eng.detection._beacons.engine.evaluate(("10.0.0.5", "c2.example"))
    assert ev["B"] and ev["R"]["fires"] is novel and ev["alert"] is novel
