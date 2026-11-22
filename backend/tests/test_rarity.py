from spectra.modules.corr.rarity import score_window


def _f(src, dst, t, sni=None, dur=0.0):
    return {"src": f"{src}:50000", "dst": f"{dst}:443", "start_ts": t, "duration": dur, "sni": sni}


def _net(extra=()):
    recs = [_f(f"10.0.0.{i}", "8.8.8.8", h * 3600.0 + i, "Popular.example.") for i in range(1, 11) for h in range(3)]
    return recs + list(extra)


def test_too_few_hosts_gives_no_verdict():
    assert score_window([_f("10.0.0.1", "1.2.3.4", 0.0)] * 3) is None


def test_rare_persistent_destination_scores_one_and_popular_is_low():
    c2 = [_f("10.0.0.3", "6.6.6.6", h * 3600.0) for h in range(4)]
    out = score_window(_net(c2))
    assert out["N"] == 10
    h3 = out["hosts"]["10.0.0.3"]
    assert h3["score"] == 1.0 and h3["alert"] and h3["top"][0]["dest"] == "6.6.6.6"
    assert out["hosts"]["10.0.0.1"]["score"] == 0.1      # popular.example shared by 10 hosts, SNI lower-cased


def test_single_flow_internal_and_one_hour_rules():
    extra = [_f("10.0.0.4", "7.7.7.7", 5.0),                            # one flow: not scored
             _f("10.0.0.5", "10.0.0.9", 5.0), _f("10.0.0.5", "10.0.0.9", 9.0),   # internal-internal: ignored
             _f("10.0.0.6", "5.5.5.5", 10.0), _f("10.0.0.6", "5.5.5.5", 20.0),   # unique, one hour -> 1/3
             _f("10.0.0.7", "4.4.4.4", 3599.0, dur=2.0), _f("10.0.0.7", "4.4.4.4", 3599.0, dur=2.0)]  # dup + spans 2 h
    h = score_window(_net(extra))["hosts"]
    assert h["10.0.0.4"]["score"] == 0.1 and h["10.0.0.5"]["score"] == 0.1
    assert abs(h["10.0.0.6"]["score"] - 1 / 3) < 1e-9 and not h["10.0.0.6"]["alert"]
    assert h["10.0.0.7"]["score"] == 0.1          # duplicate flow removed -> 1 flow -> not scored
