"""Set-B beacon simulator: pure schedule/manifest generator (no network, no docker)."""
import importlib.util
import ipaddress
from collections import Counter
from pathlib import Path

SIM = Path(__file__).resolve().parents[1] / "scripts" / "lab" / "beacon_sim"
_spec = importlib.util.spec_from_file_location("simsched", SIM / "simsched.py")
S = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(S)


def test_deterministic():
    assert S.build_manifest() == S.build_manifest()
    assert S.build_manifest(seed=1) != S.build_manifest()
    p = S.build_manifest()["hosts"][0]["profiles"][0]
    assert S.events(p, 36000) == S.events(p, 36000)


def test_cells_and_hosts():
    m = S.build_manifest()
    beacons = [(h["host"], p) for h in m["hosts"] for p in h["profiles"] if p["class"] == "beacon"]
    assert len(beacons) == 48
    cells = Counter((p["interval"], p["jitter"]) for _, p in beacons)
    assert len(cells) == 16 and set(cells.values()) == {3}
    for h in m["hosts"]:
        ivs = [p["interval"] for p in h["profiles"] if p["class"] == "beacon"]
        assert sorted(ivs) == sorted(S.INTERVALS)


def test_addresses():
    m = S.build_manifest()
    srv, cli = ipaddress.ip_network(S.SERVER_HALF), ipaddress.ip_network(S.CLIENT_HALF)
    assert all(ipaddress.ip_address(s["ip"]) in srv for s in m["servers"])
    assert len({s["ip"] for s in m["servers"]}) == len(m["servers"])
    assert all(ipaddress.ip_address(h["ip"]) in cli for h in m["hosts"])


def test_beacon_event_shape():
    p = next(p for p in S.build_manifest()["hosts"][0]["profiles"] if p["class"] == "beacon" and p["interval"] == 60)
    ev = S.events(p, 36000)
    assert 590 <= len(ev) <= 610 and ev[0][0] < 60 and all(300 * .95 <= e[3] <= 300 * 1.05 for e in ev)


def test_committed_compose_matches_generator():
    assert (SIM / "docker-compose.yml").read_text() == S.compose(S.build_manifest())
