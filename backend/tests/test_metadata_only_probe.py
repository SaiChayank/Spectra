"""Metadata-only runtime probe (docs/33 Phase 10 §2, project rule 2.1).

A capture is built whose payload carries a unique marker three ways (inside a
TLS application-data record, in a plaintext TCP flow, in a UDP datagram).  It
is uploaded and processed, then:

* every GET route in the OpenAPI document is requested (path/query parameters
  filled from what the run produced, plus the marker itself as a search term)
  and no response may contain the marker - raw, hex, base64 (4 alignments) or
  percent-encoded;
* the engine's in-memory flow/detection buffers and the SQLite files hold no
  marker either;
* the marker exists NOWHERE under the data directory: uploads are rewritten on
  import (``spectra.capture.sanitize``) so no payload bytes are stored.  Only the
  explicit opt-in ``store_raw_captures`` keeps the upload verbatim, and a second
  test pins that opt-in as the one place payload may then rest.
"""

from __future__ import annotations

import base64
import binascii
import glob
import os
import urllib.parse

import pytest
from scapy.all import IP, UDP, PcapWriter, Raw

from spectra.demo import BASE, _pkt, tls_flow_packets

MARKER = b"SPECTRA-PROBE-9d41c7e2b0a8"


def _encodings(marker: bytes) -> dict[str, bytes]:
    out = {"raw": marker, "hex": binascii.hexlify(marker),
           "HEX": binascii.hexlify(marker).upper(),
           "url": urllib.parse.quote(marker.decode()).encode()}
    for pad in range(3):                      # base64 alignment of the marker
        enc = base64.b64encode(b"x" * pad + marker)
        out[f"b64+{pad}"] = enc[4:-4]         # the stable middle, alignment-independent
        out[f"b64u+{pad}"] = base64.urlsafe_b64encode(b"x" * pad + marker)[4:-4]
    return out


def _marked_pcap(path: str) -> str:
    pkts = tls_flow_packets(src="10.77.0.5", dst="203.0.113.50", sni="probe.example",
                            start=BASE)
    # an application-data record (type 23) carrying the marker, inside the TLS flow
    record = b"\x17\x03\x03" + (len(MARKER) + 16).to_bytes(2, "big") + MARKER + bytes(16)
    pkts.append(_pkt("10.77.0.5", "203.0.113.50", 40000, 443, "PA", 9000, 9000,
                     payload=record, t=BASE + 3.0))
    # a plaintext TCP flow whose request line carries the marker
    http = b"GET /?token=" + MARKER + b" HTTP/1.1\r\nHost: plain.example\r\n\r\n"
    pkts += [_pkt("10.77.0.6", "203.0.113.51", 41000, 80, "S", 1, 0, t=BASE + 4.0),
             _pkt("10.77.0.6", "203.0.113.51", 41000, 80, "PA", 2, 1, payload=http,
                  t=BASE + 4.1),
             _pkt("10.77.0.6", "203.0.113.51", 41000, 80, "FA", 3 + len(http), 1,
                  t=BASE + 4.2)]
    # a UDP datagram
    udp = IP(src="10.77.0.7", dst="203.0.113.52") / UDP(sport=5353, dport=5353) / Raw(load=MARKER)
    udp.time = BASE + 5.0
    pkts.append(udp)
    pkts.sort(key=lambda p: float(p.time))
    w = PcapWriter(path, sync=True)
    for p in pkts:
        w.write(p)
    w.close()
    return path


def _fill(path: str, ctx: dict) -> str | None:
    """Substitute {param} placeholders; None if we cannot (route not probeable)."""
    out = path
    for name in [seg[1:-1] for seg in path.split("/") if seg.startswith("{")]:
        if name not in ctx:
            return None
        out = out.replace("{" + name + "}", urllib.parse.quote(str(ctx[name]), safe=""))
    return out


@pytest.fixture
def probed(client, upload_capture, process_capture, tmp_path):
    cap = upload_capture(client, _marked_pcap(str(tmp_path / "probe.pcap")))
    cid = int(cap["capture_id"])
    det = process_capture(client, cid)
    assert det.get("status") == "COMPLETED", det
    return client, cid


def test_marker_reaches_the_parser_but_no_api_response(probed):
    client, cid = probed
    flows = client.get("/api/history/flows", params={"capture_id": cid, "limit": 100}).json()
    snis = {f.get("sni") for f in flows["items"]}
    assert "probe.example" in snis, "the probe capture was not actually parsed"
    assert len(flows["items"]) >= 3                       # TLS + plaintext TCP + UDP

    ctx = {"capture_id": cid, "id": "host:10.77.0.5", "src": "host:10.77.0.5",
           "dst": "ip:203.0.113.50", "q": "probe.example", "seq": 1, "leaf": 0,
           "alert_id": "x", "incident_id": 1, "user_id": 1, "model_id": "x",
           "name": "x", "a": "x", "b": "x"}
    spec = client.get("/openapi.json").json()
    needles = _encodings(MARKER)
    probed_routes, leaks = 0, []
    for route, methods in sorted(spec["paths"].items()):
        if "get" not in methods:
            continue
        path = _fill(route, ctx)
        if path is None:
            continue
        params = {p["name"]: ctx[p["name"]] for p in methods["get"].get("parameters", [])
                  if p["in"] == "query" and p.get("required") and p["name"] in ctx}
        body = client.get(path, params=params).content
        probed_routes += 1
        for kind, needle in needles.items():
            if needle in body:
                leaks.append((route, kind))
    assert probed_routes >= 40, f"only {probed_routes} GET routes were probed"
    assert not leaks, f"payload marker found in API responses: {leaks}"

    # searching for the marker itself finds nothing (the response may echo the
    # caller's own query; remove that echo before looking for stored content)
    found = client.get("/api/search", params={"q": MARKER.decode()}).json()
    assert "9d41c7e2b0a8" not in str(found).replace(MARKER.decode(), "<echo>")
    assert found["count"] == 0, found


def test_marker_is_not_in_memory_buffers_or_database(probed):
    import spectra.api.app as app_module
    client, cid = probed
    engine = app_module.engine
    mem = repr(list(engine.flows)) + repr(list(engine.detections))
    assert MARKER.decode() not in mem

    data_dir = engine.config.data_dir
    needles = _encodings(MARKER)
    holders = []
    for path in glob.glob(os.path.join(data_dir, "**", "*"), recursive=True):
        if not os.path.isfile(path):
            continue
        with open(path, "rb") as fh:
            blob = fh.read()
        if any(n in blob for n in needles.values()):
            holders.append(os.path.relpath(path, data_dir))
    assert not holders, f"payload bytes at rest by default: {holders}"


def test_raw_storage_is_an_explicit_opt_in(client, upload_capture, tmp_path):
    import spectra.api.app as app_module
    engine = app_module.engine
    cfg = engine.capture_resources.config
    assert cfg.store_raw_captures is False                # the default
    cfg.store_raw_captures = True
    try:
        pcap = _marked_pcap(str(tmp_path / "raw.pcap"))
        cap = upload_capture(client, pcap, filename="raw-optin.pcap")
        path = engine.capture_resources.storage.path_for(cap["stored_name"])
        assert MARKER in open(path, "rb").read(), "opt-in should keep the verbatim upload"
        client.delete(f"/api/captures/{cap['capture_id']}")
    finally:
        cfg.store_raw_captures = False
