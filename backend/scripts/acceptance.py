#!/usr/bin/env python
"""Spectra acceptance runner.

Exercises every API route group against a running server, opens the WebSocket,
runs negative-path checks, and sweeps the CLI. Prints a PASS/WARN/FAIL table.

    cd backend
    python scripts/acceptance.py                 # API + WS + CLI
    python scripts/acceptance.py --skip-cli      # API + WS only
    python scripts/acceptance.py --skip-ws       # API + CLI only

Exit code 0 = no FAILs (warnings allowed); 1 = at least one FAIL.
Requires the API to be running:  python -m spectra.cli serve --port 8787
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

BACKEND = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BASE = "http://127.0.0.1:8787"
PCAP_BASE = os.path.join(BACKEND, "demo_pcaps", "baseline.pcap")
PCAP_SUSP = os.path.join(BACKEND, "demo_pcaps", "suspicious.pcap")

results: list[tuple[str, str, str, str]] = []
PROOF_SEQ: int | None = None


def add(group: str, name: str, state: str, detail: str = "") -> None:
    results.append((group, name, state, detail))
    mark = {"pass": "PASS", "warn": "WARN", "fail": "FAIL"}[state]
    print(f"  [{mark}] {group:<12} {name}" + (f"  — {detail}" if detail else ""))


def req(method: str, path: str, body=None, timeout: int = 60):
    data = json.dumps(body).encode() if body is not None else None
    r = urllib.request.Request(
        BASE + path, data=data, method=method,
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(r, timeout=timeout) as resp:
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        try:
            return exc.code, json.loads(exc.read())
        except Exception:  # noqa: BLE001
            return exc.code, {}


def check(group: str, name: str, cond, detail="") -> bool:
    add(group, name, "pass" if cond else "fail", detail if not cond else "")
    return bool(cond)


def want(group: str, name: str, status: int, ok_codes=(200,), detail="") -> bool:
    return check(group, name, status in ok_codes,
                 f"HTTP {status} {detail}".strip())


def wait_capture(timeout: float = 45.0) -> dict:
    deadline = time.time() + timeout
    st: dict = {}
    while time.time() < deadline:
        _, st = req("GET", "/api/status")
        if not st.get("running"):
            return st
        time.sleep(0.4)
    return st


# ---------------------------------------------------------------- API groups


def run_core() -> None:
    g = "core"
    want(g, "GET /api/health", req("GET", "/api/health")[0])
    want(g, "GET /api/status", req("GET", "/api/status")[0])
    want(g, "GET /api/stats", req("GET", "/api/stats")[0])
    want(g, "GET /api/flows", req("GET", "/api/flows?limit=5")[0])
    want(g, "GET /api/detections", req("GET", "/api/detections?limit=5")[0])
    want(g, "GET /api/interfaces", req("GET", "/api/interfaces")[0])
    want(g, "GET /api/metrics", req("GET", "/api/metrics")[0])

    st, _ = req("POST", "/api/capture/start",
                {"mode": "pcap", "path": PCAP_SUSP})
    if not want(g, "POST /api/capture/start", st, (200, 409)):
        return
    final = wait_capture()
    check(g, "capture completed", not final.get("running")
          and (final.get("flows") or 0) > 0,
          f"flows={final.get('flows')} error={final.get('error')}")


def run_ws() -> None:
    g = "ws"
    try:
        import websockets  # noqa: F401
    except ImportError:
        add(g, "websocket events", "warn", "websockets lib not installed")
        return

    async def _run() -> list[str]:
        import websockets

        types: list[str] = []
        url = BASE.replace("http", "ws", 1) + "/ws/events"
        async with websockets.connect(url, open_timeout=10) as ws:
            await asyncio.to_thread(
                lambda: req("POST", "/api/capture/start",
                            {"mode": "pcap", "path": PCAP_SUSP}))
            await asyncio.to_thread(wait_capture)
            deadline = time.time() + 12
            while time.time() < deadline:
                try:
                    raw = await asyncio.wait_for(ws.recv(), timeout=4)
                except asyncio.TimeoutError:
                    break
                try:
                    types.append(json.loads(raw).get("type", "?"))
                except Exception:  # noqa: BLE001
                    continue
                if "flow" in types and "status" in types:
                    break
        return types

    try:
        types = asyncio.run(asyncio.wait_for(_run(), timeout=60))
        ok = "flow" in types and "status" in types
        check(g, "flow + status events received", ok, f"types={sorted(set(types))}")
    except Exception as exc:  # noqa: BLE001
        add(g, "flow + status events received", "fail", str(exc))


def run_model() -> None:
    g = "model"
    st, body = req("POST", "/api/model/train",
                   {"pcap_path": PCAP_BASE, "contamination": 0.05})
    check(g, "POST /api/model/train", st == 200 and body.get("n_train", 0) > 0,
          f"HTTP {st} {body.get('detail', '')}")
    st, body = req("GET", "/api/model")
    check(g, "GET /api/model", st == 200 and body.get("trained") is True,
          f"HTTP {st}")
    want(g, "GET /api/model/drift", req("GET", "/api/model/drift")[0])
    want(g, "GET /api/model/evasion", req("GET", "/api/model/evasion")[0])
    want(g, "POST /api/model/robustness", req("POST", "/api/model/robustness", {})[0])


def run_history() -> None:
    g = "history"
    for name in ("flows", "detections", "captures", "stats", "model-runs"):
        want(g, f"GET /api/history/{name}", req("GET", f"/api/history/{name}")[0])


def run_graph() -> None:
    g = "graph"
    want(g, "GET /api/graph/summary", req("GET", "/api/graph/summary")[0])
    st, snap = req("GET", "/api/graph")
    if not want(g, "GET /api/graph", st):
        return
    nodes = snap.get("nodes") or []
    edges = snap.get("edges") or []
    if not nodes:
        add(g, "node/cascade/path", "warn", "graph empty (no flows yet)")
        return
    nid = nodes[0].get("id") if isinstance(nodes[0], dict) else nodes[0]
    want(g, "GET /api/graph/node", req("GET", f"/api/graph/node?id={urllib.parse.quote(str(nid))}")[0],
         (200, 404))
    want(g, "GET /api/graph/cascade",
         req("GET", f"/api/graph/cascade?id={urllib.parse.quote(str(nid))}")[0],
         (200, 404))
    if edges:
        src = urllib.parse.quote(str(edges[0].get("source", "")))
        dst = urllib.parse.quote(str(edges[0].get("target", "")))
        want(g, "GET /api/graph/path",
             req("GET", f"/api/graph/path?src={src}&dst={dst}")[0], (200, 404))
    else:
        add(g, "GET /api/graph/path", "warn", "no edges")


def run_pqc() -> None:
    g = "pqc"
    want(g, "GET /api/pqc", req("GET", "/api/pqc")[0])
    want(g, "GET /api/pqc/inventory", req("GET", "/api/pqc/inventory")[0])
    want(g, "GET /api/pqc/scan",
         req("GET", "/api/pqc/scan?pcap=" + urllib.parse.quote(PCAP_SUSP))[0])


def run_audit() -> None:
    global PROOF_SEQ
    g = "audit"
    want(g, "GET /api/audit/head", req("GET", "/api/audit/head")[0])
    st, entries = req("GET", "/api/audit/entries?limit=5")
    check(g, "GET /api/audit/entries (key: items)", st == 200 and "items" in entries,
          f"HTTP {st}")
    want(g, "GET /api/audit/verify", req("GET", "/api/audit/verify")[0])
    st, ck = req("POST", "/api/audit/checkpoint")
    if not check(g, "POST /api/audit/checkpoint", st == 200 and "seq" in ck,
                 f"HTTP {st} {ck.get('detail', '')}"):
        return
    seq = ck["seq"]
    want(g, "GET /api/audit/checkpoint/verify",
         req("GET", f"/api/audit/checkpoint/verify?seq={seq}")[0])
    # inclusion proofs target the capture.stop entry: its leaves are the
    # session's flow records (checkpoint entries carry no leaves)
    st, stops = req("GET", "/api/audit/entries?kind=capture.stop&limit=10")
    proof_seq = None
    if st == 200:
        for item in stops.get("items", []):
            st2, proof = req("GET",
                             f"/api/audit/proof?seq={item.get('seq')}&leaf=0")
            if st2 == 200 and proof.get("merkle_root"):
                proof_seq = item.get("seq")
                break
    if check(g, "GET /api/audit/proof (capture.stop leaf 0)", proof_seq is not None,
             "no capture.stop entry with leaves found"):
        st2, proof = req("GET", f"/api/audit/proof?seq={proof_seq}&leaf=0")
        check(g, "proof carries root + siblings",
              st2 == 200 and proof.get("siblings") is not None
              and proof.get("merkle_root"),
              f"HTTP {st2} keys={list(proof)}")
        PROOF_SEQ = proof_seq
    st, cert = req("POST", "/api/audit/certificate",
                   {"profile": "hipaa", "min_flows": 1})
    if check(g, "POST /api/audit/certificate", st == 200 and cert, f"HTTP {st}"):
        st2, v = req("POST", "/api/audit/certificate/verify", {"certificate": cert})
        check(g, "POST /api/audit/certificate/verify",
              st2 == 200 and v.get("ok") is True, f"HTTP {st2} ok={v.get('ok')}")


def run_twin() -> None:
    g = "twin"
    want(g, "GET /api/twin/topology", req("GET", "/api/twin/topology")[0])
    st, pbs = req("GET", "/api/twin/playbooks")
    if not want(g, "GET /api/twin/playbooks", st):
        return
    items = pbs.get("items") or pbs.get("playbooks") or []
    name = items[0].get("name") if items and isinstance(items[0], dict) else None
    sim = {"seed": 3, "rounds": 4, "capability": 0.6}
    want(g, "POST /api/twin/simulate", req("POST", "/api/twin/simulate", sim)[0])
    if name:
        want(g, "POST /api/twin/playbook",
             req("POST", "/api/twin/playbook", {"name": name, **sim})[0])
    else:
        add(g, "POST /api/twin/playbook", "warn", "no library playbooks listed")
    want(g, "POST /api/twin/evaluate", req("POST", "/api/twin/evaluate", sim)[0])
    want(g, "POST /api/twin/recommend", req("POST", "/api/twin/recommend", sim)[0])
    want(g, "POST /api/twin/shadow",
         req("POST", "/api/twin/shadow", {"pcap": PCAP_BASE, "retrain": True})[0])


def run_bio() -> None:
    g = "bio"
    st, body = req("GET", "/api/bio/status")
    check(g, "GET /api/bio/status", st == 200 and body.get("available") is True,
          f"HTTP {st} available={body.get('available')}")
    st, body = req("POST", "/api/bio/assess",
                   {"features": [0.0] * 39, "score": 42.0})
    check(g, "POST /api/bio/assess", st == 200 and body.get("available") is True,
          f"HTTP {st} {body.get('detail', '')}")


def run_tee() -> None:
    g = "tee"
    st, q = req("POST", "/api/tee/attest", {"nonce": "acc-1"})
    if not check(g, "POST /api/tee/attest", st == 200 and q.get("signature"),
                 f"HTTP {st}"):
        return
    st, v = req("POST", "/api/tee/verify", {"quote": q, "nonce": "acc-1"})
    checks_ok = all(c.get("ok") for c in v.get("checks", []))
    check(g, "POST /api/tee/verify (7 checks)", st == 200 and v.get("ok") and checks_ok,
          f"HTTP {st} ok={v.get('ok')}")
    st, v2 = req("POST", "/api/tee/verify", {"quote": q, "measurement": "0" * 64})
    check(g, "verify rejects wrong measurement", st == 200 and v2.get("ok") is False,
          f"ok={v2.get('ok')}")
    st, inf = req("POST", "/api/tee/infer", {"features": [0.1] * 39})
    check(g, "POST /api/tee/infer", st == 200 and inf.get("score") is not None
          and inf.get("receipt"), f"HTTP {st}")
    st, fed = req("POST", "/api/tee/federate",
                  {"deltas": [[0.1, 0.2], [0.3, 0.4]], "shareholders": 2, "seed": 5})
    check(g, "POST /api/tee/federate", st == 200 and fed.get("exact") is True
          and fed.get("aggregate") == [0.4, 0.6],
          f"HTTP {st} aggregate={fed.get('aggregate')}")


def run_edge() -> None:
    g = "edge"
    st, rep = req("GET", "/api/edge/report")
    check(g, "GET /api/edge/report",
          st == 200 and all(k in rep for k in
                            ("link", "link_profiles", "micro", "deployments",
                             "slices", "slice_counts")),
          f"HTTP {st} keys={list(rep) if st == 200 else rep}")
    st, out = req("POST", "/api/edge/link", {"link": "geostationary"})
    ok = st == 200 and abs(out.get("link", {}).get("timing_scale", 0) - 40.0) < 0.01
    check(g, "POST /api/edge/link (geo, scale 40)", ok, f"HTTP {st} {out}")
    st, out = req("POST", "/api/edge/link", {"link": "terrestrial"})
    check(g, "restore terrestrial link", st == 200, f"HTTP {st}")
    st, out = req("POST", "/api/edge/slice",
                  {"record": {"sni": "portal.hospital.example", "bytes": 900,
                              "packets": 6, "duration": 1.0,
                              "tls_version": "TLS 1.3"},
                   "level": 2})
    check(g, "POST /api/edge/slice (urllc escalates)",
          st == 200 and out.get("slice") == "urllc"
          and out.get("adjusted_level") == 3, f"HTTP {st} {out}")
    st, out = req("POST", "/api/edge/deploy", {"node": "mec-acc", "slice": "embb"})
    check(g, "POST /api/edge/deploy", st == 200 and out.get("digest"),
          f"HTTP {st} {out.get('detail', '')}")


def run_negative() -> None:
    g = "negative"
    cases = [
        ("train missing field -> 422",
         ("POST", "/api/model/train", {}), (422,)),
        ("pqc/scan unknown file -> 400",
         ("GET", "/api/pqc/scan?pcap=nope.pcap", None), (400,)),
        ("graph/node unknown -> 404",
         ("GET", "/api/graph/node?id=host:nope", None), (404,)),
        ("bio/assess wrong length -> 400",
         ("POST", "/api/bio/assess", {"features": [0.1] * 3}), (400,)),
        ("tee/federate 1 party -> 400",
         ("POST", "/api/tee/federate",
          {"deltas": [[0.1]], "shareholders": 3}), (400,)),
        ("edge/link unknown -> 400",
         ("POST", "/api/edge/link", {"link": "warp_drive"}), (400,)),
        ("capture/start bad mode -> 422",
         ("POST", "/api/capture/start", {"mode": "bogus"}), (422,)),
        ("audit/proof far seq -> 404",
         ("GET", "/api/audit/proof?seq=999999&leaf=0", None), (404,)),
        ("twin/simulate rounds over cap -> 422",
         ("POST", "/api/twin/simulate", {"rounds": 999}), (422,)),
    ]
    for name, (m, p, b), codes in cases:
        st, _ = req(m, p, b)
        check(g, name, st in codes, f"got HTTP {st}, want {codes}")


# ------------------------------------------------------------------ CLI sweep


def run_cli(tmp: str) -> None:
    g = "cli"
    env = dict(os.environ)
    env["PYTHONPATH"] = BACKEND + os.pathsep + env.get("PYTHONPATH", "")
    m2 = os.path.join(tmp, "m2.joblib")

    def run(args: list[str], name: str, timeout: int = 180):
        proc = subprocess.run(
            [sys.executable, "-m", "spectra.cli", *args],
            cwd=BACKEND, env=env, capture_output=True, text=True,
            encoding="utf-8", errors="replace", timeout=timeout,
        )
        out = (proc.stdout or "") + (proc.stderr or "")
        check(g, "spectra " + name, proc.returncode == 0,
              f"exit={proc.returncode} {out.strip().splitlines()[-1][:160] if out.strip() else ''}")
        return proc

    run(["demo", "--out", os.path.join(tmp, "demo"), "--flows", "10",
         "--train", "--model", os.path.join(tmp, "m.joblib")], "demo")
    run(["train", PCAP_BASE, "--out", m2, "--contamination", "0.05"], "train")
    run(["scan", PCAP_SUSP, "--model", m2], "scan")
    run(["pqc", PCAP_SUSP], "pqc")
    run(["adversarial", PCAP_SUSP, "--model", m2], "adversarial")

    run(["audit", "entries", "--limit", "5"], "audit entries")
    run(["audit", "verify"], "audit verify")
    run(["audit", "checkpoint", "--json"], "audit checkpoint")
    proof_seq = PROOF_SEQ
    if proof_seq is None:
        try:
            _, stops = req("GET", "/api/audit/entries?kind=capture.stop&limit=5")
            proof_seq = (stops.get("items") or [{}])[0].get("seq")
        except Exception:  # noqa: BLE001
            proof_seq = None
    if proof_seq:
        run(["audit", "proof", "--seq", str(proof_seq), "--leaf", "0"],
            "audit proof")
    else:
        add(g, "spectra audit proof", "warn", "no capture.stop entry found")
    cert = os.path.join(tmp, "cert.json")
    if run(["audit", "certify", "--profile", "hipaa", "--out", cert],
           "audit certify").returncode == 0 and os.path.isfile(cert):
        run(["audit", "verify-cert", cert], "audit verify-cert")
    run(["audit", "profiles"], "audit profiles")

    run(["twin", "topology"], "twin topology")
    run(["twin", "playbooks"], "twin playbooks")
    run(["twin", "simulate", "--rounds", "4", "--seed", "3"], "twin simulate")
    run(["twin", "playbook", "--name", "beacon_containment", "--rounds", "4"],
        "twin playbook")
    run(["twin", "shadow", "--pcap", PCAP_BASE], "twin shadow")

    run(["bio", "status"], "bio status")
    run(["bio", "assess", PCAP_SUSP], "bio assess")

    proc = run(["tee", "attest", "--json"], "tee attest")
    quote = os.path.join(tmp, "quote.json")
    with open(quote, "w", encoding="utf-8") as fh:
        fh.write(proc.stdout)
    run(["tee", "verify", quote], "tee verify")
    run(["tee", "infer", PCAP_SUSP], "tee infer")
    run(["tee", "federate", "--pcap", PCAP_SUSP], "tee federate")

    run(["edge", "report"], "edge report")
    run(["edge", "link", "leo_satellite"], "edge link")
    run(["edge", "link", "terrestrial"], "edge link restore")
    run(["edge", "slice", "--sni", "x.example", "--bytes", "500",
         "--packets", "4", "--level", "2"], "edge slice")
    run(["edge", "deploy", "mec-cli-acc", "--slice", "embb"], "edge deploy")

    run(["status"], "status")
    add(g, "spectra serve", "pass", "covered by the running acceptance server")


def _npcap_present() -> bool:
    return os.path.exists(r"C:\Windows\System32\wpcap.dll")


def _make_https_traffic() -> None:
    """Poke a few HTTPS endpoints so live capture has TLS flows to track."""
    for url in ("https://www.example.com/", "https://www.cloudflare.com/",
                "https://github.com/", "https://www.wikipedia.org/"):
        try:
            urllib.request.urlopen(url, timeout=4).read(256)
        except Exception:  # noqa: BLE001 - best-effort traffic generation
            pass
        time.sleep(0.3)


def run_live(skip: bool = False) -> None:
    """Live NIC capture: gated on Npcap; requires an elevated API server."""
    g = "live"
    if skip:
        add(g, "live capture", "warn", "skipped via --skip-live")
        return
    if not _npcap_present():
        add(g, "live capture", "warn",
            "Npcap not installed - live path unverified (install from "
            "https://nmap.org/npcap/ and rerun)")
        return

    st, body = req("GET", "/api/interfaces")
    want(g, "GET /api/interfaces", st)
    ifaces = body.get("interfaces") or []
    details = body.get("details") or []
    check(g, "interfaces listed", len(ifaces) > 0, f"got {ifaces!r}")
    if not ifaces:
        return
    # prefer the adapter that actually carries traffic (real, non-APIPA IP)
    pick = next((d["id"] for d in details
                 if d.get("ip") and not d["ip"].startswith(("169.254", "127."))),
                ifaces[0])

    st, _ = req("POST", "/api/capture/start", {"mode": "live", "iface": pick})
    if not want(g, "POST /api/capture/start (live)", st):
        return

    threading.Thread(target=_make_https_traffic, daemon=True).start()
    saw_running = False
    deadline = time.time() + 8.0
    while time.time() < deadline:
        _, poll = req("GET", "/api/status")
        saw_running = saw_running or bool(poll.get("running"))
        time.sleep(0.5)

    _, status = req("GET", "/api/status")
    packets = status.get("packets", 0)
    check(g, "live capture ran cleanly", saw_running and not status.get("error"),
          f"error={status.get('error')!r}")
    check(g, "live packets > 0", packets > 0, f"packets={packets}")

    st, _ = req("POST", "/api/capture/stop")
    want(g, "POST /api/capture/stop", st)
    _, status = req("GET", "/api/status")
    flows = status.get("flows", 0)
    check(g, "live flows tracked >= 1", flows >= 1,
          f"flows={flows}, packets={status.get('packets', 0)}")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--skip-cli", action="store_true")
    ap.add_argument("--skip-ws", action="store_true")
    ap.add_argument("--skip-live", action="store_true",
                    help="skip the Npcap-gated live capture group")
    args = ap.parse_args()

    try:
        urllib.request.urlopen(BASE + "/api/health", timeout=5)
    except Exception as exc:  # noqa: BLE001
        print(f"API not reachable at {BASE}: {exc}\n"
              f"Start it first:  cd backend && python -m spectra.cli serve --port 8787")
        return 1

    print("== core + capture ==")
    run_core()
    if not args.skip_ws:
        print("== websocket ==")
        run_ws()
    print("== model ==")
    run_model()
    print("== history ==")
    run_history()
    print("== graph (Module 7) ==")
    run_graph()
    print("== pqc (Module 1) ==")
    run_pqc()
    print("== audit (Module 5) ==")
    run_audit()
    print("== twin (Module 4) ==")
    run_twin()
    print("== bio (Module 6) ==")
    run_bio()
    print("== tee (Module 2) ==")
    run_tee()
    print("== edge (Module 8) ==")
    run_edge()
    print("== adversarial (Module 3, via robustness probe above) ==")
    print("== negative paths ==")
    run_negative()
    if not args.skip_cli:
        print("== CLI sweep ==")
        with tempfile.TemporaryDirectory(prefix="spectra_acc_") as tmp:
            run_cli(tmp)
    print("== live capture (Npcap-gated) ==")
    run_live(skip=args.skip_live)

    fails = [r for r in results if r[2] == "fail"]
    warns = [r for r in results if r[2] == "warn"]
    passes = [r for r in results if r[2] == "pass"]
    print(f"\n{len(passes)} passed, {len(warns)} warnings, {len(fails)} failed "
          f"of {len(results)} checks")
    for r in fails:
        print(f"  FAIL {r[0]} / {r[1]}: {r[3]}")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
