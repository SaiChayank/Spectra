"""Lab-only client: replays every profile of one host from /out/manifest.json on a timer.

Each check-in = new TCP + TLS 1.3 connection, one small POST, read the response, close.
Certificates are NOT verified (lab only, own servers). Runs tcpdump on its own interface to
/out/host-NN.pcap, writes a heartbeat line per minute, exits 0 after DURATION_S.
"""
import http.client
import json
import os
import signal
import socket
import ssl
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor

sys.path.insert(0, os.path.dirname(__file__))
import simsched as S  # noqa: E402

idx, dur = int(os.environ["HOST_IDX"]), int(os.environ["DURATION_S"])
man = json.load(open("/out/manifest.json"))
host = man["hosts"][idx]
name = f"host-{idx:02d}"
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
ctx.minimum_version = ssl.TLSVersion.TLSv1_3
stats = {"ok": 0, "err": 0}
lock = threading.Lock()


def checkin(sni, ip, req, resp):
    try:
        s = ctx.wrap_socket(socket.create_connection((ip, 443), timeout=30), server_hostname=sni)
        c = http.client.HTTPConnection(sni)
        c.sock = s
        c.request("POST", f"/?n={resp}", body=b"a" * req, headers={"Connection": "close"})
        r = c.getresponse()
        r.read()
        c.close()
        with lock:
            stats["ok" if r.status == 200 else "err"] += 1
    except Exception:  # noqa: BLE001 - counted, not hidden: heartbeat shows err
        with lock:
            stats["err"] += 1


def heartbeat(t0):
    with open(f"/out/{name}.heartbeat.log", "a") as f:
        while True:
            with lock:
                st = dict(stats)
            f.write(json.dumps({"wall": time.time(), "mono": time.monotonic(),
                                "since_start_s": round(time.monotonic() - t0, 1), **st}) + "\n")
            f.flush()
            time.sleep(60)


ev = sorted(e for p in host["profiles"] for e in S.events(p, dur))
dump = subprocess.Popen(["tcpdump", "-i", "eth0", "-p", "-s", "0", "-U", "-Z", "root",
                         "-w", f"/out/{name}.pcap"], stderr=subprocess.DEVNULL)
time.sleep(3)  # let tcpdump and servers come up
t0 = time.monotonic()
open(f"/out/{name}.heartbeat.log", "a").write(json.dumps({"start_wall": time.time(), "events": len(ev)}) + "\n")
threading.Thread(target=heartbeat, args=(t0,), daemon=True).start()
with ThreadPoolExecutor(16) as pool:
    for t, sni, ip, req, resp in ev:
        time.sleep(max(0.0, t0 + t - time.monotonic()))
        pool.submit(checkin, sni, ip, req, resp)
time.sleep(max(0.0, t0 + dur - time.monotonic()))
time.sleep(5)
with open(f"/out/{name}.heartbeat.log", "a") as f:
    f.write(json.dumps({"end_wall": time.time(), **stats}) + "\n")
dump.send_signal(signal.SIGINT)
dump.wait(20)
