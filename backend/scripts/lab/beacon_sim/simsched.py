"""Pure schedule + manifest generator for the set-B beacon simulator (stdlib only).

Nothing here touches the network. `events(profile, ...)` returns the full list of
(t_offset_s, sni, request_bytes, response_bytes) for one profile; the client replays it.
CLI: `python3 simsched.py compose > docker-compose.yml` (committed, checked by a test).
"""
from __future__ import annotations

import json
import math
import random
import sys

SEED = 1337
HOSTS = 12
DURATION_S = 36000
INTERVALS = (10, 60, 300, 1800)
JITTERS = (0, 25, 50, 75)
NET = "203.0.113.0/24"
SERVER_HALF, CLIENT_HALF = "203.0.113.0/25", "203.0.113.128/25"
B1_SNIS = [f"b1-{i}.lab.example" for i in range(6)]
# class -> (server name, sni); shared by all hosts
BENIGN = {"B2": "b2.lab.example", "B3": "b3.lab.example", "B4": "b4.lab.example",
          "B5": "b5.lab.example", "B6": "b6.lab.example"}


def cell_sni(interval: int, jitter: int) -> str:
    return f"c-{interval}-{jitter}.lab.example"


def servers(seed: int = SEED) -> list[dict]:
    out = [{"name": f"srv-c-{i}-{j}", "sni": cell_sni(i, j), "class": "beacon"}
           for i in INTERVALS for j in JITTERS]
    out += [{"name": f"srv-b1-{k}", "sni": s, "class": "B1"} for k, s in enumerate(B1_SNIS)]
    out += [{"name": f"srv-{c.lower()}", "sni": s, "class": c} for c, s in BENIGN.items()]
    for k, s in enumerate(out):
        s["ip"] = f"203.0.113.{10 + k}"  # servers in .0/25 (gateway is .1)
    return out


def build_manifest(seed: int = SEED, hosts: int = HOSTS, duration_s: int = DURATION_S) -> dict:
    assert hosts % 4 == 0
    srv = servers(seed)
    ip = {s["sni"]: s["ip"] for s in srv}
    rot = random.Random(f"{seed}-rotation")
    shift = {i: rot.randrange(4) for i in INTERVALS}  # jitter index = (host + shift) % 4
    scale = min(1.0, duration_s / DURATION_S)  # only B2 periods / B3 windows scale (dry runs)
    hs = []
    for h in range(hosts):
        profs = []
        for i in INTERVALS:
            j = JITTERS[(h + shift[i]) % 4]
            sni = cell_sni(i, j)
            profs.append({"class": "beacon", "sni": sni, "ip": ip[sni], "interval": i,
                          "jitter": j, "seed": f"{seed}-{h}-beacon-{i}-{j}"})
        rnd = random.Random(f"{seed}-{h}-windows")
        a, b = sorted(rnd.uniform(0, duration_s - 4 * 7200 * scale) for _ in range(2))
        w = 7200 * scale
        profs.append({"class": "B1", "sni": B1_SNIS, "ip": [ip[s] for s in B1_SNIS],
                      "seed": f"{seed}-{h}-B1"})
        profs.append({"class": "B2", "sni": BENIGN["B2"], "ip": ip[BENIGN["B2"]],
                      "seed": f"{seed}-{h}-B2", "scale": scale})
        profs.append({"class": "B3", "sni": BENIGN["B3"], "ip": ip[BENIGN["B3"]],
                      "seed": f"{seed}-{h}-B3", "windows": [[a, a + w], [b + w, b + 2 * w]]})
        for c, interval, jit in (("B4", 300, 0.10), ("B5", 64, 0.0), ("B6", 3600, 300 / 3600)):
            profs.append({"class": c, "sni": BENIGN[c], "ip": ip[BENIGN[c]], "interval": interval,
                          "jitter_frac": jit, "seed": f"{seed}-{h}-{c}"})
        hs.append({"host": h, "ip": f"203.0.113.{129 + h}", "profiles": profs})
    return {"seed": seed, "duration_s": duration_s, "network": NET, "servers": srv, "hosts": hs}


def _periodic(rng, duration, interval, jit, size_fn):
    t = rng.uniform(0, interval)
    out = []
    while t < duration:
        out.append((t, *size_fn(rng)))
        t += interval * (1 + rng.uniform(-jit, jit))
    return out


def events(p: dict, duration: int) -> list[tuple]:
    """[(t_offset_s, sni, ip, req_bytes, resp_bytes)] for one profile, sorted by time."""
    rng = random.Random(p["seed"])
    c = p["class"]
    sni, ip = p["sni"], p["ip"]
    u = lambda lo, hi: int(rng.uniform(lo, hi))  # noqa: E731
    if c == "beacon":
        def sz(r):
            resp = r.uniform(2000, 20000) if r.random() < 0.05 else 200 * r.uniform(.95, 1.05)
            return int(300 * r.uniform(.95, 1.05)), int(resp)
        ev = _periodic(rng, duration, p["interval"], p["jitter"] / 100, sz)
    elif c in ("B4", "B5", "B6"):
        sz = {"B4": lambda r: (int(r.uniform(500, 20000)), 300),
              "B5": lambda r: (100, 100),
              "B6": lambda r: (int(r.uniform(900, 1100)), int(r.uniform(900, 1100)))}[c]
        ev = _periodic(rng, duration, p["interval"], p["jitter_frac"], sz)
    elif c == "B1":
        ev, t = [], rng.expovariate(1 / 1200)
        while t < duration:
            s = t
            for _ in range(rng.randint(5, 40)):
                k = rng.randrange(len(sni))
                resp = int(min(200000, 1000 * rng.paretovariate(1.2)))
                ev.append((s, sni[k], ip[k], u(200, 2000), resp))
                s += rng.lognormvariate(math.log(2), 1.0)
            t += rng.expovariate(1 / 1200)
        return sorted(e for e in ev if e[0] < duration)
    elif c == "B2":
        sc = p["scale"]
        ev, t, active = [], 0.0, rng.random() < 0.5
        while t < duration:
            end = t + sc * 60 * (rng.uniform(60, 120) if active else rng.uniform(30, 90))
            while active and t < min(end, duration):
                ev.append((t, u(100, 5000), u(100, 5000)))
                t += rng.uniform(30, 90)
            t, active = end, not active
    elif c == "B3":
        ev = []
        for lo, hi in p["windows"]:
            t = lo
            while t < min(hi, duration):
                ev.append((t, u(150, 400), u(200, 50000)))
                t += 15 * (1 + rng.uniform(-.1, .1))
    else:
        raise ValueError(c)
    if c != "B1":
        ev = [(t, sni, ip, a, b) for (t, a, b) in ev]
    return [e for e in ev if e[0] < duration]


COMPOSE_HEAD = """\
# GENERATED by `python3 simsched.py compose > docker-compose.yml` (checked by a test); do not edit.
# Run via run.sh, which sets RUN_ID, OUT_DIR, DURATION_S and builds the image first.
name: spectra-setb
x-server: &server
  image: spectra-setb-sim:latest
  command: ["python3", "/app/server.py"]
  user: "65534:65534"
  restart: "no"
  read_only: true
  cap_drop: [ALL]
  security_opt: ["no-new-privileges:true"]
  sysctls: {net.ipv4.ip_unprivileged_port_start: "0"}
  mem_limit: 40m
  pids_limit: 64
x-client: &client
  image: spectra-setb-sim:latest
  command: ["python3", "/app/client.py"]
  restart: "no"
  read_only: true
  tmpfs: ["/tmp"]
  cap_drop: [ALL]
  cap_add: [NET_RAW]
  security_opt: ["no-new-privileges:true"]
  mem_limit: 48m
  pids_limit: 64
  volumes: ["${OUT_DIR:?run via run.sh}:/out"]
networks:
  lab:
    internal: true
    ipam:
      config: [{subnet: 203.0.113.0/24}]
services:
"""


def compose(m: dict) -> str:
    o = [COMPOSE_HEAD]
    for s in m["servers"]:
        o.append(f"  {s['name']}:\n    <<: *server\n    environment: {{SNI: {s['sni']}, DURATION_S: \"${{DURATION_S:?}}\"}}\n"
                 f"    networks: {{lab: {{ipv4_address: {s['ip']}}}}}\n")
    deps = ", ".join(s["name"] for s in m["servers"])
    for h in m["hosts"]:
        o.append(f"  host-{h['host']:02d}:\n    <<: *client\n    environment: {{HOST_IDX: \"{h['host']}\", DURATION_S: \"${{DURATION_S:?}}\"}}\n"
                 f"    networks: {{lab: {{ipv4_address: {h['ip']}}}}}\n    depends_on: [{deps}]\n")
    return "".join(o)


if __name__ == "__main__":
    m = build_manifest()
    print(compose(m) if sys.argv[1:] == ["compose"] else json.dumps(m, indent=1), end="")
