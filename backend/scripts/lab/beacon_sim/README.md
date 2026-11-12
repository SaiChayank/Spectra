# Set B beacon simulator (lab only, harmless)

Generates the labelled "set B" corpus for the beaconing preregistration (`ci/prereg/e21.json`, amendment 3). It is plain Python
clients making ordinary HTTPS requests (one small POST, one small response, new TCP + TLS 1.3 connection each time) to plain Python
servers, on an isolated Docker network. No offensive tooling, no implants, no remote command execution, nothing downloaded at run time.
The traffic is **simulated**: results bound what the detector can do and say nothing about any specific C2 framework.

* 27 server containers (16 beacon cells, 6 browsing SNIs, chat, app polling, telemetry, time-sync, update check) and 12 client hosts.
* Network `spectra-setb_lab`: `internal: true`, 203.0.113.0/24 (TEST-NET-3), no published ports, no route out. Servers 203.0.113.0/25
  (.10 upward), clients 203.0.113.128/25 (.129-.140). Score set B with `beaconing_internal_nets = ["203.0.113.128/25"]`, empty allow-list.
* Containers: all capabilities dropped, read-only root, `no-new-privileges`, memory limits (servers 40 MB, clients 48 MB; about 0.7 GB in use).
  Clients add only `NET_RAW` for their own tcpdump. Servers bind 443 as an unprivileged user via the namespaced sysctl
  `net.ipv4.ip_unprivileged_port_start=0`, not via a capability.
* **Clients do not verify the server certificate** (one self-signed cert made at image build; lab only, own servers, never use this client elsewhere).
* Servers discard request bodies and log nothing; the only payload anywhere is our own synthetic filler in the pcaps.

## Run
`./run.sh <run-id> <duration_s>` builds the image (the only step that needs internet), writes the output directory and starts everything detached:

    ./run.sh dry-1 180                                  # 3 minute dry run
    ./run.sh setb-$(date -u +%Y%m%dT%H%MZ) 36000        # the real 10 h run
    OUT_DIR=x DURATION_S=1 docker compose -p spectra-setb down   # tidy up (servers stop themselves 5 min after the clients)

Output: `~/Projects/Spectra_bench_data/setb/<run-id>/` with `host-NN.pcap` (full snaplen, own interface), `host-NN.heartbeat.log`
(JSON lines; wall clock and monotonic time every minute, so a suspended laptop shows as a wall/monotonic jump; plus ok/err counters),
and `manifest.json` (seed, every profile's parameters, per host the ground-truth list of class / SNI / server IP / interval / jitter,
image id, git commit, start time). The directory is world-writable because the containers have no `DAC_OVERRIDE`; pcaps are owned by root.
Pcaps live outside the repo and are never committed.

## Files
`simsched.py` pure schedule and manifest generator (also prints the compose file: `python3 simsched.py compose`; a test checks the committed
`docker-compose.yml` matches). `server.py`, `client.py` stdlib only. All randomness: seed 1337 plus host index and profile.

Notes: every request uses a fresh connection, including browsing (B1). Next check-in time = previous scheduled time + delay (no drift from request
time). For runs shorter than 10 h only the B2 period lengths and B3 windows are scaled down so a dry run exercises them; at 36000 s nothing is scaled.
Containers have IPv6 link-local on eth0, so an occasional fe80:: multicast flow can appear in a pcap; it is outside the internal subnet.
