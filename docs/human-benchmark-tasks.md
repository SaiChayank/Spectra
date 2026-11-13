# Benchmark tasks only the owner can do

Two Gate B items need a person with a real network and `sudo`. Both are written and tested as far as the agent can test
them; neither has been run on real hardware by the agent. Send back the **summary files named below**, not raw captures.

## Task 12 - benign baseline from your own network (24-72 hours)

**Why.** Every benchmark so far trains on one lab and tests on another or on the same lab. Only a capture from the network
Spectra will watch answers "does a baseline from the first days cover the later days?" (the README's baseline-matching
limitation). The result is a flag rate on traffic you know is benign, plus drift over days.

**Rules.** Only a network you own or are authorised to monitor, and tell everyone on it. Capture headers and the TLS handshake
only (Spectra is metadata-only), so cap the snapshot length: nothing here needs application payload.

**Capture** (Linux, as root, on the host that sees the traffic: the gateway, a mirror/SPAN port or a tap; `eth0` is an example):

```bash
sudo mkdir -p /var/spectra-baseline && cd /var/spectra-baseline
sudo tcpdump -i eth0 -s 1600 -n -G 3600 -w 'base-%Y%m%d-%H%M.pcap' 'not port 22'
```

`-s 1600` keeps a whole Ethernet frame: modern TLS ClientHellos are about 1.7 KB and span two packets, so a smaller snapshot can cut off the server name. The cost is that full packets (encrypted content included) are on disk: keep the directory private and delete it after analysis; `-G 3600` starts a new file every hour; the last file ends
mid-record when you stop it (the script below handles that). Budget a few GB per day on a busy small office; check with `df -h`.
Run it 24-72 hours (at least 3 days is better: the first day trains, the rest tests). Keep the directory off any shared disk.

**Analyse** (labels are not needed; nothing leaves the machine except the JSON you choose to send):

```bash
cd backend
python scripts/bench_own_network.py --pcap-dir /var/spectra-baseline --train-hours 24 --out ~/own-network-report.json
```

**Send back** `~/own-network-report.json`: counts, hourly flag rates and per-day drift only, no addresses.
How to read it: `overall_flag_rate_on_test` near `expected_if_baseline_matched` (2%) means the first day covered your network;
much higher means the baseline missed normal behaviour (try `--train-hours 48`); rising `drift_by_day` PSI means behaviour changes
day to day.

## Task 13 - live-capture sizing rig (needs `sudo`)

**Why.** `docs/evaluation-report.md` §13 measures offline parsing only (about 4-7 thousand packets per second per core). The
sizing guide needs real live-capture numbers: packets received/dropped at fixed rates, flows, CPU and memory.

**Prerequisites.** `sudo apt install tcpreplay iproute2 jq curl` (or your distro's equivalent), a venv with Spectra installed
(`pip install backend/dist/spectra-*.whl`, built by `scripts/build_release.sh`), and a pcap to replay, for example the
CTU-Normal-28 capture already in `~/Projects/Spectra_bench_data/datasets/ctu_normal--2017-05-01_normal.pcap`.

**Run** (it creates a veth pair, starts `spectra serve` as root against it, replays the pcap with `tcpreplay` at each rate,
prints one table, and removes the veth pair and its temporary data directory on exit):

```bash
sudo SPECTRA_BIN=$(command -v spectra) backend/scripts/bench_perf.sh \
  ~/Projects/Spectra_bench_data/datasets/ctu_normal--2017-05-01_normal.pcap 1000 5000 10000 25000 50000 topspeed
```

**Send back** the whole printed table (it starts with a machine line: CPU model, cores, RAM, kernel). The columns are `offered`
(packets replayed), `received`/`dropped` (Spectra's queue counters), `flows`, server `cpu_s` and peak `rss_mb`. The first rate with
non-zero `dropped` is the sensor's limit on that machine. If you have a Raspberry Pi 5-class box, run it there too.

**If it fails.** The script prints the server log path on exit; the usual causes are a missing `tcpreplay`, the port 8899
already in use (`PORT=8898 sudo ...`), or no raw-socket permission (it must be `sudo`).

Not yet run by anyone. Treat its first output as the first measurement, and expect to fix a script issue or two.
