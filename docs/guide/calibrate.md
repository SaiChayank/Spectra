# Calibrate on your own network

## Why this matters

Spectra learns what *your* normal looks like and flags deviations. A baseline from somewhere else is wrong for you.
Measured in this repository ([limitations](../limitations.md) section 5): with the bundled synthetic demo baseline,
ordinary real traffic scored about 97.6 and 472 real flows were flagged; a matching 70-second real baseline flagged
4 of 112 flows (3.6 %). If everything scores near 100, the baseline does not match the network.

Assumptions you take on:

* The baseline must be **benign**. Poisoning it is not defended against (training is admin-only and audited, nothing
  more).
* It must be **long enough** to include your normal rhythms, such as office hours, nightly jobs and updates.
* The percentage "expected to be anomalous" (`contamination`, default 0.02) only moves the threshold. It does not give
  you a measured false-alarm rate.

## Capture procedure (24-72 hours)

Taken from task 12 in [human-benchmark-tasks.md](../human-benchmark-tasks.md). Rules first: capture only on a network
you own or are authorised to monitor, and tell the people on it.

Run as root on a host that sees the traffic (gateway, SPAN/mirror port or tap). `eth0` is an example interface name:

```bash
sudo mkdir -p /var/spectra-baseline && cd /var/spectra-baseline
sudo tcpdump -i eth0 -s 1600 -n -G 3600 -w 'base-%Y%m%d-%H%M.pcap' 'not port 22'
```

* `-G 3600` starts a new file every hour. The last file ends mid-record when you stop it; the analysis script handles
  that.
* Run it for 24 to 72 hours; three days is better, since the first day trains and the rest test.
* Budget a few GB per day on a busy small office; check with `df -h`. Keep the directory off any shared disk.

### Snaplen: use `-s 1600`, not `-s 600`

The task 12 text uses `-s 600`. Modern TLS ClientHellos are about 1.7 KB, so a 600-byte snapshot can cut the
handshake off before the server name (SNI) and other fields Spectra reads. `-s 1600` captures far more of each
handshake. This guide recommends it; the task 12 text has not been updated yet. How much a 1600-byte cut still loses on very large ClientHellos
has not been tested; if you still see missing server names, use `-s 0` (whole packet), which stores even more.

**The trade-off:** with `-s 1600` the capture files contain most packet payload up to 1600 bytes, not just headers.
Treat the directory as sensitive: restrict permissions (`sudo chmod 700 /var/spectra-baseline`), do not copy it
off the machine, and **delete the raw files once you have trained and analysed**. Spectra's own upload step then
rewrites an imported file down to headers, lengths and handshake records, but the original on your disk is still the
full-size copy.

## Analyse and train

To measure how well a first-day baseline covers later days (labels not needed; only the JSON you choose to send
leaves the machine):

```bash
cd backend
python scripts/bench_own_network.py --pcap-dir /var/spectra-baseline --train-hours 24 --out ~/own-network-report.json
```

`overall_flag_rate_on_test` near `expected_if_baseline_matched` (2 %) means the first day covered your network. A much
higher rate means the baseline missed normal behaviour; try `--train-hours 48`. A rising `drift_by_day` PSI means
behaviour changes from day to day.

To train the live model, upload a baseline file (one of the hourly files, or a merged one under the 256 MiB upload
cap) and train as in [first run](./first-run.md), step 6, or with the CLI:

```bash
python -m spectra.cli train /var/spectra-baseline/base-YYYYMMDD-HHMM.pcap
```

`train` also accepts `--contamination` and `--augment N` (mixes N synthetic benign flows in; default 0, off).

## Retraining

Retrain when the network changes (new services, a move, a long holiday pattern) or when drift says so:
`GET /api/model/drift` reports PSI below 0.10 stable, 0.10 to 0.25 moderate, above 0.25 significant; above that
scores are no longer calibrated. Training registers a new model and, by default, activates it; model history and
rollback are in the dashboard's Models page and under `/api/model/registry`. Back up before big changes
([operate](./operate.md)).

## If you enable the beaconing detector

Its results depend on a site-specific allow-list of known periodic services (NTP, update checks, monitoring probes),
and it has not passed its evaluation gate ([alerts](./alerts.md)). Your own-network capture is exactly the precision
measurement the evaluation report says is still missing; read its results as a ranking, not as verdicts.
