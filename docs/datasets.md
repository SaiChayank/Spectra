# Spectra — evaluation datasets

Where the public evaluation data comes from, how it is fetched, labeled and
registered, and what each dataset can and cannot honestly score.

Code: `backend/spectra/datasets.py` (registry + manifest),
`backend/spectra/eval/adapters.py` (label adapters).
Scripts: `backend/scripts/fetch_datasets.py`, `backend/scripts/make_labels.py`.
Schema/mapping: `docs/evaluation.md` §3–§4.

---

## 1. Rules

1. **Nothing is fetched at runtime.** The Spectra service has no network
   client for datasets; fetching multi-GB captures is an explicit operator
   action (`fetch_datasets.py`) run offline from the service.
2. **Bytes live outside git.** Everything lands under
   `backend/data/datasets/` (git-ignored) with a SHA-256 manifest entry;
   labels sit *next to* the dataset in the same directory. The repo carries
   only code, docs and synthetic fixtures.
3. **Every artifact is hashed.** `dataset import` records sha256 + size +
   provenance; `dataset verify` re-hashes and flags missing/changed files.
   An evaluation trusts nothing that did not pass verify.
4. **A gated source is never faked.** CICIDS2017 and ISCX VPN-nonVPN sit
   behind a registration form; the fetch script detects the HTML form page
   (and deletes it if a URL ever returns one) and prints a manual recipe
   instead of storing HTML as capture data.

## 2. Catalog

| Key (`--only`) | Dataset | Size | Purpose / honest limits |
|---|---|---|---|
| `ctu13-s1-pcap` / `-flows` | CTU-13 scenario 1 (Botnet-42, neris) | 58.3 MB pcap + 696 MB binetflow | `C2_BEACONING` recall. **The public pcap is botnet-host traffic only** (the full capture with normal and background traffic is not published, per the dataset page), so *normal rows in the flow-label file have no flows in this pcap*: it can score recall, never an FPR. Mostly plaintext (SMTP/DNS/HTTP/IRC), only 0.6 % TLS. Evaluation report §9 |
| `ctu13-s2-pcap` / `-flows` | CTU-13 scenario 2 (Botnet-43) | 36.3 MB + 635 MB | second, independent C2 scenario (different bot + layout) |
| `mawi` | MAWI samplepoint-F daily trace (2018-01-01 14:00) | 1.3 GB (gz) | **no labels**: parser coverage under real payload truncation + an *unscored* observational anomaly rate. Never an FPR/recall source. |
| `sslbl` | abuse.ch SSLBL JA3 blacklist | ~8 KB (frozen 2021) | seeds `data/intel/ja3.txt` for `spectra intel`; **a signal, never a verdict** — the list stopped updating in 2021 and can false-positive |
| `cicids2017` | CICIDS2017 (UNB CIC) | ~50 GB pcaps / 1.2 GB CSVs | primary precision/recall benchmark — **registration-gated, manual only** |
| `vpn2016` | ISCX VPN-nonVPN 2016 | large | encrypted-app behaviour — registration-gated; its labels are app types, not attacks (see evaluation.md §4) |
| `synthetic` | in-repo demo captures | KB | CI-safe harness self-test |

## 3. Fetching (operator)

```powershell
cd backend
python scripts/fetch_datasets.py --list           # catalog + local state
python scripts/fetch_datasets.py                  # everything fetchable
python scripts/fetch_datasets.py --only ctu13-s1-pcap --only ctu13-s1-flows
python scripts/fetch_datasets.py --only mawi --force   # re-download
```

* Plain `urllib`, streaming, resumable: partial files stay as `.part` and
  continue via HTTP Range; transient resets are retried with backoff.
* After download each artifact is imported into the manifest (sha256 +
  provenance), CTU-13 ground truth is converted to label CSVs through the
  §4 adapters, and the SSLBL CSV is merged into `data/intel/ja3.txt`.
* Manual datasets print their recipe (`--only cicids2017`).

### Manual recipe: CICIDS2017

1. Register at <https://www.unb.ca/cic/datasets/ids-2017.html> (form
   gate at cicresearch.ca; the link arrives by email).
2. Download `MachineLearningCSV.zip` (flow CSVs) and, for recall/FPR runs,
   the Monday (benign) + Friday (attacks) pcaps.
3. Import + label:

```powershell
python -m spectra.cli dataset import <csv> --as cicids2017
python scripts/make_labels.py cicids2017 --labels <csv> --pcap <pcap> `
    --out data/datasets/cicids2017-fri-labels.csv
```

Unknown label wordings fail the conversion on purpose — map them in
`docs/evaluation.md` §4 first, regenerate, and record the mapping revision.

## 4. Labels

Label CSVs follow `docs/evaluation.md` §3 and are generated from each
dataset's *own* ground truth — never hand-edited:

```powershell
python scripts/make_labels.py ctu13 --labels <binetflow> --pcap <pcap> `
    --out data/datasets/ctu13-s1-labels.csv
```

* Dataset timestamps are naive **local** time; the adapter derives the UTC
  offset from the capture's first packet (whole hours, residual recorded)
  or takes `--tz-offset`. Without either it assumes UTC **and says so** in
  the summary — expect 1–3 h misalignment if you ignore the warning.
* Known quirks (background rows, non-TCP/UDP protocols, invalid endpoints,
  negative durations, empty labels) are skipped *and counted* in the
  summary; structural problems raise instead of guessing.
* The summary (rows read/written, per-category counts, skip counts, raw
  label census, timezone provenance) is printed as JSON — archive it next
  to the eval report.

## 5. Registration + integrity

```powershell
python -m spectra.cli dataset list                 # catalog + local artifacts
python -m spectra.cli dataset verify               # re-hash everything
python -m spectra.cli dataset verify --dataset ctu13
```

`manifest.json` (inside `data/datasets/`) records dataset, filename,
sha256, size, import time and source URL for every artifact. Eval reports
carry the artifact hash so a number is always traceable to exact bytes
(`docs/evaluation.md` §2 rule 3).

## 5b. Attribution (required by the dataset terms)

CTU-13 is free to use "as long as you reference this project and the authors": Sebastian Garcia, Martin Grill, Jan Stiborek and Alejandro Zunino, *An empirical comparison of botnet detection methods*, Computers and Security, vol. 45, pp. 100-123, Elsevier, 2014 (DOI 10.1016/j.cose.2014.05.011). Capture provided by the Stratosphere Laboratory, CTU Prague (https://www.stratosphereips.org/datasets-ctu13). Spectra redistributes none of its bytes. The first use is recorded in `docs/evaluation-report.md` §9 (file SHA-256 `b89cd5931f62d87ceff266568c97c6e36e56dd0330813cacadbc14a6c5576a36`).

## 5c. Phase B datasets (approved by the owner 2026-11-07; fetched into a fresh directory, never in git)

Approvals in chat 2026-11-07: CTU-Normal + CTU-13 botnet, Stratosphere botnet captures, HIKARI-2021 (2.1 GB subset; the owner
was told CSE-CIC-IDS2018 day archives are 37-50 GB each and chose to skip them), and the Suricata/Zeek Docker images.

**CTU-Normal-\* / CTU-Malware-Capture-Botnet-\* / CTU-13** (Stratosphere Laboratory, CTU Prague, https://www.stratosphereips.org).
Licence: CTU-13 is CC-BY per the Stratosphere site; **no licence text was found for the other captures** - the owner should
confirm terms before any redistribution (Spectra redistributes none). CTU-Normal README: scripted browsing of Alexa top-1000
HTTPS sites from lab hosts.

| File | Size | SHA-256 | Source |
|---|---|---|---|
| `ctu13--botnet-capture-20110810-neris.pcap` | 56 MB | `b89cd5931f62d87ceff266568c97c6e36e56dd0330813cacadbc14a6c5576a36` | https://mcfp.felk.cvut.cz/publicDatasets/CTU-Malware-Capture-Botnet-42/botnet-capture-20110810-neris.pcap |
| `ctu13--botnet-capture-20110811-neris.pcap` | 35 MB | `189b38247b614ae51feee0e75b360552eecdee0b68843b88c7d9ed88d7be7631` | https://mcfp.felk.cvut.cz/publicDatasets/CTU-Malware-Capture-Botnet-43/botnet-capture-20110811-neris.pcap |
| `ctu_normal--2017-04-30_win-normal.pcap` | 269 MB | `c78a00728f115ab8fc495fd395894c43fd90cb61054eb9ef4f2d024658d5ffc5` | https://mcfp.felk.cvut.cz/publicDatasets/CTU-Normal-20/2017-04-30_win-normal.pcap |
| `ctu_normal--2017-04-18_win-normal.pcap` | 281 MB | `50ccaa483200a73c87be73ce3cae95c16afe0941021ff6d5e8e1cacf5a90807b` | https://mcfp.felk.cvut.cz/publicDatasets/CTU-Normal-23/2017-04-18_win-normal.pcap |
| `ctu_normal--2017-04-19_win-normal.pcap` | 202 MB | `31a9a2a88b0d24283288058f7c2dbad057e3d7d7bb2ad2427302dc954c7e1471` | https://mcfp.felk.cvut.cz/publicDatasets/CTU-Normal-24/2017-04-19_win-normal.pcap |
| `ctu_normal--2017-04-28_normal.pcap` | 113 MB | `b66103fd89c8f0fc53b76e718f53320f3af27edd302c58695fc1870ede3663c5` | https://mcfp.felk.cvut.cz/publicDatasets/CTU-Normal-26/2017-04-28_normal.pcap |
| `ctu_normal--2017-05-01_normal.pcap` | 137 MB | `a2f3e60fa0eb2a924a3795644ac09a0f1ea48c45c30ebcc663af9641580b9a5c` | https://mcfp.felk.cvut.cz/publicDatasets/CTU-Normal-28/2017-05-01_normal.pcap |
| `ctu_normal--2017-05-02_kali-normal.pcap` | 297 MB | `53acb10b26ca6446b5bba2efd9d957a9faa15209029d58c10a8c1d1bd299c42b` | https://mcfp.felk.cvut.cz/publicDatasets/CTU-Normal-21/2017-05-02_kali-normal.pcap |
| `ctu_botnet--botnet-capture-20110812-rbot.pcap` | 123 MB | `41880c3a3acfa5ef794abc7b9142b4b41670419c74900e1e953b4a0e75fe55ee` | https://mcfp.felk.cvut.cz/publicDatasets/CTU-Malware-Capture-Botnet-44/botnet-capture-20110812-rbot.pcap |
| `ctu_botnet--botnet-capture-20110815-fast-flux.pcap` | 30 MB | `716f7c43df5df7dff5b14b0cbe4767ca85a656769864fa66b6eda59764316efc` | https://mcfp.felk.cvut.cz/publicDatasets/CTU-Malware-Capture-Botnet-46/botnet-capture-20110815-fast-flux.pcap |
| `ctu_botnet--2014-12-20_capture-win5.pcap` | 36 MB | `c534f2ff831d89606deca46ba738b622b66f85c6c19fda7769df3626d9bface8` | https://mcfp.felk.cvut.cz/publicDatasets/CTU-Malware-Capture-Botnet-100/2014-12-20_capture-win5.pcap |
| `ctu_botnet--capture.botnet2.infected.1.pcap` | 26 MB | `c8c66b3f4a56144eb3d0246e64cf65942d92afa07d1c18019f255225f93a5974` | https://mcfp.felk.cvut.cz/publicDatasets/CTU-Malware-Capture-Botnet-91/capture.botnet2.infected.1.pcap |

**HIKARI-2021** (Ferriyan et al., Keio University; Zenodo record 6463389, DOI 10.5281/zenodo.6463389). Licence CC-BY-4.0 (record
metadata). Cite: *Generating Network Intrusion Detection Dataset Based on Real and Encrypted Synthetic Attack Traffic* (Applied
Sciences 2021) and the Zenodo record.

| File | Size | Checksum | Source |
|---|---|---|---|
| `BRUTEFORCE_HTTPS/pcap/Sunday_2021-04-11_2154.pcap` | 679 MB | `30520b12ce52c33604df4b6f5182723e1db2ecb04eef7c41c7c351a5ea933d4f` | Zenodo 6463389 |
| `BRUTEFORCE_XML/pcap/Monday_2021-04-12_0611.pcap` | 259 MB | `c2d16c3a3b17f4e2f6ce82c6dbc952af9f67ac1e864e12a02e8731a274fc7ab1` | Zenodo 6463389 |
| `BRUTEFORCE_XML/pcap/Saturday_2021-04-17_0357.pcap` | 615 MB | `9a8000c232b69316ea43ec657489e792db10af9894dc53b4fe28a3fd84115f80` | Zenodo 6463389 |
| `Monday_2022-04-11_0622_BRUTEFORCE_XML_150s.pcap` | 258 MB | `139e14e922b25f3ceadce6c1d6a26209317d42d49bb02d66dec27b757194306f` | Zenodo 6463389 |
| `Sunday_2022-04-10_2335_BRUTEFORCE_HTTPS_150s.pcap` | 262 MB | `efeee340ff4b150fac3f0d538839192bf2de27c5c6c87207b20666e3280e82a2` | Zenodo 6463389 |
| `ALLFLOWMETER_HIKARI2021.csv.zip` (labels) | 65 MB | md5 `d7d9e277fe4a66cb00764d7f91a810dd` (Zenodo-published; verified) | Zenodo 6463389 |
| `ground-truth.zip` (anonymised full captures; **downloaded but not used** - it holds pcaps, not labels) | 93 MB | `4005ec39ba2d3a26e224312957191fe00f43423c3f0dd41e72ec7f7441aa8e25` | Zenodo 6463389 |

**Baselines fetched at run time:** Suricata 7.0.8 image (`jasonish/suricata:7.0.8`) with ET Open rules from `suricata-update` on
2026-11-07 (69,342 rules, 53,373 enabled); Zeek 7.0.5 (`zeek/zeek:7.0.5`); abuse.ch SSLBL JA3 list (CC0, 16 entries, SHA-256
prefix `37fcee5a0845b1f7`). A third-party Zeek JA3 package was NOT installed (blocked by the safety classifier).

## 6. Results

Real-dataset runs and their numbers (with every caveat) live in
`docs/evaluation-report.md`. The honesty rules binding what may be claimed
are `docs/evaluation.md` §2 — notably: unlabeled time is never benign time,
`METADATA_INVISIBLE` attacks are counted but never scored, and a good score
on one dataset does not license a general accuracy claim
(`docs/limitations.md` §2).
