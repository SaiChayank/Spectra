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
| `ctu13-s1-pcap` / `-flows` | CTU-13 scenario 1 (Botnet-42, neris) | 58.3 MB pcap + 696 MB binetflow | `C2_BEACONING` recall; normal rows are the FPR reference; background is excluded |
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

## 6. Results

Real-dataset runs and their numbers (with every caveat) live in
`docs/evaluation-report.md`. The honesty rules binding what may be claimed
are `docs/evaluation.md` §2 — notably: unlabeled time is never benign time,
`METADATA_INVISIBLE` attacks are counted but never scored, and a good score
on one dataset does not license a general accuracy claim
(`docs/limitations.md` §2).
