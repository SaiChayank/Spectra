# Spectra — local threat intel (JA3 / JA4 / SNI lists)

Operator-maintained, **file-based** intelligence that the classifier uses as
an *independent* evidence source — separate from the anomaly score.

Code: `backend/spectra/intel.py`; config: `SPECTRA_INTEL_DIR`
(default `backend/data/intel/`); consumed by `spectra.threats` (classification
signals) and shown by `GET /api/model/intel` + `spectra intel status`.

---

## 1. What it is (and is not)

| It is | It is not |
|---|---|
| Local plain-text lists you edit with any editor | A feed — nothing is ever downloaded or uploaded by the app |
| Evidence attached to alerts (`intel_ja3_match`, ...) | An automatic verdict — a listed fingerprint **alone never classifies** |
| An *independent* signal: curated list vs. detector statistics | A replacement for the detector — scores still gate alerts |
| SHA-256-provenanced: the status shows each file's hash | A commercial TI platform — no scoring, no expiry tracking |

Honesty note (SSLBL's own caution, copied deliberately): malicious
fingerprints were collected from malware PCAPs and **not tested against
known-good traffic** — expect false positives; treat a hit as "investigate",
never "block".

## 2. List files

Drop files into `backend/data/intel/` (git-ignored):

| File | Entries | Format |
|---|---|---|
| `ja3.txt` | 32-hex JA3 MD5 digests | one per line; case-insensitive |
| `ja4.txt` | full JA4 values or prefixes (`t13d`, `t13d1516h2`) | one per line |
| `sni.txt` | exact domains (`evil.example.com`) or wildcards (`*.bad.net` matches any subdomain, not the apex) | one per line |

`#` starts a comment; blank lines are skipped. Malformed entries are
**rejected and counted** in the status output (never silently dropped).

A seeded sample lives at `backend/examples/intel/` — copy it to start:

```powershell
New-Item -ItemType Directory -Force backend\data\intel | Out-Null
Copy-Item backend\examples\intel\* backend\data\intel\
```

## 3. Operations

```powershell
cd backend
python -m spectra.cli intel status          # counts, per-file sha256, errors
python -m spectra.cli intel load            # re-read after editing files
python -m spectra.cli intel load --ja3 <hash> --sni <host>   # offline check
```

The engine reloads on every start. List changes during a run require
`intel load` (CLI) or a service restart — by design: no API write surface.

## 4. Effect on classification

A hit becomes a supporting signal in up to three rules
(`spectra.threats._intel_signals`):

| Signal | Weight | Rules it feeds |
|---|---|---|
| `intel_ja3_match` / `intel_ja4_match` / `intel_sni_match` | 0.5 | `C2_BEACONING`, `TLS_ANOMALY`, `QUIC_ANOMALY` |

0.5 is deliberately below the two-signal minimum (`_MIN_SIGNALS = 2`): intel
alone yields `UNKNOWN_ANOMALY` with the candidate named — one strong signal
never classifies. Combined with cadence/oddity evidence it can push a
category over its threshold.

Flows that hit are stamped `record["intel"]` (see `FlowRecord`), rendered as
structured alert evidence, and returned by the intel status route.

## 5. Failure contract

Same guard as every optional module: bad directory, unreadable file, or
corrupt content → empty lists, counted failure, capture unaffected;
`status` reports `error` and `available: false`. A **missing** directory is
not a failure (intel is simply off).

## 6. Provenance of the shipped seed

`backend/examples/intel/ja3.txt` contains a handful of JA3 hashes published
by abuse.ch SSLBL (CC0, list frozen in 2021) with family notes in comments —
sample material for getting started, **not** a current threat feed. Refresh
it from <https://sslbl.abuse.ch/blacklist/> (regenerate at most every
5 minutes per their ToS) or maintain your own.
