# Evidence — 2026-11-07

| File | What |
|---|---|
| `gitleaks.txt`, `gitleaks.json` | gitleaks 8.30.1 over all refs of the repository (redacted; 0 findings) |
| `ctu13-s1-flagrate.json`, `.stdout.txt` | `scripts/eval_real_pcap.py` on CTU-13 scenario 1 (`botnet-capture-20110810-neris.pcap`, SHA-256 `b89cd593…6a36`): parser coverage and flag rates with a benign control — see `docs/evaluation-report.md` §9 |

The capture itself is not in the repository (`backend/data/datasets/` is git-ignored; fetched with `scripts/fetch_datasets.py` under the dataset's attribution terms, `docs/datasets.md`).
