#!/usr/bin/env python
"""Operator fetch pipeline for Spectra's evaluation datasets (docs/datasets.md).

Downloads the approved public datasets with plain ``urllib`` (this is an
offline operator tool — the Spectra *service* gains no network client),
records each artifact in the dataset manifest, generates ground-truth
labels through the docs/evaluation.md §4 adapters, and converts the
abuse.ch SSLBL JA3 list into local threat intel.

    cd backend
    python scripts/fetch_datasets.py --list            # catalog + local state
    python scripts/fetch_datasets.py                   # fetch everything fetchable
    python scripts/fetch_datasets.py --only ctu13-s1   # one scenario (pcap+flows+labels)
    python scripts/fetch_datasets.py --only sslbl --force

Notes
* Resumable: partial downloads live in ``<file>.part`` and continue with
  an HTTP Range request; transient resets (the CTU server drops
  connections) are retried with backoff.
* CICIDS2017 and ISCX VPN-nonVPN are registration-form gated at the source
  and can never be fetched automatically.  If a download ever returns the
  form page instead of data, it is detected (HTML sniff) and deleted —
  HTML is never stored or imported as capture data.  ``--only cicids2017``
  prints the manual-download recipe.
* MAWI traces are gzip and stay gzip: the capture reader decompresses
  ``.gz`` natively (there is no bz2 support, so bz2 sources are avoided).
* Labels are written *next to* the dataset under ``data/datasets/`` and are
  never imported into the manifest or git.

Exit code 0 = every selected fetchable item ok (manual items just print
instructions); 1 = at least one failure.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass

BACKEND = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BACKEND not in sys.path:
    sys.path.insert(0, BACKEND)

from spectra import datasets as ds                    # noqa: E402
from spectra.config import Config                     # noqa: E402
from spectra.eval.adapters import ctu13_to_labels     # noqa: E402
from spectra.eval.labels import LabelError            # noqa: E402

USER_AGENT = "Spectra-Fetch/0.2 (operator evaluation-dataset script)"
_CHUNK = 1 << 20                 # 1 MiB streaming reads
_MD5_RE = re.compile(r"^[0-9a-f]{32}$")


class FetchError(RuntimeError):
    """A download or conversion step failed after its retries."""


@dataclass
class Item:
    """One fetch step: a remote file and what to do with it once local."""

    key: str
    dataset: str                      # manifest dataset name ("" = manual)
    url: str
    filename: str                     # stored as <datasets>/<dataset>--<filename>
    size_hint: str = ""
    #: Non-empty => never fetched automatically; printed as instructions.
    manual: str = ""
    #: Convert this file's rows into <data_dir>/intel/ja3.txt.
    intel: bool = False
    #: (adapter, pcap-item-key): generate labels once both files are local.
    labels_from: tuple[str, str] = ("", "")
    label_out: str = ""


CTU13_S1 = "https://mcfp.felk.cvut.cz/publicDatasets/CTU-Malware-Capture-Botnet-42"
CTU13_S2 = "https://mcfp.felk.cvut.cz/publicDatasets/CTU-Malware-Capture-Botnet-43"

ITEMS: tuple[Item, ...] = (
    Item("ctu13-s1-pcap", "ctu13",
         f"{CTU13_S1}/botnet-capture-20110810-neris.pcap",
         "botnet-capture-20110810-neris.pcap", "58.3 MB"),
    Item("ctu13-s1-flows", "ctu13",
         f"{CTU13_S1}/capture20110810.binetflow.2format",
         "capture20110810.binetflow.2format", "696 MB",
         labels_from=("ctu13", "ctu13-s1-pcap"),
         label_out="ctu13-s1-labels.csv"),
    Item("ctu13-s2-pcap", "ctu13",
         f"{CTU13_S2}/botnet-capture-20110811-neris.pcap",
         "botnet-capture-20110811-neris.pcap", "36.3 MB"),
    Item("ctu13-s2-flows", "ctu13",
         f"{CTU13_S2}/capture20110811.pcap.netflow.labeled",
         "capture20110811.pcap.netflow.labeled", "635 MB",
         labels_from=("ctu13", "ctu13-s2-pcap"),
         label_out="ctu13-s2-labels.csv"),
    Item("mawi", "mawi",
         "https://mawi.wide.ad.jp/mawi/samplepoint-F/2018/201801011400.pcap.gz",
         "201801011400.pcap.gz", "1.3 GB (gz)"),
    Item("sslbl", "sslbl_ja3",
         "https://sslbl.abuse.ch/blacklist/ja3_fingerprints.csv",
         "ja3_fingerprints.csv", "~1 MB", intel=True),
    Item("cicids2017", "", "", "", manual="""
CICIDS2017 is registration-form gated (cicresearch.ca) and can never be
fetched automatically.  Manual recipe (~50 GB of pcaps; the CSVs alone are
~1.2 GB):
  1. Open https://www.unb.ca/cic/datasets/ids-2017.html and submit the
     registration form; the download link arrives by email.
  2. Download at least 'MachineLearningCSV.zip' (flow CSVs) plus the
     Monday (benign baseline) and Friday (attacks) pcaps if you want
     recall/FPR runs.
  3. Import and label:
       python -m spectra.cli dataset import <csv> --as cicids2017
       python scripts/make_labels.py cicids2017 --labels <csv> \
           --pcap <pcap> --out data/datasets/cicids2017-<day>-labels.csv
     Mapping: docs/evaluation.md §4.  Unknown label wordings fail loudly.
"""),
    Item("vpn2016", "", "", "", manual="""
ISCX VPN-nonVPN 2016 is registration-form gated (cicresearch.ca); same
manual recipe as CICIDS2017.  Note: its app-type labels are not attack
labels — see docs/evaluation.md §4 for what this dataset can and cannot
score before investing the download.
"""),
)


# -- download -----------------------------------------------------------------


def _is_html(path: str) -> bool:
    with open(path, "rb") as f:
        head = f.read(512).lstrip()
    return head[:15].lower().startswith((b"<!doctype html", b"<html"))


def download(url: str, dest: str, *, retries: int = 4, timeout: int = 120,
             force: bool = False, quiet: bool = False) -> dict:
    """Stream ``url`` to ``dest``, resuming a ``.part`` file when possible.

    Raises :class:`FetchError` after the retries are exhausted; a form/HTML
    response is never stored (it is deleted and reported).
    """
    os.makedirs(os.path.dirname(dest), exist_ok=True)
    part = f"{dest}.part"
    if os.path.isfile(dest) and not force:
        return {"status": "exists", "path": dest,
                "bytes": os.path.getsize(dest)}

    last_error = ""
    for attempt in range(1, retries + 1):
        offset = os.path.getsize(part) if os.path.isfile(part) else 0
        try:
            req = urllib.request.Request(url, headers={
                "User-Agent": USER_AGENT,
                **({"Range": f"bytes={offset}-"} if offset else {}),
            })
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                if offset and resp.status != 206:
                    offset = 0          # server ignored Range: restart
                mode = "ab" if offset else "wb"
                done = offset
                last_print = 0.0
                with open(part, mode) as f:
                    while True:
                        block = resp.read(_CHUNK)
                        if not block:
                            break
                        f.write(block)
                        done += len(block)
                        now = time.monotonic()
                        if not quiet and now - last_print > 10:
                            last_print = now
                            print(f"    {done / 2**20:,.0f} MiB ...",
                                  flush=True)
            if _is_html(part):
                os.remove(part)
                raise FetchError(
                    f"{url} returned an HTML page, not data "
                    "(registration gate?) - see this item's manual recipe")
            os.replace(part, dest)
            return {"status": "downloaded", "path": dest,
                    "bytes": os.path.getsize(dest)}
        except (urllib.error.URLError, urllib.error.HTTPError,
                TimeoutError, ConnectionError, OSError) as exc:
            last_error = f"{type(exc).__name__}: {exc}"
            if attempt < retries:
                time.sleep(2 * attempt)
    raise FetchError(f"download failed after {retries} attempts: "
                     f"{url} ({last_error})")


# -- post-processing ----------------------------------------------------------


def sslbl_to_ja3(csv_path: str, intel_dir: str) -> dict:
    """abuse.ch SSLBL JA3 CSV -> merged ``intel_dir/ja3.txt`` (one per line).

    Existing entries are preserved; new hashes are appended.  The list is a
    *signal*, never an auto-verdict — SSLBL stopped updating in 2021 and its
    hashes can false-positive (docs/intel.md).
    """
    hashes: list[str] = []
    with open(csv_path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            if line.lstrip().startswith("#"):
                continue
            first = line.split(",", 1)[0].strip().strip('"').lower()
            if _MD5_RE.match(first):
                hashes.append(first)
    if not hashes:
        raise FetchError(f"{csv_path}: no JA3 digests parsed from SSLBL CSV")

    os.makedirs(intel_dir, exist_ok=True)
    dest = os.path.join(intel_dir, "ja3.txt")
    existing: set[str] = set()
    if os.path.isfile(dest):
        with open(dest, "r", encoding="utf-8") as f:
            existing = {ln.strip().lower() for ln in f
                        if _MD5_RE.match(ln.strip().lower())}
    new = [h for h in dict.fromkeys(hashes) if h not in existing]
    if new:
        with open(dest, "a", encoding="utf-8") as f:
            f.write(f"# abuse.ch SSLBL JA3 blacklist (frozen 2021) - "
                    f"appended {time.strftime('%Y-%m-%d')} by "
                    f"fetch_datasets.py; FP caution docs/intel.md\n")
            for h in new:
                f.write(h + "\n")
    return {"path": dest, "entries": len(existing) + len(new),
            "appended": len(new)}


def generate_labels(item: Item, local: dict[str, str],
                    dest_dir: str) -> dict:
    """Run the §4 adapter once a scenario's pcap + ground truth are local."""
    adapter, pcap_key = item.labels_from
    flows = local.get(item.key)
    pcap = local.get(pcap_key)
    if adapter != "ctu13":
        raise FetchError(f"no adapter wired for {item.key!r}")
    if not flows or not os.path.isfile(flows):
        return {"status": "skipped", "reason": "ground truth not local"}
    if not pcap or not os.path.isfile(pcap):
        return {"status": "skipped",
                "reason": f"pcap {pcap_key} not local (labels need its "
                          "first packet for the UTC offset)"}
    out = os.path.join(dest_dir, item.label_out)
    summary = ctu13_to_labels(flows, out, pcap_path=pcap)
    return {"status": "labels", **summary}


# -- driver -------------------------------------------------------------------


def _dest_path(cfg_datasets: str, item: Item) -> str:
    return os.path.join(cfg_datasets, f"{item.dataset}--{item.filename}")


def run(args: argparse.Namespace) -> int:
    cfg = Config.from_env()
    dest_dir = os.path.abspath(args.dest or ds.datasets_dir(cfg))
    selected = [i for i in ITEMS
                if not args.only or i.key in args.only]
    unknown = (set(args.only) or set()) - {i.key for i in ITEMS}
    if unknown:
        print(f"fetch_datasets: unknown item(s) {sorted(unknown)}; "
              f"known: {[i.key for i in ITEMS]}", file=sys.stderr)
        return 2

    if args.list:
        for item in ITEMS:
            mark = "selected" if item in selected else "filtered-out"
            local = os.path.isfile(_dest_path(dest_dir, item))
            print(f"{item.key:16} {item.size_hint:12} "
                  f"{'local' if local else 'remote':6} {mark}")
        return 0

    print(f"datasets dir: {dest_dir}")
    results: dict[str, dict] = {}
    local: dict[str, str] = {}
    failures = 0
    for item in selected:
        print(f"[{item.key}] {item.url or '(manual)'}")
        if item.manual:
            print(item.manual)
            results[item.key] = {"status": "manual"}
            continue
        dest = _dest_path(dest_dir, item)
        local[item.key] = dest
        try:
            if args.dry_run:
                results[item.key] = {"status": "dry-run", "path": dest}
                continue
            dl = download(item.url, dest, retries=args.retries,
                          force=args.force, quiet=args.quiet)
            print(f"    {dl['status']}: {dest} "
                  f"({dl['bytes'] / 2**20:,.1f} MiB)")
            results[item.key] = dict(dl)

            if not args.no_import:
                entry = ds.import_artifact(cfg, dest, item.dataset,
                                           source_note=item.url)
                results[item.key]["sha256"] = entry.sha256
                print(f"    imported: sha256 {entry.sha256[:16]}...")

            if item.intel:
                intel = sslbl_to_ja3(dest, cfg.intel_dir)
                results[item.key]["intel"] = intel
                print(f"    ja3.txt: {intel['entries']} entries "
                      f"({intel['appended']} new)")

            if item.labels_from[0]:
                lab = generate_labels(item, local, dest_dir)
                results[item.key]["labels"] = lab
                if lab["status"] == "labels":
                    print(f"    labels: {lab['labels_written']} rows "
                          f"(benign windows {lab['benign_windows']}, "
                          f"skipped {sum(lab['skipped'].values())})")
                else:
                    print(f"    labels: {lab['reason']}")
        except (FetchError, LabelError, ds.DatasetError) as exc:
            failures += 1
            results[item.key] = {"status": "failed", "error": str(exc)}
            print(f"    FAILED: {exc}", file=sys.stderr)

    print("\nsummary:")
    print(json.dumps(results, indent=2, sort_keys=True))
    if failures:
        print(f"{failures} item(s) failed", file=sys.stderr)
        return 1
    print("next: python -m spectra.cli dataset list | dataset verify | "
          "eval train --dataset-artifact ...")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="fetch_datasets.py",
        description="Fetch + register Spectra evaluation datasets "
                    "(docs/datasets.md).  Operator tool; the service "
                    "itself never downloads anything.")
    p.add_argument("--only", action="append", default=[],
                   metavar="ITEM", help="restrict to item key(s) "
                   "(repeatable): " + ", ".join(i.key for i in ITEMS))
    p.add_argument("--dest", default=None,
                   help="datasets directory (default: <data_dir>/datasets)")
    p.add_argument("--list", action="store_true",
                   help="show items and local state, then exit")
    p.add_argument("--dry-run", action="store_true",
                   help="resolve selections without downloading")
    p.add_argument("--force", action="store_true",
                   help="re-download even when the file exists")
    p.add_argument("--no-import", action="store_true",
                   help="download only; skip manifest registration")
    p.add_argument("--no-labels", action="store_true",
                   help="skip ground-truth label generation")
    p.add_argument("--retries", type=int, default=4)
    p.add_argument("--quiet", action="store_true",
                   help="suppress progress printing")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.no_labels:
        global ITEMS
        ITEMS = tuple(i for i in ITEMS if not i.labels_from[0])
    return run(args)


if __name__ == "__main__":
    raise SystemExit(main())
