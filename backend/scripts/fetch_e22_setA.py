#!/usr/bin/env python
"""Fetch the E22 set_A host captures exactly as amendment A1 of ci/prereg/e22.json fixes them (stdlib only).

    python -I backend/scripts/fetch_e22_setA.py ~/Projects/Spectra_bench_data/cic2018_infil

Reads each day's pcap.zip central directory from the public AWS bucket by HTTP range requests, checks the member list
against the SHA-256 recorded in A1 (refuses on mismatch), and downloads every member of the A1 hosts.  Resumable:
finished files are skipped; a cut-off download leaves only a .part file, which is redone.  One "OK name bytes sha256"
line per file goes to stdout.
"""
from __future__ import annotations

import hashlib
import io
import json
import os
import re
import sys
import urllib.request
import zipfile

BASE = "https://cse-cic-ids2018.s3.ca-central-1.amazonaws.com/Original%20Network%20Traffic%20and%20Log%20data"
PREREG = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "ci", "prereg", "e22.json")


class RangeFile(io.RawIOBase):
    """Seekable read-only view of a remote file; each read is one HTTP range request."""

    def __init__(self, url: str):
        self.url, self.pos = url, 0
        self.size = int(urllib.request.urlopen(urllib.request.Request(url, method="HEAD"), timeout=60).headers["Content-Length"])

    def seekable(self): return True
    def readable(self): return True
    def tell(self): return self.pos

    def seek(self, off, whence=0):
        self.pos = off if whence == 0 else self.pos + off if whence == 1 else self.size + off
        return self.pos

    def readinto(self, b):
        if self.pos >= self.size or not len(b):
            return 0
        end = min(self.pos + len(b), self.size) - 1
        req = urllib.request.Request(self.url, headers={"Range": f"bytes={self.pos}-{end}"})
        data = urllib.request.urlopen(req, timeout=300).read()
        b[:len(data)] = data
        self.pos += len(data)
        return len(data)


def main() -> int:
    out = os.path.expanduser(sys.argv[1])
    a1 = json.load(open(PREREG))["amendments"][0]
    assert a1["id"] == "A1"
    samp = a1["sampling"]
    for day, want_sha in samp["member_list_sha256"].items():
        z = zipfile.ZipFile(io.BufferedReader(RangeFile(f"{BASE}/{day}/pcap.zip"), buffer_size=1 << 20))
        listing = json.dumps([[i.filename, i.file_size] for i in z.infolist()]).encode() + b"\n"   # hashed as the A1 listing file was written
        got = hashlib.sha256(listing).hexdigest()
        if got != want_sha:
            sys.exit(f"{day}: member list sha256 {got} != A1 {want_sha}; refusing")
        hosts = set(a1["positives"][day]) | set(samp["sampled_negatives"][day])
        names = [i.filename for i in z.infolist() if (m := re.search(r"(\d+\.\d+\.\d+\.\d+)", i.filename)) and m.group(1) in hosts]
        os.makedirs(os.path.join(out, day), exist_ok=True)
        for name in names:
            dst = os.path.join(out, day, name.replace("/", "__"))
            if os.path.exists(dst):
                continue
            h, n = hashlib.sha256(), 0
            with z.open(name) as src, open(dst + ".part", "wb") as f:
                while chunk := src.read(8 << 20):
                    f.write(chunk)
                    h.update(chunk)
                    n += len(chunk)
            os.replace(dst + ".part", dst)
            print("OK ", day, os.path.basename(dst), n, h.hexdigest(), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
