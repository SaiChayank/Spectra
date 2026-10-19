"""Local threat-intel matching: JA3/JA4 fingerprints + SNI domain lists.

File-based lists the operator maintains (see ``docs/intel.md``); nothing
here fetches or uploads anything.  A hit is *evidence*, never an automatic
verdict: matched flows carry an ``intel`` key that the classifier consumes
as an independent signal (``spectra.threats``) and the alert layer renders
as structured evidence.

Guard-failure contract (same as every optional module): a bad directory or
malformed list degrades to an empty list with a counted failure - capture
and scoring continue with intel unavailable, and :meth:`status` says why.
"""

from __future__ import annotations

import hashlib
import logging
import os
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone

log = logging.getLogger("spectra.engine")

#: List files the loader recognises inside the intel directory.
LIST_FILES: tuple[str, ...] = ("ja3.txt", "ja4.txt", "sni.txt")

_JA3_RE = re.compile(r"^[0-9a-f]{32}$")
#: JA4 = "{proto}{version}{sni}{ciphers}{exts}_{hash}_{alpn}", e.g.
#: "t13d1516h2_8daaf6152771_b0da82dd1658" - matching is by full value or
#: prefix ("t13d"-style prefixes are common on blocklists).
_JA4_RE = re.compile(
    r"^[a-z][0-9]{2}[a-z][0-9]{3,4}[a-z0-9]{1,4}_[0-9a-f]{8,}_[0-9a-z,]+$")
_DOMAIN_RE = re.compile(
    r"^(\*\.)?([a-z0-9]([a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}$")


@dataclass
class IntelLists:
    """Parsed intel lists (immutable after load)."""

    ja3: frozenset[str] = frozenset()
    ja4: frozenset[str] = frozenset()
    #: exact domain or wildcard suffix ("*.example.com" matches any subdomain)
    sni: frozenset[str] = frozenset()
    #: per-list provenance: filename, sha256, parsed/total line counts
    sources: list[dict] = field(default_factory=list)
    loaded_at: str = ""
    #: load failure reason (empty when the load succeeded)
    error: str = ""

    @property
    def total(self) -> int:
        return len(self.ja3) + len(self.ja4) + len(self.sni)


class IntelService:
    """Loads and answers queries over the operator's intel lists.

    Lists live in ``<data_dir>/intel/`` as plain text files (one entry per
    line, ``#`` comments): ``ja3.txt`` (32-hex digests), ``ja4.txt`` (full
    JA4 values or prefixes) and ``sni.txt`` (domains; ``*.suffix`` matches
    subdomains).
    """

    def __init__(self, directory: str) -> None:
        self.directory = directory
        self.lists = IntelLists()
        self._failures = 0
        self.reload()

    # -- loading ------------------------------------------------------------

    def reload(self) -> dict:
        """(Re)read every list file; failures degrade to an empty list."""
        try:
            self.lists = self._load()
            self._failures = 0
        except Exception as exc:  # noqa: BLE001 - intel must never break capture
            self._failures += 1
            log.warning("intel lists not loaded: %s", exc)
            self.lists = IntelLists(error=str(exc),
                                    loaded_at=datetime.now(
                                        timezone.utc).isoformat(
                                            timespec="seconds"))
        return self.status()

    def _read_entries(self, path: str) -> tuple[set[str], dict]:
        entries: set[str] = set()
        total = 0
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                total += 1
                entries.add(line.lower())
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for block in iter(lambda: f.read(1 << 20), b""):
                h.update(block)
        return entries, {
            "file": os.path.basename(path),
            "sha256": h.hexdigest(),
            "entries": len(entries),
            "lines": total,
        }

    def _load(self) -> IntelLists:
        if os.path.exists(self.directory) and not os.path.isdir(self.directory):
            # a file where the directory should be: misconfiguration, not "off"
            raise ValueError(
                f"intel path is not a directory: {self.directory}")
        if not os.path.isdir(self.directory):
            # no directory yet = intel simply off, not a failure
            return IntelLists(loaded_at=datetime.now(timezone.utc)
                              .isoformat(timespec="seconds"))
        ja3: set[str] = set()
        ja4: set[str] = set()
        sni: set[str] = set()
        sources: list[dict] = []
        for name in LIST_FILES:
            path = os.path.join(self.directory, name)
            if not os.path.isfile(path):
                continue
            entries, meta = self._read_entries(path)
            if name == "ja3.txt":
                valid = {e for e in entries if _JA3_RE.match(e)}
            elif name == "ja4.txt":
                valid = {e for e in entries if _JA4_RE.match(e)}
            else:
                valid = {e for e in entries if _DOMAIN_RE.match(e)}
            meta["rejected"] = meta["entries"] - len(valid)
            sources.append(meta)
            (ja3 if name == "ja3.txt" else
             ja4 if name == "ja4.txt" else sni).update(valid)
        return IntelLists(
            ja3=frozenset(ja3), ja4=frozenset(ja4), sni=frozenset(sni),
            sources=sources,
            loaded_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
        )

    # -- queries --------------------------------------------------------------

    def match(self, record: dict) -> list[dict]:
        """Intel hits for one flow record (empty list when clean).

        Only reads handshake metadata the parser already extracted
        (``ja3``/``ja4``/``sni`` on the record) - never payload.
        """
        hits: list[dict] = []
        lists = self.lists
        if lists.error or not lists.total:
            return hits

        ja3 = str(record.get("ja3") or "").lower()
        if ja3 and ja3 in lists.ja3:
            hits.append({"list": "ja3", "value": ja3,
                         "detail": f"JA3 {ja3} is on the local blacklist"})

        ja4 = str(record.get("ja4") or "").lower()
        if ja4:
            for entry in lists.ja4:
                # full-value or prefix match ("t13d" style prefixes)
                if ja4 == entry or (len(entry) >= 4 and ja4.startswith(entry)):
                    hits.append({"list": "ja4", "value": ja4,
                                 "detail": f"JA4 {ja4} matches listed {entry}"})
                    break

        sni = str(record.get("sni") or "").lower().rstrip(".")
        if sni:
            if sni in lists.sni:
                hits.append({"list": "sni", "value": sni,
                             "detail": f"SNI {sni} is on the local list"})
            else:
                for entry in lists.sni:
                    if entry.startswith("*.") and sni.endswith(entry[1:]):
                        hits.append({
                            "list": "sni", "value": sni,
                            "detail": f"SNI {sni} matches listed {entry}"})
                        break
        return hits

    # -- reporting --------------------------------------------------------------

    def status(self) -> dict:
        """Counts + provenance for the API/CLI/UI (never raises)."""
        lists = self.lists
        return {
            "available": not lists.error and lists.total > 0,
            "directory": self.directory,
            "counts": {"ja3": len(lists.ja3), "ja4": len(lists.ja4),
                       "sni": len(lists.sni), "total": lists.total},
            "sources": lists.sources,
            "loaded_at": lists.loaded_at,
            "error": lists.error or None,
            "failures": self._failures,
        }


__all__ = ["IntelService", "IntelLists", "LIST_FILES"]
