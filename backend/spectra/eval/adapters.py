"""Per-dataset ground-truth adapters: a dataset's own labels -> label CSV.

``docs/evaluation.md`` §3 defines the label CSV and §4 fixes the mapping
from each dataset's wording to Spectra's categories.  This module implements
that mapping as *code* — one converter per dataset format — plus
:func:`write_labels`, which validates every row through the schema in
:mod:`spectra.eval.labels` before it reaches disk (an unknown category fails
loudly, it is never guessed).

Rules (docs/evaluation.md §3):

* **Structural problems raise** :class:`LabelError` — an unknown label
  wording, a missing column or an unparseable time must fail the conversion,
  not silently corrupt an evaluation.
* **Known data quirks are skipped and counted** in the returned summary
  (background rows, non-TCP/UDP protocols, invalid endpoints, negative
  durations, empty labels) so a report can state exactly what was excluded.
* **Dataset timestamps are naive local time.**  The UTC offset comes from an
  explicit argument, or is derived by matching label flows to capture
  packets on their 5-tuple and taking the modal whole-hour difference
  (insufficient or ambiguous matches raise rather than guess — first-packet
  proximity alone was measurably wrong on CTU-13, where captures start tens
  of minutes before the first labeled flow).  With neither, the adapter
  assumes UTC and records ``source: null`` — never silently.  Label rows
  outside the capture's time window (which could never join a flow) are
  pruned from support and counted as ``outside_capture``.
* **Output is written atomically** (tmp + rename): a mid-stream failure
  never leaves a half-written file that could be mistaken for ground truth.

Pure data transformation: no pipeline, model or network imports.
"""

from __future__ import annotations

import csv
import gzip
import os
import struct
from collections import Counter
from collections.abc import Iterable, Iterator, Mapping
from dataclasses import dataclass
from datetime import datetime, timezone

from .labels import (
    BENIGN_LABELS,
    LABEL_COLUMNS,
    METADATA_INVISIBLE,
    LabelError,
    parse_row,
)

__all__ = ["cicids2017_to_labels", "ctu13_to_labels", "write_labels"]

# -- timezone derivation tuning ------------------------------------------------
#
# A dataset's timestamps are naive local time; the UTC offset is decided by
# matching label flows to capture packets by 5-tuple and taking the modal
# whole-hour difference (label naive − packet epoch).  First-packet proximity
# alone is unreliable: captures often start tens of minutes before the first
# labeled flow, which pushes the rounding the wrong way (measured on CTU-13).

#: Most capture packets walked while collecting first-seen flow times.
_MAX_TZ_PACKETS = 2_000_000
#: Fewer matched flows than this cannot support a modal decision.
_MIN_TZ_MATCHES = 25
#: The modal hour bucket must beat the runner-up by this factor.
_TZ_AMBIGUITY_RATIO = 2.0
#: Label rows within this margin of the capture window are still kept
#: (covers the join tolerance of docs/evaluation.md §5).
_CAPTURE_EDGE_MARGIN_S = 60.0


# -- schema gate ---------------------------------------------------------------


def write_labels(rows: Iterable[Mapping[str, object]], path: str) -> dict:
    """Validate and stream label rows into a §3 label CSV.

    Every row passes :func:`spectra.eval.labels.parse_row`, so an unknown
    ``mapped_category`` or a bad time range raises :class:`LabelError`
    naming the offending row.  Writing zero rows is an error too: a
    converter that matched nothing must not leave a plausible-looking empty
    file that could be fed to an evaluation.

    Returns ``{"path", "labels_written", "by_category", "benign_windows"}``.
    """
    tmp = f"{path}.tmp"
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    written = 0
    by_cat: Counter[str] = Counter()
    benign_windows = 0
    try:
        with open(tmp, "w", encoding="utf-8", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(LABEL_COLUMNS)
            for i, raw in enumerate(rows, start=1):
                cells = {str(k).strip().lower():
                         ("" if v is None else str(v).strip())
                         for k, v in raw.items()}
                row = parse_row(cells, i)
                writer.writerow([
                    f"{row.t_start:.6f}", f"{row.t_end:.6f}",
                    row.src_ip,
                    "*" if row.src_port is None else str(row.src_port),
                    row.dst_ip,
                    "*" if row.dst_port is None else str(row.dst_port),
                    row.proto, row.dataset_label, row.mapped_category,
                ])
                written += 1
                if row.benign:
                    benign_windows += 1
                else:
                    by_cat[row.mapped_category] += 1
        if written == 0:
            raise LabelError("no labels written (the source matched nothing)")
        os.replace(tmp, path)
    except BaseException:
        if os.path.exists(tmp):
            os.remove(tmp)
        raise
    return {
        "path": path,
        "labels_written": written,
        "by_category": dict(sorted(by_cat.items())),
        "benign_windows": benign_windows,
    }


# -- timezone derivation -------------------------------------------------------


def _pcap_flow_firsts(
    path: str, *, max_packets: int = _MAX_TZ_PACKETS,
) -> tuple[dict, float | None, float | None]:
    """First-seen time per 5-tuple of a classic pcap (+ first/last packet ts).

    Streaming (works on gzipped captures); pcapng is rejected with a clear
    message — pass an explicit ``tz_offset_s`` instead of guessing.
    ``max_packets`` bounds the walk on multi-GB captures: the first packets
    already contain enough flows to decide the offset statistically.
    """
    opener = gzip.open if path.endswith(".gz") else open
    base = os.path.basename(path)
    firsts: dict = {}
    pkt_first: float | None = None
    pkt_last: float | None = None
    with opener(path, "rb") as f:  # type: ignore[operator]
        magic = f.read(4)
        if magic == b"\x0a\x0d\x0d\x0a":
            raise LabelError(
                f"{base}: pcapng captures are not supported for timezone "
                "derivation - pass tz_offset_s explicitly (and no --pcap)")
        if magic == b"\xd4\xc3\xb2\xa1":
            endian, per_second = "<", 1_000_000
        elif magic == b"\xa1\xb2\xc3\xd4":
            endian, per_second = ">", 1_000_000
        elif magic == b"\x4d\x3c\xb2\xa1":
            endian, per_second = "<", 1_000_000_000
        elif magic == b"\xa1\xb2\x3c\x4d":
            endian, per_second = ">", 1_000_000_000
        else:
            raise LabelError(f"{base}: not a pcap file (magic {magic.hex()})")
        if len(f.read(20)) < 20:      # thiszone, sigfigs, snaplen, network
            raise LabelError(f"{base}: truncated pcap header")
        count = 0
        while count < max_packets:
            hdr = f.read(16)          # ts_sec, ts_frac, incl_len, orig_len
            if len(hdr) < 16:
                break
            ts_sec, ts_frac, incl_len, _orig = struct.unpack(
                endian + "IIII", hdr)
            ts = ts_sec + ts_frac / per_second
            if pkt_first is None:
                pkt_first = ts
            pkt_last = ts
            pkt = f.read(incl_len)
            if len(pkt) < 34:
                count += 1
                continue
            if pkt[12:14] == b"\x08\x00" and pkt[14] >> 4 == 4:
                ihl = (pkt[14] & 0x0F) * 4
                proto = pkt[23]
                if proto in (6, 17) and 14 + ihl + 4 <= len(pkt):
                    sport, dport = struct.unpack(">HH", pkt[14 + ihl:14 + ihl + 4])
                    src = ".".join(str(b) for b in pkt[26:30])
                    dst = ".".join(str(b) for b in pkt[30:34])
                    key = (src, sport, dst, dport, proto)
                    if key not in firsts:
                        firsts[key] = ts
            count += 1
    if pkt_first is None:
        raise LabelError(f"{base}: pcap contains no packets")
    return firsts, pkt_first, pkt_last


@dataclass
class _Tz:
    """UTC offset for a dataset's naive local timestamps — always recorded.

    ``source`` is ``"pcap-5tuple"`` (modal first-packet alignment over
    matched flows), ``"argument"`` (operator-supplied), or ``None``
    (assumed UTC — flagged in the summary so a misaligned evaluation is
    visible).  ``window`` is the capture's packet time range widened by
    :data:`_CAPTURE_EDGE_MARGIN_S`; label rows outside it can never join to
    a flow and are pruned from support (counted as ``outside_capture``).
    """

    pcap_path: str | None = None
    offset_arg: float | None = None
    offset_s: float = 0.0
    source: str | None = None
    matches: int = 0
    modal_share: float | None = None
    top_offsets: list = ()
    window: tuple[float, float] | None = None

    def resolve(self, pairs: Iterable[tuple[tuple, float]],
                base: str) -> None:
        """Decide the offset: capture is always walked for its time window;
        the offset comes from the explicit argument, else from matching
        ``pairs`` (label 5-tuple, naive time) against capture flow times.

        ``pairs`` is consumed lazily — an explicit argument skips the
        label pre-pass entirely.
        """
        if self.pcap_path is not None:
            firsts, pkt_first, pkt_last = _pcap_flow_firsts(self.pcap_path)
            self.window = (pkt_first - _CAPTURE_EDGE_MARGIN_S,
                           pkt_last + _CAPTURE_EDGE_MARGIN_S)
        else:
            firsts = None
        if self.offset_arg is not None:
            self.offset_s = float(self.offset_arg)
            self.source = "argument"
        elif self.pcap_path is not None:
            votes: Counter[float] = Counter()
            for key, naive in pairs:        # generator: consumed only here
                ts = firsts.get(key) if firsts is not None else None
                if ts is not None:
                    self.matches += 1
                    votes[float(round((naive - ts) / 3600) * 3600)] += 1
            if self.matches < _MIN_TZ_MATCHES:
                raise LabelError(
                    f"{base}: only {self.matches} label flows matched the "
                    "capture - cannot derive the timezone; pass tz_offset_s "
                    "explicitly")
            common = votes.most_common(2)
            (top, top_votes) = common[0]
            if len(common) > 1:
                runner, runner_votes = common[1]
                if top_votes < _TZ_AMBIGUITY_RATIO * runner_votes:
                    raise LabelError(
                        f"{base}: ambiguous timezone derivation - hour "
                        f"buckets {top:+.0f}s ({top_votes} votes) and "
                        f"{runner:+.0f}s ({runner_votes} votes) are too "
                        "close; pass tz_offset_s explicitly")
            self.offset_s = -float(top)      # naive = epoch - offset_s
            self.source = "pcap-5tuple"
            self.modal_share = top_votes / self.matches
            self.top_offsets = [
                [float(hour), n] for hour, n in votes.most_common(5)]
        # else: assume UTC — flagged via source=None in the summary

    def outside_capture(self, t_start: float, t_end: float) -> bool:
        """True when a shifted label window cannot join any capture flow."""
        if self.window is None:
            return False
        lo, hi = self.window
        return t_end < lo or t_start > hi

    def to_dict(self) -> dict:
        out = {"offset_s": self.offset_s, "source": self.source,
               "assumed_utc": self.source is None}
        if self.source == "pcap-5tuple":
            out.update({"matches": self.matches,
                        "modal_share": self.modal_share,
                        "top_offsets": [list(p) for p in self.top_offsets]})
        return out


def _naive_ts(value: str, formats: tuple[str, ...]) -> float | None:
    """Parse a naive local timestamp to 'epoch as if it were UTC' seconds."""
    v = value.strip()
    for fmt in formats:
        try:
            dt = datetime.strptime(v, fmt)
        except ValueError:
            continue
        return dt.replace(tzinfo=timezone.utc).timestamp()
    return None


# -- label pre-pass: (5-tuple, naive time) pairs for timezone voting ----------
# Advisory only — malformed rows are skipped here (the main pass reports them
# properly); the schema and mapping rules are NOT applied.


def _iter_s1_pairs(src: str) -> Iterator[tuple[tuple, float]]:
    """Pairs over a comma binetflow (CTU-13 scenario 1)."""
    with _open_text(src) as f:
        reader = csv.reader(f)
        try:
            header = [h.strip() for h in next(reader)]
        except StopIteration:
            return
        need = ("SrcAddr", "Sport", "DstAddr", "Dport", "Proto", "StartTime")
        if any(c not in header for c in need):
            return
        ix = {c: header.index(c) for c in need}
        for cells in reader:
            if len(cells) != len(header):
                continue
            try:
                key = (cells[ix["SrcAddr"]].strip(), int(cells[ix["Sport"]]),
                       cells[ix["DstAddr"]].strip(), int(cells[ix["Dport"]]),
                       _proto_num(cells[ix["Proto"]]))
                naive = _naive_ts(cells[ix["StartTime"]], _CTU13_S1_TS)
            except ValueError:
                continue
            if key[4] and naive is not None:
                yield key, naive


def _iter_s2_pairs(src: str) -> Iterator[tuple[tuple, float]]:
    """Pairs over a tab netflow file (CTU-13 scenario 2)."""
    with _open_text(src) as f:
        for line in f:
            if line.startswith("#") or not line.strip():
                continue
            cells = line.rstrip("\r\n").split("\t")
            if len(cells) < _CTU13_S2_FIELDS:
                continue
            try:
                sa, _, sp = cells[3].rpartition(":")
                da, _, dp = cells[5].rpartition(":")
                key = (sa, int(sp), da, int(dp), _proto_num(cells[2]))
                naive = _naive_ts(cells[0], _CTU13_S2_TS)
            except ValueError:
                continue
            if key[4] and naive is not None:
                yield key, naive


def _iter_cicids_pairs(src: str) -> Iterator[tuple[tuple, float]]:
    """Pairs over a CICIDS2017 flow CSV (Protocol is IANA numbering)."""
    with _open_text(src) as f:
        reader = csv.reader(f)
        try:
            header = [h.strip() for h in next(reader)]
        except StopIteration:
            return
        need = ("Src IP", "Src Port", "Dst IP", "Dst Port", "Protocol",
                "Timestamp")
        if any(c not in header for c in need):
            return
        ix = {c: header.index(c) for c in need}
        width = len(header)
        for cells in reader:
            if not any(cells):
                continue
            while len(cells) > width:
                cells = [cells[0] + "," + cells[1]] + cells[2:]
            if len(cells) != width:
                continue
            try:
                key = (cells[ix["Src IP"]].strip(), int(cells[ix["Src Port"]]),
                       cells[ix["Dst IP"]].strip(), int(cells[ix["Dst Port"]]),
                       int(cells[ix["Protocol"]]))
                naive = _naive_ts(cells[ix["Timestamp"]], _CICIDS_TS)
            except ValueError:
                continue
            if key[4] in (6, 17) and naive is not None:
                yield key, naive


def _proto_num(raw: str) -> int:
    """'TCP'/'tcp'/6 -> 6, 'UDP'/17 -> 17, anything else -> 0."""
    v = raw.strip().lower()
    if v == "tcp":
        return 6
    if v == "udp":
        return 17
    try:
        n = int(v)
    except ValueError:
        return 0
    return n if n in (6, 17) else 0


# -- shared cell helpers -------------------------------------------------------


def _proto(raw: str) -> str | None:
    p = raw.strip().upper()
    return p if p in ("TCP", "UDP") else None


def _endpoint(raw_ip: str, raw_port: str, skipped: Counter,
              ip_key: str, port_key: str) -> tuple[str, int | None] | None:
    ip = raw_ip.strip()
    if not ip or ip == "-" or " " in ip or not ("." in ip or ":" in ip):
        skipped[ip_key] += 1
        return None
    port = raw_port.strip()
    if port in ("", "-", "*"):
        return ip, None
    try:
        n = int(port)
    except ValueError:
        skipped[port_key] += 1
        return None
    if not 0 <= n <= 65535:
        skipped[port_key] += 1
        return None
    return ip, n


def _flow_endpoints(src_ip: str, sport: str, dst_ip: str, dport: str,
                    skipped: Counter) -> tuple | None:
    s = _endpoint(src_ip, sport, skipped, "invalid_ip", "invalid_port")
    if s is None:
        return None
    d = _endpoint(dst_ip, dport, skipped, "invalid_ip", "invalid_port")
    if d is None:
        return None
    return s[0], s[1], d[0], d[1]


def _split_host_port(raw: str, skipped: Counter) -> tuple | None:
    """``ip:port`` cell (CTU-13 scenario 2) -> endpoint pair."""
    value = raw.strip()
    if ":" not in value:
        skipped["invalid_endpoint"] += 1
        return None
    ip, _, port = value.rpartition(":")
    if not ip:
        skipped["invalid_endpoint"] += 1
        return None
    return _endpoint(ip, port, skipped, "invalid_ip", "invalid_port")


def _open_text(path: str):
    if path.endswith(".gz"):
        return gzip.open(path, "rt", encoding="utf-8", errors="replace",
                         newline="")
    return open(path, "r", encoding="utf-8", errors="replace", newline="")


def _adapter_summary(adapter: str, fmt: str, src: str, summary: dict,
                     rows_read: int, skipped: Counter,
                     raw_labels: Counter, tz: _Tz) -> dict:
    return {
        "adapter": adapter,
        "format": fmt,
        "input": os.path.abspath(src),
        "output": os.path.abspath(summary["path"]),
        "rows_read": rows_read,
        "labels_written": summary["labels_written"],
        "by_category": summary["by_category"],
        "benign_windows": summary["benign_windows"],
        "skipped": dict(sorted(skipped.items())),
        "raw_labels": dict(sorted(raw_labels.items())),
        "tz": tz.to_dict(),
    }


# -- CTU-13 --------------------------------------------------------------------

_CTU13_S1_REQUIRED = ("SrcAddr", "DstAddr", "Proto", "Sport", "Dport",
                      "StartTime", "LastTime", "Label")
_CTU13_S1_TS = ("%Y/%m/%d %H:%M:%S.%f", "%Y/%m/%d %H:%M:%S")
_CTU13_S2_TS = ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S")
_CTU13_S2_FIELDS = 12


def _detect_ctu13(path: str) -> str:
    """Scenario 1 ships a comma binetflow, scenario 2 a tab netflow file."""
    base = os.path.basename(path)
    with _open_text(path) as f:
        first = f.readline()
    if not first.strip():
        raise LabelError(f"{base}: empty label source")
    if first.lstrip().startswith("#") or "\t" in first:
        return "binetflow-tab"
    if "SrcAddr" in first and "," in first:
        return "binetflow-csv"
    raise LabelError(f"{base}: unrecognised CTU-13 label format")


def ctu13_to_labels(labels_path: str, out_path: str, *,
                    pcap_path: str | None = None,
                    tz_offset_s: float | None = None) -> dict:
    """CTU-13 binetflow ground truth -> Spectra label CSV (§4 mapping).

    Handles both published layouts: the comma-separated ``2format``
    binetflow (scenario 1) and the tab-separated ``netflow.labeled``
    (scenario 2).  ``botnet`` labels become ``C2_BEACONING``, ``normal`` /
    ``LEGITIMATE`` become benign windows, ``background`` is skipped — it is
    unlabeled traffic, never attack and never benign.
    """
    fmt = _detect_ctu13(labels_path)
    if fmt == "binetflow-csv":
        return _ctu13_comma(labels_path, out_path, pcap_path, tz_offset_s)
    return _ctu13_tab(labels_path, out_path, pcap_path, tz_offset_s)


def _ctu13_comma(src: str, out_path: str, pcap_path: str | None,
                 tz_offset_s: float | None) -> dict:
    base = os.path.basename(src)
    skipped: Counter[str] = Counter()
    raw_labels: Counter[str] = Counter()
    tz = _Tz(pcap_path, tz_offset_s)
    if pcap_path is not None or tz_offset_s is not None:
        tz.resolve(_iter_s1_pairs(src), base)
    rows_read = 0

    def rows() -> Iterator[dict]:
        nonlocal rows_read
        with _open_text(src) as f:
            reader = csv.reader(f)
            try:
                header = [h.strip() for h in next(reader)]
            except StopIteration:
                raise LabelError(f"{base}: empty label source") from None
            missing = [c for c in _CTU13_S1_REQUIRED if c not in header]
            if missing:
                raise LabelError(f"{base}: missing columns {missing}")
            idx = {c: header.index(c) for c in _CTU13_S1_REQUIRED}
            for lineno, cells in enumerate(reader, start=2):
                if not any(cells):
                    continue
                rows_read += 1
                if len(cells) != len(header):
                    raise LabelError(
                        f"{lineno}: expected {len(header)} columns, "
                        f"got {len(cells)}")

                def cell(col: str) -> str:
                    return cells[idx[col]].strip()

                raw = cell("Label")
                raw_labels[raw] += 1
                key = raw.lower()
                if not key:
                    skipped["empty_label"] += 1
                    continue
                if "background" in key:
                    skipped["background"] += 1
                    continue
                if "botnet" in key:
                    category, out_label = "C2_BEACONING", raw
                elif "normal" in key:
                    # written as a BENIGN_LABELS wording so the benign flag
                    # derives; the verbatim wording stays in raw_labels
                    category, out_label = "RECONNAISSANCE", "normal"
                else:
                    raise LabelError(f"{lineno}: unknown CTU-13 label {raw!r}")
                proto = _proto(cell("Proto"))
                if proto is None:
                    skipped["invalid_proto"] += 1
                    continue
                endpoint = _flow_endpoints(
                    cell("SrcAddr"), cell("Sport"),
                    cell("DstAddr"), cell("Dport"), skipped)
                if endpoint is None:
                    continue
                t_start = _naive_ts(cell("StartTime"), _CTU13_S1_TS)
                t_end = _naive_ts(cell("LastTime"), _CTU13_S1_TS)
                if t_start is None or t_end is None or t_end < t_start:
                    skipped["invalid_time"] += 1
                    continue
                s = t_start + tz.offset_s
                e = t_end + tz.offset_s
                if tz.outside_capture(s, e):
                    skipped["outside_capture"] += 1
                    continue
                yield {
                    "t_start": s,
                    "t_end": e,
                    "src_ip": endpoint[0], "src_port": endpoint[1],
                    "dst_ip": endpoint[2], "dst_port": endpoint[3],
                    "proto": proto, "dataset_label": out_label,
                    "mapped_category": category,
                }

    try:
        summary = write_labels(rows(), out_path)
    except LabelError as exc:
        raise LabelError(f"{base}: {exc}") from exc
    return _adapter_summary("ctu13", "binetflow-csv", src, summary,
                            rows_read, skipped, raw_labels, tz)


def _ctu13_tab(src: str, out_path: str, pcap_path: str | None,
               tz_offset_s: float | None) -> dict:
    base = os.path.basename(src)
    skipped: Counter[str] = Counter()
    raw_labels: Counter[str] = Counter()
    tz = _Tz(pcap_path, tz_offset_s)
    if pcap_path is not None or tz_offset_s is not None:
        tz.resolve(_iter_s2_pairs(src), base)
    rows_read = 0

    def rows() -> Iterator[dict]:
        nonlocal rows_read
        with _open_text(src) as f:
            for lineno, line in enumerate(f, start=1):
                line = line.rstrip("\r\n")
                if not line.strip() or line.lstrip().startswith("#"):
                    continue
                cells = line.split("\t")
                if len(cells) < _CTU13_S2_FIELDS:
                    raise LabelError(
                        f"{lineno}: expected {_CTU13_S2_FIELDS} tab-separated "
                        f"fields, got {len(cells)}")
                rows_read += 1
                raw = cells[-1].strip()
                raw_labels[raw] += 1
                key = raw.lower()
                if not key:
                    skipped["empty_label"] += 1
                    continue
                if "background" in key:
                    skipped["background"] += 1
                    continue
                if key == "botnet":
                    category = "C2_BEACONING"
                elif key == "legitimate":
                    category = "RECONNAISSANCE"
                else:
                    raise LabelError(f"{lineno}: unknown CTU-13 label {raw!r}")
                proto = _proto(cells[2])
                if proto is None:
                    skipped["invalid_proto"] += 1
                    continue
                src_ep = _split_host_port(cells[3], skipped)
                dst_ep = _split_host_port(cells[5], skipped)
                if src_ep is None or dst_ep is None:
                    continue
                t_start = _naive_ts(cells[0], _CTU13_S2_TS)
                try:
                    dur = float(cells[1])
                except ValueError:
                    dur = -1.0
                if t_start is None or dur < 0:
                    skipped["invalid_time"] += 1
                    continue
                s = t_start + tz.offset_s
                e = s + dur
                if tz.outside_capture(s, e):
                    skipped["outside_capture"] += 1
                    continue
                yield {
                    "t_start": s,
                    "t_end": e,
                    "src_ip": src_ep[0], "src_port": src_ep[1],
                    "dst_ip": dst_ep[0], "dst_port": dst_ep[1],
                    "proto": proto, "dataset_label": raw,
                    "mapped_category": category,
                }

    try:
        summary = write_labels(rows(), out_path)
    except LabelError as exc:
        raise LabelError(f"{base}: {exc}") from exc
    return _adapter_summary("ctu13", "binetflow-tab", src, summary,
                            rows_read, skipped, raw_labels, tz)


# -- CICIDS2017 ----------------------------------------------------------------

_CICIDS_REQUIRED = ("Src IP", "Src Port", "Dst IP", "Dst Port", "Protocol",
                    "Timestamp", "Flow Duration", "Label")
_CICIDS_TS = ("%d/%m/%Y %H:%M:%S.%f", "%d/%m/%Y %H:%M:%S")

#: Fixed wording -> category (docs/evaluation.md §4).  A label that is not
#: listed here and not benign raises: new dataset wording must be mapped by
#: a human in §4 first, never guessed by the adapter.
_CICIDS_MAP: dict[str, str] = {
    "portscan": "RECONNAISSANCE",
    "ftp-patator": "RECONNAISSANCE",
    "ssh-patator": "RECONNAISSANCE",
    "ftp-bruteforce": "RECONNAISSANCE",
    "ssh-bruteforce": "RECONNAISSANCE",
    "dos slowloris": "VOLUMETRIC_ANOMALY",
    "dos goldeneye": "VOLUMETRIC_ANOMALY",
    "dos hulk": "VOLUMETRIC_ANOMALY",
    "dos slowhttptest": "VOLUMETRIC_ANOMALY",
    "dos syn": "VOLUMETRIC_ANOMALY",
    "ddos": "VOLUMETRIC_ANOMALY",
    "bot": "C2_BEACONING",
    "infiltration": "DATA_EXFILTRATION_SUSPECTED",
    "heartbleed": METADATA_INVISIBLE,
}

#: Dataset wordings that are benign but not in ``BENIGN_LABELS`` (§4):
#: written back as a BENIGN_LABELS wording so the benign flag derives; the
#: verbatim wording stays in the summary's ``raw_labels``.
_CICIDS_BENIGN = {"email bounce": "benign"}


def _cicids_category(raw: str, lineno: int) -> tuple[str, str]:
    label = raw.strip()
    key = label.lower()
    if key in _CICIDS_BENIGN:
        return _CICIDS_BENIGN[key], "RECONNAISSANCE"
    if key in _CICIDS_MAP:
        return label, _CICIDS_MAP[key]
    if key.startswith("web attack"):
        return label, METADATA_INVISIBLE
    if key in BENIGN_LABELS:
        return label, "RECONNAISSANCE"
    raise LabelError(
        f"{lineno}: unknown CICIDS2017 label {label!r} - map it in "
        "docs/evaluation.md §4 first")


def cicids2017_to_labels(labels_path: str, out_path: str, *,
                         pcap_path: str | None = None,
                         tz_offset_s: float | None = None) -> dict:
    """CICIDS2017 flow CSV -> Spectra label CSV (§4 mapping).

    ``Flow Duration`` is microseconds and extends each window; ``Protocol``
    is IANA numbering (6 = TCP, 17 = UDP).  CIC's ``Flow ID`` occasionally
    contains unquoted commas — those rows are merged back to the header
    width before indexing.
    """
    src = labels_path
    base = os.path.basename(src)
    skipped: Counter[str] = Counter()
    raw_labels: Counter[str] = Counter()
    tz = _Tz(pcap_path, tz_offset_s)
    if pcap_path is not None or tz_offset_s is not None:
        tz.resolve(_iter_cicids_pairs(src), base)
    rows_read = 0

    def rows() -> Iterator[dict]:
        nonlocal rows_read
        with _open_text(src) as f:
            reader = csv.reader(f)
            try:
                header = [h.strip() for h in next(reader)]
            except StopIteration:
                raise LabelError(f"{base}: empty label source") from None
            missing = [c for c in _CICIDS_REQUIRED if c not in header]
            if missing:
                raise LabelError(f"{base}: missing columns {missing}")
            idx = {c: header.index(c) for c in _CICIDS_REQUIRED}
            width = len(header)
            for lineno, cells in enumerate(reader, start=2):
                if not any(cells):
                    continue
                rows_read += 1
                while len(cells) > width:
                    cells = [cells[0] + "," + cells[1]] + cells[2:]
                if len(cells) < width:
                    raise LabelError(
                        f"{lineno}: expected {width} columns, "
                        f"got {len(cells)}")

                def cell(col: str) -> str:
                    return cells[idx[col]].strip()

                raw = cell("Label")
                raw_labels[raw] += 1
                if not raw:
                    skipped["empty_label"] += 1
                    continue
                out_label, category = _cicids_category(raw, lineno)
                try:
                    proto_num = int(cell("Protocol"))
                except ValueError:
                    proto_num = -1
                proto = ("TCP" if proto_num == 6
                         else "UDP" if proto_num == 17 else None)
                if proto is None:
                    skipped["invalid_proto"] += 1
                    continue
                endpoint = _flow_endpoints(
                    cell("Src IP"), cell("Src Port"),
                    cell("Dst IP"), cell("Dst Port"), skipped)
                if endpoint is None:
                    continue
                t_start = _naive_ts(cell("Timestamp"), _CICIDS_TS)
                try:
                    dur_us = int(cell("Flow Duration"))
                except ValueError:
                    dur_us = -1
                if t_start is None or dur_us < 0:
                    skipped["invalid_time"] += 1
                    continue
                s = t_start + tz.offset_s
                e = s + dur_us / 1e6
                if tz.outside_capture(s, e):
                    skipped["outside_capture"] += 1
                    continue
                yield {
                    "t_start": s,
                    "t_end": e,
                    "src_ip": endpoint[0], "src_port": endpoint[1],
                    "dst_ip": endpoint[2], "dst_port": endpoint[3],
                    "proto": proto, "dataset_label": out_label,
                    "mapped_category": category,
                }

    try:
        summary = write_labels(rows(), out_path)
    except LabelError as exc:
        raise LabelError(f"{base}: {exc}") from exc
    return _adapter_summary("cicids2017", "flow-csv", src, summary,
                            rows_read, skipped, raw_labels, tz)
