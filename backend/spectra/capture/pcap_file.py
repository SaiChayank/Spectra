"""Offline PCAP/PCAPNG file source (in-tree reader, ADR-011: no scapy).

Reads classic pcap (both byte orders, micro- and nanosecond), pcapng (SHB/IDB/EPB/SPB/PB; other blocks skipped) and gzip of
either.  Hostile-input rules:

* every length read from the file is checked against what is left of the file *before* any allocation, so a header that
  claims a 4 GiB record is a truncation error, not a 4 GiB allocation; a gzip stream has no knowable size, so a record or
  block there is capped at ``_MAX_GZIP_RECORD``;
* a file that ends inside a header or record, a block whose lengths disagree, or a bad magic raises :class:`CaptureError`
  after the packets before the defect were yielded - a cut-off capture is never analysed as if complete;
* each loop iteration consumes at least 8 bytes, so no input can make the reader spin.
"""

from __future__ import annotations

import gzip
import os
import struct
from typing import IO, Iterator

from ..filters import compile_filter
from .base import CaptureError, CaptureSource
from .packet import Packet, dissect

#: One record/block read from a *compressed* capture is capped here instead of by the file size: the decompressed length is
#: not knowable without inflating the whole stream, and no single packet record or block legitimately approaches this.
_MAX_GZIP_RECORD = 16 * 1024 * 1024

_PCAP_MAGICS = {                      # magic -> (byte order, nanosecond timestamps)
    b"\xd4\xc3\xb2\xa1": ("<", False), b"\xa1\xb2\xc3\xd4": (">", False),
    b"\x4d\x3c\xb2\xa1": ("<", True), b"\xa1\xb2\x3c\x4d": (">", True),
}
_NG_SHB, _NG_IDB, _NG_PB, _NG_SPB, _NG_EPB = 0x0A0D0D0A, 1, 2, 3, 6


class _Truncated(Exception):
    """The file ends (or lies about a length) inside a header or record."""


class _Stream:
    """File wrapper with an exact-read primitive that refuses lengths beyond what the file can hold."""

    def __init__(self, fh: IO[bytes], limit: int | None, max_record: int) -> None:
        self.fh, self.limit, self.max_record = fh, limit, max_record   # limit: file size, None for gzip

    def left(self) -> int:
        return self.max_record if self.limit is None else self.limit - self.fh.tell()

    def read(self, n: int, what: str) -> bytes:
        if n > self.max_record or n > self.left():
            raise _Truncated(f"the file ends inside {what} (truncated capture): it claims {n} bytes the file does not hold")
        data = self.fh.read(n)
        if len(data) != n:
            raise _Truncated(f"the file ends inside {what} (truncated capture)")
        return data

    def read_or_eof(self, n: int, what: str) -> bytes | None:
        """Like read, but zero bytes available is a clean end of file (None)."""
        data = self.fh.read(n)
        if not data:
            return None
        if len(data) != n:
            raise _Truncated(f"the file ends inside {what} (truncated capture)")
        return data


def _open_capture(path: str) -> tuple[_Stream, IO[bytes]]:
    """Open ``path``; gzip is sniffed from its magic.  Returns (stream, raw file) - the caller closes the raw file."""
    raw = open(path, "rb")                    # caller checked isfile first
    try:
        head = raw.read(2)
        raw.seek(0)
        if head == b"\x1f\x8b":
            return _Stream(gzip.GzipFile(fileobj=raw), None, _MAX_GZIP_RECORD), raw
        size = os.path.getsize(path)
        return _Stream(raw, size, max(size, 1)), raw
    except Exception:
        raw.close()
        raise


def _read_pcap(st: _Stream, magic: bytes) -> Iterator[Packet]:
    endian, nano = _PCAP_MAGICS[magic]
    hdr = st.read(20, "the pcap global header")
    _vmaj, _vmin, _tz, _sig, _snaplen, linktype = struct.unpack(endian + "HHIIII", hdr)
    rec = struct.Struct(endian + "IIII")
    div = 1_000_000_000 if nano else 1_000_000
    while True:
        h = st.read_or_eof(16, "a record header")
        if h is None:
            return
        sec, frac, caplen, wirelen = rec.unpack(h)
        data = st.read(caplen, "a packet record")
        yield dissect(data, linktype, (sec * div + frac) / div, wirelen)


def _ng_options(buf: bytes, endian: str) -> dict[int, bytes]:
    opts: dict[int, bytes] = {}
    off = 0
    while len(buf) - off >= 4:
        code, length = struct.unpack_from(endian + "HH", buf, off)
        if code == 0:
            break
        off += 4
        if off + length > len(buf):
            break
        opts.setdefault(code, buf[off:off + length])
        off += length + (-length % 4)
    return opts


def _read_pcapng(st: _Stream) -> Iterator[Packet]:
    endian = ">"
    ifaces: list[tuple[int, int, int]] = []     # (linktype, snaplen, ticks per second)
    first = True
    while True:
        h = st.read_or_eof(8, "a block header") if not first else st.read(8, "the section header")
        if h is None:
            return
        btype = struct.unpack(endian + "I", h[:4])[0] if not first else 0x0A0D0D0A
        if first or btype == _NG_SHB:
            # The byte order is announced inside the SHB; the type field is palindromic so it reads the same either way.
            if h[:4] != b"\x0a\x0d\x0d\x0a":
                raise _Truncated("bad section header block")
            bom = st.read(4, "the section header")
            if bom == b"\x1a\x2b\x3c\x4d":
                endian = ">"
            elif bom == b"\x4d\x3c\x2b\x1a":
                endian = "<"
            else:
                raise _Truncated("bad byte-order magic in the section header block")
            blen = struct.unpack(endian + "I", h[4:])[0]
            if blen < 28 or blen % 4:
                raise _Truncated(f"invalid section header block length {blen}")
            st.read(blen - 16, "the section header")
            if struct.unpack(endian + "I", st.read(4, "the section header"))[0] != blen:
                raise _Truncated("section header block lengths disagree")
            ifaces = []                          # interfaces are per section
            first = False
            continue
        blen = struct.unpack(endian + "I", h[4:])[0]
        if blen < 12 or blen % 4:
            raise _Truncated(f"invalid pcapng block length {blen}")
        body = st.read(blen - 12, "a pcapng block")
        if struct.unpack(endian + "I", st.read(4, "a pcapng block"))[0] != blen:
            raise _Truncated("pcapng block lengths disagree")
        if btype == _NG_IDB:
            if len(body) < 8:
                raise _Truncated("interface description block too short")
            lt, snaplen = struct.unpack(endian + "HxxI", body[:8])
            tsr = _ng_options(body[8:], endian).get(9)
            ticks = 1_000_000
            if tsr is not None and len(tsr) == 1:
                ticks = (2 if tsr[0] & 128 else 10) ** (tsr[0] & 127)
            ifaces.append((lt, snaplen, ticks))
        elif btype == _NG_EPB or btype == _NG_PB:
            if len(body) < 20:
                raise _Truncated("packet block too short")
            if btype == _NG_EPB:
                iid, thi, tlo, caplen, wirelen = struct.unpack(endian + "5I", body[:20])
            else:
                iid, _drops, thi, tlo, caplen, wirelen = struct.unpack(endian + "HH4I", body[:20])
            if caplen > len(body) - 20:
                raise _Truncated("packet block claims more bytes than it holds")
            if iid < len(ifaces):                # a block for an undeclared interface is skipped
                lt, _snap, ticks = ifaces[iid]
                yield dissect(body[20:20 + caplen], lt, ((thi << 32) + tlo) / ticks, wirelen)
        elif btype == _NG_SPB:
            if len(body) < 4:
                raise _Truncated("simple packet block too short")
            if ifaces:
                lt, snap, _ticks = ifaces[0]
                wirelen = struct.unpack(endian + "I", body[:4])[0]
                caplen = min(wirelen, len(body) - 4, snap or wirelen)
                yield dissect(body[4:4 + caplen], lt, 0.0, wirelen)


class PcapFileSource(CaptureSource):
    name = "pcap-file"

    def __init__(self, path: str, bpf_filter: str = ""):
        if not os.path.isfile(path):
            # Basename only: this reaches an HTTP response, the storage path
            # must not leak.
            raise CaptureError(f"PCAP file not found: {os.path.basename(path)}")
        self.path = path
        self.bpf_filter = bpf_filter
        try:
            self._predicate = compile_filter(bpf_filter) if bpf_filter else None
        except ValueError as exc:
            raise CaptureError(f"invalid filter {bpf_filter!r}: {exc}") from exc

    def packets(self) -> Iterator[Packet]:
        def failure(exc: BaseException) -> CaptureError:
            # Basename only - the message is returned to API clients.
            return CaptureError(f"cannot read PCAP {os.path.basename(self.path)}: {exc}")

        try:
            st, raw = _open_capture(self.path)
        except OSError as exc:
            raise failure(exc) from exc
        try:
            try:
                magic = st.read(4, "the file magic")
                if magic in _PCAP_MAGICS:
                    it = _read_pcap(st, magic)
                elif magic == b"\x0a\x0d\x0d\x0a":
                    st.fh.seek(0)
                    it = _read_pcapng(st)
                else:
                    raise _Truncated(f"not a pcap or pcapng capture (bad magic {magic!r})")
                pred = self._predicate
                for pkt in it:
                    if pred is None or pred(pkt):
                        yield pkt
            except _Truncated as exc:
                raise failure(exc) from exc
            except (OSError, EOFError, struct.error, ValueError, OverflowError) as exc:   # incl. zlib.error, bad gzip
                raise failure(exc) from exc
        finally:
            st.fh.close()
            raw.close()          # a gzip reader does not own its file object

    def __repr__(self) -> str:
        return f"PcapFileSource({self.path!r})"
