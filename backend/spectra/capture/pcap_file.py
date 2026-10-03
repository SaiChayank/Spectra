"""Offline PCAP/PCAPNG file source."""

from __future__ import annotations

import gzip
import os
from typing import IO, Iterator

from scapy.packet import Packet

# Register IP/TCP decoders with conf.l2types *before* any PCAP is read;
# otherwise linktype 228 (raw IP) packets decode as opaque Raw payloads.
import scapy.layers.inet  # noqa: F401
import scapy.layers.inet6  # noqa: F401

from ..filters import compile_filter
from .base import CaptureError, CaptureSource

#: One read from a *compressed* capture is capped here instead of by the file
#: size: the decompressed length is not knowable without inflating the whole
#: stream, and no single packet record or PCAPNG block legitimately approaches
#: this (snaplen is a few tens of kilobytes in practice).
_MAX_GZIP_RECORD = 16 * 1024 * 1024


class _SizeBoundedFile:
    """File proxy that caps how many bytes one ``read()`` may ask for.

    scapy's readers take the record length straight from the bytes on disk -
    ``RawPcapReader._read_packet`` does ``self.f.read(caplen)`` with ``caplen``
    taken from the 16-byte record header, and ``RawPcapNgReader._read_block``
    does ``self.f.read(blocklen - 12)`` - allocating *before* it knows whether
    the record is really there.  A capture consisting of nothing but a 40-byte
    header whose record claims a 4 GiB packet therefore makes the interpreter
    try to allocate 4 GiB (measured: a 512 MiB claim on a 40-byte file peaks at
    ~512 MiB of traced memory).

    No record can be longer than the file it lives in, so clamping the request
    to that size turns a crafted length into the short read a truncated record
    really is.  Well-formed captures never ask for more bytes than they
    contain, so their behaviour is unchanged.
    """

    def __init__(self, fh: IO[bytes], bound: int) -> None:
        # Stored in __dict__ (not attributes) so __getattr__ - which delegates
        # everything else to the wrapped file - can never recurse mid-init.
        self.__dict__["_fh"] = fh
        self.__dict__["_bound"] = int(bound)

    def read(self, n: int = -1) -> bytes:
        if n is None or n < 0:
            return self._fh.read()            # read to EOF: bounded by itself
        return self._fh.read(min(int(n), self._bound))

    def read1(self, n: int = -1) -> bytes:
        return self.read(n)

    def __getattr__(self, name: str):
        # seek / tell / close / fileno / name / ... pass straight through.
        fh = self.__dict__.get("_fh")
        if fh is None:                        # __init__ has not run yet
            raise AttributeError(name)
        return getattr(fh, name)


def _open_capture(path: str) -> tuple[_SizeBoundedFile, IO[bytes]]:
    """Open ``path`` as a scapy input stream clamped to its own size.

    Returns ``(stream, raw_file)``: the caller closes both (closing twice is
    harmless).  Gzip is sniffed here because the reader only auto-detects it
    when it is handed a *path*, and the path form leaves the first, unclamped
    reads - including PCAPNG's block-length read during construction - to
    scapy.
    """
    raw = open(path, "rb")                    # caller checked isfile first
    try:
        head = raw.read(2)
        raw.seek(0)
        if head == b"\x1f\x8b":               # gzip - no file size to clamp to
            stream: _SizeBoundedFile = _SizeBoundedFile(
                gzip.GzipFile(fileobj=raw), _MAX_GZIP_RECORD)
        else:
            stream = _SizeBoundedFile(raw, os.path.getsize(path))
        return stream, raw
    except Exception:
        raw.close()
        raise


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
        from scapy.utils import PcapReader

        def failure(exc: Exception) -> CaptureError:
            # Basename only - the message is returned to API clients.
            return CaptureError(
                f"cannot read PCAP {os.path.basename(self.path)}: {exc}")

        try:
            stream, raw = _open_capture(self.path)
        except OSError as exc:
            raise failure(exc) from exc

        reader = None
        try:
            try:
                # Hand scapy the clamped stream rather than the path. The
                # reader's own open() only runs for a str, so every read -
                # magic, header, record and the PCAP<->PCAPNG fallback - goes
                # through the clamp. Passing a file object behaves identically
                # (verified for PCAP, PCAPNG and gzip) and keeps scapy's
                # `alternative` fallback pointing at the same stream.
                reader = PcapReader(stream)
            except Exception as exc:  # noqa: BLE001 - scapy raises many types
                raise failure(exc) from exc
            # Malformed files also fail mid-iteration (truncated records,
            # broken block lengths): keep the same 400-mapped CaptureError
            # instead of letting a raw scapy/OSError escape as a 500.
            try:
                for pkt in reader:
                    if self._predicate is None or self._predicate(pkt):
                        yield pkt
            except CaptureError:
                raise
            except Exception as exc:  # noqa: BLE001
                raise failure(exc) from exc
        finally:
            if reader is not None:
                reader.close()
            stream.close()
            raw.close()          # a gzip reader does not own its file object

    def __repr__(self) -> str:
        return f"PcapFileSource({self.path!r})"
