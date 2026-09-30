"""Managed capture storage: validated imports into a controlled local directory.

Every PCAP the platform accepts lands here - never at a client-chosen path.
The rules that keep the filesystem safe are enforced in this one module:

* filename      - sanitized to a printable basename (metadata only; path
                  separators, ``..`` and control characters never survive)
* extension     - ``.pcap`` / ``.pcapng`` only (the two formats scapy's
                  ``PcapReader`` - the parser ``PcapFileSource`` uses -
                  dispatches on by magic and supports reliably)
* signature     - first bytes must be a known PCAP/PCAPNG magic number, so a
                  renamed arbitrary file is rejected even with a valid name
* size          - streamed with a hard cap (``Config.capture_max_bytes``);
                  the upload is never buffered whole in memory
* destination   - on-disk names are generated (uuid); the original name is
                  never used to build a path
* traversal     - :meth:`CaptureStorage.path_for` re-derives every path from
                  the store directory and rejects anything that is not a bare
                  basename, so even a tampered database row cannot escape

Duplicate detection lives one layer up (the service): it matches the sha256
computed while streaming against persisted capture rows.
"""

from __future__ import annotations

import hashlib
import logging
import os
import uuid
from dataclasses import dataclass
from typing import Iterable

log = logging.getLogger("spectra.capture.storage")

#: Accepted extensions. ``PcapReader`` reads the file by its magic, so both
#: classic PCAP and PCAPNG work regardless of how the file was named.
ALLOWED_EXTENSIONS: tuple[str, ...] = (".pcap", ".pcapng")

#: Known capture signatures (first four bytes): classic PCAP little/big endian
#: in micro- and nanosecond flavours, plus the PCAPNG section header block.
MAGIC_NUMBERS: tuple[bytes, ...] = (
    b"\xd4\xc3\xb2\xa1",  # PCAP, little endian, microseconds
    b"\xa1\xb2\xc3\xd4",  # PCAP, big endian, microseconds
    b"\x4d\x3c\xb2\xa1",  # PCAP, little endian, nanoseconds
    b"\xa1\xb2\x3c\x4d",  # PCAP, big endian, nanoseconds
    b"\x0a\x0d\x0d\x0a",  # PCAPNG section header block
)

#: Upper bound for a display filename (ext4/NTFS component limit).
MAX_NAME_LENGTH = 255


class CaptureFileError(ValueError):
    """The client-supplied file was rejected (routers map this to HTTP 400)."""


class CaptureTooLargeError(CaptureFileError):
    """The upload exceeds ``Config.capture_max_bytes`` (routers: HTTP 413)."""


@dataclass(frozen=True)
class StoredCapture:
    """A file that passed validation and now lives in the store."""

    stored_name: str  # generated basename - the only name that touches disk
    path: str         # absolute path inside the store (internal use only)
    size: int
    sha256: str


class CaptureStorage:
    """Controlled local storage for imported capture files.

    ``directory`` is the single root files are written to and read from;
    every path this class returns is a realpath contained in it.
    """

    def __init__(self, directory: str, max_bytes: int = 256 * 1024 * 1024):
        self.directory = os.path.realpath(directory)
        self.max_bytes = max(1, int(max_bytes))
        os.makedirs(self.directory, exist_ok=True)

    # -- validation -----------------------------------------------------------

    @staticmethod
    def sanitize_name(raw: str | None) -> str:
        """Reduce a client filename to a safe display basename.

        The result is metadata only - it is never used to build a filesystem
        path (``save_stream`` generates the on-disk name instead). Browsers
        may send ``C:\\fakepath\\x.pcap`` or a full path; only the final
        component survives, and only if it is printable and within length.
        """
        if not raw:
            raise CaptureFileError("a filename is required")
        name = os.path.basename(str(raw).replace("\\", "/"))
        if not name or name in (".", ".."):
            raise CaptureFileError("filename does not contain a usable name")
        if len(name) > MAX_NAME_LENGTH:
            raise CaptureFileError(
                f"filename is longer than {MAX_NAME_LENGTH} characters")
        if not all(ch.isprintable() for ch in name):
            raise CaptureFileError("filename contains control characters")
        return name

    @staticmethod
    def check_extension(name: str) -> str:
        """Validate the extension; returns it lowercased."""
        ext = os.path.splitext(name)[1].lower()
        if ext not in ALLOWED_EXTENSIONS:
            raise CaptureFileError(
                f"unsupported file type {ext or '(none)'}; "
                f"expected {' or '.join(ALLOWED_EXTENSIONS)}")
        return ext

    def path_for(self, stored_name: str | None) -> str:
        """Absolute path for a stored capture, re-validated against escapes."""
        base = os.path.basename(stored_name or "")
        if not base or base != stored_name or base in (".", ".."):
            raise CaptureFileError(
                f"invalid stored capture name {stored_name!r}")
        if "/" in stored_name or "\\" in stored_name:
            raise CaptureFileError(
                f"invalid stored capture name {stored_name!r}")
        path = os.path.realpath(os.path.join(self.directory, base))
        if not path.startswith(self.directory + os.sep):
            raise CaptureFileError(
                "stored capture path escapes the capture store")
        return path

    # -- writes -----------------------------------------------------------------

    def save_stream(self, chunks: Iterable[bytes]) -> StoredCapture:
        """Stream a validated upload into the store under a generated name.

        Enforces size, emptiness and signature while writing to a temporary
        ``.part`` file; only a fully valid upload is renamed into place, so a
        failed or interrupted import never leaves a readable capture behind
        (and any ``.part`` debris is swept as an orphan later).
        """
        stored_name = f"cap_{uuid.uuid4().hex}"
        # placeholder extension until the first bytes reveal a known magic
        tmp = os.path.join(self.directory, f".{stored_name}.part")
        digest = hashlib.sha256()
        head = b""
        total = 0
        try:
            with open(tmp, "wb") as fh:
                for chunk in chunks:
                    if not chunk:
                        continue
                    total += len(chunk)
                    if total > self.max_bytes:
                        raise CaptureTooLargeError(
                            f"capture exceeds the maximum size of "
                            f"{self.max_bytes} bytes")
                    if len(head) < 4:
                        head = (head + chunk)[:4]
                    digest.update(chunk)
                    fh.write(chunk)
            if total == 0:
                raise CaptureFileError("the uploaded file is empty")
            if head not in MAGIC_NUMBERS:
                raise CaptureFileError(
                    "file does not start with a PCAP/PCAPNG signature")
            # The stored extension comes from the *content* (the signature
            # that validated it), never from anything the client sent.
            ext = ".pcapng" if head == b"\x0a\x0d\x0d\x0a" else ".pcap"
            final_name = f"{stored_name}{ext}"
            final_path = self.path_for(final_name)
            os.replace(tmp, final_path)
        except BaseException:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise
        return StoredCapture(stored_name=final_name, path=final_path,
                             size=total, sha256=digest.hexdigest())

    def remove(self, stored_name: str | None) -> bool:
        """Delete one stored file (best effort); True when it was removed."""
        if not stored_name:
            return False
        try:
            path = self.path_for(stored_name)
        except CaptureFileError:
            log.warning("refusing to remove unsafe stored name %r", stored_name)
            return False
        try:
            os.unlink(path)
            return True
        except FileNotFoundError:
            return False
        except OSError as exc:
            log.warning("could not remove stored capture %s: %s",
                        stored_name, exc)
            return False
