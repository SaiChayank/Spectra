"""TLS handshake metadata extraction.

Only structural handshake metadata is parsed: TLS version, cipher suites,
extensions, SNI, ALPN, and JA3/JA4 fingerprints. Application data payloads
are never inspected or stored.

The parser is streaming: feed it TCP payload chunks in order and it buffers
partial TLS records until they are complete.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field

# --- well-known constants ---------------------------------------------------

CONTENT_TYPE_HANDSHAKE = 22
CONTENT_TYPE_ALERT = 21
CONTENT_TYPE_APP_DATA = 23

CLIENT_HELLO = 1
SERVER_HELLO = 2

EXT_SERVER_NAME = 0
EXT_SUPPORTED_GROUPS = 10
EXT_EC_POINT_FORMATS = 11
EXT_ALPN = 16
EXT_SUPPORTED_VERSIONS = 43
EXT_SIGNATURE_ALGORITHMS = 13
EXT_KEY_SHARE = 51

TLS_VERSIONS = {
    0x0300: "SSL 3.0",
    0x0301: "TLS 1.0",
    0x0302: "TLS 1.1",
    0x0303: "TLS 1.2",
    0x0304: "TLS 1.3",
}


def _grease(value: int) -> bool:
    """A value is GREASE if both bytes are equal and the low nibble is 0x0A."""
    return (value & 0xFF) == (value >> 8) and (value & 0x0F) == 0x0A and value > 0x0000


def tls_version_name(code: int) -> str:
    return TLS_VERSIONS.get(code, f"0x{code:04x}")


# --- data model -------------------------------------------------------------


@dataclass
class TlsMetadata:
    """Metadata gathered from one direction's handshake."""

    role: str = ""                      # "client" | "server"
    legacy_version: int = 0
    negotiated_version: int = 0
    cipher_suites: list[int] = field(default_factory=list)
    extensions: list[int] = field(default_factory=list)
    curves: list[int] = field(default_factory=list)
    point_formats: list[int] = field(default_factory=list)
    signature_algorithms: list[int] = field(default_factory=list)
    sni: str = ""
    alpn: list[str] = field(default_factory=list)
    key_share_groups: list[int] = field(default_factory=list)  # groups client offers shares for
    selected_group: int = 0                                     # group chosen by server
    ja3: str = ""
    ja4: str = ""
    selected_cipher: int = 0
    hello_time: float = 0.0             # capture timestamp of the hello, if known

    @property
    def version(self) -> int:
        """Effective protocol version: negotiated when known, else legacy."""
        return self.negotiated_version or self.legacy_version

    @property
    def version_name(self) -> str:
        return tls_version_name(self.version)

    @property
    def cipher_count(self) -> int:
        return len(self.cipher_suites)

    @property
    def extension_count(self) -> int:
        return len(self.extensions)


# --- low level readers ------------------------------------------------------


class _Buf:
    __slots__ = ("data", "pos")

    def __init__(self, data: bytes):
        self.data = data
        self.pos = 0

    def remaining(self) -> int:
        return len(self.data) - self.pos

    def take(self, n: int) -> bytes | None:
        if self.remaining() < n:
            return None
        out = self.data[self.pos:self.pos + n]
        self.pos += n
        return out

    def u8(self) -> int | None:
        b = self.take(1)
        return b[0] if b else None

    def u16(self) -> int | None:
        b = self.take(2)
        return (b[0] << 8) | b[1] if b else None

    def u24(self) -> int | None:
        b = self.take(3)
        return (b[0] << 16) | (b[1] << 8) | b[2] if b else None


# --- handshake parsers ------------------------------------------------------


def _parse_client_hello(body: bytes, meta: TlsMetadata) -> None:
    buf = _Buf(body)
    meta.role = "client"
    ver = buf.u16()
    if ver is None:
        return
    meta.legacy_version = ver
    buf.take(32)  # random
    sid_len = buf.u8()
    if sid_len is None:
        return
    buf.take(sid_len)
    cs_len = buf.u16()
    if cs_len is None:
        return
    cs = buf.take(cs_len)
    if cs is None:
        return
    meta.cipher_suites = [cs[i] << 8 | cs[i + 1] for i in range(0, len(cs) - 1, 2)]
    comp_len = buf.u8()
    if comp_len is None:
        return
    buf.take(comp_len)
    if buf.remaining() < 2:
        return  # no extensions
    ext_total = buf.u16()
    if ext_total is None:
        return
    ext_buf = _Buf(buf.take(ext_total) or b"")
    while ext_buf.remaining() >= 4:
        etype = ext_buf.u16()
        elen = ext_buf.u16()
        if etype is None or elen is None:
            break
        edata = ext_buf.take(elen)
        if edata is None:
            break
        meta.extensions.append(etype)
        if etype == EXT_SERVER_NAME:
            meta.sni = _parse_sni(edata)
        elif etype == EXT_SUPPORTED_GROUPS:
            meta.curves = _u16_list(edata[2:])
        elif etype == EXT_EC_POINT_FORMATS:
            n = edata[0] if edata else 0
            meta.point_formats = list(edata[1:1 + n])
        elif etype == EXT_ALPN:
            meta.alpn = _parse_alpn(edata)
        elif etype == EXT_SIGNATURE_ALGORITHMS:
            meta.signature_algorithms = _u16_list(edata[2:])
        elif etype == EXT_KEY_SHARE:
            meta.key_share_groups = _parse_key_share_client(edata)
        elif etype == EXT_SUPPORTED_VERSIONS and len(edata) >= 3:
            # client form: 1-byte list length then versions
            if len(edata) == edata[0] + 1:
                meta.negotiated_version = int.from_bytes(edata[1:3], "big")
            else:  # server form: single selected version
                meta.negotiated_version = int.from_bytes(edata[:2], "big")


def _parse_server_hello(body: bytes, meta: TlsMetadata) -> None:
    buf = _Buf(body)
    meta.role = "server"
    ver = buf.u16()
    if ver is None:
        return
    meta.legacy_version = ver
    buf.take(32)
    sid_len = buf.u8()
    if sid_len is None:
        return
    buf.take(sid_len)
    cipher = buf.u16()
    if cipher is None:
        return
    meta.selected_cipher = cipher
    meta.cipher_suites = [cipher]
    buf.u8()  # compression method
    if buf.remaining() < 2:
        return
    ext_total = buf.u16()
    if ext_total is None:
        return
    ext_buf = _Buf(buf.take(ext_total) or b"")
    while ext_buf.remaining() >= 4:
        etype = ext_buf.u16()
        elen = ext_buf.u16()
        if etype is None or elen is None:
            break
        edata = ext_buf.take(elen)
        if edata is None:
            break
        meta.extensions.append(etype)
        if etype == EXT_SUPPORTED_VERSIONS and len(edata) >= 2:
            meta.negotiated_version = int.from_bytes(edata[:2], "big")
        elif etype == EXT_ALPN:
            meta.alpn = _parse_alpn(edata)
        elif etype == EXT_KEY_SHARE and len(edata) >= 2:
            # server form: single selected group + key exchange
            meta.selected_group = int.from_bytes(edata[:2], "big")


def _parse_sni(data: bytes) -> str:
    buf = _Buf(data)
    list_len = buf.u16()
    if list_len is None:
        return ""
    name_type = buf.u8()
    name_len = buf.u16()
    if name_type != 0 or name_len is None:
        return ""
    raw = buf.take(name_len)
    if raw is None:
        return ""
    if not _is_ascii(raw):
        return raw.hex()
    try:
        return raw.decode("idna")
    except UnicodeError:
        return raw.decode("ascii", errors="replace")


def _is_ascii(b: bytes) -> bool:
    return all(32 <= c < 127 for c in b)


def _parse_alpn(data: bytes) -> list[str]:
    buf = _Buf(data)
    total = buf.u16()
    if total is None:
        return []
    out: list[str] = []
    while buf.remaining() >= 1:
        n = buf.u8()
        if n is None:
            break
        raw = buf.take(n)
        if raw is None:
            break
        out.append(raw.decode("ascii", errors="replace"))
    return out


def _u16_list(data: bytes) -> list[int]:
    return [data[i] << 8 | data[i + 1] for i in range(0, len(data) - 1, 2)]


def _parse_key_share_client(data: bytes) -> list[int]:
    """Client key_share: 2-byte list length, then {group, keylen, key} entries."""
    buf = _Buf(data)
    total = buf.u16()
    if total is None:
        return []
    groups: list[int] = []
    while buf.remaining() >= 4:
        group = buf.u16()
        klen = buf.u16()
        if group is None or klen is None:
            break
        if buf.take(klen) is None:
            break
        groups.append(group)
    return groups


# --- fingerprints ------------------------------------------------------------


def ja3(meta: TlsMetadata) -> str:
    """Classic JA3 (RFC-draft style, GREASE values removed)."""

    def seg(values: list[int]) -> str:
        return "-".join(str(v) for v in values if not _grease(v))

    if meta.role == "server":
        # Server JA3 uses only the selected cipher.
        raw = f"{meta.legacy_version},{seg(meta.cipher_suites)},,,"
    else:
        raw = ",".join([
            str(meta.legacy_version),
            seg(meta.cipher_suites),
            seg(meta.extensions),
            seg(meta.curves),
            "-".join(str(v) for v in meta.point_formats),
        ])
    return hashlib.md5(raw.encode()).hexdigest()


def ja4(meta: TlsMetadata) -> str:
    """JA4 fingerprint: {type}{version}{sni}{ciphers:02d}{exts:02d}{alpn}_{hash}_{sig}."""
    proto = "t"  # TCP
    if meta.role == "server":
        proto = "T"
    version = (meta.negotiated_version or meta.legacy_version) or 0
    ver_str = {0x0301: "10", 0x0302: "11", 0x0303: "12", 0x0304: "13"}.get(
        version, "00"
    )
    sni = "d" if meta.sni else "i"
    ciphers = [c for c in meta.cipher_suites if not _grease(c)]
    exts = [e for e in meta.extensions if not _grease(e)]
    # SNI(0) and ALPN(16) are excluded from the count per the JA4 spec.
    ext_count = sum(1 for e in exts if e not in (EXT_SERVER_NAME, EXT_ALPN))
    alpn = (meta.alpn[0][:2] if meta.alpn else "00")
    alpn = alpn if len(alpn) == 2 else alpn.ljust(2, "0")

    if meta.role == "server":
        hash_input = ",".join(str(c) for c in ciphers)
    else:
        hash_input = ",".join(
            ["-".join(str(c) for c in ciphers), "-".join(str(e) for e in exts)]
        )
    h1 = hashlib.sha256(hash_input.encode()).hexdigest()[:12]
    sig = ",".join(str(s) for s in meta.signature_algorithms if not _grease(s))
    h2 = hashlib.sha256(sig.encode()).hexdigest()[:12] if sig else "000000000000"

    return f"{proto}{ver_str}{sni}{len(ciphers):02d}{ext_count:02d}{alpn}_{h1}_{h2}"


# --- streaming record parser ------------------------------------------------


@dataclass
class TlsRecord:
    content_type: int
    version: int
    payload: bytes


class TlsStreamParser:
    """Feed TCP payload bytes from one direction; yields completed TLS records."""

    def __init__(self) -> None:
        self._buf = bytearray()
        self.records_seen = 0
        self.hello_parsed = False

    def feed(self, chunk: bytes) -> list[TlsRecord]:
        if chunk:
            self._buf.extend(chunk)
        records: list[TlsRecord] = []
        while True:
            if len(self._buf) < 5:
                break
            ctype = self._buf[0]
            if ctype not in (20, 21, 22, 23, 24):
                # Not a TLS record: drop a byte and resync (plaintext or mid-stream join).
                del self._buf[0]
                continue
            version = self._buf[1] << 8 | self._buf[2]
            length = self._buf[3] << 8 | self._buf[4]
            if length > 16384 + 2048:  # TLS max record plus expansion allowance
                del self._buf[0]
                continue
            if len(self._buf) < 5 + length:
                break  # incomplete record, wait for more data
            payload = bytes(self._buf[5:5 + length])
            del self._buf[:5 + length]
            self.records_seen += 1
            records.append(TlsRecord(ctype, version, payload))
        return records

    def reset(self) -> None:
        self._buf.clear()


def parse_handshake(records: list[TlsRecord], meta: TlsMetadata) -> bool:
    """Parse complete handshake messages from records; returns True on a hello."""
    handshake = bytearray()
    for rec in records:
        if rec.content_type == CONTENT_TYPE_HANDSHAKE:
            handshake.extend(rec.payload)
    if not handshake:
        return False

    buf = _Buf(bytes(handshake))
    found_hello = False
    while buf.remaining() >= 4:
        msg_type = buf.u8()
        msg_len = buf.u24()
        if msg_type is None or msg_len is None:
            break
        body = buf.take(msg_len)
        if body is None:
            break  # fragmented handshake message - incomplete
        if msg_type == CLIENT_HELLO and not found_hello:
            _parse_client_hello(body, meta)
            found_hello = True
        elif msg_type == SERVER_HELLO and not found_hello:
            _parse_server_hello(body, meta)
            found_hello = True
    if found_hello and not meta.ja3:
        meta.ja3 = ja3(meta)
        meta.ja4 = ja4(meta)
    return found_hello
