"""QUIC handshake metadata extraction (RFC 9000/9001).

QUIC encrypts the transport, but the *Initial* packet keys are derived
deterministically from the client's initial destination connection ID, which
travels in the clear (RFC 9001 5.2). Spectra can therefore read the QUIC
handshake with no endpoint cooperation - exactly like passive TLS parsing -
and feeds the result through the same TLS metadata pipeline, so JA3/JA4, SNI,
ALPN, cipher/key-share offers and the PQC assessment all work unchanged for
HTTP/3 traffic.

Privacy boundary (identical to the TCP path): only handshake structure is
parsed. 0-RTT, Handshake and 1-RTT packets use keys derived from the
handshake transcript and are never decrypted - we record their sizes and
counts only. No application payload is ever stored.

Everything degrades gracefully: without the optional `cryptography` package
(or for unknown QUIC versions) we still recover cleartext header metadata
(version, connection IDs, packet types).

Conformance is verified against the RFC 9001 Appendix A sample packets.
"""

from __future__ import annotations

import hashlib
import hmac
import struct

from .tls import CONTENT_TYPE_HANDSHAKE, TlsMetadata, TlsRecord, parse_handshake

try:  # pragma: no cover - exercised implicitly by the rest of the module
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    CRYPTO_AVAILABLE = True
except ImportError:  # pragma: no cover
    CRYPTO_AVAILABLE = False  # type: ignore[assignment]

# --- constants ---------------------------------------------------------------

INITIAL_SALTS = {
    0x00000001: bytes.fromhex("38762cf7f55934b34d179ae6a4c80cadccbb7f0a"),  # QUIC v1 (RFC 9001 5.2)
    0x6B3343CF: bytes.fromhex("0dede3def700a6db819381be6e269dcbf9bd2ed9"),  # QUIC v2 (RFC 9369)
    0xFF00001D: bytes.fromhex("afbfec289993d24c9e9786f19c6111e04390a899"),  # draft-29
}

QUIC_VERSIONS = {
    0x00000001: "QUIC v1",
    0x6B3343CF: "QUIC v2",
    0xFF00001D: "QUIC draft-29",
}


def quic_version_name(code: int) -> str:
    return QUIC_VERSIONS.get(code, f"QUIC 0x{code:08x}")


def quic_packet_type(first_byte: int) -> str:
    """Long-header packet type from the (unprotected) first byte."""
    return {0: "initial", 1: "0rtt", 2: "handshake", 3: "retry"}[(first_byte >> 4) & 0x03]


# --- varints (RFC 9000 16) ---------------------------------------------------


def read_varint(data: bytes, off: int) -> tuple[int | None, int]:
    """Read a QUIC variable-length integer; (value|None, next_offset)."""
    if off >= len(data):
        return None, off
    length = 1 << (data[off] >> 6)
    if off + length > len(data):
        return None, off
    raw = int.from_bytes(data[off:off + length], "big")
    value = raw & ((1 << (8 * length - 2)) - 1)  # top 2 bits are the length prefix
    return value, off + length


def encode_varint(value: int) -> bytes:
    if value < 64:
        return bytes([value])
    if value < 16384:
        return struct.pack("!H", 0x4000 | value)
    if value < 1073741824:
        return struct.pack("!I", 0x80000000 | value)
    if value < 4611686018427387904:
        return struct.pack("!Q", 0xC000000000000000 | value)
    raise ValueError("varint too large")


# --- HKDF (RFC 5869 + TLS 1.3 labels) ---------------------------------------


def _hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    return hmac.new(salt, ikm, hashlib.sha256).digest()


def _hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    out = b""
    t = b""
    i = 1
    while len(out) < length:
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        out += t
        i += 1
    return out[:length]


def _expand_label(secret: bytes, label: bytes, length: int) -> bytes:
    full = b"tls13 " + label
    hkdf_label = struct.pack("!H", length) + bytes([len(full)]) + full + b"\x00"
    return _hkdf_expand(secret, hkdf_label, length)


def initial_secrets(version: int, dcid: bytes) -> dict | None:
    """Client/server Initial keys from the client's original DCID (RFC 9001 5.2).

    Returns {"client": {...}, "server": {...}} with key/iv/hp, or None for an
    unknown QUIC version (no published salt).
    """
    salt = INITIAL_SALTS.get(version)
    if salt is None:
        return None
    prk = _hkdf_extract(salt, dcid)

    def direction(label: bytes) -> dict:
        secret = _expand_label(prk, label, 32)
        return {
            "key": _expand_label(secret, b"quic key", 16),
            "iv": _expand_label(secret, b"quic iv", 12),
            "hp": _expand_label(secret, b"quic hp", 16),
        }

    return {"client": direction(b"client in"), "server": direction(b"server in")}


# --- cleartext header parsing ------------------------------------------------


def parse_long_header(payload: bytes) -> dict | None:
    """Structural parse of a QUIC long-header packet. None if it isn't one."""
    if len(payload) < 7:
        return None
    first = payload[0]
    if not first & 0x80:  # short header (1-RTT): not identifiable in isolation
        return None
    version = int.from_bytes(payload[1:5], "big")
    off = 5
    dcid_len = payload[off]
    off += 1
    if dcid_len > 20 or off + dcid_len + 1 > len(payload):
        return None
    dcid = payload[off:off + dcid_len]
    off += dcid_len
    scid_len = payload[off]
    off += 1
    if scid_len > 20 or off + scid_len > len(payload):
        return None
    scid = payload[off:off + scid_len]
    off += scid_len

    if version == 0:  # Version Negotiation (RFC 9000 17.2.1)
        versions = [
            int.from_bytes(payload[i:i + 4], "big")
            for i in range(off, len(payload) - 3, 4)
        ]
        return {"type": "version_negotiation", "version": 0, "dcid": dcid,
                "scid": scid, "versions": versions}

    ptype = quic_packet_type(first)
    if ptype == "retry":
        return {"type": "retry", "version": version, "dcid": dcid, "scid": scid}

    if ptype == "initial":
        token_len, off = read_varint(payload, off)
        if token_len is None:
            return None
        off += token_len
        if off >= len(payload):
            return None
    length, off = read_varint(payload, off)
    if length is None or off > len(payload):
        return None
    return {"type": ptype, "version": version, "dcid": dcid, "scid": scid,
            "pn_offset": off, "length": length}


def is_quic(payload: bytes) -> bool:
    """Cheap filter: does this look like a QUIC long-header packet?"""
    return parse_long_header(payload) is not None


# --- packet protection (RFC 9001 5.3/5.4) -----------------------------------


def _ecb_encrypt(key: bytes, block: bytes) -> bytes:
    encryptor = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    return encryptor.update(block) + encryptor.finalize()


def _nonce(iv: bytes, pn_bytes: bytes) -> bytes:
    padded = pn_bytes.rjust(len(iv), b"\x00")
    return bytes(a ^ b for a, b in zip(iv, padded))


def open_initial(payload: bytes, keys: dict, hdr: dict | None = None) -> dict | None:
    """Remove header protection and AEAD-decrypt a QUIC Initial packet.

    `keys` is one side's {"key","iv","hp"} dict from initial_secrets().
    Returns {"pn", "plaintext"} or None (not an Initial / failed authentication).
    """
    if not CRYPTO_AVAILABLE:
        return None
    if hdr is None:
        hdr = parse_long_header(payload)
    if hdr is None or hdr["type"] != "initial":
        return None
    pn_off = hdr["pn_offset"]
    if pn_off + 20 > len(payload):  # need the 16-byte protection sample
        return None
    end = min(pn_off + hdr["length"], len(payload))

    sample = payload[pn_off + 4:pn_off + 20]
    mask = _ecb_encrypt(keys["hp"], sample)
    first = payload[0] ^ (mask[0] & 0x0F)
    pn_len = (first & 0x03) + 1
    if pn_off + pn_len >= end:
        return None
    pn_bytes = bytes(payload[pn_off + i] ^ mask[1 + i] for i in range(pn_len))

    header = bytes([first]) + payload[1:pn_off] + pn_bytes
    ciphertext = payload[pn_off + pn_len:end]
    try:
        plain = AESGCM(keys["key"]).decrypt(
            _nonce(keys["iv"], pn_bytes), ciphertext, header
        )
    except Exception:  # noqa: BLE001 - wrong keys / not actually QUIC
        return None
    return {"pn": int.from_bytes(pn_bytes, "big"), "pn_len": pn_len,
            "plaintext": plain}


def seal_initial(
    handshake: bytes,
    *,
    side: str = "client",
    key_dcid: bytes,
    header_dcid: bytes | None = None,
    scid: bytes = b"",
    pn: int = 0,
    pn_len: int = 4,
    version: int = 0x00000001,
    min_size: int = 1200,
    token: bytes = b"",
    prelude: bytes = b"",
) -> bytes:
    """Build a protected QUIC Initial packet carrying `handshake` bytes.

    `prelude` is raw frame data emitted before the CRYPTO frame (e.g. an ACK
    frame, as servers send). The inverse of open_initial(); used by the demo
    PCAP generator and the RFC conformance tests (seal(A.2/A.3 inputs) must
    byte-equal the RFC packets).
    """
    if not CRYPTO_AVAILABLE:  # pragma: no cover
        raise RuntimeError("cryptography package required to seal QUIC packets")
    secrets = initial_secrets(version, key_dcid)
    if secrets is None:
        raise ValueError(f"no initial salt for version 0x{version:08x}")
    keys = secrets["client" if side == "client" else "server"]
    if header_dcid is None:
        header_dcid = key_dcid

    # CRYPTO frame: type, offset 0, length, data - then PADDING to min_size.
    frames = prelude + (
        bytes([0x06]) + encode_varint(0) + encode_varint(len(handshake)) + handshake
    )
    pad = 0
    for _ in range(4):  # varint width of `length` can grow as we pad
        plaintext = frames + b"\x00" * pad
        value = pn_len + len(plaintext) + 16
        total = (1 + 4 + 1 + len(header_dcid) + 1 + len(scid)
                 + len(encode_varint(len(token))) + len(token)
                 + len(encode_varint(value)) + value)
        if total >= min_size:
            break
        pad += min_size - total

    plaintext = frames + b"\x00" * pad
    value = pn_len + len(plaintext) + 16
    first = 0xC0 | (pn_len - 1)  # long header, fixed bit, Initial, unmasked pn bits
    body = (
        bytes([first]) + struct.pack("!I", version)
        + bytes([len(header_dcid)]) + header_dcid
        + bytes([len(scid)]) + scid
        + encode_varint(len(token)) + token
        + encode_varint(value)
    )
    pn_bytes = pn.to_bytes(pn_len, "big")
    aad = body + pn_bytes
    ciphertext = AESGCM(keys["key"]).encrypt(
        _nonce(keys["iv"], pn_bytes), plaintext, aad
    )

    sample = (pn_bytes + ciphertext)[4:20]
    if len(sample) < 16:  # pragma: no cover - packets are always big enough
        raise ValueError("packet too small for header protection sample")
    mask = _ecb_encrypt(keys["hp"], sample)
    masked_first = first ^ (mask[0] & 0x0F)
    masked_pn = bytes(pn_bytes[i] ^ mask[1 + i] for i in range(pn_len))
    return bytes([masked_first]) + body[1:] + masked_pn + ciphertext


# --- frame parsing (RFC 9000 12) ---------------------------------------------


def extract_crypto(data: bytes) -> bytes:
    """Reassemble CRYPTO frame data from decrypted packet payload.

    Stops early on frame types it doesn't know (returns what was collected);
    Initial packets realistically only carry PADDING/PING/ACK/CRYPTO/close.
    """
    out = bytearray()
    off = 0
    n = len(data)
    while off < n:
        ftype, off = read_varint(data, off)
        if ftype is None:
            break
        if ftype in (0x00, 0x01):  # PADDING, PING
            continue
        if ftype in (0x02, 0x03):  # ACK / ACK_ECN
            _largest, off = read_varint(data, off)
            _delay, off = read_varint(data, off)
            range_count, off = read_varint(data, off)
            _first_range, off = read_varint(data, off)
            if range_count is None:
                break
            for _ in range(range_count):
                _gap, off = read_varint(data, off)
                _range, off = read_varint(data, off)
                if _gap is None or _range is None:
                    return bytes(out)
            if ftype == 0x03:
                for _ in range(3):  # ECN counts
                    _, off = read_varint(data, off)
            continue
        if ftype == 0x06:  # CRYPTO
            offset, off = read_varint(data, off)
            length, off = read_varint(data, off)
            if offset is None or length is None or off + length > n:
                break
            chunk = data[off:off + length]
            off += length
            if offset > len(out):
                out.extend(b"\x00" * (offset - len(out)))
            out[offset:offset + length] = chunk
            continue
        if ftype == 0x07:  # NEW_TOKEN
            length, off = read_varint(data, off)
            if length is None or off + length > n:
                break
            off += length
            continue
        if ftype in (0x1C, 0x1D):  # CONNECTION_CLOSE
            _, off = read_varint(data, off)     # error code
            if ftype == 0x1C:
                _, off = read_varint(data, off)  # triggering frame type
            length, off = read_varint(data, off)
            if length is None or off + length > n:
                break
            off += length
            continue
        if ftype in (0x04, 0x05):  # RESET_STREAM / STOP_SENDING
            for _ in range(3):
                _, off = read_varint(data, off)
            continue
        if 0x08 <= ftype <= 0x0F:  # STREAM
            _, off = read_varint(data, off)      # stream id
            if ftype & 0x04:
                _, off = read_varint(data, off)  # offset present
            if ftype & 0x02:
                length, off = read_varint(data, off)
                if length is None or off + length > n:
                    break
                off += length
            else:
                off = n                          # length omitted: rest of packet
            continue
        break  # unknown frame type - stop, keep what we have
    return bytes(out)


def handshake_metadata(crypto: bytes) -> TlsMetadata | None:
    """Parse reassembled CRYPTO bytes as TLS handshake messages."""
    if not crypto:
        return None
    meta = TlsMetadata()
    records = [TlsRecord(CONTENT_TYPE_HANDSHAKE, 0x0303, crypto)]
    if parse_handshake(records, meta):
        return meta
    return None
