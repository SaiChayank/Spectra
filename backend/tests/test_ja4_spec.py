"""JA4 (client) against FoxIO's published definition and worked example.

Base JA4 is BSD-3-Clause (FoxIO-LLC/ja4, technical_details/JA4.md); the
literals below are copied from that document, not recomputed with the code
under test: the 15-cipher / 16-extension example that yields
``t13d1516h2_8daaf6152771_e5627efa2ab1``, its no-signature-algorithm variant
(``6d807ffa2a79``), the ALPN character table, and the version table.
JA4+ (JA4S, JA4L, ...) is a different license and is deliberately not here.
"""

from __future__ import annotations

import pytest

from spectra.parse.tls import (
    TlsMetadata,
    TlsRecord,
    _alpn_chars,
    ja4,
    parse_handshake,
)

# original order, exactly as printed in the spec ("JA4_ro")
CIPHERS = [0x1301, 0x1302, 0x1303, 0xC02B, 0xC02F, 0xC02C, 0xC030, 0xCCA9, 0xCCA8,
           0xC013, 0xC014, 0x009C, 0x009D, 0x002F, 0x0035]
EXT_ORDER = [0x001B, 0x0000, 0x0033, 0x0010, 0x4469, 0x0017, 0x002D, 0x000D,
             0x0005, 0x0023, 0x0012, 0x002B, 0xFF01, 0x000B, 0x000A, 0x0015]
SIGALGS = [0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601]
EXPECTED = "t13d1516h2_8daaf6152771_e5627efa2ab1"
EXPECTED_NO_SIG = "t13d1516h2_8daaf6152771_6d807ffa2a79"


def u16(v):
    return v.to_bytes(2, "big")


def ext_payload(etype, *, sni="example.com", alpn=(b"h2",), versions=(0x0304, 0x0303),
                sigalgs=SIGALGS):
    if etype == 0x0000:
        name = sni.encode()
        return u16(len(name) + 3) + b"\x00" + u16(len(name)) + name
    if etype == 0x0010:
        body = b"".join(bytes([len(a)]) + a for a in alpn)
        return u16(len(body)) + body
    if etype == 0x002B:
        body = b"".join(u16(v) for v in versions)
        return bytes([len(body)]) + body
    if etype == 0x000D:
        body = b"".join(u16(s) for s in sigalgs)
        return u16(len(body)) + body
    return b"\x00"                                 # content is irrelevant to JA4


def client_hello(ciphers=CIPHERS, ext_order=EXT_ORDER, legacy=0x0303, **kw):
    cs = b"".join(u16(c) for c in ciphers)
    exts = b"".join(u16(t) + u16(len(p)) + p
                    for t in ext_order for p in [ext_payload(t, **kw)])
    body = (u16(legacy) + b"\x00" * 32 + b"\x00" + u16(len(cs)) + cs + b"\x01\x00"
            + (u16(len(exts)) + exts if ext_order else b""))
    msg = b"\x01" + len(body).to_bytes(3, "big") + body
    meta = TlsMetadata()
    assert parse_handshake([TlsRecord(22, 0x0301, msg)], meta)
    return meta


def test_foxio_worked_example():
    assert client_hello().ja4 == EXPECTED


def test_grease_is_ignored_everywhere_and_order_does_not_matter():
    grease = client_hello(ciphers=[0x0A0A] + CIPHERS,
                          ext_order=[0x1A1A] + EXT_ORDER[::-1],
                          versions=(0x2A2A, 0x0304, 0x0303))
    assert grease.ja4 == EXPECTED                      # counts stay 15 / 16 as in the spec


def test_no_signature_algorithms_hashes_the_extensions_alone():
    assert client_hello(sigalgs=()).ja4 == EXPECTED_NO_SIG


def test_signature_algorithm_order_is_significant():
    assert client_hello(sigalgs=SIGALGS[::-1]).ja4 != EXPECTED


def test_sni_alpn_and_version_fields():
    no_sni = client_hello(ext_order=[e for e in EXT_ORDER if e != 0x0000])
    assert no_sni.ja4.startswith("t13i1515h2_")        # 'i', 15 extensions
    h11 = client_hello(alpn=(b"http/1.1",))
    assert h11.ja4.startswith("t13d1516h1_")           # first and last char of http/1.1
    no_alpn = client_hello(ext_order=[e for e in EXT_ORDER if e != 0x0010])
    assert no_alpn.ja4.startswith("t13d1515" + "00_")
    # no supported_versions -> the hello's protocol version
    tls12 = client_hello(ext_order=[e for e in EXT_ORDER if e != 0x002B])
    assert tls12.ja4.startswith("t12d1515h2_")
    assert client_hello(legacy=0x0300, ext_order=[0x0000]).ja4.startswith("ts3d")
    assert client_hello(legacy=0x7777, ext_order=[0x0000]).ja4.startswith("t00d")


def test_a_grease_first_version_list_negotiates_the_real_version():
    meta = client_hello(versions=(0x0A0A, 0x0304, 0x0303))
    assert meta.negotiated_version == 0x0304 and meta.version_name == "TLS 1.3"
    assert meta.supported_versions == [0x0A0A, 0x0304, 0x0303]
    # highest non-GREASE, not merely the first
    assert client_hello(versions=(0x0303, 0x0304)).negotiated_version == 0x0304


def test_empty_cipher_or_extension_lists_use_zeros_not_a_hash_of_nothing():
    assert client_hello(ciphers=[]).ja4.split("_")[1] == "000000000000"
    bare = client_hello(ext_order=[])
    assert bare.ja4.endswith("_000000000000") and bare.ja4.startswith("t12i")
    only_sni_alpn = client_hello(ext_order=[0x0000, 0x0010])
    assert only_sni_alpn.ja4.split("_")[2] == "000000000000"   # both are excluded from c


@pytest.mark.parametrize("raw,expected", [        # FoxIO's ALPN table
    (b"h2", "h2"), (b"http/1.1", "h1"), (b"", "00"), (b"x", "xx"),
    (b"\xab", "ab"), (b"\x20", "20"), (b"\xab\xcd", "ad"), (b"\x20\x61", "21"),
    (b"\x30\xab", "3b"), (b"\x61\x20", "60"), (b"\x30\x31\xab\xcd", "3d"),
    (b"\x30\xab\xcd\x31", "01"),
])
def test_alpn_characters(raw, expected):
    assert _alpn_chars(raw) == expected


def test_server_hellos_get_no_ja4():
    """The server-side fingerprint is JA4S (JA4+, FoxIO License 1.1): not implemented."""
    meta = TlsMetadata(role="server", legacy_version=0x0303, cipher_suites=[0x1301])
    assert ja4(meta) == ""


def test_counts_cap_at_99():
    many = list(range(0x0100, 0x0100 + 120))
    assert client_hello(ciphers=many).ja4[4:6] == "99"
