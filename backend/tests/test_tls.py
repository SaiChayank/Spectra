"""Unit tests for TLS handshake metadata parsing."""

from spectra.parse.tls import TlsMetadata, TlsStreamParser, parse_handshake

from spectra.demo import make_client_hello, make_server_hello


def test_client_hello_metadata():
    hello = make_client_hello(sni="api.bank.test", alpn="h2")
    parser = TlsStreamParser()
    records = parser.feed(hello)
    assert records, "no TLS records parsed"

    meta = TlsMetadata()
    assert parse_handshake(records, meta)
    assert meta.role == "client"
    assert meta.sni == "api.bank.test"
    assert meta.alpn[0] == "h2"
    assert meta.cipher_count == 10
    assert 0 in meta.extensions          # server_name
    assert 16 in meta.extensions         # ALPN
    assert 43 in meta.extensions         # supported_versions -> TLS 1.3 offered
    assert meta.negotiated_version == 0x0304
    assert len(meta.ja3) == 32 and all(c in "0123456789abcdef" for c in meta.ja3)
    assert meta.ja4.startswith("t13d")
    assert meta.ja4.split("_")[1] and meta.ja4.split("_")[2]


def test_server_hello_metadata():
    parser = TlsStreamParser()
    records = parser.feed(make_server_hello(selected_cipher=0x1303))
    meta = TlsMetadata()
    assert parse_handshake(records, meta)
    assert meta.role == "server"
    assert meta.selected_cipher == 0x1303
    assert meta.negotiated_version == 0x0304
    assert meta.version_name == "TLS 1.3"
    assert len(meta.ja3) == 32


def test_fragmented_handshake_across_chunks():
    hello = make_client_hello(sni="split.example.org")
    parser = TlsStreamParser()
    collected = []
    for i in range(0, len(hello), 17):     # dribble bytes like a small MSS
        collected.extend(parser.feed(hello[i:i + 17]))
    meta = TlsMetadata()
    assert parse_handshake(collected, meta)
    assert meta.sni == "split.example.org"


def test_garbage_before_tls_is_skipped():
    hello = make_client_hello()
    noisy = b"HTTP/1.1 200 OK\r\n\r\n" + hello
    parser = TlsStreamParser()
    records = parser.feed(noisy)
    meta = TlsMetadata()
    assert parse_handshake(records, meta)
    assert meta.sni == "example.com"


def test_app_data_records_do_not_break_stream():
    parser = TlsStreamParser()
    out = parser.feed(make_client_hello())
    out += parser.feed(b"\x17\x03\x03\x00\x05hello")
    out += parser.feed(make_server_hello())
    assert [r.content_type for r in out] == [22, 23, 22]
