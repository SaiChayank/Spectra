"""Phase 4: QUIC/HTTP3 Initial-packet parsing (RFC 9000/9001 conformance).

Crypto correctness is pinned against the RFC 9001 Appendix A sample
packets: derived keys, decrypt of the client/server Initial samples, and
byte-exact re-sealing of both. The rest exercises the demo generator,
flow-tracker integration, PQC assessment of QUIC handshakes, and hostile
or unrecognisable packets (never a crash, never a false QUIC claim).
"""

import time

import numpy as np
import pytest
from scapy.utils import PcapWriter

from spectra.demo import make_baseline_pcap, quic_flow_packets, write_pcap
from spectra.features.extractor import N_FEATURES, extract_features
from spectra.modules.pqc import assess_flow
from spectra.parse.flow import FlowTracker
from spectra.parse.quic import (
    encode_varint,
    extract_crypto,
    handshake_metadata,
    initial_secrets,
    is_quic,
    open_initial,
    parse_long_header,
    quic_version_name,
    read_varint,
    seal_initial,
)
from spectra.tools import collect_flows

DCID = bytes.fromhex("8394c8f03e515708")   # RFC 9001 A.1 connection ID

# RFC 9001 A.2: ClientHello carried in the client Initial (241 bytes).
CLIENT_HELLO = bytes.fromhex(
    "010000ed0303ebf8fa56f12939b9584a3896472ec40bb863cfd3e86804fe3a47f06a2b69484c0000041301"
    "1302010000c000000010000e00000b6578616d706c652e636f6dff01000100000a00080006001d0017001800100007"
    "000504616c706e000500050100000000003300260024001d00209370b2c9caa47fbabaf4559fedba753de171fa71f50f1"
    "ce15d43e994ec74d748002b0003020304000d0010000e0403050306030203080408050806002d00020101001c000240"
    "01003900320408ffffffffffffffff05048000ffff07048000ffff0801100104800075300901100f088394c8f03e51"
    "570806048000ffff"
)

# RFC 9001 A.2: the protected client Initial datagram (1200 bytes).
CLIENT_INITIAL_PROTECTED = bytes.fromhex(
    "c000000001088394c8f03e5157080000449e7b9aec34d1b1c98dd7689fb8ec11d242b123dc9bd8bab936b47d92ec356c"
    "0bab7df5976d27cd449f63300099f3991c260ec4c60d17b31f8429157bb35a1282a643a8d2262cad67500cadb8e7378c"
    "8eb7539ec4d4905fed1bee1fc8aafba17c750e2c7ace01e6005f80fcb7df621230c83711b39343fa028cea7f7fb5ff89"
    "eac2308249a02252155e2347b63d58c5457afd84d05dfffdb20392844ae812154682e9cf012f9021a6f0be17ddd0c208"
    "4dce25ff9b06cde535d0f920a2db1bf362c23e596d11a4f5a6cf3948838a3aec4e15daf8500a6ef69ec4e3feb6b1d98e"
    "610ac8b7ec3faf6ad760b7bad1db4ba3485e8a94dc250ae3fdb41ed15fb6a8e5eba0fc3dd60bc8e30c5c4287e53805db"
    "059ae0648db2f64264ed5e39be2e20d82df566da8dd5998ccabdae053060ae6c7b4378e846d29f37ed7b4ea9ec5d82e7"
    "961b7f25a9323851f681d582363aa5f89937f5a67258bf63ad6f1a0b1d96dbd4faddfcefc5266ba6611722395c906556"
    "be52afe3f565636ad1b17d508b73d8743eeb524be22b3dcbc2c7468d54119c7468449a13d8e3b95811a198f3491de3e7"
    "fe942b330407abf82a4ed7c1b311663ac69890f4157015853d91e923037c227a33cdd5ec281ca3f79c44546b9d90ca00"
    "f064c99e3dd97911d39fe9c5d0b23a229a234cb36186c4819e8b9c5927726632291d6a418211cc2962e20fe47feb3edf"
    "330f2c603a9d48c0fcb5699dbfe5896425c5bac4aee82e57a85aaf4e2513e4f05796b07ba2ee47d80506f8d2c25e50fd"
    "14de71e6c418559302f939b0e1abd576f279c4b2e0feb85c1f28ff18f58891ffef132eef2fa09346aee33c28eb130ff2"
    "8f5b766953334113211996d20011a198e3fc433f9f2541010ae17c1bf202580f6047472fb36857fe843b19f5984009dd"
    "c324044e847a4f4a0ab34f719595de37252d6235365e9b84392b061085349d73203a4a13e96f5432ec0fd4a1ee65accd"
    "d5e3904df54c1da510b0ff20dcc0c77fcb2c0e0eb605cb0504db87632cf3d8b4dae6e705769d1de354270123cb11450e"
    "fc60ac47683d7b8d0f811365565fd98c4c8eb936bcab8d069fc33bd801b03adea2e1fbc5aa463d08ca19896d2bf59a07"
    "1b851e6c239052172f296bfb5e72404790a2181014f3b94a4e97d117b438130368cc39dbb2d198065ae3986547926cd2"
    "162f40a29f0c3c8745c0f50fba3852e566d44575c29d39a03f0cda721984b6f440591f355e12d439ff150aab7613499d"
    "bd49adabc8676eef023b15b65bfc5ca06948109f23f350db82123535eb8a7433bdabcb909271a6ecbcb58b936a88cd4e"
    "8f2e6ff5800175f113253d8fa9ca8885c2f552e657dc603f252e1a8e308f76f0be79e2fb8f5d5fbbe2e30ecadd220723"
    "c8c0aea8078cdfcb3868263ff8f0940054da48781893a7e49ad5aff4af300cd804a6b6279ab3ff3afb64491c85194aab"
    "760d58a606654f9f4400e8b38591356fbf6425aca26dc85244259ff2b19c41b9f96f3ca9ec1dde434da7d2d392b905dd"
    "f3d1f9af93d1af5950bd493f5aa731b4056df31bd267b6b90a079831aaf579be0a39013137aac6d404f518cfd4684064"
    "7e78bfe706ca4cf5e9c5453e9f7cfd2b8b4c8d169a44e55c88d4a9a7f9474241e221af44860018ab0856972e194cd934"
)

# RFC 9001 A.3: ServerHello carried in the server Initial (90 bytes).
SERVER_HELLO = bytes.fromhex(
    "020000560303eefce7f7b37ba1d1632e96677825ddf73988cfc79825df566dc5430b9a045a12001301"
    "00002e00330024001d00209d3c940d89690b84d08a60993c144eca684d1081287c834d5311bcf32bb9da1"
    "a002b00020304"
)

# RFC 9001 A.3: the protected server Initial (ACK + CRYPTO, no padding).
SERVER_INITIAL_PROTECTED = bytes.fromhex(
    "cf000000010008f067a5502a4262b5004075c0d95a482cd0991cd25b0aac406a5816b6394100f37a1c69797554780bb3"
    "8cc5a99f5ede4cf73c3ec2493a1839b3dbcba3f6ea46c5b7684df3548e7ddeb9c3bf9c73cc3f3bded74b562bfb19fb84"
    "022f8ef4cdd93795d77d06edbb7aaf2f58891850abbdca3d20398c276456cbc42158407dd074ee"
)


# -- low-level primitives -----------------------------------------------------

def test_varint_roundtrip():
    for v in (0, 1, 63, 64, 16383, 16384, 1073741823, 1073741824, 2**62 - 1):
        enc = encode_varint(v)
        got, off = read_varint(enc, 0)
        assert got == v
        assert off == len(enc)
    # truncated / empty buffers must not raise
    assert read_varint(b"", 0) == (None, 0)
    assert read_varint(b"\x40", 0)[0] is None
    assert read_varint(b"\x80\x00\x00", 0)[0] is None


def test_long_header_detection():
    hdr = parse_long_header(CLIENT_INITIAL_PROTECTED)
    assert hdr is not None
    assert hdr["type"] == "initial"
    assert hdr["version"] == 0x00000001
    assert hdr["dcid"] == DCID
    assert hdr["scid"] == b""
    assert hdr["pn_offset"] == 18
    assert hdr["length"] == 1182
    assert is_quic(CLIENT_INITIAL_PROTECTED)

    # TLS records, short headers, tiny datagrams: not QUIC long headers.
    assert parse_long_header(b"\x16\x03\x01\x00\x04abcd") is None
    assert parse_long_header(b"\x40" + b"\x00" * 40) is None
    assert parse_long_header(b"\xc0\x00") is None
    assert not is_quic(b"GET / HTTP/1.1\r\n\r\n")

    # Unknown QUIC version: header parses, but there is no salt to open it.
    assert initial_secrets(0x12345678, DCID) is None
    assert quic_version_name(0x00000001) == "QUIC v1"
    assert quic_version_name(0x6B3343CF) == "QUIC v2"
    assert "0x" in quic_version_name(0x0ABCDEF0)


# -- RFC 9001 Appendix A conformance ------------------------------------------

def test_rfc9001_a1_initial_keys():
    secrets = initial_secrets(0x00000001, DCID)
    assert secrets is not None
    assert secrets["client"]["key"].hex() == "1f369613dd76d5467730efcbe3b1a22d"
    assert secrets["client"]["iv"].hex() == "fa044b2f42a3fd3b46fb255c"
    assert secrets["client"]["hp"].hex() == "9f50449e04a0e810283a1e9933adedd2"
    assert secrets["server"]["key"].hex() == "cf3a5331653c364c88f0f379b6067e37"
    assert secrets["server"]["iv"].hex() == "0ac1493ca1905853b0bba03e"
    assert secrets["server"]["hp"].hex() == "c206b8d9b9f0f37644430b490eeaa314"


def test_rfc9001_client_initial_decrypt():
    secrets = initial_secrets(0x00000001, DCID)
    opened = open_initial(CLIENT_INITIAL_PROTECTED, secrets["client"])
    assert opened is not None
    assert opened["pn"] == 2
    assert opened["pn_len"] == 4
    assert len(opened["plaintext"]) == 1162          # CRYPTO + PADDING
    assert extract_crypto(opened["plaintext"]) == CLIENT_HELLO
    # Wrong side's keys must fail authentication, not return garbage.
    assert open_initial(CLIENT_INITIAL_PROTECTED, secrets["server"]) is None


def test_rfc9001_client_initial_reseal_is_byte_exact():
    sealed = seal_initial(
        CLIENT_HELLO, side="client", key_dcid=DCID, header_dcid=DCID,
        scid=b"", pn=2, min_size=1200,
    )
    assert sealed == CLIENT_INITIAL_PROTECTED


def test_rfc9001_client_initial_metadata():
    meta = handshake_metadata(CLIENT_HELLO)
    assert meta is not None
    assert meta.role == "client"
    assert meta.sni == "example.com"
    assert meta.alpn == ["alpn"]                     # quirk of the RFC sample
    assert 0x001D in meta.key_share_groups
    assert meta.ja4.startswith("t13d")


def test_rfc9001_server_initial_decrypt_and_metadata():
    secrets = initial_secrets(0x00000001, DCID)
    opened = open_initial(SERVER_INITIAL_PROTECTED, secrets["server"])
    assert opened is not None
    assert opened["pn"] == 1
    plain = opened["plaintext"]
    crypto = extract_crypto(plain)                   # ACK frame skipped, CRYPTO read
    assert crypto == SERVER_HELLO
    meta = handshake_metadata(crypto)
    assert meta is not None
    assert meta.role == "server"
    assert meta.selected_cipher == 0x1301
    assert meta.selected_group == 0x001D

    sealed = seal_initial(
        SERVER_HELLO, side="server", key_dcid=DCID, header_dcid=b"",
        scid=bytes.fromhex("f067a5502a4262b5"), pn=1, pn_len=2, min_size=1,
        prelude=bytes.fromhex("0200000000"),         # the ACK frame from A.3
    )
    assert sealed == SERVER_INITIAL_PROTECTED


# -- flow-tracker integration -------------------------------------------------

@pytest.mark.parametrize("profile,group", [
    ("classic", 0x001D),
    ("hybrid", 0x11EC),
    ("pqc_auth", 0x11EC),
])
def test_demo_quic_flow_extracts_metadata(profile, group):
    tracker = FlowTracker()
    for pkt in quic_flow_packets(profile=profile, sni="cdn.example"):
        tracker.process(pkt)
    flows = list(tracker.flush_all())
    assert len(flows) == 1
    flow = flows[0]

    assert flow.quic["version_name"] == "QUIC v1"
    assert flow.client_tls is not None
    assert flow.client_tls.sni == "cdn.example"
    assert flow.server_tls is not None
    assert flow.server_tls.selected_group == group
    assert flow.client_hello_ts > 0 and flow.server_hello_ts > 0

    rec = flow.record()
    assert rec["quic_version"] == "QUIC v1"
    assert rec["sni"] == "cdn.example"
    assert rec["proto"] == "UDP"

    feats = extract_features(flow)
    assert feats.shape == (N_FEATURES,)
    assert np.all(np.isfinite(feats))

    # short-header data packets were counted but never claimed as QUIC frames
    assert flow.packets_fwd > 2 and flow.packets_bwd > 2


def test_quic_pqc_assessment(tmp_path):
    pcap = write_pcap(str(tmp_path / "quic_hybrid.pcap"),
                      quic_flow_packets(profile="hybrid", sni="cdn.example"))
    flows = collect_flows(pcap)
    assert len(flows) == 1
    hybrid = assess_flow(flows[0])
    assert hybrid["applicable"] is True
    assert hybrid["score"] >= 80
    assert hybrid["risk"] == "quantum_ready"

    pcap = write_pcap(str(tmp_path / "quic_classic.pcap"),
                      quic_flow_packets(profile="classic", sni="cdn.example"))
    classic = assess_flow(collect_flows(pcap)[0])
    assert classic["applicable"] is True
    assert classic["score"] < 55                      # VULNERABLE_BELOW
    assert classic["risk"] != "quantum_ready"

    # QUIC mandates TLS 1.3: the rsa12 profile degrades to classic behaviour
    # and must still not be mistaken for an RSA key-transport session.
    rsa12 = assess_flow(collect_flows(write_pcap(
        str(tmp_path / "quic_rsa12.pcap"),
        quic_flow_packets(profile="rsa12", sni="cdn.example")))[0])
    assert rsa12["applicable"] is True
    assert rsa12["version_code"] == 0x0304
    assert rsa12["cipher"]["scheme"] != "rsa_transport"


def test_quic_engine_end_to_end(tmp_path):
    from spectra.pipeline import SpectraEngine

    baseline = str(tmp_path / "baseline.pcap")
    make_baseline_pcap(baseline, n_flows=30)

    quic_pcap = write_pcap(str(tmp_path / "quic.pcap"),
                           quic_flow_packets(profile="pqc_auth", sni="edge.site"))

    engine = SpectraEngine(model_path=str(tmp_path / "model.joblib"))
    engine.train_from_pcap(baseline, contamination=0.05)
    engine.start("pcap", path=quic_pcap)
    deadline = time.time() + 10
    while engine.running and time.time() < deadline:
        time.sleep(0.02)
    assert not engine.running

    records = [r for r in engine.flows if r.get("quic_version")]
    assert records, "QUIC flow missing from engine output"
    rec = records[0]
    assert rec["quic_version"] == "QUIC v1"
    assert rec["sni"] == "edge.site"
    assert rec["pqc"]["applicable"] is True
    assert rec["score"] is not None


# -- hostile / unusual packets ------------------------------------------------

def test_version_negotiation_packet():
    # Server VN: form bit set, version 0, then a list of supported versions.
    vn = (bytes([0xC0 | 0x0D]) + b"\x00\x00\x00\x00"        # random unused bits
          + bytes([4]) + b"\xaa\xbb\xcc\xdd"                 # dcid
          + bytes([0])                                        # scid
          + b"\x00\x00\x00\x01" + b"\x6b\x33\x43\xcf")       # offered versions
    tracker = FlowTracker()
    tracker.process(_udp("10.0.0.5", "10.0.0.6", 40000, 443, vn))
    flows = list(tracker.flush_all())
    assert len(flows) == 1
    flow = flows[0]
    assert flow.quic is not None
    assert flow.quic["version_name"] == "version negotiation"
    assert "0x00000001" in flow.quic["offered_versions"]
    assert flow.client_tls is None


def test_unknown_version_and_opaque_packets_never_claim_quic():
    tracker = FlowTracker()

    # Long header but an unpublished version: no salt, so no claim.
    unknown = (bytes([0xE0]) + b"\x12\x34\x56\x78"           # handshake type, ver
               + bytes([4]) + b"\x01\x02\x03\x04" + bytes([0])
               + encode_varint(16) + b"\x00" * 16)
    f = tracker.process(_udp("10.0.0.5", "10.0.0.6", 40001, 443, unknown))
    assert f is not None and f.quic is None

    # 1-RTT short header: unidentifiable in isolation.
    f = tracker.process(_udp("10.0.0.5", "10.0.0.6", 40002, 443, b"\x30" + b"\x11" * 60))
    assert f is not None and f.quic is None

    # Ordinary UDP noise on 443, including long-header-ish bytes that fail
    # the structural checks (bad CID lengths).
    noise = b"\xff\xff\xff\xff\xff\xff" + b"\x00" * 40
    f = tracker.process(_udp("10.0.0.5", "10.0.0.6", 40003, 443, noise))
    assert f is not None and f.quic is None


def test_server_first_capture_does_not_crash():
    """Capture starting mid-handshake: server Initial arrives first."""
    tracker = FlowTracker()
    tracker.process(_udp("93.184.216.34", "10.0.0.5", 443, 40000,
                         SERVER_INITIAL_PROTECTED))
    tracker.process(_udp("10.0.0.5", "93.184.216.34", 40000, 443,
                         CLIENT_INITIAL_PROTECTED))
    flows = list(tracker.flush_all())
    assert len(flows) == 1
    # keys were derived from the wrong DCID, so nothing authenticates - but
    # the tracker survives and still recognises the protocol from headers.
    flow = flows[0]
    assert flow.quic is not None
    assert flow.client_tls is None and flow.server_tls is None


def test_truncated_initial_is_rejected():
    secrets = initial_secrets(0x00000001, DCID)
    # Cut before the header-protection sample: cannot be opened.
    assert open_initial(CLIENT_INITIAL_PROTECTED[:24], secrets["client"]) is None
    # Bit-flipped ciphertext: AEAD must fail closed.
    tampered = bytes([CLIENT_INITIAL_PROTECTED[0]]) + CLIENT_INITIAL_PROTECTED[1:100] \
        + bytes([CLIENT_INITIAL_PROTECTED[100] ^ 0xFF]) + CLIENT_INITIAL_PROTECTED[101:]
    assert open_initial(tampered, secrets["client"]) is None


def _udp(src, dst, sport, dport, payload):
    from scapy.all import IP, UDP, Raw
    pkt = IP(src=src, dst=dst) / UDP(sport=sport, dport=dport) / Raw(load=payload)
    pkt.time = 1_700_000_000.0
    return pkt
