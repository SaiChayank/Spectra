"""In-tree pcap reader (ADR-011): no scapy on the import path, agrees with scapy, fails closed on corrupt input."""
import os
import random
import subprocess
import sys

import pytest

from spectra.capture import PcapFileSource
from spectra.capture.base import CaptureError
from spectra.demo import make_baseline_pcap, make_suspicious_pcap

_PROBE = """
import sys
sys.modules['scapy'] = None            # any 'import scapy...' now raises ImportError
from spectra.tools import collect_flows
from spectra.capture import open_source
from spectra.services import training  # imports spectra.demo
n = len(collect_flows(sys.argv[1]))
assert sum(1 for _ in open_source("pcap", path=sys.argv[1]).packets()) > 0 and n > 0 and not any(m == 'scapy' or m.startswith('scapy.') for m in sys.modules if sys.modules[m]), n
print('ok')
"""


def test_pcap_import_path_does_not_need_scapy(tmp_path):
    pcap = make_baseline_pcap(str(tmp_path / "b.pcap"), n_flows=3)
    env = {**os.environ, "SPECTRA_DATA_DIR": str(tmp_path / "data"), "PYTHONPATH": os.pathsep.join(sys.path)}
    r = subprocess.run([sys.executable, "-c", _PROBE, pcap], capture_output=True, text=True, env=env, timeout=120)
    assert r.returncode == 0 and r.stdout.startswith("ok"), r.stderr[-1500:]


def test_reader_matches_scapy_packet_for_packet(tmp_path):
    from scapy.all import IP, TCP, UDP, Ether, rdpcap

    for make in (make_baseline_pcap, make_suspicious_pcap):
        path = make(str(tmp_path / f"{make.__name__}.pcap"))
        ours = list(PcapFileSource(path).packets())
        theirs = list(rdpcap(path))
        assert len(ours) == len(theirs) > 0
        for a, b in zip(ours, theirs, strict=True):
            ip, l4 = b[IP], b[TCP] if b.haslayer(TCP) else b[UDP]
            assert (a.src, a.dst, a.sport, a.dport, a.size) == (ip.src, ip.dst, l4.sport, l4.dport, ip.len)
            assert a.payload == bytes(l4.payload) and abs(a.time - float(b.time)) < 1e-6
            assert a.data == bytes(b) and isinstance(b, Ether)
            if b.haslayer(TCP):
                assert a.flags == int(l4.flags)


def _drain(path):
    for _ in PcapFileSource(path).packets():
        pass


def test_truncated_and_bit_flipped_files_fail_closed_or_stay_bounded(tmp_path):
    path = make_baseline_pcap(str(tmp_path / "t.pcap"), n_flows=2)
    raw = open(path, "rb").read()
    cut = tmp_path / "cut.pcap"
    cut.write_bytes(raw[:-5])
    with pytest.raises(CaptureError, match="ends inside a packet record"):
        _drain(str(cut))
    rng = random.Random(11)
    for i in range(60):                     # random flips: either a clean read or CaptureError, never a hang/other error
        b = bytearray(raw)
        for _ in range(8):
            b[rng.randrange(len(b))] ^= 1 << rng.randrange(8)
        f = tmp_path / f"f{i}.pcap"
        f.write_bytes(bytes(b))
        try:
            _drain(str(f))
        except CaptureError:
            pass


def test_huge_claimed_record_is_not_allocated(tmp_path):
    import struct
    f = tmp_path / "huge.pcap"
    f.write_bytes(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1) + struct.pack("<IIII", 0, 0, 0xFFFFFFF0, 0xFFFFFFF0) + b"x" * 8)
    with pytest.raises(CaptureError):
        _drain(str(f))
