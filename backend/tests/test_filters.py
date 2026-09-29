"""Tests for the pure-Python BPF-style packet filter."""

import pytest
from scapy.all import ICMP, IP, TCP, UDP

from spectra.filters import FilterError, compile_filter


def pkt(src="10.0.0.5", dst="93.184.216.34", sport=40000, dport=443, proto="tcp"):
    if proto == "tcp":
        return IP(src=src, dst=dst) / TCP(sport=sport, dport=dport)
    if proto == "udp":
        return IP(src=src, dst=dst) / UDP(sport=sport, dport=dport)
    return IP(src=src, dst=dst) / ICMP()


def test_host_filter_both_directions():
    f = compile_filter("host 10.0.0.5")
    assert f(pkt(src="10.0.0.5"))
    assert f(pkt(src="8.8.8.8", dst="10.0.0.5"))
    assert not f(pkt(src="8.8.8.8", dst="9.9.9.9"))


def test_src_dst_host():
    assert compile_filter("src host 10.0.0.5")(pkt(src="10.0.0.5"))
    assert not compile_filter("src host 10.0.0.5")(pkt(src="8.8.8.8", dst="10.0.0.5"))
    assert compile_filter("dst host 93.184.216.34")(pkt())


def test_net_filter_cidr():
    f = compile_filter("dst net 93.184.216.0/24")
    assert f(pkt())
    assert not f(pkt(dst="10.0.0.1"))
    # shorthand: `dst 10.0.0.0/24` == `dst net ...`
    assert compile_filter("dst 10.0.0.0/24")(pkt(src="1.1.1.1", dst="10.0.0.9"))


def test_port_filters():
    assert compile_filter("port 443")(pkt())
    assert not compile_filter("port 80")(pkt())
    assert compile_filter("dst port 443")(pkt())
    assert not compile_filter("src port 443")(pkt())
    assert compile_filter("portrange 40000-40100")(pkt())
    assert not compile_filter("portrange 100-200")(pkt())


def test_protocol_filters():
    assert compile_filter("tcp")(pkt())
    assert not compile_filter("udp")(pkt())
    assert compile_filter("udp")(pkt(proto="udp"))
    assert compile_filter("icmp")(pkt(proto="icmp"))


def test_boolean_combinators():
    assert compile_filter("tcp and port 443")(pkt())
    assert not compile_filter("tcp and port 80")(pkt())
    assert compile_filter("port 443 or port 80")(pkt())
    assert not compile_filter("host 10.0.0.5 and port 80")(pkt())
    assert compile_filter("not port 80")(pkt())
    assert compile_filter("host 10.0.0.5 or host 1.1.1.1")(
        pkt(src="1.1.1.1")
    )


def test_implicit_and():
    # whitespace-separated predicates act as AND
    assert compile_filter("tcp port 443 host 10.0.0.5")(pkt())
    assert not compile_filter("tcp port 80 host 10.0.0.5")(pkt())


def test_empty_filter_matches_everything():
    assert compile_filter("")(pkt())
    assert compile_filter("   ")(pkt())


def test_src_dst_shorthand_ports():
    assert compile_filter("src 10.0.0.5")(pkt())
    assert not compile_filter("src 10.0.0.6")(pkt())


@pytest.mark.parametrize(
    "expr",
    [
        "host not-an-ip",
        "port abc",
        "port 70000",
        "net 10.0.0.0/99",
        "portrange 80",
        "tcp and",
        "host",
        "( tcp )",
        "src banana",
    ],
)
def test_invalid_expressions_raise(expr):
    with pytest.raises(FilterError):
        compile_filter(expr)


def test_filter_applied_by_capture_source(tmp_path):
    from scapy.utils import PcapWriter

    from spectra.capture import PcapFileSource

    path = str(tmp_path / "mixed.pcap")
    writer = PcapWriter(path, sync=True)
    writer.write(pkt(src="10.0.0.5"))
    writer.write(pkt(src="8.8.8.8", dport=80))
    writer.close()

    source = PcapFileSource(path, bpf_filter="host 10.0.0.5")
    got = list(source.packets())
    assert len(got) == 1
    assert got[0][IP].src == "10.0.0.5"
