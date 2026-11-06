# Test fixture for spectra-payload-access-outside-parser (run: semgrep --test security/semgrep)
from scapy.all import IP, TCP, UDP, Raw, raw


def joblib_like(x):
    return x


def violations(pkt):
    # ruleid: spectra-payload-access-outside-parser
    a = pkt[TCP].payload
    # ruleid: spectra-payload-access-outside-parser
    b = bytes(pkt["UDP"].payload)
    # ruleid: spectra-payload-access-outside-parser
    c = pkt[Raw]
    # ruleid: spectra-payload-access-outside-parser
    d = pkt.getlayer(Raw)
    # ruleid: spectra-payload-access-outside-parser
    e = pkt.haslayer(Raw)
    # ruleid: spectra-payload-access-outside-parser
    f = raw(pkt)
    # ruleid: spectra-payload-access-outside-parser
    g = pkt.load
    # ruleid: spectra-payload-access-outside-parser
    h = joblib_like(pkt.load)          # a payload value passed into some call is still access
    return a, b, c, d, e, f, g, h


def clean(record, pkt, joblib, packet_meta):
    # ok: spectra-payload-access-outside-parser
    n = packet_meta.payload            # Spectra's own record: an int length, not bytes
    # ok: spectra-payload-access-outside-parser
    m = joblib.load("model.joblib")    # a method call named load
    # ok: spectra-payload-access-outside-parser
    s = pkt[IP].src                    # header fields are metadata
    # ok: spectra-payload-access-outside-parser
    t = pkt[TCP].sport
    # ok: spectra-payload-access-outside-parser
    u = pkt[UDP].dport
    return n, m, s, t, u
