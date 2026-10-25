"""Per-dataset label adapters: a dataset's own ground truth -> label CSV.

Every fixture here is a hand-built fragment of the *real* published format
(CTU-13 binetflow in both of its layouts, CICIDS2017 flow CSV) so the
mapping, skip and timezone rules of docs/evaluation.md §3/§4 are asserted
without any external download.  The honesty rules are tested directly:

* unknown label wordings raise (a human must map them in §4 first) —
  never a silent guess;
* known data quirks are skipped *and counted* in the summary;
* the UTC offset is derived or explicit, and its source is always recorded;
* a mid-stream failure never leaves a partial label file behind.
"""

from __future__ import annotations

import socket
import struct
from datetime import datetime, timezone

import pytest

import spectra.eval as ev
from spectra.eval import LabelError, label_summary, load_labels
from spectra.eval.adapters import (
    cicids2017_to_labels,
    ctu13_to_labels,
    write_labels,
)


# -- helpers ------------------------------------------------------------------

def _udp_packet(src: str, dst: str, sport: int, dport: int) -> bytes:
    """Minimal ethernet + IPv4 + UDP frame (parser ignores checksums)."""
    ip = bytearray(20)
    ip[0] = 0x45
    struct.pack_into(">H", ip, 2, 28)              # total length: 20 + 8
    ip[8] = 64                                     # ttl
    ip[9] = 17                                     # UDP
    ip[12:16] = socket.inet_aton(src)
    ip[16:20] = socket.inet_aton(dst)
    return b"\x00" * 12 + b"\x08\x00" + bytes(ip) + struct.pack(
        ">HHHH", sport, dport, 8, 0)


def _write_pcap(path, packets) -> None:
    """Classic little-endian pcap from (epoch, raw-packet) pairs."""
    blob = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    for ts, raw in packets:
        sec = int(ts)
        usec = int(round((ts - sec) * 1_000_000))
        blob += struct.pack("<IIII", sec, usec, len(raw), len(raw)) + raw
    path.write_bytes(blob)


def _epoch(*args) -> float:
    return datetime(*args, tzinfo=timezone.utc).timestamp()


def _fmt_s1(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime(
        "%Y/%m/%d %H:%M:%S.%f")


def _s1_matched(tmp_path, votes_by_diff: dict[int, int],
                packets_per_flow: int | None = None):
    """S1 fixture + pcap whose packets vote for hour-offsets (naive − pcap).

    One botnet DNS flow per minute; the matching pcap packet sits at
    ``naive − diff`` seconds.  ``packets_per_flow`` limits how many flows
    get a packet (for the pruning test the capture ends early).
    """
    base = _epoch(2011, 8, 10, 9, 0, 0)
    rows, packets, i = [], [], 0
    for diff, n in votes_by_diff.items():
        for _ in range(n):
            naive = base + i * 60.0
            sport = 49000 + i
            rows.append(
                f"147.32.84.165,8.8.8.8,udp,{sport},53,S_?,D,"
                f"{_fmt_s1(naive)},{_fmt_s1(naive + 1)},"
                f"flow=From-Botnet-V42-UDP-DNS")
            if packets_per_flow is None or i < packets_per_flow:
                packets.append((naive - diff,
                                _udp_packet("147.32.84.165", "8.8.8.8",
                                            sport, 53)))
            i += 1
    if not packets:
        # keep the capture valid-but-unrelated: a pcap with no packets is a
        # different failure (truncated capture), not a tz-derivation miss
        packets.append((_epoch(2011, 8, 10, 6, 0, 0),
                        _udp_packet("203.0.113.9", "198.51.100.7", 1111, 2222)))
    lab = tmp_path / "capture.binetflow"
    lab.write_text(S1_HEADER + "\n".join(rows) + "\n", encoding="utf-8")
    pcap = tmp_path / "capture.pcap"
    _write_pcap(pcap, packets)
    return str(lab), str(pcap)


# -- write_labels (schema gate) ----------------------------------------------

ROWS = [
    {"t_start": 100.0, "t_end": 200.0, "src_ip": "10.0.0.1", "src_port": "*",
     "dst_ip": "10.0.0.2", "dst_port": "443", "proto": "TCP",
     "dataset_label": "PortScan", "mapped_category": "RECONNAISSANCE"},
    {"t_start": 100.0, "t_end": 200.0, "src_ip": "10.0.0.3", "src_port": 53,
     "dst_ip": "10.0.0.4", "dst_port": "*", "proto": "UDP",
     "dataset_label": "BENIGN", "mapped_category": "RECONNAISSANCE"},
]


def test_write_labels_roundtrip(tmp_path):
    out = tmp_path / "labels.csv"
    summary = write_labels(ROWS, str(out))
    assert summary["labels_written"] == 2
    assert summary["by_category"] == {"RECONNAISSANCE": 1}
    assert summary["benign_windows"] == 1

    rows = load_labels(str(out))
    assert rows[0].src_port is None           # "*" round-trips as any
    assert rows[0].dst_port == 443
    assert rows[1].proto == "UDP"
    assert rows[1].benign is True             # BENIGN wording derives benign


def test_write_labels_unknown_category_leaves_no_file(tmp_path):
    out = tmp_path / "labels.csv"
    bad = [dict(ROWS[0], mapped_category="MAGIC_CATEGORY")]
    with pytest.raises(LabelError, match="MAGIC_CATEGORY"):
        write_labels(bad, str(out))
    assert not out.exists()                  # no partial file to mistake
    assert not (tmp_path / "labels.csv.tmp").exists()


def test_write_labels_empty_is_an_error(tmp_path):
    out = tmp_path / "labels.csv"
    with pytest.raises(LabelError, match="no labels written"):
        write_labels([], str(out))
    assert not out.exists()


# -- CTU-13, comma "2format" binetflow (scenario 1) ---------------------------

S1_HEADER = ("SrcAddr,DstAddr,Proto,Sport,Dport,State,Dir,"
             "StartTime,LastTime,Label\n")
S1_ROWS = [
    # botnet C2 DNS - written, verbatim label
    "147.32.84.165,8.8.8.8,udp,49244,53,S_?,D,"
    "2011/08/10 09:46:59.607825,2011/08/10 09:46:59.612000,"
    "flow=From-Botnet-V42-UDP-DNS",
    # botnet attempt - written
    "147.32.84.165,8.8.4.4,udp,49245,53,S_?,D,"
    "2011/08/10 09:47:00.100000,2011/08/10 09:47:00.200000,"
    "flow=From-Botnet-V42-UDP-Attempt-DNS",
    # normal rows - written as benign windows
    "10.0.0.5,147.32.80.9,udp,53,40001,SF,DC,"
    "2011/08/10 09:48:00.000000,2011/08/10 09:48:01.000000,"
    "flow=From-Normal-V42-UDP-CVUT-DNS-Server",
    "10.0.0.6,147.32.80.11,tcp,50001,80,SF,DC,"
    "2011/08/10 09:49:00.000000,2011/08/10 09:49:02.000000,"
    "flow=From-Normal-V42-Stribrek",
    # background rows - skipped, never attack and never benign
    "10.0.0.7,93.184.216.34,tcp,50002,80,SF,DC,"
    "2011/08/10 09:50:00.000000,2011/08/10 09:50:01.000000,"
    "flow=Background-10.0.0.7-TCP-50002-80",
    "10.0.0.8,93.184.216.35,tcp,50003,443,SF,DC,"
    "2011/08/10 09:51:00.000000,2011/08/10 09:51:01.000000,"
    "flow=To-Background-93.184.216.35-TCP-443",
    # botnet over icmp - non-TCP/UDP quirk, skipped
    "147.32.84.165,147.32.84.160,icmp,0,0,0,DC,"
    "2011/08/10 09:52:00.000000,2011/08/10 09:52:00.100000,"
    "flow=From-Botnet-V42-ICMP",
    # out-of-range port - skipped
    "147.32.84.165,8.8.8.8,udp,70000,53,S_?,D,"
    "2011/08/10 09:53:00.000000,2011/08/10 09:53:00.100000,"
    "flow=From-Botnet-V42-UDP-DNS",
    # empty source address - skipped
    ",8.8.8.8,udp,49246,53,S_?,D,"
    "2011/08/10 09:54:00.000000,2011/08/10 09:54:00.100000,"
    "flow=From-Botnet-V42-UDP-DNS",
    # empty label - skipped
    "10.0.0.9,8.8.8.8,udp,49247,53,S_?,D,"
    "2011/08/10 09:55:00.000000,2011/08/10 09:55:00.100000,",
]


def _s1(tmp_path) -> str:
    p = tmp_path / "capture.binetflow"
    p.write_text(S1_HEADER + "\n".join(S1_ROWS) + "\n", encoding="utf-8")
    return str(p)


def test_ctu13_s1_maps_and_skips(tmp_path):
    out = tmp_path / "s1-labels.csv"
    summary = ctu13_to_labels(_s1(tmp_path), str(out), tz_offset_s=0)

    assert summary["adapter"] == "ctu13"
    assert summary["format"] == "binetflow-csv"
    assert summary["rows_read"] == 10
    assert summary["labels_written"] == 4
    assert summary["by_category"] == {"C2_BEACONING": 2}
    assert summary["benign_windows"] == 2
    assert summary["skipped"] == {
        "background": 2, "invalid_proto": 1, "invalid_port": 1,
        "invalid_ip": 1, "empty_label": 1,
    }
    # the dataset's own wording is preserved verbatim, counted — including
    # rows later skipped (3 rows carry this label: 1 written, 2 skipped)
    assert summary["raw_labels"]["flow=From-Botnet-V42-UDP-DNS"] == 3
    assert summary["raw_labels"]["flow=From-Normal-V42-Stribrek"] == 1
    assert summary["tz"]["source"] == "argument"
    assert summary["tz"]["offset_s"] == 0.0

    rows = load_labels(str(out))
    assert len(rows) == 4
    assert rows[0].dataset_label == "flow=From-Botnet-V42-UDP-DNS"
    assert rows[0].mapped_category == "C2_BEACONING"
    assert rows[0].benign is False
    assert rows[0].src_port == 49244 and rows[0].dst_port == 53
    # normal rows are benign windows (mapped_category is the schema
    # convention for benign rows; metrics gate on .benign)
    assert rows[2].dataset_label == "normal"
    assert rows[2].benign is True
    assert rows[2].mapped_category == "RECONNAISSANCE"
    assert label_summary(rows)["benign_windows"] == 2


def test_ctu13_tz_derived_from_pcap_5tuple(tmp_path):
    lab, pcap = _s1_matched(tmp_path, {7200: 30})
    out = tmp_path / "labels.csv"
    summary = ctu13_to_labels(lab, str(out), pcap_path=pcap)

    tz = summary["tz"]
    assert tz["offset_s"] == -7200.0          # CEST: naive wall clock = UTC+2
    assert tz["source"] == "pcap-5tuple"      # modal first-packet alignment
    assert tz["assumed_utc"] is False
    assert tz["matches"] == 30
    assert tz["modal_share"] == pytest.approx(1.0)
    assert tz["top_offsets"][0] == [7200.0, 30]

    # 09:00:00 local becomes 07:00:00 UTC; every flow is inside the capture
    assert summary["labels_written"] == 30
    assert "outside_capture" not in summary["skipped"]
    first = load_labels(str(out))[0]
    assert first.t_start == pytest.approx(_epoch(2011, 8, 10, 7, 0, 0),
                                          abs=1e-6)


def test_ctu13_tz_ambiguous_pcap_raises(tmp_path):
    # two competing hour buckets without a 2x margin: refuse to guess
    lab, pcap = _s1_matched(tmp_path, {7200: 20, 3600: 15})
    with pytest.raises(LabelError, match="ambiguous"):
        ctu13_to_labels(lab, str(tmp_path / "out.csv"), pcap_path=pcap)
    assert not (tmp_path / "out.csv").exists()


def test_ctu13_tz_unmatched_pcap_raises(tmp_path):
    lab, pcap = _s1_matched(tmp_path, {7200: 30}, packets_per_flow=0)
    with pytest.raises(LabelError, match="tz_offset"):
        ctu13_to_labels(lab, str(tmp_path / "out.csv"), pcap_path=pcap)


def test_ctu13_prunes_labels_outside_capture_window(tmp_path):
    # capture covers only the first minutes of the labeled period: label
    # rows the capture can never join are excluded from support (counted),
    # so recall is not deflated by guaranteed misses
    lab, pcap = _s1_matched(tmp_path, {7200: 10}, packets_per_flow=3)
    out = tmp_path / "labels.csv"
    # explicit offset: derivation is refused below the match floor (correctly),
    # but the capture is still walked for its window so pruning applies
    summary = ctu13_to_labels(lab, str(out), pcap_path=pcap, tz_offset_s=-7200)
    # flows at 07:00/01/02 UTC + 60 s edge margin keep the 07:03 flow
    assert summary["labels_written"] == 4
    assert summary["skipped"]["outside_capture"] == 6
    assert load_labels(str(out))[0].t_start == pytest.approx(
        _epoch(2011, 8, 10, 7, 0, 0), abs=1e-6)


def test_ctu13_s1_tz_without_pcap_assumes_utc_and_says_so(tmp_path):
    summary = ctu13_to_labels(_s1(tmp_path), str(tmp_path / "s1.csv"))
    assert summary["tz"] == {
        "offset_s": 0.0, "source": None, "assumed_utc": True,
    }


def test_ctu13_pcapng_capture_raises(tmp_path):
    pcap = tmp_path / "capture.pcapng"
    pcap.write_bytes(b"\x0a\x0d\x0d\x0a" + b"\x00" * 28)
    with pytest.raises(LabelError, match="pcapng"):
        ctu13_to_labels(_s1(tmp_path), str(tmp_path / "s1.csv"),
                        pcap_path=str(pcap))


def test_ctu13_s1_unknown_label_raises(tmp_path):
    p = tmp_path / "capture.binetflow"
    p.write_text(S1_HEADER +
                 "10.0.0.1,10.0.0.2,tcp,1,2,SF,DC,"
                 "2011/08/10 09:46:00.000000,2011/08/10 09:46:01.000000,"
                 "flow=From-Mystery-V42\n", encoding="utf-8")
    with pytest.raises(LabelError, match="Mystery"):
        ctu13_to_labels(str(p), str(tmp_path / "out.csv"), tz_offset_s=0)
    assert not (tmp_path / "out.csv").exists()


def test_ctu13_s1_missing_columns_raises(tmp_path):
    p = tmp_path / "capture.binetflow"
    p.write_text("SrcAddr,DstAddr,Proto\n1.1.1.1,2.2.2.2,tcp\n",
                 encoding="utf-8")
    with pytest.raises(LabelError, match="Label"):
        ctu13_to_labels(str(p), str(tmp_path / "out.csv"))


def test_ctu13_unrecognised_format_raises(tmp_path):
    p = tmp_path / "capture.binetflow"
    p.write_text("hello world\n", encoding="utf-8")
    with pytest.raises(LabelError, match="unrecognised"):
        ctu13_to_labels(str(p), str(tmp_path / "out.csv"))


# -- CTU-13, tab-separated netflow.labeled (scenario 2) -----------------------

def _s2_line(dt, dur, proto, src, dst, label) -> str:
    return "\t".join([dt, dur, proto, src, "->", dst,
                      "INT", "0", "2", "135", "1", label])


S2_HEADER = ("#Date_flow start Durat Prot Src_IP_Addr:Port -> "
             "Dst_IP_Addr:Port Flags Tos Packets Bytes Flows "
             "Label(LEGITIMATE:Botnet:Background)")
S2_ROWS = [
    _s2_line("2011-08-11 10:10:00.003", "0.967", "UDP",
             "89.31.8.11:23929", "147.32.84.229:13363", "Botnet"),
    _s2_line("2011-08-11 10:10:01.000", "1.500", "TCP",
             "147.32.80.9:53", "10.0.0.5:40001", "LEGITIMATE"),
    _s2_line("2011-08-11 10:10:02.000", "0.250", "UDP",
             "10.0.0.7:123", "130.149.1.1:123", "Background"),
    _s2_line("2011-08-11 10:10:03.000", "-0.500", "TCP",
             "10.0.0.8:50000", "10.0.0.9:80", "Botnet"),
    _s2_line("2011-08-11 10:10:04.000", "1.000", "ICMP",
             "10.0.0.10:0", "10.0.0.11:0", "Botnet"),
]


def _s2(tmp_path) -> str:
    p = tmp_path / "capture.netflow.labeled"
    p.write_text(S2_HEADER + "\n" + "\n".join(S2_ROWS) + "\n",
                 encoding="utf-8")
    return str(p)


def test_ctu13_s2_maps_and_skips(tmp_path):
    out = tmp_path / "s2-labels.csv"
    summary = ctu13_to_labels(_s2(tmp_path), str(out), tz_offset_s=-7200)

    assert summary["format"] == "binetflow-tab"
    assert summary["rows_read"] == 5
    assert summary["labels_written"] == 2
    assert summary["by_category"] == {"C2_BEACONING": 1}
    assert summary["benign_windows"] == 1
    assert summary["skipped"] == {
        "background": 1, "invalid_time": 1, "invalid_proto": 1,
    }
    assert summary["raw_labels"]["LEGITIMATE"] == 1

    rows = load_labels(str(out))
    assert rows[0].dataset_label == "Botnet"
    assert rows[0].proto == "UDP"
    assert rows[0].src_port == 23929 and rows[0].dst_port == 13363
    # duration extends the window; -7200 shifts CEST local time to UTC
    assert rows[0].t_start == pytest.approx(_epoch(2011, 8, 11, 8, 10, 0, 3000),
                                            abs=1e-6)
    assert rows[0].t_end == pytest.approx(_epoch(2011, 8, 11, 8, 10, 0, 970000),
                                          abs=1e-6)
    assert rows[1].dataset_label == "LEGITIMATE"
    assert rows[1].benign is True       # legitimate derives via BENIGN_LABELS


def test_ctu13_s2_unknown_label_raises(tmp_path):
    p = tmp_path / "capture.netflow.labeled"
    p.write_text(S2_HEADER + "\n" +
                 _s2_line("2011-08-11 10:10:00.003", "0.967", "UDP",
                          "89.31.8.11:23929", "147.32.84.229:13363", "Mystery")
                 + "\n", encoding="utf-8")
    with pytest.raises(LabelError, match="Mystery"):
        ctu13_to_labels(str(p), str(tmp_path / "out.csv"), tz_offset_s=0)


# -- CICIDS2017 flow CSV ------------------------------------------------------

CICIDS_HEADER = ("Flow ID,Src IP,Src Port,Dst IP,Dst Port,Protocol,"
                 "Timestamp,Flow Duration,Tot Fwd Pkts,Label\n")
CICIDS_ROWS = [
    "10.0.0.1:50000-10.0.0.2:80,10.0.0.1,50000,10.0.0.2,80,6,"
    "14/07/2017 08:59:00,5000000,4,BENIGN",
    "10.0.0.3:51000-147.32.80.9:21,10.0.0.3,51000,147.32.80.9,21,6,"
    "14/07/2017 08:59:10,200000,3,FTP-Patator",
    "10.0.0.4:51001-147.32.80.9:22,10.0.0.4,51001,147.32.80.9,22,6,"
    "14/07/2017 08:59:20,200000,3,SSH-Patator",
    "10.0.0.5:51002-10.0.0.2:80,10.0.0.5,51002,10.0.0.2,80,6,"
    "14/07/2017 08:59:30,1000000,10,DoS Hulk",
    "10.0.0.6:51003-10.0.0.2:80,10.0.0.6,51003,10.0.0.2,80,6,"
    "14/07/2017 08:59:40,3000000,20,DDoS",
    "10.0.0.7:51004-10.0.0.2:80,10.0.0.7,51004,10.0.0.2,80,6,"
    "14/07/2017 08:59:50,400000,2,Web Attack - Brute Force",
    "10.0.0.8:51005-10.0.0.2:443,10.0.0.8,51005,10.0.0.2,443,6,"
    "14/07/2017 09:00:00,100000,1,Heartbleed",
    "10.0.0.9:51006-10.0.0.2:25,10.0.0.9,51006,10.0.0.2,25,6,"
    "14/07/2017 09:00:10,900000,5,Email Bounce",
    "10.0.0.10:51007-10.0.0.2:80,10.0.0.10,51007,10.0.0.2,80,6,"
    "14/07/2017 09:00:20,50000,1,PortScan",
    "10.0.0.11:51008-10.0.0.2:80,10.0.0.11,51008,10.0.0.2,80,6,"
    "14/07/2017 09:00:30,600000,3,Bot",
    "10.0.0.12:51009-10.0.0.2:80,10.0.0.12,51009,10.0.0.2,80,6,"
    "14/07/2017 09:00:40,700000,3,Infiltration",
    # ICMP (protocol 0) - non-TCP/UDP quirk, skipped
    "10.0.0.13:0-10.0.0.14:0,10.0.0.13,0,10.0.0.14,0,1,"
    "14/07/2017 09:00:50,1000,1,PortScan",
    # negative flow duration - skipped
    "10.0.0.15:51010-10.0.0.2:80,10.0.0.15,51010,10.0.0.2,80,6,"
    "14/07/2017 09:01:00,-250000,1,Bot",
    # empty label - skipped
    "10.0.0.16:51011-10.0.0.2:80,10.0.0.16,51011,10.0.0.2,80,6,"
    "14/07/2017 09:01:10,100000,1,",
    # unquoted comma inside Flow ID - merged back to header width
    "172.217.12.14,51765-10.0.0.2,443,10.0.2.9,51765,10.0.0.2,443,6,"
    "14/07/2017 09:01:20,80000,1,PortScan",
]


def _cicids(tmp_path) -> str:
    p = tmp_path / "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv"
    p.write_text(CICIDS_HEADER + "\n".join(CICIDS_ROWS) + "\n",
                 encoding="utf-8")
    return str(p)


def test_cicids2017_maps_per_mapping_table(tmp_path):
    out = tmp_path / "cicids-labels.csv"
    summary = cicids2017_to_labels(_cicids(tmp_path), str(out), tz_offset_s=0)

    assert summary["adapter"] == "cicids2017"
    assert summary["format"] == "flow-csv"
    assert summary["rows_read"] == 15
    assert summary["labels_written"] == 12
    assert summary["by_category"] == {
        "C2_BEACONING": 1,
        "DATA_EXFILTRATION_SUSPECTED": 1,
        "METADATA_INVISIBLE": 2,
        "RECONNAISSANCE": 4,          # 2x patator + 2x PortScan
        "VOLUMETRIC_ANOMALY": 2,      # DoS Hulk + DDoS
    }
    assert summary["benign_windows"] == 2  # BENIGN + Email Bounce
    assert summary["skipped"] == {
        "invalid_proto": 1, "invalid_time": 1, "empty_label": 1,
    }

    rows = load_labels(str(out))
    by_label = {r.dataset_label: r for r in rows}
    assert by_label["FTP-Patator"].mapped_category == "RECONNAISSANCE"
    assert by_label["SSH-Patator"].mapped_category == "RECONNAISSANCE"
    assert by_label["DoS Hulk"].mapped_category == "VOLUMETRIC_ANOMALY"
    assert by_label["DDoS"].mapped_category == "VOLUMETRIC_ANOMALY"
    assert by_label["Web Attack - Brute Force"].mapped_category == "METADATA_INVISIBLE"
    assert by_label["Heartbleed"].mapped_category == "METADATA_INVISIBLE"
    assert by_label["Bot"].mapped_category == "C2_BEACONING"
    assert by_label["Infiltration"].mapped_category == "DATA_EXFILTRATION_SUSPECTED"
    # BENIGN wording and the normalised Email Bounce are both benign windows
    assert by_label["BENIGN"].benign is True
    assert by_label["benign"].benign is True
    assert "Email Bounce" not in by_label
    # Flow Duration (microseconds) extends the window
    assert by_label["BENIGN"].t_end - by_label["BENIGN"].t_start == pytest.approx(5.0)


def test_cicids2017_flow_id_commas_are_merged(tmp_path):
    out = tmp_path / "cicids-labels.csv"
    cicids2017_to_labels(_cicids(tmp_path), str(out), tz_offset_s=0)
    rows = load_labels(str(out))
    merged = [r for r in rows if r.src_ip == "10.0.2.9"]
    assert len(merged) == 1
    assert merged[0].mapped_category == "RECONNAISSANCE"   # PortScan


def test_cicids2017_unknown_label_raises(tmp_path):
    p = tmp_path / "Monday-WorkingHours-Morning.pcap_ISCX.csv"
    p.write_text(CICIDS_HEADER +
                 "a:1-b:2,10.0.0.1,1,10.0.0.2,2,6,"
                 "14/07/2017 08:59:00,1000,1,EvilLabel\n", encoding="utf-8")
    with pytest.raises(LabelError, match="EvilLabel"):
        cicids2017_to_labels(str(p), str(tmp_path / "out.csv"), tz_offset_s=0)
    assert not (tmp_path / "out.csv").exists()


def test_cicids2017_missing_columns_raises(tmp_path):
    p = tmp_path / "Monday.csv"
    p.write_text("Src IP,Src Port\n10.0.0.1,1\n", encoding="utf-8")
    with pytest.raises(LabelError, match="Label"):
        cicids2017_to_labels(str(p), str(tmp_path / "out.csv"))


# -- public surface -----------------------------------------------------------

def test_eval_reexports_adapter_api():
    for name in ("write_labels", "ctu13_to_labels", "cicids2017_to_labels"):
        assert hasattr(ev, name), name
