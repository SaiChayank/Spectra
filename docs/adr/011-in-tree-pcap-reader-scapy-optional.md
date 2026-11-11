# ADR-011: Replace scapy with an in-tree pcap reader; scapy becomes an optional extra for live capture

**Status:** Decided by the owner on 2026-11-07 (accepted the recommendation). **Implemented on branch `claude/nostalgic-moore-fd6f1f` (2026-11-12), not merged to main, not signed off by the owner.** Acceptance results below. Written by the implementing agent.

## Context
scapy is GPL-2.0-only and is a hard runtime dependency. An Apache-2.0 release that bundles it (wheel dependencies, the container image, an offline bundle) is not licence-clean (`docs/release-policy.md`, `HANDOFF_FINDINGS.md`). scapy is also the slowest part of the pipeline (about 4-7 thousand packets per second per core, `docs/evaluation-report.md` §13) and has caused two silent-data-loss bugs in this project (truncated captures treated as EOF).

## Decision
Packet reading, dissection and writing move to code in this repository; scapy is dropped from the runtime dependencies and survives only as an *optional* extra (`pip install spectra[live]`) for live NIC capture, imported lazily and with a clear error when missing. Test and demo packet *builders* keep scapy as a **dev** dependency only (never installed with the product).

Where scapy is used today and what replaces it:

| Use | Files | Replacement |
|---|---|---|
| pcap / pcapng / gzip reading | `capture/pcap_file.py` | `struct`-based reader: classic pcap (both endians, micro/nano), pcapng (SHB/IDB/EPB/SPB), the existing size clamp and truncation detection |
| dissection (Ethernet/VLAN, IPv4/IPv6, TCP/UDP, ICMP) | `parse/flow.py`, `filters.py`, `capture/sanitize.py` | a small `Packet` value object (addresses, ports, flags, seq/ack, payload offset, IP total length) built from bytes |
| BPF-style filter | `filters.py` | same filter grammar, evaluated on the new object |
| pcap writing | `capture/sanitize.py` | `struct` writer |
| interface listing | `services/system.py` | `socket.if_nameindex()` |
| live capture | `capture/live.py` | stays scapy (optional extra); an in-tree `AF_PACKET` source is a later option |
| synthetic traffic | `demo.py` | scapy as dev extra, or in-tree builders |

## Acceptance (what "done" means)
1. **Differential test against scapy** on every real capture used in this project (CTU, HIKARI, CIC-2018, about 150 files in `~/Projects/Spectra_bench_data`, plus the demo generators): identical flow records and identical feature matrices, packet for packet. Scapy is available in the dev environment for exactly this test.
2. All existing tests pass; the licence checker (`backend/scripts/check_licenses.py`) shows no GPL package in the runtime closure; the wheel's `Requires-Dist` has no scapy outside the `live` extra; the container image contains no scapy.
3. Throughput is not worse than today's; truncated and malformed inputs still end in `CaptureError`, never a silent short read; fuzz the reader (random byte flips of valid files must not hang or exceed the clamp).

## Consequences
Weeks of regression risk are traded for a clean licence and a faster reader. The dissector must keep scapy's behaviour where features depend on it (for example packet size from the IP total length when present, payload length from the transport payload including Ethernet padding). Live capture on an installation without the extra fails with an actionable message.

## Alternatives considered
Relicense the project as GPL-2.0 (simple, but closes the Apache-2.0 decision and the intended user base); dpkt / pyshark / Wireshark's tshark (dpkt is BSD and small but still needs an adapter and gives no pcapng writing; pyshark/tshark are GPL or external binaries); keep scapy and document the exception (does not resolve the distribution problem).

## Acceptance results (2026-11-12; evidence in `docs/evidence/2026-11-12/reader/`)

**1. Differential against scapy** (`backend/scripts/diff_reader_vs_scapy.py`, `diff-summary.txt`, per-file JSON in `diff/`).
The "about 150 files" named above are **not on disk**: `~/Projects/Spectra_bench_data` holds 12 CTU pcaps (`datasets/`), 11 HIKARI pcaps,
and about 25 CIC-2018 capture files (no extension). Used: all 12 CTU, 4 HIKARI (3 full-anonymized days + `Monday_2022-04-11_0622_BRUTEFORCE_XML_150s`), 13 CIC-2018 (Friday 2018-03-02
`cap*`/`UCAP*` files, 7 of them cut off mid-record, plus the Wednesday `DESKTOP` file), 29 files in all. Cap: 2,000,000 packets per file, never reached; every
file was read to its end or to its cut-off. Both readers feed the same `FlowTracker`; scapy side uses the pre-ADR layer rules. Compared: packet count, flow
count, every field of `Flow.record()`, and the `flows_to_matrix` matrix (exact equality, no tolerance).
Result: **28 of 29 files identical** (packets, flows, flow records, matrix). **1 mismatch remains**: `Friday-02-03-2018__UCAP172.31.69.27`
(6,860 packets both; 889 flows in-tree vs 890 scapy). Cause (packet-level check): one ICMP destination-unreachable packet (index 2814) quotes the
start of a GRE-encapsulated packet; scapy decodes that quote as a nested GRE/Ethernet/IP/UDP stack and reports a UDP flow (outer addresses, ports
8441 -> 51817) from it; the in-tree dissector does not look inside ICMP error quotes, so it reports no flow. Not changed: reading a flow out of an ICMP error quote
is arguably a scapy artefact, but this is a real behavioural difference and the owner should decide.
Found and fixed by the differential: GRE tunnels (IP and transparent Ethernet bridging; HIKARI `Monday_2022-04-11`, 2 packets, flow count 20,348 vs 20,350 before; first-run
output kept in `diff-run1-before-gre-fix/`) and the cut-off message lacking the word "truncated" for a cut inside a record header (`bench_cic2018` matches on it).
Eight files end inside a record: the in-tree reader raises `CaptureError` after yielding the same packets scapy yielded; scapy raises nothing (the old silent
short read). Flow results are equal up to the cut in all but the mismatch above.

**2. Licence/packaging.** `requirements.lock` regenerated with the original command (`uv pip compile pyproject.toml --extra dev --generate-hashes --universal --python-version 3.11`):
byte-identical, because the lock includes the `dev` extra and scapy is a dev dependency; it is a dev/CI lock, the wheel metadata is the runtime closure.
Wheel `Requires-Dist`: no scapy except `extra == "live"` and `extra == "dev"` (`wheel-metadata.txt`). Fresh venv with the core wheel: scapy absent,
offline pcap analysis works, live capture raises the actionable `CaptureError` (`core-install-check.txt`). `scripts/check_licenses.py`: 66 packages, 65 ok, scapy
`optional-extra` (new status, see `security/license-policy.json`). Container: default image has no scapy and reaches healthy; compose `capture` builds
`spectra-live` with the `live` extra, scapy importable, reaches healthy (`image-check.txt`). Packets from a real interface were not captured.

**3. Throughput** (`bench-*.json`, `bench-notes.txt`; 3 runs, median; whole files; machine not perfectly idle, load 1.5-2 from an unrelated process). Packets/s read only /
packets/s to completed flows / flows/s: `ctu_normal--2017-04-18_win-normal` (440,240 packets, 17,965 flows) in-tree 437,307 / 139,821 / 5,706, scapy 9,557 / 8,905 / 363;
`ctu_normal--2017-05-02_kali-normal` (442,488 packets, 11,455 flows) in-tree 273,512 / 97,324 / 2,519, scapy 8,988 / 8,149 / 211. About 15-30x faster end to end.
Truncated/malformed input: `CaptureError` (tests `test_pcap_reader.py`); fuzz: 60 random bit-flip files per run in the test suite, plus size clamps. A longer fuzz campaign was not run.
