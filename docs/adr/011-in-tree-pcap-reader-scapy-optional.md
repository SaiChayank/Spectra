# ADR-011: Replace scapy with an in-tree pcap reader; scapy becomes an optional extra for live capture

**Status:** Decided by the owner on 2026-11-07 (accepted the recommendation); **not implemented.** Written by the implementing agent.

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
