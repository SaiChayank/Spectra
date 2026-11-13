# Spectra user guide

Spectra looks at network traffic **metadata** (flow timing and sizes, TLS and QUIC handshake fields such as
the server name) and flags flows that look unusual compared with a baseline of your own normal traffic. It
never decrypts traffic and does not store payload bytes. It is passive: it reads a capture file or an
interface and never sends packets.

**What it is not.** It is not a proven malware detector: on the real public captures tested so far, the
default detector flagged almost none of the attacks (see [alerts](./alerts.md) and the
[FAQ](./faq.md)). It does not block, quarantine or respond to anything. It cannot see content: file
contents, DNS names inside a tunnel and malware signatures are invisible by design. It is a single-process
tool with no high availability, and it is not on PyPI yet.

**Who it is for.** Someone who owns or is authorised to monitor a network, can capture traffic (or has
`.pcap` files), and is happy to read a ranked list of oddities and judge them. If you need a tool that
reliably catches malware out of the box, Spectra is not that yet.

## Pages

| Page | Read it to |
|---|---|
| [install.md](./install.md) | install from source or run the container; platform support; the optional `live` extra |
| [first-run.md](./first-run.md) | start the server, sign in, upload a capture, train a baseline, read the result |
| [alerts.md](./alerts.md) | understand score, confidence, severity, "unscored", and what Spectra cannot see |
| [calibrate.md](./calibrate.md) | build a baseline from your own network (24-72 h), snaplen caveat, retraining |
| [operate.md](./operate.md) | pointers for backup, restore, upgrades, monitoring, retention, health checks |
| [faq.md](./faq.md) | short answers to the common questions |

Deeper reference lives outside the guide: [limitations](../limitations.md),
[evaluation report](../evaluation-report.md), [security](../security.md), [runbook](../runbook.md).
