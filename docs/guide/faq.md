# FAQ

**Does Spectra decrypt traffic?**
No. It reads flow statistics and TLS/QUIC handshake fields (server name, versions, cipher suites, fingerprints) and
timing. Payload bytes are used only to find message boundaries, then discarded. It never derives key material.

**Will it catch malware on my network?**
Not reliably yet. On three real public datasets the default detector flagged 0.4 % to 2.9 % of attack flows and 0 of
98,700 command-and-control flows in one set, while keeping false flags on benign traffic at 1-4 %
([evaluation report](../evaluation-report.md) section 14). The beaconing detector failed its gate twice and is off by
default. Spectra may surface odd behaviour worth a look; it should not be your only control.

**Why does my first scan flag everything?**
The model was trained on a baseline that does not match the network. The bundled demo baseline is synthetic. Train on
a benign capture of your own network ([calibrate](./calibrate.md)).

**What does "unscored" mean?**
No usable model was loaded, so flows were stored but not scored; zero detections then means nothing
([alerts](./alerts.md)).

**Does it send data anywhere?**
The release policy says it makes no outbound network calls and sends no telemetry. Threat-intel lists are files you
place locally, never fetched at runtime. It only sees data you give it, and it never transmits packets.

**Is it safe to expose to the internet?**
No. It binds to loopback by default, has no TLS in-process and no idle-session timeout. Put a TLS reverse proxy in
front and set `SPECTRA_SESSION_COOKIE_SECURE=true` before any non-local exposure ([limitations](../limitations.md)
section 7).

**Does it block or respond to threats?**
No. There is no blocking, quarantine or automated response; triage ends with acknowledge, resolve and notes.

**Can I use my own packet captures?**
Yes, `.pcap` and `.pcapng` up to 256 MiB per file by default. Only deploy it on networks you own or are authorised to
monitor, and keep in mind that captures can contain private data; stored uploads are rewritten to metadata only
unless you set `SPECTRA_STORE_RAW_CAPTURES=1`.

**What do the confidence and severity mean, and why is my high-score alert "LOW"?**
Score says how unusual; confidence says how strongly independent rules agree on a category; severity is ordinal
urgency from several inputs. A very unusual flow with no named category is LOW on purpose ([alerts](./alerts.md)).

**How do I report a security problem?**
Use GitHub private vulnerability reporting on the repository (Security tab); do not open a public issue.
See [SECURITY.md](../../SECURITY.md). There has been no public release yet, so report against `main`.
