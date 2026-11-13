# Security Policy

## Supported versions

Spectra has had **no public release yet**. There are no released versions to
support, and no past releases exist. This table states the rule that applies
from the first release.

| Release line | Security fixes |
|---|---|
| Latest minor release (for example 1.0.x once 1.0.0 is published) | Yes |
| Any other release line | No. Whether to also support the previous minor is a proposal for the owner to decide. |

Until the first release, report problems against the `main` branch.

## Reporting a vulnerability privately

Please **do not open a public issue** for a security problem.

Use GitHub's private vulnerability reporting: open the repository's **Security**
tab and choose **Report a vulnerability**.

> **Owner to fill in (not yet provided):** an optional alternative contact for
> reporters who cannot use GitHub. No email address, phone number or PGP key is
> published here until the owner adds one.

### What to include

- the affected version or commit,
- the component (API, auth/RBAC, audit chain, pcap parsing, web UI, image, wheel),
- the impact you expect,
- reproduction steps. Metadata-only steps or **synthetic** captures are preferred.

### What not to send

- Real packet captures from a network you do not own or are not authorised to monitor.
- Credentials, keys, tokens or session cookies.
- Personal data.

## Process (proposed targets, not commitments)

These timelines are **proposed**. The owner will confirm them before the first release.

| Step | Proposed target |
|---|---|
| Acknowledge the report | within 7 days |
| Triage and severity assessment | within 14 days of the report |
| Fix, or a mitigation and a date | within 90 days of the report |
| Public disclosure | after a fix is released, or at 90 days, coordinated with the reporter |

Disclosure is coordinated: please keep the details private until a fix is
available. We will credit you in the advisory if you want it, and leave you out
if you prefer.

## Scope

In scope:

- the backend API,
- authentication and RBAC,
- the audit hash chain,
- capture parsing of untrusted pcaps,
- the web UI,
- the container image and wheel as built by this repository's scripts.

**Metadata-only is a security property.** Spectra must never decrypt, log or
persist payload bytes. A report that payload bytes reach storage, logs or API
responses is in scope and high priority.

Out of scope:

- the optional `live` extra's third-party scapy code itself (report upstream),
- findings that need an already-compromised host or admin account,
- the beacon detector's detection quality: this is a documented limitation
  (`docs/limitations.md`), not a vulnerability,
- denial of service by an authenticated admin,
- third-party services.

## Safe harbour

We will not pursue action against good-faith security research that is done on
**your own installation** of Spectra, stays within the scope above, avoids
privacy violations and data destruction, and follows this policy. Do not test
against systems or networks you do not own.

## Security design

See [`docs/security.md`](docs/security.md) and
[`docs/threat-model.md`](docs/threat-model.md). Spectra binds to `127.0.0.1` by
default; exposing it on a network needs TLS in front of it and
`SPECTRA_SESSION_COOKIE_SECURE=true`.
