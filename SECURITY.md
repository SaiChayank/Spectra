# Security Policy

## Reporting a vulnerability

Please **do not open a public issue** for a security problem.

Report it privately through GitHub: **Security → Report a vulnerability** on
this repository (GitHub private vulnerability reporting). Include:

- the affected version or commit,
- steps to reproduce, or a proof of concept,
- the impact you expect (for example, auth bypass or payload exposure).

You should get an acknowledgement within **7 days**. Once a fix is ready we
publish a GitHub Security Advisory, crediting you unless you ask us not to.

## Supported versions

| Version | Security fixes |
|---|---|
| latest minor release | yes |
| previous minor release | for 3 months after the next minor ships |
| older | no |

## Scope

In scope: the Spectra backend, API, CLI, dashboard and the published
packages and images.

Especially important are any way to make Spectra:

- decrypt, log, persist or return packet payload bytes,
- bypass authentication or RBAC,
- break the audit hash chain undetected,
- write outside its data directory.

Out of scope: vulnerabilities in third-party dependencies that do not affect
Spectra (report those upstream), and findings that need an already-compromised
admin account or host.

## Design notes

Spectra is metadata-only by design (see `docs/project-rules.md` and
`docs/security.md`). It binds to `127.0.0.1` by default. Exposing it on a
network needs TLS in front of it and `SPECTRA_SESSION_COOKIE_SECURE=true`;
see `docs/security.md`.
