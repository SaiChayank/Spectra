# Evidence — 2026-11-06

Raw, unedited tool output behind `docs/sast-report.md`, `docs/sca-report.md` and `docs/dast-report.md`. Re-run the commands in those reports to reproduce; the Semgrep/Bandit/pip-audit/npm files are JSON, `*.txt` files are the console transcripts.

| File | Tool |
|---|---|
| `semgrep-custom-rule.txt`, `semgrep-violating-patch-blocked.txt` | Semgrep 1.184.0 — custom payload-access rule: rule tests, real tree, deliberate violation |
| `semgrep-registry.json` | Semgrep 1.184.0 — `p/python`, `p/owasp-top-ten` |
| `bandit.json` | Bandit 1.9.4 |
| `pip-audit.json` (+ `.header.txt`) | pip-audit on `requirements.lock` |
| `npm-audit-before-fix.json`, `npm-audit.json`, `npm-audit-production.txt` | npm audit, before / after the non-breaking fix |
| `licenses.json` | `backend/scripts/check_licenses.py --frontend` |
| `schemathesis.txt`, `schemathesis-junit.xml` | Schemathesis 4.33.1 against a throwaway loopback instance |

Not here, and why: gitleaks and OWASP ZAP (**NOT RUN** — would need downloads that have not been approved).
