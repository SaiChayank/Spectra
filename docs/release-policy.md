# Release policy: names, platforms, licences (owner decisions of 2026-11-07)

The owner accepted the recommendations below. Items marked **owner** need an action only the owner can take.

## Package and image name

`spectra` is already taken on PyPI (a different project, HTTP 200 on `pypi.org/pypi/spectra/json` on 2026-11-07), so the wheel needs a
distinct distribution name. Availability on PyPI checked the same day (404 = not registered; **this is not a trademark search**):

| Candidate | PyPI 2026-11-07 |
|---|---|
| `spectra-sensor` (recommended: says what it is) | free |
| `spectra-nids` | free |
| `spectra-ids` | free |
| `spectra-tls`, `spectra-flow`, `spectra-netwatch`, `spectra-detector`, `tlsspectra` | free |

* **Owner:** pick the name, run a trademark search for "Spectra" in the security-software class in the markets you ship to, and create the PyPI
  project (and the GHCR namespace / TestPyPI project). Nothing is published until then.
* Keep the import package (`spectra`) and the console command (`spectra`) as they are for now. **Known clash:** the unrelated PyPI project `spectra`
  also installs an import package called `spectra`; the two cannot live in one environment. Renaming the import package is a breaking change
  that needs a major version, so it is deferred; the docs should tell users to install into a dedicated virtual environment.
* Only `pyproject.toml`'s `name` changes when the owner picks; `scripts/check_wheel.py`, the Dockerfile `ARG WHEEL` and the CI paths use the wheel
  filename and need the same edit.

## Supported platforms

* **Linux (x86-64 and ARM64): full support** - live capture, offline analysis, the container image, CI-tested (Python 3.11 and 3.13).
* **macOS and Windows: best effort, offline pcap analysis and the dashboard only.** Live capture on these needs a platform packet-capture driver
  that is not tested here. No CI job covers them yet; the release gate in `docs/34_ship_plan.md` §13 ("installed on fresh Linux, macOS and
  Windows machines") is therefore **not met** and must be done by a person on those systems before they are described as supported.

## Licence notes

* Project licence: Apache-2.0 (`backend/LICENSE`).
* **JA4+ is not implemented** and will not be shipped. Only base JA4 (client, BSD-3-Clause) is implemented in `parse/tls.py`. JA4S, JA4L, JA4H, JA4X,
  JA4T and the rest are under FoxIO License 1.1 (non-commercial, patent-pending) and are excluded. This keeps the Apache-2.0 release clean.
* **scapy is GPL-2.0-only.** The owner chose to replace it with an in-tree pcap reader and make scapy an optional extra for live capture only
  (ADR-011, implemented on branch `claude/nostalgic-moore-fd6f1f`, not yet merged to main). On that branch the wheel's core `Requires-Dist`
  and the default container image no longer contain scapy; `spectra[live]` and the compose `capture` image (`spectra-live`) do, under scapy's own
  licence. `check_licenses.py` lists scapy as `optional-extra`; that is a statement of fact, not an owner approval of shipping the extra.
  An offline bundle must still be built from the core install only. Until the branch is merged and released, this paragraph describes the
  branch, not main.
* No dataset bytes are redistributed; the attribution list is in `docs/datasets.md` §5b/§5c.

## Acceptable use and privacy (to appear in the README and the docs site)

* Deploy only on networks you own or are authorised to monitor; capture and works-council rules differ by jurisdiction.
* Spectra is metadata-only by design: it does not decrypt, log or persist payload bytes, makes no outbound network calls and sends no telemetry.
  Known exception, pending the owner's decision 5: uploaded pcaps are stored verbatim (`docs/security.md` §4.9).

## Third-party notices

`THIRD_PARTY_NOTICES.md` (repo root) lists what Spectra ships, with name, exact version, SPDX licence, upstream URL and the verbatim licence/NOTICE
texts: (1) the Python core closure of a plain `pip install spectra` (not the `dev` extra), (2) the npm production closure of the dashboard,
(3) the optional `live` extra (scapy, GPL-2.0-only) in its own section, (4) the container image (pinned base; its Debian packages carry their
own licences under `/usr/share/doc`). It is generated, never hand-edited: `python scripts/gen_third_party_notices.py` (needs an environment with
the wheel plus `spectra[live]` installed at the `requirements.lock` versions, `packaging`, and `frontend/node_modules` from `npm ci`; no network
access). `--check` exits 1 when the committed file is stale and 2 when the environment does not match the lockfiles. Packages without a licence
file are listed under "Needs attention" in the file.

* The closure is walked from `backend/pyproject.toml` through installed `Requires-Dist` metadata, markers evaluated for CPython 3.13 / Linux (the
  image), so the output does not depend on the interpreter that runs it.
* Wiring: `scripts/build_release.sh` stages the file into `backend/` (git-ignored) so the wheel carries it as
  `*.dist-info/licenses/THIRD_PARTY_NOTICES.md` (`scripts/check_wheel.py` enforces this); the `Dockerfile` also copies it to
  `/usr/share/doc/spectra/`; the CI `package` job runs `--check` against the built wheel (clean 3.13 venv, lock constraints) and
  `backend/tests/test_third_party_notices.py` runs it locally when `frontend/node_modules` exists. After changing any dependency, regenerate and commit.
* Not a legal review: the texts are what the packages ship; the owner decides on the licence mix (see the scapy note above).
