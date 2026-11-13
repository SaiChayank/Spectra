# Install

Spectra is **not on PyPI yet**. The `spectra` name there belongs to an unrelated project, and the owner has not
chosen a distribution name ([release policy](../release-policy.md)). Install from a checkout of this repository.
Because the unrelated project also installs a Python package called `spectra`, always use a dedicated virtual
environment.

## Platform support

| Platform | Status |
|---|---|
| Linux (x86-64, ARM64) | Full support: offline analysis, live capture, container image, tested in CI on Python 3.11 and 3.13. |
| macOS, Windows | Best effort: offline pcap analysis and the dashboard only. Live capture needs a packet-capture driver that is not tested here, and no CI job covers these systems. |

## Requirements (as the docs state them)

* Python 3.11 or newer (`requires-python` in `backend/pyproject.toml`).
* Node.js `^20.19.0` or `>= 22.12.0` only if you want the dashboard from a source checkout
  ([local setup](../local-setup.md) section 1).
* No external database: state is SQLite files under the data directory.
* The docs give no CPU, RAM or disk sizing. Capture files can be large; the upload cap is 256 MiB per file by default
  (`SPECTRA_CAPTURE_MAX_BYTES`). Live-capture sizing has not been measured on real hardware.

## Install from source

```bash
cd backend
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

`requirements.txt` lists the core dependencies only. The CLI is then run as `python -m spectra.cli ...` from the
`backend` directory (that is how the rest of this guide runs it; the repository's own docs do the same). Installing
the package itself (`pip install ./backend`) would also give you a `spectra` command, as `pyproject.toml` declares;
that route was not exercised while writing this guide.

**The dashboard.** A source checkout does not contain the compiled dashboard: with only the steps above,
`http://127.0.0.1:8787/` answers 404 (observed). Two ways to get it:

* Development server: `cd frontend && npm install && npm run dev`, then open `http://localhost:5173` (use `localhost`,
  not `127.0.0.1`, because of the session cookie). See [local setup](../local-setup.md) section 4.
* Build the wheel with the dashboard inside it: `scripts/build_release.sh` (needs Node and `uv` or `python -m build`),
  then install the wheel from `backend/dist/` in your virtual environment. After that `spectra serve` serves the
  dashboard and the API on one port.

Everything in this guide that does not need the dashboard also works through the API and CLI.

## Container

Needs Docker with Compose. It was rehearsed once on 2026-11-07 ([runbook](../runbook.md), "Container").

```bash
scripts/build_release.sh && docker compose up -d api
```

* The API and dashboard listen on `http://127.0.0.1:8000` (change with `SPECTRA_PORT`). Put a TLS reverse proxy in
  front before exposing it to anyone else.
* Data lives in the Docker volume `spectra-data`.
* **First admin password:** if you did not set `SPECTRA_ADMIN_PASSWORD`, it is generated and stored in the
  container, not printed in logs:

  ```bash
  docker compose exec api cat /data/admin_bootstrap.txt
  ```

* The image runs as a non-root user with a read-only root filesystem and no extra capabilities.

## Optional: live capture (`live` extra)

Reading `.pcap` and `.pcapng` files needs nothing extra. Capturing from a network interface needs the `live` extra,
which installs **scapy, licensed GPL-2.0-only**; Spectra itself is Apache-2.0 and the default wheel and image do not
contain scapy.

```bash
pip install "spectra[live]"      # once a package name is published; from a checkout: pip install "./backend[live]"
```

Without the extra, the interface list shows OS interface names only. On Windows live capture also needs Npcap
([local setup](../local-setup.md) section 6); that claim predates the change that made scapy optional and has not been
re-validated ([limitations](../limitations.md) section 7). In a container, live capture needs the separate
`spectra-live` image (`docker compose --profile capture up -d capture`); it contains scapy and should not be
redistributed as part of the Apache-2.0 release. Packets have not been captured from a real interface in the
container rehearsal.

Spectra never transmits packets, in any mode.

## Next

[First run](./first-run.md).
