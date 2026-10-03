# Spectra — Local setup

Run everything on one machine. There is no Docker, no cloud service, and no
external database: the backend is a single Python process, the frontend is a
Vite dev server, and state lives in `backend/data/`.

---

## 1. Requirements

| Component | Requirement | Verified in this repository |
|---|---|---|
| Python | **≥ 3.11** (`requires-python` in `backend/pyproject.toml`) | 3.13.5 (Windows) |
| Node.js | **^20.19.0 or ≥ 22.12.0** (Vite 8 `engines`) | v22.14.0 (Windows) |
| npm | ships with Node | 10.x |
| OS | Windows 10/11, macOS, Linux (backend + PCAP workflow) | Windows 11 |
| Npcap | **Windows only, only for live capture** — see §6 | Npcap 1.88 validated 2026-09-29 |

### Dependencies

Backend (`backend/requirements.txt`, mirrors `pyproject.toml`):

| Package | Why |
|---|---|
| `scapy>=2.5.0` | packet/PCAP reading, live capture |
| `numpy>=1.26.0` | feature matrices, scoring |
| `scikit-learn>=1.4.0` | `StandardScaler` + `IsolationForest` |
| `joblib>=1.3.0` | model artifact (de)serialisation |
| `fastapi>=0.110.0` | REST API, WebSocket, validation |
| `uvicorn[standard]>=0.29.0` | ASGI server |
| `pydantic>=2.6.0` | request/response schemas |
| `python-multipart>=0.0.9` | multipart PCAP upload |

Test/verification tooling (`backend/requirements-dev.txt`): `pytest>=8.0`.

Frontend (`frontend/package.json`): `react`, `react-dom`, `recharts`; dev:
`vite`, `typescript`, `@vitejs/plugin-react`, React type packages.

## 2. Install

```powershell
# backend
cd backend
python -m venv .venv
.venv\Scripts\activate          # macOS/Linux: source .venv/bin/activate
pip install -r requirements.txt
pip install -r requirements-dev.txt      # only needed to run the test suite

# frontend
cd ..\frontend
npm install
```

## 3. Environment configuration

Everything is `SPECTRA_*` (see `backend/spectra/config.py`); nothing is
required for a first run — the defaults in §7 of
[security.md](./security.md) are safe for local use (loopback bind, no
wildcard CORS, no default password).

The variables you are most likely to touch:

| Variable | Default | Meaning |
|---|---|---|
| `SPECTRA_ADMIN_PASSWORD` | *(unset)* | first-run admin password; if unset a random one is written to `data/admin_bootstrap.txt` (mode 600) |
| `SPECTRA_ADMIN_USERNAME` | `admin` | name of that bootstrap account |
| `SPECTRA_DATA_DIR` | `backend/data` | SQLite DB, managed captures, model artifacts, keys |
| `SPECTRA_MODEL_PATH` | `backend/models/spectra_model.joblib` | deployed detector artifact |
| `SPECTRA_LOG_LEVEL` | `INFO` | `DEBUG`/`INFO`/`WARNING`… |
| `SPECTRA_SESSION_TTL_MINUTES` | `720` | absolute session lifetime (12 h) |
| `SPECTRA_CORS_ORIGINS` | `http://localhost:5173,http://127.0.0.1:5173` | browser origins allowed to call the API / open the WebSocket |
| `SPECTRA_CAPTURE_MAX_BYTES` | `268435456` (256 MiB) | per-import capture size cap |
| `SPECTRA_CONTAMINATION` | `0.02` | expected anomaly fraction when training |
| `SPECTRA_PERSIST` | `true` | SQLite persistence on/off (tests turn it on/off per fixture) |

`SPECTRA_DATA_DIR` should stay inside the repo (it is gitignored) unless you
intentionally keep state elsewhere. Windows users: set variables with
`$env:SPECTRA_LOG_LEVEL='DEBUG'` in PowerShell.

> `spectra serve` reads `--host`/`--port` **flags**, not `SPECTRA_API_HOST`/
> `SPECTRA_API_PORT` (documented limitation, [limitations.md](./limitations.md §7)).

## 4. Start the application

Two terminals is the transparent way; `start.ps1` (§5) runs both for you.

**Terminal 1 — backend (API + WebSocket):**

```powershell
cd backend
python -m spectra.cli serve --port 8787        # http://127.0.0.1:8787
```

**Terminal 2 — frontend (dashboard):**

```powershell
cd frontend
npm run dev                                     # http://localhost:5173
```

Open **`http://localhost:5173`** (not `127.0.0.1`): the session cookie is
`SameSite=Lax`, which is same-site across ports only on `localhost`.

| Process | Port | Notes |
|---|---|---|
| API + WS | `8787` | `--port` flag; loopback by default |
| Vite dev server | `5173` | `vite.config.ts`, `strictPort: false` (auto-bumps) |
| WS endpoint | `ws://localhost:8787/ws/events` | cookie-authenticated, `?token=` also accepted |

The backend does **not** serve `frontend/dist`; in production-style deploys a
reverse proxy would front both (out of scope — no deployment infrastructure
here).

### 4.1 First admin

On first start with an empty user table, the backend bootstraps one `ADMIN`:

1. If `SPECTRA_ADMIN_PASSWORD` is set (≥ 8 chars) it is used — nothing is
   written to disk.
2. Otherwise a random password is written to `backend/data/admin_bootstrap.txt`
   with owner-only permissions and logged as a warning.
3. Later starts never re-bootstrap, never reset, and never overwrite the
   account.

Then: sign in on the dashboard → change the password (this revokes every
session for the user) → delete `admin_bootstrap.txt`.

### 4.2 Seed data (optional)

```powershell
cd backend
python -m spectra.cli demo --out data/demo --train   # benign baseline + suspicious mix, trains the model
python -m spectra.cli scan data/demo/suspicious.pcap # prints scores + explanations
```

`backend/demo_pcaps/` ships committed fixtures (`baseline.pcap`,
`suspicious.pcap`) used by the acceptance and performance scripts, so the demo
step is optional.

## 5. Convenience start script (optional)

`start.ps1` at the repository root starts the backend, then the frontend, and
stops the backend when you press `Ctrl+C`:

```powershell
.\start.ps1               # deps present → run both
.\start.ps1 -Check        # verify toolchain + deps, start nothing
```

It performs only three transparent checks — Python importable, frontend deps
installed, port free — prints exactly what it is doing, and never installs or
mutates anything silently. Everything it does is reproducible with the two
commands in §4, which remain the documented path.

## 6. Live capture on Windows (Npcap)

Managed PCAP import works without any driver. **Live interface capture** needs
Npcap:

1. Install from <https://nmap.org/npcap/> and enable
   **"Install Npcap in WinPcap API-compatible Mode"**.
2. Restart the backend so it re-detects the driver.
3. Start a `live` capture from the **Monitor** section (`capture:manage` /
   ADMIN). If your machine requires it, run the backend in an elevated
   prompt — the validated install did not.

Capture is strictly read-only: Spectra never transmits packets.

## 7. Run the verification suites

```powershell
cd backend
python -m pytest tests -q                       # unit/integration (~500 tests)
$env:SPECTRA_ADMIN_PASSWORD='<admin password>'
python scripts/acceptance.py                    # 156 checks; API must be running on :8787
python scripts/perf.py                          # performance measurements
cd ..\frontend
npm run build                                   # tsc + vite build (type-check)
```

Details, scope and expected results: [testing.md](./testing.md).

## 8. Generated state (never committed)

| Path | Created by | Git |
|---|---|---|
| `backend/data/` — `spectra.db`, `captures/`, `model_artifacts/`, `admin_bootstrap.txt`, `audit_signing.key` | first run / import / train | ignored |
| `backend/models/` — `spectra_model.joblib` (+ `.sha256`), sidecars, `tee_attestation.key` | train / activate | ignored |
| `frontend/node_modules/`, `frontend/dist/` | `npm install` / `npm run build` | ignored |
| `__pycache__/`, `.pytest_cache/` | Python | ignored |

Delete any of them to reset that layer; the schema migrates forward on the next
start and the bootstrap password reappears only if the user table is empty.

## 9. Troubleshooting

| Symptom | Cause / fix |
|---|---|
| Browser shows "sign in" loop at `127.0.0.1:5173` | use `http://localhost:5173` (cookie `SameSite=Lax`) |
| `401` immediately after login | session TTL expired (`SPECTRA_SESSION_TTL_MINUTES`) or password changed elsewhere — sign in again |
| `403` on a panel | role lacks the permission; `ADMIN`/`ANALYST`/`VIEWER` matrix in [security.md](./security.md §3) |
| Port already in use | `python -m spectra.cli serve --port 8788` and set `VITE_API_BASE=http://localhost:8788` |
| Dashboard says "no model" | train one: Monitor → capture import → **Train**, or `spectra demo --train` |
| Live capture button says driver missing | install Npcap (§6) and restart the backend |
| Everything scores ~100 | the model was trained on a baseline from a different network — retrain on a benign baseline of *this* network ([ml.md §6](./ml.md)) |
