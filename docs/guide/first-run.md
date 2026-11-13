# First run

This walks through the whole loop with the demo captures: start, sign in, change the password, upload, train,
read the result. The command-line and API steps below were run against a throwaway data directory on `127.0.0.1`
and the outputs shown are real (trimmed). The dashboard click-paths are described from the frontend source; they
were not clicked through in a browser while writing this page.

The demo captures are **synthetic**. A model trained on them tells you nothing about your own network; for that see
[calibrate](./calibrate.md).

## 0. Use a scratch data directory

Spectra keeps its database, uploads and models in `SPECTRA_DATA_DIR` (default `backend/data`). The first start
creates an admin account there, so for a trial point it at a temporary directory:

```bash
cd backend
export SPECTRA_DATA_DIR=$(mktemp -d)
export SPECTRA_MODEL_PATH=$SPECTRA_DATA_DIR/spectra_model.joblib
```

## 1. Generate the demo captures

```bash
python -m spectra.cli demo --out $SPECTRA_DATA_DIR/demo --train
```

This writes `baseline.pcap` (benign, synthetic) and `suspicious.pcap` (a mix with a few odd flows) and trains a
model on the baseline. The repository also ships fixtures in `backend/demo_pcaps/`. A quick offline scan:

```
$ python -m spectra.cli scan $SPECTRA_DATA_DIR/demo/suspicious.pcap --top 3
scanned 288 packets -> 13 flows, 1 detections
  [ 100.0] UDP 10.0.0.7:44444 -> 93.184.216.34:443 sni=quic.example quic=QUIC v1 reasons=iat_min_s,iat_fwd_std_s,fin_count
```

## 2. Start the server

```bash
python -m spectra.cli serve --host 127.0.0.1 --port 8787
```

`serve` takes `--host` and `--port` flags; the `SPECTRA_API_HOST`/`SPECTRA_API_PORT` variables are ignored.
Check it is up:

```
$ curl -s http://127.0.0.1:8787/api/health
{"ok":true,"writable":{"data_dir":"ok","database":"ok"},"service":"spectra","version":"1.0.0","database":"enabled","schema_version":13,"uptime_s":1.4}
```

On a source checkout the dashboard is not served from this port; see [install](./install.md). Use the dev server at
`http://localhost:5173`, or an installed wheel/container where `/` serves it.

## 3. Sign in

On the first start with an empty user table, Spectra creates the user `admin`:

* If `SPECTRA_ADMIN_PASSWORD` was set (at least 8 characters), that is the password and nothing is written to disk.
* Otherwise a random password is written to `$SPECTRA_DATA_DIR/admin_bootstrap.txt` (owner-only permissions).
  In the container it is `/data/admin_bootstrap.txt` ([install](./install.md)).

Sign in on the dashboard login page, or through the API:

```
$ curl -s -c cookies.txt -H 'content-type: application/json' \
    -d '{"username":"admin","password":"<your password>"}' http://127.0.0.1:8787/api/auth/login
{"user":{"id":1,"username":"admin","role":"ADMIN","permissions":["read","investigate",...],"totp_enabled":false},"expires_at":...}
```

Sessions last 12 hours by default. Ten bad logins for the same account and address in a minute are throttled with
HTTP 429.

## 4. Change the admin password

The dashboard has **no change-password screen** (the frontend source has no call to the users API). Use the API as
the admin; the user id of the first admin is 1 (list users with `GET /api/users` to confirm):

```
$ curl -s -b cookies.txt -X PATCH -H 'content-type: application/json' \
    -d '{"password":"<new password, at least 8 characters>"}' http://127.0.0.1:8787/api/users/1
{"id":1,"username":"admin","role":"ADMIN",...}
```

This revokes every session of that user (the next call with the old cookie returned `{"detail":"not authenticated"}`),
so sign in again with the new password. Then delete `admin_bootstrap.txt` if it exists.

## 5. Upload a capture

Dashboard: **Capture** panel, Source "Import PCAP file", choose the file, **Import & run**. API:

```
$ curl -s -b cookies.txt -F file=@$SPECTRA_DATA_DIR/demo/baseline.pcap http://127.0.0.1:8787/api/captures
{"capture_id":2,"original_name":"baseline.pcap",...,"size_bytes":324108,"status":"UPLOADED",...}
```

Only `.pcap`/`.pcapng` files are accepted, the server never takes a file path, and uploads are rewritten on import
so only headers, lengths and TLS/QUIC handshake bytes remain (see [alerts](./alerts.md), "what Spectra cannot see").
Uploading identical content again returns 409 with the existing id.

## 6. Train a baseline

Dashboard: **Model** panel, choose a benign baseline file, **Train** (the default contamination is 0.02). API,
using the capture id from the upload:

```
$ curl -s -b cookies.txt -X POST -H 'content-type: application/json' \
    -d '{"capture_id":2,"contamination":0.02}' http://127.0.0.1:8787/api/model/train
{... "contamination": 0.02, "registry": {"model_id": "mdl_81d9f5c7c003", "status": "ACTIVE", "activated": true}, ...}
```

Training needs at least 10 completed flows. The demo baseline has only 42, which gives a coarse score scale.

## 7. Process the suspicious capture and read the result

Upload `suspicious.pcap` (step 5; it became capture 3 here), then **Import & run** in the dashboard, or:

```
$ curl -s -b cookies.txt -X POST http://127.0.0.1:8787/api/captures/3/process
$ curl -s -b cookies.txt http://127.0.0.1:8787/api/captures/3
{"capture_id":3,...,"status":"COMPLETED","packets":288,"flows":13,"detections":1,"unscored_flows":0,"warnings":[]}
$ curl -s -b cookies.txt "http://127.0.0.1:8787/api/alerts?limit=3"
```

The first alert returned (abridged):

```
"source":"10.0.0.7:44444","destination":"93.184.216.34:443","protocol":"UDP",
"threat_type":"UNKNOWN_ANOMALY","anomaly_score":100.0,"confidence":0.45,"severity":"LOW",
"evidence":{... "summary":"The detector flagged this flow, but behavioural evidence did not reach any specific
  threat category. Closest sub-threshold candidate: c2 beaconing."}
"metadata":{"sni":"quic.example","tls_version":"TLS 1.3","quic_version":"QUIC v1",...}
```

Score 100, confidence 0.45, severity LOW, category "unknown anomaly". That combination is exactly the case
[alerts](./alerts.md) explains: the flow is far from the baseline, but the rules did not find enough independent
signals to name an attack. In the dashboard the alerts appear in the alerts and detections views.

Next: [alerts](./alerts.md), then [calibrate](./calibrate.md) before you trust any result on your own traffic.
