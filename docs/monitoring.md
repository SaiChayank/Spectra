# Spectra — monitoring (Prometheus)

`GET /api/metrics` serves the Prometheus text exposition format (version 0.0.4, content type `text/plain; version=0.0.4; charset=utf-8`). The whole body is parsed by the official `prometheus_client` parser in `backend/tests/test_prom_metrics.py`, which also checks histogram invariants and that a scrape has no side effects. It has **not** been scraped by a real Prometheus server (none was available when this was written); the example rules below are syntax-checked only.

## Letting Prometheus in

The route needs a session with the `read` permission. A Prometheus server cannot hold a session (they expire after 12 hours), so there is an opt-in static token for this one route:

```bash
python -c 'import secrets; print(secrets.token_urlsafe(32))' > /etc/prometheus/spectra_metrics_token   # keep it private
export SPECTRA_METRICS_TOKEN="$(cat /etc/prometheus/spectra_metrics_token)"                           # on the Spectra side
```

* Off by default; when set it must be at least 32 characters or the service refuses to start.
* It is accepted **only** for `GET /api/metrics` (checked in constant time) and grants no role elsewhere: every other route still answers `401` to it. The token is never logged or returned.
* It is a shared secret, so scrape over TLS (`scheme: https` behind your terminator) and rotate it by changing the variable and restarting. Metrics contain counters and gauges only: no addresses, names or payload.

A scrape config and alert rules are in `deploy/prometheus/` (`prometheus.example.yml`, `spectra.rules.yml`).

## What is exposed

| Series | Type | Meaning |
|---|---|---|
| `spectra_build_info{version}` | gauge | always 1; the running version |
| `spectra_packets_total`, `spectra_flows_total`, `spectra_detections_total` | counter | processed in the current engine |
| `spectra_anomaly_rate`, `spectra_avg_score` | gauge | `avg_score` is `-1` before any flow is scored |
| `spectra_capture_running`, `spectra_model_trained`, `spectra_model_train_flows`, `spectra_uptime_seconds` | gauge | state |
| `spectra_queue_packets_{received,queued,dropped}`, `spectra_queue_depth`, `spectra_queue_max_depth` | gauge | live-capture queue of the current session |
| `spectra_{packet,flow,publish}_queue_{depth,max_depth,limit}` | gauge | the three bounded pipeline queues |
| `spectra_{packet,flow,publish}_queue_dropped_total` | counter | items shed because the queue was full |
| `spectra_packets_per_second`, `spectra_flows_per_second` | gauge | throughput |
| `spectra_processing_lag_ms`, `spectra_inference_latency_ms` | gauge | smoothed (EMA) lag / per-flow scoring cost |
| `spectra_inference_latency_p50_ms`, `..._p95_ms`, `spectra_db_write_latency_p95_ms` | gauge | over the last 1 024 samples |
| `spectra_inference_duration_seconds` | histogram | **cumulative** per-flow scoring time, buckets 0.1 ms … 1 s |
| `spectra_db_write_duration_seconds` | histogram | **cumulative** database write time, same buckets |
| `spectra_active_flows`, `spectra_active_flows_max` | gauge | flow-table size / high-water mark |
| `spectra_flow_evictions_total`, `spectra_flows_dropped_total` | counter | flows force-completed / dropped under load |
| `spectra_stream_overload` | gauge | 1 while any queue has dropped items |
| `spectra_db_errors_total` | counter | failed database writes |
| `spectra_websocket_clients`, `spectra_websocket_slow_client_drops_total` | gauge / counter | event stream |
| `spectra_pipeline_failures{component}` | gauge | errors counted per optional component |
| `spectra_flows_by_proto{proto}` | gauge | flows by protocol |
| `spectra_drift_psi{baseline="train"\|"recent"}`, `spectra_drift_level` | gauge | newest drift check (`0` stable, `1` moderate, `2` significant); **absent until a check has run** |
| `spectra_bio_assessments_total{response}` | counter | flows per bio response: `ignore` / `monitor` / `alert` / `isolate` |
| `spectra_audit_head_seq` | gauge | sequence number of the audit-chain head |

Notes that matter when reading the numbers:

* The streaming series (`packets`, `flows`, queues, inference histogram) describe the **current capture session** and reset when a new capture starts; Prometheus `rate()`/`increase()` handle resets, but absolute values are not lifetime totals.
* Drift is **not recomputed by a scrape** (that would be expensive and could raise an alert): the series show the newest check, which runs every 200 scored flows or when `GET /api/model/drift` is called.
* The histograms are lifetime-cumulative for their reservoir. `histogram_quantile(0.95, sum by (le) (rate(spectra_inference_duration_seconds_bucket[5m])))` is the right way to get a percentile; the `_p50_ms`/`_p95_ms` gauges are kept for dashboards that already use them.

## Changes from earlier builds

Counters that lacked the `_total` suffix were renamed to follow Prometheus convention: `spectra_flow_evictions`, `spectra_flows_dropped`, `spectra_db_errors`, `spectra_websocket_slow_client_drops` and the three `spectra_*_queue_dropped` series now end in `_total`. Update any dashboard or rule that used the old names.
