import { useMemo, useState } from "react";
import {
  Empty,
  ErrorBox,
  KV,
  Loading,
  PageHeader,
  Pager,
} from "../components/states";
import { api, type CaptureRow, type FlowRecord } from "../lib/api";
import {
  formatBytes,
  formatNum,
  formatScore,
  formatTs,
  scoreClass,
} from "../lib/format";
import { useFetch } from "../lib/useFetch";

const PAGE_SIZE = 100;

/** datetime-local value → epoch seconds (empty → undefined). */
const toEpoch = (value: string): number | undefined =>
  value ? new Date(value).getTime() / 1000 : undefined;

interface Props {
  can: (permission: string) => boolean;
}

/**
 * Traffic: historical flow search over persisted history — server-side
 * filter set (time, protocol, endpoints, capture, score) plus client-side
 * TLS/QUIC facet narrowing of the returned page (the server filter set
 * does not expose handshake versions, so facets are honest page-scoped).
 */
export default function TrafficPage({ can }: Props) {
  const [mode, setMode] = useState<"flows" | "detections">("flows");
  const [since, setSince] = useState("");
  const [until, setUntil] = useState("");
  const [proto, setProto] = useState("");
  const [src, setSrc] = useState("");
  const [dst, setDst] = useState("");
  const [sni, setSni] = useState("");
  const [minScore, setMinScore] = useState("");
  const [maxScore, setMaxScore] = useState("");
  const [captureId, setCaptureId] = useState("");
  const [tlsFacet, setTlsFacet] = useState("");
  const [quicFacet, setQuicFacet] = useState("");
  const [offset, setOffset] = useState(0);

  const stats = useFetch(() => api.historyStats(), []);
  const captures = useFetch<{ count: number; items: CaptureRow[] }>(
    () => api.historyCaptures({ limit: 100 }),
    [],
    { enabled: can("read") },
  );

  const rows = useFetch(
    () =>
      mode === "flows"
        ? api.historyFlows({
            limit: PAGE_SIZE,
            offset,
            since: toEpoch(since),
            until: toEpoch(until),
            proto: proto || undefined,
            src: src.trim() || undefined,
            dst: dst.trim() || undefined,
            sni: sni.trim() || undefined,
            min_score: minScore === "" ? undefined : Number(minScore),
            max_score: maxScore === "" ? undefined : Number(maxScore),
            capture_id: captureId === "" ? undefined : Number(captureId),
          })
        : api.historyDetections({
            limit: PAGE_SIZE,
            offset,
            since: toEpoch(since),
            until: toEpoch(until),
            proto: proto || undefined,
            src: src.trim() || undefined,
            dst: dst.trim() || undefined,
            min_score: minScore === "" ? undefined : Number(minScore),
            max_score: maxScore === "" ? undefined : Number(maxScore),
          }),
    [mode, offset, since, until, proto, src, dst, sni, minScore, maxScore, captureId],
  );

  /** Handshake facets derived from the rows actually on this page. */
  const facets = useMemo(() => {
    const tls = new Set<string>();
    const quic = new Set<string>();
    for (const row of rows.data?.items ?? []) {
      if (row.tls_version) tls.add(row.tls_version);
      if (row.quic_version) quic.add(row.quic_version);
    }
    return { tls: [...tls].sort(), quic: [...quic].sort() };
  }, [rows.data]);

  const items = useMemo(() => {
    let filtered: FlowRecord[] = rows.data?.items ?? [];
    if (tlsFacet) {
      filtered = filtered.filter((row) => row.tls_version === tlsFacet);
    }
    if (quicFacet) {
      filtered = filtered.filter((row) => row.quic_version === quicFacet);
    }
    return filtered;
  }, [rows.data, tlsFacet, quicFacet]);

  const reset = () => {
    setSince("");
    setUntil("");
    setProto("");
    setSrc("");
    setDst("");
    setSni("");
    setMinScore("");
    setMaxScore("");
    setCaptureId("");
    setTlsFacet("");
    setQuicFacet("");
    setOffset(0);
  };

  const facetActive = tlsFacet !== "" || quicFacet !== "";

  return (
    <>
      <PageHeader
        title="Traffic"
        subtitle="Persisted flow history: filter by time, protocol, endpoints, capture and handshake metadata."
        actions={
          <>
            <div className="segmented">
              <button
                className={mode === "flows" ? "active" : ""}
                onClick={() => {
                  setMode("flows");
                  setOffset(0);
                }}
              >
                Flows
              </button>
              <button
                className={mode === "detections" ? "active" : ""}
                onClick={() => {
                  setMode("detections");
                  setOffset(0);
                }}
              >
                Detections
              </button>
            </div>
            <button className="ghost" onClick={rows.reload}>
              Refresh
            </button>
          </>
        }
      />

      <section className="panel" style={{ marginBottom: 16 }}>
        <h2>History totals</h2>
        {stats.loading && !stats.data && <Loading label="Loading stats…" />}
        {stats.error && <ErrorBox message={stats.error} onRetry={stats.reload} />}
        {stats.data && (
          <div className="health-metrics">
            <div className="health-metric">
              <span className="health-metric-label">flows</span>
              <span className="health-metric-value">{formatNum(stats.data.flows)}</span>
            </div>
            <div className="health-metric">
              <span className="health-metric-label">detections</span>
              <span className="health-metric-value">{formatNum(stats.data.detections)}</span>
            </div>
            <div className="health-metric">
              <span className="health-metric-label">anomaly rate</span>
              <span className="health-metric-value">
                {(stats.data.anomaly_rate * 100).toFixed(2)}%
              </span>
            </div>
            <div className="health-metric">
              <span className="health-metric-label">avg score</span>
              <span className="health-metric-value">{formatScore(stats.data.avg_score)}</span>
            </div>
            <div className="health-metric">
              <span className="health-metric-label">first seen</span>
              <span className="health-metric-value" title={formatTs(stats.data.first_ts)}>
                {formatTs(stats.data.first_ts)}
              </span>
            </div>
            <div className="health-metric">
              <span className="health-metric-label">last seen</span>
              <span className="health-metric-value" title={formatTs(stats.data.last_ts)}>
                {formatTs(stats.data.last_ts)}
              </span>
            </div>
          </div>
        )}
        {stats.data && (
          <div className="kv-list" style={{ marginTop: 10 }}>
            <KV k="by protocol">
              {Object.entries(stats.data.by_proto)
                .map(([name, count]) => `${name} ×${count}`)
                .join(", ") || "—"}
            </KV>
            <KV k="top SNI">
              {stats.data.top_sni
                .slice(0, 5)
                .map((row) => `${row.sni} (${row.flows})`)
                .join(", ") || "—"}
            </KV>
          </div>
        )}
      </section>

      <section className="panel" style={{ marginBottom: 16 }}>
        <h2>Filters</h2>
        <div className="controls">
          <label>
            From
            <input type="datetime-local" value={since} onChange={(e) => { setSince(e.target.value); setOffset(0); }} />
          </label>
          <label>
            To
            <input type="datetime-local" value={until} onChange={(e) => { setUntil(e.target.value); setOffset(0); }} />
          </label>
          <label>
            Protocol
            <input
              value={proto}
              placeholder="tcp / udp / quic…"
              onChange={(e) => { setProto(e.target.value); setOffset(0); }}
            />
          </label>
          <label>
            Source
            <input
              value={src}
              placeholder="host or ip:port"
              onChange={(e) => { setSrc(e.target.value); setOffset(0); }}
            />
          </label>
          <label>
            Destination
            <input
              value={dst}
              placeholder="host or ip:port"
              onChange={(e) => { setDst(e.target.value); setOffset(0); }}
            />
          </label>
          {mode === "flows" && (
            <label>
              SNI contains
              <input
                value={sni}
                placeholder="example.com"
                onChange={(e) => { setSni(e.target.value); setOffset(0); }}
              />
            </label>
          )}
          <label>
            Min score
            <input
              type="number"
              min={0}
              max={100}
              value={minScore}
              placeholder="0"
              onChange={(e) => { setMinScore(e.target.value); setOffset(0); }}
            />
          </label>
          <label>
            Max score
            <input
              type="number"
              min={0}
              max={100}
              value={maxScore}
              placeholder="100"
              onChange={(e) => { setMaxScore(e.target.value); setOffset(0); }}
            />
          </label>
          {mode === "flows" && (
            <label>
              Capture
              <select
                value={captureId}
                onChange={(e) => { setCaptureId(e.target.value); setOffset(0); }}
              >
                <option value="">any</option>
                {(captures.data?.items ?? []).map((capture) => (
                  <option key={capture.id} value={capture.id}>
                    #{capture.id} {capture.original_name ?? capture.stored_name ?? ""}
                  </option>
                ))}
              </select>
            </label>
          )}
          <label>
            TLS version (page facet)
            <select value={tlsFacet} onChange={(e) => setTlsFacet(e.target.value)}>
              <option value="">any</option>
              {facets.tls.map((value) => (
                <option key={value} value={value}>{value}</option>
              ))}
            </select>
          </label>
          <label>
            QUIC version (page facet)
            <select value={quicFacet} onChange={(e) => setQuicFacet(e.target.value)}>
              <option value="">any</option>
              {facets.quic.map((value) => (
                <option key={value} value={value}>{value}</option>
              ))}
            </select>
          </label>
          <button className="ghost" onClick={reset}>
            Clear
          </button>
        </div>
        <p className="note">
          Server filters apply across all history; TLS/QUIC version facets
          narrow the {rows.data ? rows.data.items.length : 0} row(s) returned
          for this page only (handshake versions are not server filterable).
        </p>
      </section>

      <section className="panel">
        <h2>
          {mode === "flows" ? "Historical flows" : "Stored detections"}{" "}
          {rows.data ? `(${rows.data.count} total)` : ""}
        </h2>
        {rows.loading && !rows.data && <Loading label="Querying history…" />}
        {rows.error && <ErrorBox message={rows.error} onRetry={rows.reload} />}
        {rows.data && (
          <>
            {rows.data.items.length === 0 ? (
              <Empty
                message="No rows match these filters"
                hint="Widen the time range or clear a filter."
              />
            ) : items.length === 0 ? (
              <Empty
                message="No rows on this page carry the selected handshake version"
                hint="Page-scoped facets apply to the current page only — clear the facet or page through."
              />
            ) : (
              <div className="table-wrap">
                <table>
                  <thead>
                    <tr>
                      <th>Id</th>
                      <th>Time</th>
                      <th>Proto</th>
                      <th>Source</th>
                      <th>Destination</th>
                      <th>SNI</th>
                      <th>Handshake</th>
                      <th>Score</th>
                      <th>Pkts</th>
                      <th>Bytes</th>
                      <th>JA4</th>
                    </tr>
                  </thead>
                  <tbody>
                    {items.map((row) => (
                      <tr key={row.id ?? `${row.src}-${row.start_ts}`}>
                        <td className="mono dim">{row.id ?? "—"}</td>
                        <td className="dim" title={formatTs(row.start_ts)}>
                          {formatTs(row.start_ts)}
                        </td>
                        <td>{row.proto}</td>
                        <td className="mono">{row.src}</td>
                        <td className="mono">{row.dst}</td>
                        <td className="mono">{row.sni ?? <span className="dim">—</span>}</td>
                        <td className="mono dim">
                          {row.quic_version
                            ? `QUIC ${row.quic_version}`
                            : row.tls_version ?? "—"}
                        </td>
                        <td>
                          {row.score != null ? (
                            <span className={`badge ${scoreClass(row.score)}`}>
                              {formatScore(row.score)}
                            </span>
                          ) : (
                            <span className="dim">—</span>
                          )}
                        </td>
                        <td>{row.packets}</td>
                        <td>{formatBytes(row.bytes)}</td>
                        <td className="mono dim">{row.ja4 ?? "—"}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
            <Pager
              shown={rows.data.items.length}
              total={rows.data.count}
              offset={rows.data.offset}
              limit={PAGE_SIZE}
              onChange={setOffset}
            />
            {facetActive && (
              <p className="note">
                TLS/QUIC facet active — {items.length} of{" "}
                {rows.data.items.length} page row(s) shown.
              </p>
            )}
          </>
        )}
      </section>
    </>
  );
}
