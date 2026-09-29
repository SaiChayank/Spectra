import type { FlowRecord } from "../lib/api";
import { formatBytes, formatClock, scoreClass } from "../lib/format";

export default function FlowsTable({ items }: { items: FlowRecord[] }) {
  return (
    <section className="panel">
      <h2>Recent flows ({items.length})</h2>
      {items.length === 0 ? (
        <div className="empty">No flows yet.</div>
      ) : (
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Score</th>
                <th>Immune</th>
                <th>Time</th>
                <th>Proto</th>
                <th>Source</th>
                <th>Destination</th>
                <th>SNI / TLS</th>
                <th>Pkts</th>
                <th>Bytes</th>
                <th>JA4</th>
              </tr>
            </thead>
            <tbody>
              {items.map((f, i) => (
                <tr key={`${f.src}-${f.start_ts}-${i}`}>
                  <td>
                    {f.score != null ? (
                      <span className={`badge ${scoreClass(f.score)}`}>{f.score.toFixed(0)}</span>
                    ) : (
                      <span className="dim">—</span>
                    )}
                  </td>
                  <td>
                    {f.immune ? (
                      <span
                        className={`tag imm-${f.immune.response}`}
                        title={[
                          `affinity ${f.immune.affinity.toFixed(2)}`,
                          `danger ${f.immune.danger_total.toFixed(2)}`,
                          f.immune.memory_hit ? "memory hit" : null,
                          f.snn_score != null ? `snn ${f.snn_score.toFixed(0)}%` : null,
                          f.swarm_flag ? "swarm flagged" : null,
                        ]
                          .filter(Boolean)
                          .join(" · ")}
                      >
                        {f.immune.response}
                      </span>
                    ) : (
                      <span className="dim">—</span>
                    )}
                    {f.slice && f.slice !== "default" ? (
                      <span className="tag slice-tag">{f.slice}</span>
                    ) : null}
                  </td>
                  <td className="dim">{formatClock(f.start_ts)}</td>
                  <td>{f.proto}</td>
                  <td className="mono">{f.src}</td>
                  <td className="mono">{f.dst}</td>
                  <td className="mono">
                    {f.sni ? (
                      <>
                        {f.sni} <span className="dim">({f.tls_version})</span>
                      </>
                    ) : (
                      <span className="dim">{f.tls_version ?? "no TLS"}</span>
                    )}
                  </td>
                  <td>{f.packets}</td>
                  <td>{formatBytes(f.bytes)}</td>
                  <td className="mono dim">{f.ja4 ?? "—"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}
