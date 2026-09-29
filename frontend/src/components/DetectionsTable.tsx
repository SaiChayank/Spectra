import type { Detection } from "../lib/api";
import { formatClock, prettyFeature, scoreClass } from "../lib/format";

export default function DetectionsTable({ items }: { items: Detection[] }) {
  return (
    <section className="panel">
      <h2>Detections ({items.length})</h2>
      {items.length === 0 ? (
        <div className="empty">Nothing flagged yet — score 0–100 with explanations when it is.</div>
      ) : (
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Score</th>
                <th>Time</th>
                <th>Flow</th>
                <th>SNI</th>
                <th>Why it was flagged</th>
              </tr>
            </thead>
            <tbody>
              {items.map((d, i) => (
                <tr key={`${d.src}-${d.detected_at}-${i}`}>
                  <td>
                    <span className={`badge ${scoreClass(d.score)}`}>{d.score.toFixed(1)}</span>
                  </td>
                  <td className="dim">{formatClock(d.detected_at)}</td>
                  <td className="mono">
                    {d.proto} {d.src} → {d.dst}
                  </td>
                  <td className="mono">{d.sni ?? <span className="dim">no TLS</span>}</td>
                  <td>
                    {d.reasons.length === 0 ? (
                      <span className="dim">—</span>
                    ) : (
                      d.reasons.map((r) => (
                        <span key={r.feature} className="tag" title={`value ${r.value}`}>
                          {prettyFeature(r.feature)} {r.z_score > 0 ? "+" : ""}
                          {r.z_score}σ
                        </span>
                      ))
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}
