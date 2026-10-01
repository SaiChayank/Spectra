import type { EvidenceItem, ThreatAlert } from "../lib/api";
import { formatClock, prettyThreat, scoreClass, severityClass, statusClass } from "../lib/format";

/** Technical evidence line: `periodicity = 30.2 s` (falls back to detail). */
const evidenceLine = (item: EvidenceItem): string =>
  item.value === null || item.value === undefined
    ? `${item.key}: ${item.detail}`
    : `${item.key} = ${item.value}${item.unit ? ` ${item.unit}` : ""}`;

/**
 * Tooltip: machine-readable evidence first (supporting, then contradicting),
 * then the severity derivation — everything behind one glance.
 */
function alertTitle(alert: ThreatAlert): string {
  const parts = [
    ...alert.evidence.supporting.map((item) => `• ${evidenceLine(item)}`),
    ...alert.evidence.contradicting.map((item) => `✗ ${evidenceLine(item)}`),
    ...alert.severity_factors.map((factor) => `severity: ${factor}`),
  ];
  if (alert.occurrences > 1) parts.push(`${alert.occurrences} sightings grouped`);
  return parts.join("\n") || "no evidence recorded";
}

interface Props {
  items: ThreatAlert[];
  /** The server enforces `incidents:manage`; the UI just reflects it. */
  canTriage: boolean;
  onAcknowledge: (alertId: string) => void;
  onResolve: (alertId: string) => void;
}

/**
 * Analyst alerts: severity, threat type, confidence and anomaly score shown
 * as four independent columns, with the evidence summary explaining *why*.
 */
export default function AlertsPanel({ items, canTriage, onAcknowledge, onResolve }: Props) {
  return (
    <section className="panel">
      <h2>Alerts ({items.length})</h2>
      {items.length === 0 ? (
        <div className="empty">
          No analyst alerts yet — correlated threat verdicts group and stream here as they occur.
        </div>
      ) : (
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Severity</th>
                <th>Threat</th>
                <th>Confidence</th>
                <th>Score</th>
                <th>Why it was raised (evidence)</th>
                <th>Flow</th>
                <th>Seen</th>
                <th>Status</th>
              </tr>
            </thead>
            <tbody>
              {items.map((alert) => (
                <tr key={alert.alert_id} title={alertTitle(alert)}>
                  <td>
                    <span className={`severity ${severityClass(alert.severity)}`}>
                      {alert.severity}
                    </span>
                  </td>
                  <td>
                    <span
                      className={
                        alert.threat_type === "UNKNOWN_ANOMALY" ? "tag dim" : "tag"
                      }
                    >
                      {prettyThreat(alert.threat_type)}
                    </span>
                  </td>
                  <td>{Math.round(alert.confidence * 100)}%</td>
                  <td>
                    <span className={`badge ${scoreClass(alert.anomaly_score)}`}>
                      {alert.anomaly_score == null ? "—" : alert.anomaly_score.toFixed(1)}
                    </span>
                  </td>
                  <td>
                    {alert.evidence.summary}
                    {alert.occurrences > 1 && (
                      <span className="tag" title={`${alert.occurrences} sightings grouped`}>
                        ×{alert.occurrences}
                      </span>
                    )}
                  </td>
                  <td className="mono">
                    {alert.protocol} {alert.source} → {alert.destination}
                  </td>
                  <td>
                    {formatClock(alert.first_seen)}
                    {alert.last_seen !== alert.first_seen && (
                      <span className="dim"> – {formatClock(alert.last_seen)}</span>
                    )}
                  </td>
                  <td>
                    <span className={`status ${statusClass(alert.status)}`}>
                      {alert.status}
                    </span>
                    {canTriage && alert.status !== "RESOLVED" && (
                      <button
                        className="ghost"
                        onClick={() =>
                          alert.status === "OPEN"
                            ? onAcknowledge(alert.alert_id)
                            : onResolve(alert.alert_id)
                        }
                        title={
                          alert.status === "OPEN"
                            ? "Mark this alert as acknowledged"
                            : "Mark this alert as resolved (terminal)"
                        }
                      >
                        {alert.status === "OPEN" ? "Ack" : "Resolve"}
                      </button>
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
