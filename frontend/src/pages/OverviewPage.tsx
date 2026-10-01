import CapabilityStrip from "../components/CapabilityStrip";
import StatCards from "../components/StatCards";
import Timeline from "../components/Timeline";
import { Empty, ErrorBox, KV, Loading, PageHeader } from "../components/states";
import {
  api,
  type DriftReport,
  type RegistryList,
  type Snapshot,
  type SystemHealth,
  type ThreatAlert,
} from "../lib/api";
import {
  formatDuration,
  formatNum,
  formatRate,
  formatTs,
  pct,
  relTime,
  severityClass,
  shortHash,
} from "../lib/format";
import { navigate } from "../lib/router";
import { useFetch } from "../lib/useFetch";

interface Props {
  snapshot: Snapshot | null;
  alerts: ThreatAlert[];
  can: (permission: string) => boolean;
}

/** Tally hosts appearing in recent alerts (port stripped). */
function hostOf(endpoint: string): string {
  const withoutPort = endpoint.replace(/:\d+$/, "");
  return withoutPort || endpoint;
}

function hostTally(alerts: ThreatAlert[]): { host: string; count: number }[] {
  const counts = new Map<string, number>();
  for (const alert of alerts) {
    for (const endpoint of [alert.source, alert.destination]) {
      if (!endpoint) continue;
      const host = hostOf(endpoint);
      counts.set(host, (counts.get(host) ?? 0) + 1);
    }
  }
  return [...counts.entries()]
    .map(([host, count]) => ({ host, count }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 8);
}

/**
 * Overview: the operational answer to "what is happening right now" —
 * system state, active model, rates, severity spread, recent incidents,
 * top affected hosts, detection trend, drift and capability health.
 */
export default function OverviewPage({ snapshot, alerts, can }: Props) {
  const health = useFetch<SystemHealth>(
    () => api.systemHealth(),
    [],
    { intervalMs: 10000 },
  );
  const registry = useFetch<RegistryList>(() => api.registryList(), [], {
    intervalMs: 15000,
  });
  const incidents = useFetch(
    () => api.incidents({ limit: 5 }),
    [],
    { enabled: can("investigate") },
  );
  const drift = useFetch<DriftReport>(() => api.modelDrift(), [], {
    enabled: can("investigate"),
  });

  const metrics = health.data?.metrics;
  const model = snapshot?.model;
  const active = registry.data?.active ?? null;

  const severityCounts = ["CRITICAL", "HIGH", "MEDIUM", "LOW"].map(
    (severity) => ({
      severity,
      count: alerts.filter((a) => a.severity === severity).length,
    }),
  );
  const worst = severityCounts.reduce((max, row) => Math.max(max, row.count), 0);
  const hosts = hostTally(alerts);
  const maxHost = hosts.reduce((max, row) => Math.max(max, row.count), 0);

  return (
    <>
      <PageHeader
        title="Overview"
        subtitle="System state, active model and the current detection picture."
      />

      <StatCards snapshot={snapshot} />

      <div className="grid two-col" style={{ marginBottom: 16 }}>
        <section className="panel">
          <h2>System state</h2>
          {health.loading && !health.data && <Loading label="Loading health…" />}
          {health.error && (
            <ErrorBox message={health.error} onRetry={health.reload} />
          )}
          {health.data && (
            <>
              <div className="health-overall">
                <span
                  className={`state-chip state-${health.data.state.toLowerCase()}`}
                >
                  {health.data.state}
                </span>
                <span className="health-overall-reason">
                  {health.data.reason}
                </span>
                <span className="health-counts">
                  up {formatDuration(health.data.uptime_s)}
                </span>
              </div>
              <div className="health-metrics">
                <div className="health-metric">
                  <span className="health-metric-label">packets/s</span>
                  <span className="health-metric-value">
                    {formatRate(metrics?.packets.rate_pps)}
                  </span>
                </div>
                <div className="health-metric">
                  <span className="health-metric-label">flows/s</span>
                  <span className="health-metric-value">
                    {formatRate(metrics?.flows.rate_fps)}
                  </span>
                </div>
                <div className={`health-metric${(metrics?.packets.drop_ratio ?? 0) > 0.01 ? " warn" : ""}`}>
                  <span className="health-metric-label">dropped</span>
                  <span className="health-metric-value">
                    {formatNum(metrics?.packets.dropped)} (
                    {pct(metrics?.packets.drop_ratio, 2)})
                  </span>
                </div>
                <div className="health-metric">
                  <span className="health-metric-label">active flows</span>
                  <span className="health-metric-value">
                    {formatNum(metrics?.flows.active)} / {formatNum(metrics?.flows.active_limit)}
                  </span>
                </div>
                <div className="health-metric">
                  <span className="health-metric-label">inference p95</span>
                  <span className="health-metric-value">
                    {metrics ? `${metrics.inference.p95_ms} ms` : "—"}
                  </span>
                </div>
                <div className="health-metric">
                  <span className="health-metric-label">processing lag</span>
                  <span className="health-metric-value">
                    {metrics ? `${Math.round(metrics.processing_lag_ms)} ms` : "—"}
                  </span>
                </div>
              </div>
            </>
          )}
        </section>

        <section className="panel">
          <h2>Active model</h2>
          {!model && <Empty message="No snapshot yet" hint="Waiting for the first /api/stats refresh." />}
          {model && (
            <>
              <KV k="model ready">{model.trained ? "yes" : "no — train a baseline"}</KV>
              <KV k="threshold">{model.threshold ?? "—"}</KV>
              <KV k="training rows">{formatNum(model.n_train)}</KV>
              <KV k="contamination">{model.contamination}</KV>
              <KV k="feature schema">{model.n_features} features</KV>
              <KV k="trained">
                {model.trained_at
                  ? new Date(model.trained_at).toLocaleString()
                  : "—"}
              </KV>
            </>
          )}
          {registry.loading && !registry.data && <Loading label="Registry…" />}
          {registry.error && (
            <ErrorBox message={registry.error} onRetry={registry.reload} />
          )}
          {registry.data && (
            <>
              <KV
                k="registry"
                verdict={registry.data.enabled ? undefined : "bad"}
              >
                {registry.data.enabled
                  ? `${registry.data.count} model(s)`
                  : "disabled (persistence off)"}
              </KV>
              {active && (
                <>
                  <KV k="active id">
                    <span className="mono">{active.model_id}</span>
                  </KV>
                  <KV k="artifact sha256">
                    <span className="mono">{shortHash(active.artifact_sha256, 16)}</span>
                  </KV>
                  <KV k="last activated">{relTime(active.last_activated_at)}</KV>
                </>
              )}
              <button
                className="ghost"
                style={{ marginTop: 8 }}
                onClick={() => navigate("#/models")}
              >
                Open Models
              </button>
            </>
          )}
        </section>
      </div>

      <div className="grid two-col" style={{ marginBottom: 16 }}>
        <Timeline points={snapshot?.timeline ?? []} />

        <section className="panel">
          <h2>Alert severity distribution</h2>
          {alerts.length === 0 ? (
            <Empty
              message="No alerts in the live window"
              hint="Alerts appear once correlated threat verdicts fire."
            />
          ) : (
            severityCounts.map((row) => (
              <div className="bar-row" key={row.severity}>
                <span className={`severity ${severityClass(row.severity)}`}>
                  {row.severity}
                </span>
                <div className="bar">
                  <div
                    className="bar-fill"
                    style={{
                      width: `${worst ? (row.count / worst) * 100 : 0}%`,
                    }}
                  />
                </div>
                <span className="bar-num">{row.count}</span>
              </div>
            ))
          )}
        </section>
      </div>

      <div className="grid two-col" style={{ marginBottom: 16 }}>
        <section className="panel">
          <h2>Recent incidents</h2>
          {!can("investigate") && (
            <p className="note">
              Incident lists require the “investigate” permission — your role
              can watch Overview, Monitor, Traffic, Models and System.
            </p>
          )}
          {can("investigate") && incidents.loading && !incidents.data && (
            <Loading label="Loading incidents…" />
          )}
          {can("investigate") && incidents.error && (
            <ErrorBox message={incidents.error} onRetry={incidents.reload} />
          )}
          {can("investigate") && incidents.data && (
            <>
              {incidents.data.items.length === 0 ? (
                <Empty
                  message="No incidents yet"
                  hint="Correlate related alerts from the Incidents page to open one."
                />
              ) : (
                <div className="table-wrap">
                  <table>
                    <thead>
                      <tr>
                        <th>#</th>
                        <th>Title</th>
                        <th>Status</th>
                        <th>Severity</th>
                        <th>Seen</th>
                      </tr>
                    </thead>
                    <tbody>
                      {incidents.data.items.map((incident) => (
                        <tr
                          key={incident.id}
                          style={{ cursor: "pointer" }}
                          onClick={() => navigate(`#/incidents/${incident.id}`)}
                        >
                          <td className="mono">{incident.id}</td>
                          <td>{incident.title}</td>
                          <td>
                            <span className="status open">{incident.status}</span>
                          </td>
                          <td>
                            {incident.severity ? (
                              <span className={`severity ${severityClass(incident.severity)}`}>
                                {incident.severity}
                              </span>
                            ) : (
                              <span className="dim">—</span>
                            )}
                          </td>
                          <td className="dim">{relTime(incident.last_seen ?? incident.created_at)}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
              <button
                className="ghost"
                style={{ marginTop: 8 }}
                onClick={() => navigate("#/incidents")}
              >
                All incidents
              </button>
            </>
          )}
        </section>

        <section className="panel">
          <h2>Top affected hosts</h2>
          {hosts.length === 0 ? (
            <Empty
              message="No hosts in the alert window"
              hint="Hosts appear here once alerts reference them."
            />
          ) : (
            hosts.map((row) => (
              <div className="bar-row" key={row.host}>
                <span className="tag" title={row.host}>
                  {row.host}
                </span>
                <div className="bar">
                  <div
                    className="bar-fill"
                    style={{ width: `${(row.count / maxHost) * 100}%` }}
                  />
                </div>
                <span className="bar-num">{row.count}</span>
              </div>
            ))
          )}
        </section>
      </div>

      <div className="grid two-col" style={{ marginBottom: 16 }}>
        <section className="panel">
          <h2>Model drift (PSI)</h2>
          {!can("investigate") && (
            <p className="note">Drift analysis requires the “investigate” permission.</p>
          )}
          {can("investigate") && drift.loading && !drift.data && (
            <Loading label="Measuring drift…" />
          )}
          {can("investigate") && drift.error && (
            <ErrorBox message={drift.error} onRetry={drift.reload} />
          )}
          {can("investigate") && drift.data && !drift.data.available && (
            <Empty
              message="Drift not measurable yet"
              hint={drift.data.reason ?? "Score some traffic first."}
            />
          )}
          {can("investigate") && drift.data?.available && (
            <>
              <div className="health-overall">
                <span
                  className={`state-chip ${
                    drift.data.level === "stable"
                      ? "state-healthy"
                      : drift.data.level === "moderate"
                        ? "state-degraded"
                        : "state-unavailable"
                  }`}
                >
                  {drift.data.level}
                </span>
                <span className="health-overall-reason">
                  PSI {drift.data.psi} over {formatNum(drift.data.n)} scored
                  flow(s)
                </span>
              </div>
              {(drift.data.features ?? []).slice(0, 5).map((feature) => (
                <div className="bar-row" key={feature.feature}>
                  <span className="tag">{feature.feature}</span>
                  <div className="bar">
                    <div
                      className="bar-fill"
                      style={{
                        width: `${Math.min(100, (feature.psi / 0.3) * 100)}%`,
                      }}
                    />
                  </div>
                  <span className="bar-num">{feature.psi}</span>
                </div>
              ))}
            </>
          )}
        </section>

        <section className="panel">
          <h2>Capability health</h2>
          <CapabilityStrip showPolicy />
          <KV k="data window">
            {snapshot
              ? `${formatNum(snapshot.totals.flows)} flow(s) scored this session`
              : "—"}
          </KV>
          <KV k="session start">
            {health.data
              ? `session started ${formatTs((Date.now() / 1000) - health.data.uptime_s)}`
              : "—"}
          </KV>
        </section>
      </div>
    </>
  );
}
