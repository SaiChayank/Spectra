import { useEffect, useState } from "react";
import {
  api,
  type HealthState,
  type HealthSubsystem,
  type SystemHealth,
} from "../lib/api";

/** State colour-coding: the four states must never look alike. */
function stateClass(state: HealthState): string {
  switch (state) {
    case "HEALTHY":
      return "state-healthy";
    case "DEGRADED":
      return "state-degraded";
    case "UNAVAILABLE":
      return "state-unavailable";
    default:
      return "state-simulated"; // SIMULATED: by design, not a failure
  }
}

function Chip({ state, label }: { state: HealthState; label?: string }) {
  return (
    <span className={`state-chip ${stateClass(state)}`}>{label ?? state}</span>
  );
}

function fmtBytes(n: number): string {
  if (n >= 1024 * 1024 * 1024) return `${(n / (1024 * 1024 * 1024)).toFixed(1)} GB`;
  if (n >= 1024 * 1024) return `${(n / (1024 * 1024)).toFixed(1)} MB`;
  if (n >= 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${n} B`;
}

function fmtMs(n: number): string {
  return n >= 10 ? `${n.toFixed(0)}ms` : `${n.toFixed(1)}ms`;
}

/** One subsystem: state chip up front, the *why* underneath. */
function SubsystemCard({ sub }: { sub: HealthSubsystem }) {
  return (
    <div className={`health-card ${stateClass(sub.state)}`}>
      <div className="health-card-head">
        <span className="health-title">{sub.title}</span>
        <Chip state={sub.state} />
      </div>
      <p className="health-reason" title={sub.reason}>
        {sub.reason}
      </p>
    </div>
  );
}

/** Key runtime figures: saturation, drops, latencies, drift, errors. */
function MetricStrip({ health }: { health: SystemHealth }) {
  const m = health.metrics;
  const items: { label: string; value: string; warn?: boolean }[] = [];

  if (m.queues.saturation.length > 0) {
    items.push({
      label: "Saturation",
      value: m.queues.saturation.join(", "),
      warn: true,
    });
  }
  if (m.packets.dropped > 0) {
    items.push({
      label: "Packet drops",
      value: `${m.packets.dropped} (${(m.packets.drop_ratio * 100).toFixed(2)}%)`,
      warn: m.packets.drop_ratio >= 0.001,
    });
  }
  if (m.flows.evicted > 0) {
    items.push({ label: "Flow evictions", value: String(m.flows.evicted) });
  }
  items.push({
    label: "Scoring p95",
    value: `${fmtMs(m.inference.p95_ms)} / ${fmtMs(m.inference.budget_p95_ms)}`,
    warn: m.inference.p95_ms > m.inference.budget_p95_ms,
  });
  if (m.database.enabled) {
    items.push({
      label: "DB write p95",
      value: `${fmtMs(m.database.write_p95_ms)} · ${fmtBytes(m.database.size_bytes)}`,
      warn: m.database.write_p95_ms > m.database.budget_p95_ms,
    });
  } else {
    items.push({ label: "Database", value: "disabled", warn: true });
  }
  items.push({
    label: "WebSocket",
    value: `${m.websocket.clients} client(s), ${m.websocket.subscribers} listener(s)`,
    warn: m.websocket.slow_client_drops > 0,
  });
  items.push({
    label: "Rates",
    value: `${m.rates.detections_per_min}/min det · ${m.rates.incidents_per_min}/min inc`,
  });
  items.push({
    label: "Model drift",
    value: m.model.drift_level ?? (m.model.trained ? "stable" : "no model"),
    warn: m.model.drift_level === "moderate" || m.model.drift_level === "significant",
  });
  if (m.errors.total > 0) {
    items.push({ label: "Module errors", value: String(m.errors.total), warn: true });
  }

  return (
    <div className="health-metrics">
      {items.map((item) => (
        <div key={item.label} className={`health-metric ${item.warn ? "warn" : ""}`}>
          <span className="health-metric-label">{item.label}</span>
          <span className="health-metric-value">{item.value}</span>
        </div>
      ))}
    </div>
  );
}

/**
 * System health panel: GET /api/health/system, polled while mounted.
 *
 * Every subsystem shows its state *and* the reason it is in that state, so
 * a degraded component is identifiable without reading server logs; the
 * metric strip makes saturation, drops and latency budgets visible.
 */
export default function SystemHealthPanel() {
  const [health, setHealth] = useState<SystemHealth | null>(null);
  const [failed, setFailed] = useState(false);

  useEffect(() => {
    let alive = true;
    const load = () => {
      api
        .systemHealth()
        .then((next) => {
          if (alive) {
            setHealth(next);
            setFailed(false);
          }
        })
        .catch(() => {
          if (alive) setFailed(true);
        });
    };
    load();
    const id = setInterval(load, 8000);
    return () => {
      alive = false;
      clearInterval(id);
    };
  }, []);

  if (failed) return <p className="note">System health unavailable.</p>;
  if (!health) return <p className="note">Checking subsystem health…</p>;

  const counts = health.counts;

  return (
    <div className="health-panel">
      <div className="health-overall">
        <Chip state={health.state} label={`Overall: ${health.state}`} />
        <span className="health-overall-reason" title={health.reason}>
          {health.reason}
        </span>
        <span className="health-counts">
          {counts.HEALTHY} healthy
          {counts.DEGRADED > 0 && ` · ${counts.DEGRADED} degraded`}
          {counts.UNAVAILABLE > 0 && ` · ${counts.UNAVAILABLE} unavailable`}
          {counts.SIMULATED > 0 && ` · ${counts.SIMULATED} simulated`}
          {` · up ${Math.floor(health.uptime_s / 60)}m`}
        </span>
      </div>

      <MetricStrip health={health} />

      <div className="health-grid">
        {health.subsystems.map((sub) => (
          <SubsystemCard key={sub.name} sub={sub} />
        ))}
      </div>
    </div>
  );
}
