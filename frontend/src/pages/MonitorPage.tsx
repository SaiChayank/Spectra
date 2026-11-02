import {
  Bar,
  BarChart,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import AlertsPanel from "../components/AlertsPanel";
import CapturePanel from "../components/CapturePanel";
import DetectionsTable from "../components/DetectionsTable";
import FlowsTable from "../components/FlowsTable";
import { Empty, ErrorBox, Loading, PageHeader } from "../components/states";
import Timeline from "../components/Timeline";
import {
  api,
  type CaptureStatus,
  type Detection,
  type FlowRecord,
  type Snapshot,
  type SystemHealth,
  type ThreatAlert,
} from "../lib/api";
import { formatDuration, formatNum, formatRate, pct } from "../lib/format";
import { useFetch } from "../lib/useFetch";

interface Props {
  snapshot: Snapshot | null;
  flows: FlowRecord[];
  detections: Detection[];
  alerts: ThreatAlert[];
  connected: boolean;
  canManage: boolean;
  canTriage: boolean;
  triage: (
    alertId: string,
    action: (id: string) => Promise<ThreatAlert>,
  ) => void;
  onError: (message: string | null) => void;
  onNotice: (message: string | null) => void;
}

/**
 * Monitor: the live operation view — capture controls, real-time flows,
 * detections and alerts over the event stream, traffic charts, and the
 * queue/drop metrics that say whether the pipeline is keeping up.
 */
export default function MonitorPage({
  snapshot,
  flows,
  detections,
  alerts,
  connected,
  canManage,
  canTriage,
  triage,
  onError,
  onNotice,
}: Props) {
  const health = useFetch<SystemHealth>(() => api.systemHealth(), [], {
    intervalMs: 5000,
  });
  const status: CaptureStatus | undefined = snapshot?.status;
  const metrics = health.data?.metrics;
  const queues = metrics?.queues;

  const protocolChart = Object.entries(snapshot?.protocols ?? {})
    .map(([proto, count]) => ({ proto, count }))
    .slice(0, 8);

  return (
    <>
      <PageHeader
        title="Monitor"
        subtitle="Real-time capture, flows, alerts and pipeline pressure."
        actions={
          <span className={`pill ${connected ? "ws" : ""}`}>
            <span className="dot" />
            {connected ? "event stream live" : "reconnecting…"}
          </span>
        }
      />

      {status && (
        <div style={{ marginBottom: 16 }}>
          <CapturePanel
            status={status}
            canManage={canManage}
            onError={onError}
            onNotice={onNotice}
          />
        </div>
      )}

      <div className="grid two-col" style={{ marginBottom: 16 }}>
        <section className="panel">
          <h2>Traffic mix (this session)</h2>
          {protocolChart.length === 0 ? (
            <Empty
              message="No protocols observed yet"
              hint="Start a live capture or process a stored PCAP."
            />
          ) : (
            <div style={{ width: "100%", height: 220 }}>
              <ResponsiveContainer>
                <BarChart data={protocolChart} margin={{ top: 8, right: 8, left: -18, bottom: 0 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#1d2a3f" />
                  <XAxis dataKey="proto" tick={{ fill: "#7c8ba4", fontSize: 11 }} />
                  <YAxis tick={{ fill: "#7c8ba4", fontSize: 11 }} allowDecimals={false} />
                  <Tooltip
                    contentStyle={{
                      background: "#0d1420",
                      border: "1px solid #1d2a3f",
                      borderRadius: 8,
                      fontSize: 12,
                    }}
                  />
                  <Bar dataKey="count" fill="#35e0d0" radius={[4, 4, 0, 0]} />
                </BarChart>
              </ResponsiveContainer>
            </div>
          )}
        </section>

        <section className="panel">
          <h2>Queue &amp; drop metrics</h2>
          {health.loading && !health.data && <Loading label="Loading metrics…" />}
          {health.error && <ErrorBox message={health.error} onRetry={health.reload} />}
          {metrics && (
            <div className="health-metrics">
              <div className={`health-metric${(queues?.packet_queue.utilization ?? 0) >= 0.8 ? " warn" : ""}`}>
                <span className="health-metric-label">packet queue</span>
                <span className="health-metric-value">
                  {formatNum(queues?.packet_queue.depth)} / {formatNum(queues?.packet_queue.limit)} (
                  {pct(queues?.packet_queue.utilization, 0)})
                </span>
              </div>
              <div className={`health-metric${(queues?.flow_queue.utilization ?? 0) >= 0.8 ? " warn" : ""}`}>
                <span className="health-metric-label">flow queue</span>
                <span className="health-metric-value">
                  {formatNum(queues?.flow_queue.depth)} / {formatNum(queues?.flow_queue.limit)} (
                  {pct(queues?.flow_queue.utilization, 0)})
                </span>
              </div>
              <div className={`health-metric${(queues?.publish_queue.utilization ?? 0) >= 0.8 ? " warn" : ""}`}>
                <span className="health-metric-label">publish queue</span>
                <span className="health-metric-value">
                  {formatNum(queues?.publish_queue.depth)} / {formatNum(queues?.publish_queue.limit)} (
                  {pct(queues?.publish_queue.utilization, 0)})
                </span>
              </div>
              <div className={`health-metric${(queues?.live_capture.dropped ?? 0) > 0 ? " warn" : ""}`}>
                <span className="health-metric-label">live capture drops</span>
                <span className="health-metric-value">
                  {formatNum(queues?.live_capture.dropped)}
                </span>
              </div>
              <div className={`health-metric${(metrics.packets.drop_ratio ?? 0) > 0.01 ? " warn" : ""}`}>
                <span className="health-metric-label">packet drop ratio</span>
                <span className="health-metric-value">{pct(metrics.packets.drop_ratio, 2)}</span>
              </div>
              <div className={`health-metric${(metrics.processing_lag_ms ?? 0) > metrics.inference.budget_p95_ms ? " warn" : ""}`}>
                <span className="health-metric-label">processing lag</span>
                <span className="health-metric-value">
                  {formatRate(metrics.processing_lag_ms)} ms (p95 infer{" "}
                  {metrics.inference.p95_ms} ms)
                </span>
              </div>
            </div>
          )}
          {queues && queues.saturation.length > 0 && (
            <p className="note">
              Saturated: {queues.saturation.join(", ")} — stages at or above 80%
              capacity.
            </p>
          )}
        </section>
      </div>

      <div style={{ marginBottom: 16 }}>
        <Timeline points={snapshot?.timeline ?? []} />
      </div>

      <div className="grid two-col" style={{ marginBottom: 16 }}>
        <AlertsPanel
          items={alerts}
          canTriage={canTriage}
          onAcknowledge={(id) => triage(id, api.acknowledgeAlert)}
          onResolve={(id) => triage(id, api.resolveAlert)}
        />
        <section className="panel">
          <h2>Live system state</h2>
          <div className="health-metrics">
            <div className="health-metric">
              <span className="health-metric-label">capture</span>
              <span className="health-metric-value">
                {status?.error
                  ? "error"
                  : status?.running
                    ? `running (${status.mode})`
                    : "idle"}
              </span>
            </div>
            <div className="health-metric">
              <span className="health-metric-label">events</span>
              <span className="health-metric-value">
                {connected ? "streaming" : "reconnecting"}
              </span>
            </div>
            <div className="health-metric">
              <span className="health-metric-label">model</span>
              <span className="health-metric-value">
                {snapshot?.model.trained ? "ready" : "untrained"}
              </span>
            </div>
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
            <div className="health-metric">
              <span className="health-metric-label">uptime</span>
              <span className="health-metric-value">
                {formatDuration(metrics?.uptime_s)}
              </span>
            </div>
          </div>
          {status?.error && (
            <div className="error-banner">Capture error: {status.error}</div>
          )}
        </section>
      </div>

      <div className="grid two-col">
        <DetectionsTable items={detections} />
        <FlowsTable items={flows} />
      </div>
    </>
  );
}
