import type { Snapshot } from "../lib/api";
import { StatCard } from "./ui";

/** Overview KPIs as numbered crosshair cards. The one focal card is Detections, when there are any. */
export default function StatCards({ snapshot }: { snapshot: Snapshot | null }) {
  const t = snapshot?.totals;
  const model = snapshot?.model;
  const trend = (key: "flows" | "anomalies") => snapshot?.timeline.map((p) => p[key]);
  const pairs = (rec: Record<string, number> | undefined, strip = "") =>
    rec && Object.keys(rec).length ? Object.entries(rec).map(([k, v]) => `${k.replace(strip, "")} ${v}`).join(" · ") : "none";

  return (
    <div style={{ display: "grid", gap: 16, gridTemplateColumns: "repeat(auto-fill, minmax(min(100%, 220px), 1fr))" }}>
      <StatCard index="01" label="Packets" value={t ? t.packets.toLocaleString() : "—"} caption="parsed, metadata only" />
      <StatCard
        index="02"
        label="Flows"
        value={t ? t.flows.toLocaleString() : "—"}
        caption={model?.trained ? `model trained on ${model.n_train}` : "no trained model"}
        trend={trend("flows")}
      />
      <StatCard
        index="03"
        label="Above threshold"
        value={t ? t.detections.toLocaleString() : "—"}
        caption={t ? `${(t.anomaly_rate * 100).toFixed(1)} % of flows · unusual, not proven` : "—"}
        trend={trend("anomalies")}
        focal={(t?.detections ?? 0) > 0}
      />
      <StatCard index="04" label="Avg anomaly score" value={t?.avg_score != null ? t.avg_score.toFixed(1) : "—"} unit="/ 100" caption="percentile vs baseline" />
      <StatCard index="05" label="TLS versions" value={<span style={{ fontSize: 18 }}>{snapshot ? pairs(snapshot.tls_versions, "TLS ") : "—"}</span>} caption="negotiated" />
      <StatCard index="06" label="Protocols" value={<span style={{ fontSize: 18 }}>{snapshot ? pairs(snapshot.protocols) : "—"}</span>} caption="completed conversations" />
    </div>
  );
}
