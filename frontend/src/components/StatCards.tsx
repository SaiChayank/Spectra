import type { Snapshot } from "../lib/api";

export default function StatCards({ snapshot }: { snapshot: Snapshot | null }) {
  const t = snapshot?.totals;
  const model = snapshot?.model;

  const stats = [
    {
      label: "Packets",
      value: t ? t.packets.toLocaleString() : "—",
      sub: "packets parsed (metadata only)",
    },
    {
      label: "Flows",
      value: t ? t.flows.toLocaleString() : "—",
      sub: model?.trained ? `trained on ${model.n_train}` : "untrained model",
    },
    {
      label: "Detections",
      value: t ? t.detections.toLocaleString() : "—",
      sub: t ? `${(t.anomaly_rate * 100).toFixed(1)}% of flows` : "—",
      danger: (t?.detections ?? 0) > 0,
    },
    {
      label: "Avg anomaly score",
      value: t?.avg_score != null ? `${t.avg_score}` : "—",
      sub: "percentile vs baseline",
    },
    {
      label: "TLS flows",
      value: snapshot
        ? Object.entries(snapshot.tls_versions)
            .map(([k, v]) => `${k.replace("TLS ", "")}:${v}`)
            .join("  ") || "none"
        : "—",
      sub: "negotiated versions",
    },
    {
      label: "Protocols",
      value: snapshot
        ? Object.entries(snapshot.protocols)
            .map(([k, v]) => `${k} ${v}`)
            .join(" · ") || "—"
        : "—",
      sub: "completed conversations",
    },
  ];

  return (
    <div className="grid cards">
      {stats.map((s) => (
        <div key={s.label} className={`panel stat${s.danger ? " danger" : ""}`}>
          <div className="label">{s.label}</div>
          <div className="value">{s.value}</div>
          <div className="sub">{s.sub}</div>
        </div>
      ))}
    </div>
  );
}
