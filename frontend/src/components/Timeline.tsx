import {
  Bar,
  CartesianGrid,
  ComposedChart,
  Line,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
  Legend,
} from "recharts";
import type { TimelinePoint } from "../lib/api";
import { formatClock } from "../lib/format";

export default function Timeline({ points }: { points: TimelinePoint[] }) {
  const data = points.map((p) => ({
    ...p,
    time: formatClock(p.t),
  }));

  return (
    <section className="panel">
      <h2>Traffic &amp; anomaly timeline (5s buckets)</h2>
      {data.length === 0 ? (
        <div className="empty">No traffic yet — start a capture to see the timeline.</div>
      ) : (
        <ResponsiveContainer width="100%" height={260}>
          <ComposedChart data={data} margin={{ top: 6, right: 8, left: -14, bottom: 0 }}>
            <defs>
              <linearGradient id="sx-flow-area" x1="0" y1="0" x2="0" y2="1">
                <stop offset="0" stopColor="#5DA2F7" stopOpacity={0.7} />
                <stop offset="1" stopColor="#1A57BB" stopOpacity={0.15} />
              </linearGradient>
            </defs>
            <CartesianGrid stroke="rgba(255,255,255,0.08)" vertical={false} />
            <XAxis dataKey="time" tick={{ fill: "#8E8E93", fontSize: 11, fontFamily: "JetBrains Mono Variable, monospace" }} minTickGap={40} stroke="rgba(255,255,255,0.16)" />
            <YAxis yAxisId="left" tick={{ fill: "#8E8E93", fontSize: 11, fontFamily: "JetBrains Mono Variable, monospace" }} allowDecimals={false} stroke="rgba(255,255,255,0.16)" />
            <YAxis
              yAxisId="right"
              orientation="right"
              domain={[0, 100]}
              tick={{ fill: "#8E8E93", fontSize: 11, fontFamily: "JetBrains Mono Variable, monospace" }}
              stroke="rgba(255,255,255,0.16)"
            />
            <Tooltip
              contentStyle={{
                background: "rgba(22,23,29,0.92)",
                border: "1px solid rgba(255,255,255,0.2)",
                borderRadius: 6,
                fontSize: 12,
                fontFamily: "JetBrains Mono Variable, monospace",
              }}
              labelStyle={{ color: "#F5F5F5" }}
              cursor={{ fill: "rgba(93,162,247,0.08)" }}
            />
            <Legend wrapperStyle={{ fontSize: 12, color: "#A3A3A6" }} />
            <Bar yAxisId="left" dataKey="flows" fill="url(#sx-flow-area)" name="Flows" />
            <Bar yAxisId="left" dataKey="anomalies" fill="#FF4D5E" name="Above threshold" />
            <Line
              yAxisId="right"
              type="monotone"
              dataKey="avg_score"
              stroke="#8B7CFF"
              strokeWidth={2}
              dot={false}
              name="Avg score"
            />
          </ComposedChart>
        </ResponsiveContainer>
      )}
    </section>
  );
}
