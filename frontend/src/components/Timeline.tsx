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
            <CartesianGrid stroke="#1d2a3f" strokeDasharray="3 3" />
            <XAxis dataKey="time" tick={{ fill: "#7c8ba4", fontSize: 11 }} minTickGap={40} />
            <YAxis yAxisId="left" tick={{ fill: "#7c8ba4", fontSize: 11 }} allowDecimals={false} />
            <YAxis
              yAxisId="right"
              orientation="right"
              domain={[0, 100]}
              tick={{ fill: "#7c8ba4", fontSize: 11 }}
            />
            <Tooltip
              contentStyle={{
                background: "#0d1420",
                border: "1px solid #1d2a3f",
                borderRadius: 8,
                fontSize: 12,
              }}
              labelStyle={{ color: "#d7e1f0" }}
            />
            <Legend wrapperStyle={{ fontSize: 12 }} />
            <Bar yAxisId="left" dataKey="flows" fill="#35e0d0" fillOpacity={0.55} name="Flows" />
            <Bar yAxisId="left" dataKey="anomalies" fill="#ff4d6d" name="Detections" />
            <Line
              yAxisId="right"
              type="monotone"
              dataKey="avg_score"
              stroke="#7c5cff"
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
