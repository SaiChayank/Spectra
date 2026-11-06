import type { GraphFreshness } from "../lib/api";

/** "90 s", "12 min", "3.5 h" — flow-time lag, coarse on purpose. */
export function formatLag(seconds: number): string {
  if (seconds < 90) return `${Math.round(seconds)} s`;
  if (seconds < 5400) return `${Math.round(seconds / 60)} min`;
  return `${(seconds / 3600).toFixed(1)} h`;
}

/** Tone + copy for the staleness badge (pure, so the wording is testable). */
export function describeFreshness(f: GraphFreshness): {
  tone: "low" | "mid" | "high";
  label: string;
  detail: string;
} {
  if (f.flow_lag === null) {
    return {
      tone: "mid",
      label: "freshness unknown",
      detail:
        "Persistence is off, or the graph has not been loaded from stored history yet.",
    };
  }
  if (f.stale) {
    return {
      tone: "high",
      label: `stale · ${formatLag(f.flow_lag)} behind`,
      detail:
        "The twin and graph were built before newer stored flows arrived. " +
        "Starting a capture or restarting the API re-reads stored history.",
    };
  }
  if (f.flow_lag > 0) {
    return {
      tone: "mid",
      label: `${formatLag(f.flow_lag)} behind`,
      detail: "Slightly behind the newest stored flow.",
    };
  }
  return {
    tone: "low",
    label: "up to date",
    detail: "Matches the newest stored flow.",
  };
}

/** Staleness badge for the correlation graph (and the twin built from it). */
export default function FreshnessBadge({ freshness }: { freshness: GraphFreshness }) {
  const { tone, label, detail } = describeFreshness(freshness);
  const loaded =
    freshness.hydrated_at === null
      ? null
      : new Date(freshness.hydrated_at * 1000).toLocaleTimeString();
  return (
    <span title={detail}>
      <span className={`badge ${tone}`} role="status">
        {label}
      </span>
      {loaded && (
        <span className="dim" style={{ marginLeft: 8, fontSize: 12 }}>
          loaded from history {loaded}
        </span>
      )}
    </span>
  );
}
