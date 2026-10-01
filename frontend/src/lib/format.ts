export const formatBytes = (n: number): string => {
  if (n < 1024) return `${n} B`;
  if (n < 1024 ** 2) return `${(n / 1024).toFixed(1)} KB`;
  if (n < 1024 ** 3) return `${(n / 1024 ** 2).toFixed(1)} MB`;
  return `${(n / 1024 ** 3).toFixed(2)} GB`;
};

export const formatClock = (ts: number): string =>
  new Date(ts * 1000).toLocaleTimeString([], { hour12: false });

export const scoreClass = (score: number | null | undefined): string => {
  if (score == null) return "low";
  if (score >= 85) return "high";
  if (score >= 60) return "mid";
  return "low";
};

export const scoreColor = (score: number): string =>
  score >= 85 ? "#ff4d6d" : score >= 60 ? "#ffb347" : "#3ddc97";

export const prettyFeature = (name: string): string =>
  name
    .replace(/_s$/, " (s)")
    .replace(/_ms$/, " (ms)")
    .replace(/_/g, " ");

export const prettyThreat = (threatType: string): string =>
  threatType === "UNKNOWN_ANOMALY" ? "unknown" : threatType.replace(/_/g, " ");

/** Ordinal alert severity → CSS variant (independent of the score badge). */
export const severityClass = (severity: string | null | undefined): string => {
  if (severity === "CRITICAL") return "sev-critical";
  if (severity === "HIGH") return "sev-high";
  if (severity === "MEDIUM") return "sev-medium";
  return "sev-low";
};

/** Alert lifecycle → CSS variant. */
export const statusClass = (status: string): string => {
  if (status === "RESOLVED") return "resolved";
  if (status === "ACKNOWLEDGED") return "acknowledged";
  return "open";
};
