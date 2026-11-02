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

/** Incident lifecycle → CSS variant (FALSE_POSITIVE reads as resolved). */
export const incidentStatusClass = (status: string): string => {
  if (status === "RESOLVED" || status === "FALSE_POSITIVE") return "resolved";
  if (status === "ACKNOWLEDGED" || status === "INVESTIGATING")
    return "acknowledged";
  return "open";
};

/** Registry status → CSS variant (the five lifecycle states). */
export const registryStatusClass = (status: string): string => {
  if (status === "ACTIVE") return "state-healthy";
  if (status === "VALIDATED") return "state-simulated";
  if (status === "FAILED") return "state-unavailable";
  return "state-degraded"; // CANDIDATE / RETIRED
};

/** Capability maturity → badge class (REAL/LOCAL/SIMULATED/...). */
export const maturityClass = (status: string): string =>
  `cap-${status.toLowerCase()}`;

/** Date + time (locale, 24h clock) — for incident/audit/lineage columns. */
export const formatTs = (ts: number | null | undefined): string =>
  ts == null
    ? "—"
    : new Date(ts * 1000).toLocaleString([], {
        hour12: false,
        month: "2-digit",
        day: "2-digit",
        hour: "2-digit",
        minute: "2-digit",
        second: "2-digit",
      });

/** Compact "3m ago" / "in 2h" for relative timestamps. */
export const relTime = (ts: number | null | undefined): string => {
  if (ts == null) return "—";
  const delta = Date.now() / 1000 - ts;
  const past = delta >= 0;
  const abs = Math.abs(delta);
  const fmt = (value: number, unit: number, label: string) => {
    const n = Math.round(value / unit);
    if (n < 1) return "just now";
    return past ? `${n}${label} ago` : `in ${n}${label}`;
  };
  if (abs < 60) return "just now";
  if (abs < 3600) return fmt(abs, 60, "m");
  if (abs < 86400) return fmt(abs, 3600, "h");
  return fmt(abs, 86400, "d");
};

/** Thousands-separated integer. */
export const formatNum = (n: number | null | undefined): string =>
  n == null ? "—" : Math.round(n).toLocaleString();

/** Rate with one decimal (pps/fps style counters). */
export const formatRate = (n: number | null | undefined): string =>
  n == null ? "—" : n.toFixed(1);

/** Fraction (0-1) → percentage string. */
export const pct = (x: number | null | undefined, digits = 1): string =>
  x == null ? "—" : `${(x * 100).toFixed(digits)}%`;

/** Score (0-100) → one-decimal display, "—" for null. */
export const formatScore = (s: number | null | undefined): string =>
  s == null ? "—" : s.toFixed(1);

/** Duration in seconds → human-readable (83s, 4m 3s, 1h 12m). */
export const formatDuration = (seconds: number | null | undefined): string => {
  if (seconds == null || seconds < 0) return "—";
  const s = Math.floor(seconds);
  if (s < 60) return `${s}s`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}m ${s % 60}s`;
  const h = Math.floor(m / 60);
  return `${h}h ${m % 60}m`;
};

/** Shorten a long identifier for table cells (keeps both ends legible). */
export const shortHash = (value: string | null | undefined, keep = 12): string => {
  if (!value) return "—";
  return value.length <= keep + 3 ? value : `${value.slice(0, keep)}…`;
};

/**
 * Model-run metrics arrive as a JSON *string* (stored as TEXT); parse once,
 * tolerating malformed documents so one bad row never breaks the table.
 */
export const parseJson = <T>(raw: string | T): T => {
  if (typeof raw !== "string") return raw;
  try {
    return JSON.parse(raw) as T;
  } catch {
    return {} as T;
  }
};
