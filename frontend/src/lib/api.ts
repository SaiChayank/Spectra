/** API client for the Spectra backend (http://localhost:8000). */

export const API_BASE = import.meta.env.VITE_API_BASE ?? "http://localhost:8787";
export const WS_URL = import.meta.env.VITE_WS_URL ?? "ws://localhost:8787/ws/events";

export interface FlowRecord {
  proto: string;
  src: string;
  dst: string;
  start_ts: number;
  last_ts: number;
  duration: number;
  packets: number;
  bytes: number;
  tls_version: string | null;
  sni: string | null;
  alpn: string[] | null;
  ja3: string | null;
  ja4: string | null;
  cipher_count: number;
  extension_count: number;
  score?: number | null;
  anomaly?: boolean;
  /** Module 8: 5G/6G slice this flow was classified onto. */
  slice?: string;
  /** Module 6: immune assessment (level 0-3 → ignore/monitor/alert/isolate). */
  immune?: ImmuneAnnotation;
  /** Module 6: spiking-network timing score (percentile), when trained. */
  snn_score?: number | null;
  /** Module 6: swarm quorum flag for this flow. */
  swarm_flag?: boolean;
  /** Threat classification (anomalies only): explainable behavioural verdict. */
  threat?: ThreatAssessment;
}

export interface ThreatSignal {
  /** Stable machine-readable signal id (e.g. periodic_forward_timing). */
  signal: string;
  /** Evidence weight — 0.3 weak, 0.4 moderate, 0.5 strong. */
  weight: number;
  /** Human-readable explanation of what was observed. */
  detail: string;
}

export interface ThreatAssessment {
  /** Specific category, or UNKNOWN_ANOMALY when evidence is insufficient. */
  threat_type: string;
  /** 0-1 evidence share (unknown verdicts always stay below 0.5). */
  confidence: number;
  /** Signals supporting the classification. */
  supporting: ThreatSignal[];
  /** Signals that argue against it (lower the confidence). */
  contradicting: ThreatSignal[];
  /** Closest sub-threshold category (unknown verdicts only). */
  candidate?: string;
  /** True while no category met its evidence threshold. */
  insufficient_evidence?: boolean;
}

export interface ImmuneAnnotation {
  level: number;
  response: string;
  affinity: number;
  danger_total: number;
  memory_hit: boolean;
  slice_policy: string | null;
}

export interface Reason {
  feature: string;
  z_score: number;
  value: number;
}

export interface Detection extends FlowRecord {
  score: number;
  reasons: Reason[];
  detected_at: number;
}

/* ---------- Module 4b: analyst alerts (over detections, never instead) ---------- */

export interface EvidenceItem {
  /** Stable machine-readable key (e.g. `periodicity`). */
  key: string;
  /** Measured value — number, string or boolean; null when not measured. */
  value: number | string | boolean | null;
  unit: string | null;
  /** Human label for the item (e.g. "Periodicity"). */
  label: string;
  /** Original human phrasing of the observation. */
  detail: string;
}

export interface Evidence {
  /** Technical items supporting the classification. */
  supporting: EvidenceItem[];
  /** Technical items arguing against it (kept visible, never dropped). */
  contradicting: EvidenceItem[];
  /** One plain-sentence analyst explanation of the behaviour. */
  summary: string;
}

export type AlertSeverity = "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
export type AlertStatus = "OPEN" | "ACKNOWLEDGED" | "RESOLVED";

export interface ThreatAlert {
  alert_id: string;
  flow_id: number | null;
  capture_id: number | null;
  timestamp: number;
  first_seen: number;
  last_seen: number;
  updated_at: number;
  source: string;
  destination: string;
  protocol: string;
  threat_type: string;
  /** Detector percentile (0-100) — independent of the fields below. */
  anomaly_score: number | null;
  /** Classifier evidence share (0-1) for the chosen threat type. */
  confidence: number;
  /** Ordinal triage level — calculated separately, see severity_factors. */
  severity: AlertSeverity;
  /** Every severity input's contribution, human-readable. */
  severity_factors: string[];
  model_id: string | null;
  model_version: string | null;
  evidence: Evidence;
  metadata: Record<string, unknown>;
  module_annotations: Record<string, unknown>;
  status: AlertStatus;
  /** Sightings grouped into this alert (repeats, not duplicates). */
  occurrences: number;
}

export interface IfaceDetail {
  id: string;
  name: string;
  description: string;
  ip: string;
  mac: string;
}

export interface CaptureStatus {
  running: boolean;
  mode: "pcap" | "live" | null;
  source: string | null;
  packets: number;
  flows: number;
  detections: number;
  started_at: number | null;
  error: string | null;
  model_trained: boolean;
}

/** A managed capture resource (imported file) and its lifecycle state. */
export interface CaptureResource {
  capture_id: number;
  /** Client filename (basename only); the stored name is generated. */
  original_name: string | null;
  stored_name: string | null;
  size_bytes: number;
  source_type: string;
  mode: "pcap" | "live";
  status: "UPLOADED" | "PROCESSING" | "COMPLETED" | "FAILED" | "STOPPED";
  imported_at: number | null;
  started_at: number | null;
  stopped_at: number | null;
  packets: number;
  flows: number;
  detections: number;
  error: string | null;
  running: boolean;
}

/** 409 on import: identical content already stored under this id. */
export class DuplicateCaptureError extends Error {
  readonly captureId: number;

  constructor(captureId: number, message: string) {
    super(message);
    this.name = "DuplicateCaptureError";
    this.captureId = captureId;
  }
}

export interface ModelInfo {
  trained: boolean;
  trained_at: string | null;
  n_train: number;
  n_features: number;
  n_estimators: number;
  contamination: number;
  threshold: number | null;
  version: number;
}

export interface TimelinePoint {
  t: number;
  flows: number;
  anomalies: number;
  avg_score: number;
}

export interface Snapshot {
  status: CaptureStatus;
  model: ModelInfo;
  totals: {
    packets: number;
    flows: number;
    detections: number;
    anomaly_rate: number;
    avg_score: number | null;
  };
  protocols: Record<string, number>;
  tls_versions: Record<string, number>;
  timeline: TimelinePoint[];
}

export type WsEvent =
  | { type: "flow"; data: FlowRecord & { score: number | null; anomaly: boolean } }
  | { type: "detection"; data: Detection }
  | { type: "status"; data: CaptureStatus }
  | { type: "model"; data: ModelInfo }
  | { type: "alert"; data: ThreatAlert }
  | { type: "alert_updated"; data: ThreatAlert };

/* ---------- Module 6: bio-inspired immunity ---------- */

export interface BioStatus {
  available: boolean;
  contamination: number | null;
  self_model: { trained: boolean; n_features: number };
  snn: { trained: boolean; threshold: number | null; threshold_pct: number };
  swarm: {
    agents: string[];
    quorum: number;
    min_agents: number;
    weights: Record<string, number>;
  };
  memory_cells: number;
  assessed: number;
  response_histogram: Record<string, number>;
  drift_level: string | null;
  evasion_active: boolean;
  timing_scale: number;
}

/* ---------- Module 2: confidential computing (TEE) ---------- */

export interface TeeQuote {
  domain: string;
  measurement: string;
  nonce: string | null;
  ts: number;
  service: string;
  pubkey: string;
  signature: string;
}

export interface TeeCheck {
  name: string;
  ok: boolean;
  detail: string;
}

export interface TeeVerifyResult {
  ok: boolean;
  checks: TeeCheck[];
  measurement: string;
  expected_measurement: string;
  age_s: number;
}

export interface FederateResult {
  round_id: string;
  parties: number;
  shareholders: number;
  threshold: number;
  dim: number;
  quantize: number;
  exact: boolean;
  verified: boolean;
  aggregate: number[];
  aggregate_digest: string;
  capability: string;
  claims: Record<string, unknown>;
}

/* ---------- Module 8: edge-native (5G/6G) ---------- */

export interface EdgeLink {
  link: string;
  label: string;
  rtt_ms: number;
  jitter_ms: number;
  timing_scale: number;
}

export interface EdgeSliceDef {
  label: string;
  sensitivity: number;
  policy: string;
}

export interface EdgeLatency {
  available: boolean;
  n: number;
  p50_ms: number;
  p95_ms: number;
  budget_ms: number;
  within_budget: boolean;
}

export interface EdgeMicro {
  trained: boolean;
  n_features: number;
  features: string[];
  threshold: number | null;
  threshold_pct: number;
  digest: string;
  latency: EdgeLatency | null;
  budget_ms: number;
}

export interface EdgeDeployment {
  node: string;
  slice: string;
  link: string;
  digest: string;
  threshold_pct: number;
  budget_ms: number;
  deployed_at: number;
}

export interface EdgeReport {
  link: EdgeLink;
  link_profiles: Record<string, { rtt_ms: number; jitter_ms: number; label: string }>;
  micro: EdgeMicro;
  deployments: EdgeDeployment[];
  slices: Record<string, EdgeSliceDef>;
  slice_counts: Record<string, number>;
}

export interface EdgeSliceResult {
  slice: string;
  policy: EdgeSliceDef;
  level: number;
  adjusted_level: number;
  note: string | null;
}

/** Maturity ladder served by GET /api/capabilities (backend capabilities.py). */
export type CapabilityStatus =
  | "REAL"
  | "LOCAL"
  | "SIMULATED"
  | "EXPERIMENTAL"
  | "HARDWARE_BACKED"
  | "UNAVAILABLE";

/**
 * One advanced module's integration contract + live availability.
 * `available` is null when no probe ran ("unknown", not "down").
 */
export interface CapabilityModule {
  title: string;
  status: CapabilityStatus;
  /** Always false in this build — nothing is hardware-backed. */
  hardware_backed: boolean;
  note: string;
  consumes: string;
  produces: string;
  /** Never true here: modules contribute evidence, never move scores. */
  affects_alert_scoring: boolean;
  evidence_only: boolean;
  failure: string;
  available: boolean | null;
  detail: string | null;
  failures: number | null;
}

export interface CapabilityReport {
  statuses: CapabilityStatus[];
  definitions: Record<string, string>;
  scoring_policy: string;
  modules: Record<string, CapabilityModule>;
  hardware_backed_count: number;
}

/**
 * Operational health state of one subsystem (GET /api/health/system).
 * SIMULATED = working as designed but non-real by design (never masks a
 * failure: a failing simulated module reports DEGRADED/UNAVAILABLE).
 */
export type HealthState = "HEALTHY" | "DEGRADED" | "UNAVAILABLE" | "SIMULATED";

/** One subsystem entry: state + the *why* + the observed numbers. */
export interface HealthSubsystem {
  name: string;
  title: string;
  state: HealthState;
  reason: string;
  evidence: Record<string, string | number | boolean | null>;
}

/** One staged queue: depth/limit/utilisation + drop counters. */
export interface HealthQueue {
  depth: number;
  limit: number;
  utilization: number;
  offered: number;
  accepted: number;
  dropped: number;
}

export interface HealthMetrics {
  uptime_s: number;
  packets: { captured: number; dropped: number; drop_ratio: number; rate_pps: number };
  flows: {
    processed: number;
    rate_fps: number;
    active: number;
    active_limit: number;
    evicted: number;
    dropped: number;
  };
  queues: {
    packet_queue: HealthQueue;
    flow_queue: HealthQueue;
    publish_queue: HealthQueue;
    live_capture: {
      received: number;
      queued: number;
      dropped: number;
      depth: number;
      max_depth: number;
    };
    /** Stage names at or above the saturation threshold (>= 80% of cap). */
    saturation: string[];
  };
  inference: {
    p50_ms: number;
    p95_ms: number;
    mean_ms: number;
    max_ms: number;
    ops: number;
    budget_p95_ms: number;
  };
  processing_lag_ms: number;
  processing_lag_max_ms: number;
  database: {
    enabled: boolean;
    size_bytes: number;
    write_p50_ms: number;
    write_p95_ms: number;
    write_samples: number;
    commits: number;
    flushes: number;
    staged: number;
    errors: number;
    budget_p95_ms: number;
  };
  /** Per-minute rates measured between health reports (<= 60s window). */
  rates: Record<string, number>;
  websocket: {
    clients: number;
    subscribers: number;
    events_emitted: number;
    slow_client_drops: number;
  };
  model: {
    id: string;
    version: string | null;
    trained: boolean;
    n_train: number;
    trained_at: number | null;
    drift_level: string | null;
  };
  errors: { total: number; by_component: Record<string, number>; capture_error: string | null };
}

/** The System Health document: overall rollup + 14 subsystems + metrics. */
export interface SystemHealth {
  ts: number;
  uptime_s: number;
  state: HealthState;
  reason: string;
  counts: Record<HealthState, number>;
  subsystems: HealthSubsystem[];
  metrics: HealthMetrics;
}

/** 401: no session, or the session is no longer valid. */
export class AuthError extends Error {
  readonly status: number;

  constructor(message: string, status: number) {
    super(message);
    this.name = "AuthError";
    this.status = status;
  }
}

/** The signed-in user — never carries hash or token material. */
export interface AuthUser {
  id: number;
  username: string;
  role: "ADMIN" | "ANALYST" | "VIEWER";
  permissions: string[];
}

export interface Identity {
  user: AuthUser;
  expires_at: number;
}

/** Tell the app the session ended (drops back to the login screen). */
function notifyUnauthorized(path: string): void {
  // The login route owns its own 401s (bad credentials) — those are a
  // failed form submit, not a session that just died.
  if (!path.startsWith("/api/auth/login")) {
    window.dispatchEvent(new CustomEvent("spectra:unauthorized"));
  }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`, {
    headers: { "Content-Type": "application/json" },
    credentials: "include", // the session lives in an HttpOnly cookie
    ...init,
  });
  if (!res.ok) {
    let detail = res.statusText;
    try {
      const body = await res.json();
      detail = typeof body.detail === "string" ? body.detail : JSON.stringify(body.detail);
    } catch {
      /* non-JSON error body */
    }
    if (res.status === 401) {
      notifyUnauthorized(path);
      throw new AuthError(detail, res.status);
    }
    throw new Error(detail);
  }
  return res.json() as Promise<T>;
}

export const api = {
  // Local authentication: HttpOnly session cookie, no tokens in JS.
  me: () => request<Identity>("/api/auth/me"),
  login: (username: string, password: string) =>
    request<Identity>("/api/auth/login", {
      method: "POST",
      body: JSON.stringify({ username, password }),
    }),
  logout: () => request<{ ok: boolean }>("/api/auth/logout", { method: "POST" }),

  stats: () => request<Snapshot>("/api/stats"),
  /** Module maturity + live availability — real vs simulated, per module. */
  capabilities: () => request<CapabilityReport>("/api/capabilities"),
  /** Per-subsystem health states, reasons and runtime metrics. */
  systemHealth: () => request<SystemHealth>("/api/health/system"),
  flows: (limit = 100) => request<{ count: number; items: FlowRecord[] }>(`/api/flows?limit=${limit}`),
  detections: (limit = 100) =>
    request<{ count: number; items: Detection[] }>(`/api/detections?limit=${limit}`),
  alerts: (limit = 40) =>
    request<{ count: number; offset: number; items: ThreatAlert[] }>(
      `/api/alerts?limit=${limit}`,
    ),
  acknowledgeAlert: (alertId: string) =>
    request<ThreatAlert>(`/api/alerts/${alertId}/acknowledge`, { method: "POST" }),
  resolveAlert: (alertId: string) =>
    request<ThreatAlert>(`/api/alerts/${alertId}/resolve`, { method: "POST" }),
  model: () => request<ModelInfo>("/api/model"),
  interfaces: () =>
    request<{ interfaces: string[]; details?: IfaceDetail[]; error?: string }>("/api/interfaces"),
  /** Live capture only — file-based starts were replaced by importCapture. */
  startCapture: (body: { mode: "live"; iface?: string; bpf_filter?: string }) =>
    request<CaptureStatus>("/api/capture/start", { method: "POST", body: JSON.stringify(body) }),
  stopCapture: () => request<CaptureStatus>("/api/capture/stop", { method: "POST" }),
  train: (captureId: number, contamination: number) =>
    request<{ n_train: number; model_path: string }>("/api/model/train", {
      method: "POST",
      body: JSON.stringify({ capture_id: captureId, contamination }),
    }),

  // Managed capture resources: file bytes go up once via multipart import;
  // everything else addresses the capture id this API generated (the client
  // never sends, and the server never accepts, a filesystem path).
  importCapture: async (file: File): Promise<CaptureResource> => {
    const form = new FormData();
    form.append("file", file, file.name);
    const res = await fetch(`${API_BASE}/api/captures`, {
      method: "POST",
      body: form,
      credentials: "include",
    });
    if (!res.ok) {
      let detail: unknown = res.statusText;
      try {
        const body = (await res.json()) as { detail?: unknown };
        detail = body.detail;
      } catch {
        /* non-JSON error body */
      }
      if (res.status === 401) {
        notifyUnauthorized("/api/captures");
        throw new AuthError(
          typeof detail === "string" ? detail : res.statusText,
          res.status,
        );
      }
      if (res.status === 409 && detail && typeof detail === "object") {
        const dup = detail as { capture_id?: number; message?: string };
        if (typeof dup.capture_id === "number") {
          throw new DuplicateCaptureError(dup.capture_id, dup.message ?? "capture already imported");
        }
      }
      throw new Error(typeof detail === "string" ? detail : JSON.stringify(detail ?? res.statusText));
    }
    return res.json() as Promise<CaptureResource>;
  },
  listCaptures: (limit = 50) =>
    request<{ count: number; offset: number; items: CaptureResource[] }>(
      `/api/captures?limit=${limit}`,
    ),
  captureDetails: (captureId: number) => request<CaptureResource>(`/api/captures/${captureId}`),
  processCapture: (captureId: number) =>
    request<CaptureResource>(`/api/captures/${captureId}/process`, { method: "POST" }),
  deleteCapture: (captureId: number) =>
    request<{ deleted: number; file_removed: boolean; original_name: string | null }>(
      `/api/captures/${captureId}`,
      { method: "DELETE" },
    ),

  // Module 6: bio-inspired immunity
  bioStatus: () => request<BioStatus>("/api/bio/status"),
  bioAssess: (features: number[], score?: number, anomaly = false) =>
    request<Record<string, unknown>>("/api/bio/assess", {
      method: "POST",
      body: JSON.stringify({ features, score: score ?? null, anomaly }),
    }),

  // Module 2: confidential computing
  teeAttest: (nonce: string | null = null) =>
    request<TeeQuote>("/api/tee/attest", {
      method: "POST",
      body: JSON.stringify({ nonce }),
    }),
  teeVerify: (quote: TeeQuote, nonce: string | null = null) =>
    request<TeeVerifyResult>("/api/tee/verify", {
      method: "POST",
      body: JSON.stringify({ quote, nonce }),
    }),
  teeFederate: (body: { deltas?: number[][]; shareholders?: number; seed?: number }) =>
    request<FederateResult>("/api/tee/federate", {
      method: "POST",
      body: JSON.stringify(body),
    }),

  // Module 8: edge-native
  edgeReport: () => request<EdgeReport>("/api/edge/report"),
  edgeSetLink: (link: string) =>
    request<{ link: EdgeLink }>("/api/edge/link", {
      method: "POST",
      body: JSON.stringify({ link }),
    }),
  edgeSlice: (record: Record<string, unknown>, level: number) =>
    request<EdgeSliceResult>("/api/edge/slice", {
      method: "POST",
      body: JSON.stringify({ record, level }),
    }),
  edgeDeploy: (node: string, slice: string) =>
    request<EdgeDeployment>("/api/edge/deploy", {
      method: "POST",
      body: JSON.stringify({ node, slice }),
    }),
};
