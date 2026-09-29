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
  | { type: "model"; data: ModelInfo };

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
  parties: number;
  shareholders: number;
  dim: number;
  quantize: number;
  seed: number;
  exact: boolean;
  aggregate: number[];
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

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`, {
    headers: { "Content-Type": "application/json" },
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
    throw new Error(detail);
  }
  return res.json() as Promise<T>;
}

export const api = {
  stats: () => request<Snapshot>("/api/stats"),
  flows: (limit = 100) => request<{ count: number; items: FlowRecord[] }>(`/api/flows?limit=${limit}`),
  detections: (limit = 100) =>
    request<{ count: number; items: Detection[] }>(`/api/detections?limit=${limit}`),
  model: () => request<ModelInfo>("/api/model"),
  interfaces: () => request<{ interfaces: string[]; error?: string }>("/api/interfaces"),
  startCapture: (body: { mode: "pcap" | "live"; path?: string; iface?: string; bpf_filter?: string }) =>
    request<CaptureStatus>("/api/capture/start", { method: "POST", body: JSON.stringify(body) }),
  stopCapture: () => request<CaptureStatus>("/api/capture/stop", { method: "POST" }),
  train: (pcap_path: string, contamination: number) =>
    request<{ n_train: number; model_path: string }>("/api/model/train", {
      method: "POST",
      body: JSON.stringify({ pcap_path, contamination }),
    }),

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
