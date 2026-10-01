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
  /** QUIC version name when the flow negotiated HTTP/3. */
  quic_version?: string | null;
  sni: string | null;
  alpn: string[] | null;
  ja3: string | null;
  ja4: string | null;
  cipher_count: number;
  extension_count: number;
  score?: number | null;
  anomaly?: boolean;
  /** Persisted identity: history/detection rows carry row + batch timestamps. */
  id?: number;
  ts?: number;
  /** Persisted detector reasons (present on store rows, not live frames). */
  reasons?: { feature: string; z_score: number; value: number }[] | null;
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

/** Raw ``captures`` row as served by /api/history/captures (table columns). */
export interface CaptureRow {
  id: number;
  mode: string;
  source: string | null;
  status: string;
  original_name: string | null;
  stored_name: string | null;
  size_bytes: number;
  source_type: string;
  imported_at: number | null;
  started_at: number | null;
  stopped_at: number | null;
  packets: number;
  flows: number;
  detections: number;
  error: string | null;
}

export interface ModelInfo {
  trained: boolean;
  trained_at: string | null;
  n_train: number;
  n_features: number;
  /** Ordered detector feature names (the feature schema, in use order). */
  feature_names?: string[];
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

/* ==========================================================================
 * SOC surface: incidents, investigation bundle, global search, audit trail,
 * correlation graph, persisted history, drift and the model registry.
 * ========================================================================== */

export type IncidentStatus =
  | "OPEN"
  | "INVESTIGATING"
  | "ACKNOWLEDGED"
  | "RESOLVED"
  | "FALSE_POSITIVE";

/** One row of GET /api/incidents (JSON columns hydrated server-side). */
export interface IncidentRow {
  id: number;
  title: string;
  detection_id: number | null;
  status: IncidentStatus;
  created_by: string;
  created_at: number;
  acknowledged_by?: string | null;
  acknowledged_at?: number | null;
  resolved_by?: string | null;
  resolved_at?: number | null;
  summary: string | null;
  severity: AlertSeverity | null;
  confidence: number | null;
  first_seen: number | null;
  last_seen: number | null;
  affected_entities: string[];
  alert_count: number;
  primary_threat_class: string | null;
  related_graph_nodes: string[];
  model_versions: string[];
  evidence_summary: string | null;
  /** Added by the list endpoint (per-page note counts). */
  note_count?: number;
}

export interface IncidentNote {
  id: number;
  incident_id: number;
  author: string;
  body: string;
  created_at: number;
}

/** One incident-timeline entry (state changes, links, notes). */
export interface IncidentEvent {
  id: number;
  incident_id: number;
  ts: number;
  kind: string;
  actor: string;
  data: Record<string, unknown>;
}

/** GET /api/incidents/{id}: the row + notes, member alerts, timeline. */
export interface IncidentDetail extends IncidentRow {
  notes: IncidentNote[];
  alerts: ThreatAlert[];
  timeline: IncidentEvent[];
}

/** Response of POST /api/incidents/correlate. */
export interface CorrelateResult {
  created: IncidentRow[];
  clusters: number;
  considered: number;
  ungrouped: string[];
}

/** One bounded section of GET /api/search. */
export interface SearchSection {
  count: number;
  items: Record<string, unknown>[];
}

export interface SearchResults {
  query: string;
  kinds: string[];
  count: number;
  limit: number;
  results: Record<string, SearchSection>;
}

/* ---------- investigation bundle (GET /api/investigations/{id}) ---------- */

export interface BundleWindow {
  since: number;
  until: number;
  evidence_rows: number;
  evidence_total: number;
}

export interface TlsFingerprint {
  kind: "ja3" | "ja4" | string;
  value: string;
  flows: number;
  snis: string[];
}

/** TLS/QUIC metadata aggregated over the evidence window. */
export interface TlsSummary {
  tls_versions: Record<string, number>;
  quic_versions: Record<string, number>;
  alpn: Record<string, number>;
  fingerprints: TlsFingerprint[];
  sampled: number;
  flows_total: number;
}

export interface EvidenceAlert {
  alert_id: string;
  threat_type: string;
  severity: AlertSeverity;
  confidence: number;
  anomaly_score: number | null;
  evidence: Evidence;
}

export interface InvestigationEvidence {
  summary: string | null;
  primary_threat: string | null;
  severity_factors: string[];
  alerts: EvidenceAlert[];
  flow_reasons: { flow_id: number; score: number | null; reasons: Reason[] }[];
  sampled: number;
}

export interface RelatedHost {
  host: string;
  flows: number;
  detections: number;
  roles: string[];
  first_ts: number | null;
  last_ts: number | null;
}

export interface RelatedDomain {
  domain: string;
  flows: number;
  detections: number;
  first_ts: number | null;
  last_ts: number | null;
}

/** PQC / behavioural / edge annotations over the evidence window. */
export interface BundleAnnotations {
  pqc: { ref: string; assessment: unknown }[];
  bio: { ref: string; immune?: unknown; snn_score?: number; swarm_flag?: boolean }[];
  edge: { ref: string; slice: string }[];
  counts: { pqc: number; bio: number; edge: number };
}

export interface BundleGraph {
  available: boolean;
  nodes: GraphNode[];
  edges: GraphEdge[];
  missing: string[];
  truncated?: boolean;
}

export interface BundleTwin {
  available: boolean;
  error?: string;
  nodes?: { id: string; asset: boolean; [k: string]: unknown }[];
  zones?: { assets?: string[]; [k: string]: unknown }[];
  asset_edges?: GraphEdge[];
  summary?: { nodes: number; assets: number; zones: number; edges: number };
}

/** An audit-log reference attached to the incident (seq + parsed payload). */
export interface AuditRef {
  seq: number;
  ts: number;
  kind: string;
  actor: string | null;
  payload: Record<string, unknown>;
  entry_hash: string;
}

export interface BundleModels {
  current: Record<string, unknown>;
  versions: string[];
  alerts: { alert_id: string; model_id: string | null; model_version: string | null }[];
}

/** One module's maturity + its evidence contribution to THIS incident. */
export interface BundleModuleItem {
  key: string;
  title: string;
  status: CapabilityStatus;
  hardware_backed: boolean;
  evidence_only: boolean;
  affects_alert_scoring: boolean;
  available: boolean | null;
  detail: string | null;
  failures: number | null;
  contributed: number;
  summary: string;
}

export interface InvestigationBundle {
  incident: IncidentRow;
  notes: IncidentNote[];
  note_count: number;
  timeline: IncidentEvent[];
  alerts: { count: number; items: ThreatAlert[] };
  flows: { count: number; offset: number; items: FlowRecord[] };
  window: BundleWindow;
  tls: TlsSummary;
  evidence: InvestigationEvidence;
  hosts: RelatedHost[];
  domains: RelatedDomain[];
  annotations: BundleAnnotations;
  graph: BundleGraph;
  twin: BundleTwin;
  audit: { count: number; items: AuditRef[] };
  models: BundleModels;
  modules: { scoring_policy: string; items: BundleModuleItem[] };
  generated_at: number;
}

/* ---------- audit trail (Module 5) ---------- */

export interface AuditEntry {
  seq: number;
  ts: number;
  kind: string;
  actor: string | null;
  /** Parsed payload document (the client never sees raw JSON text). */
  payload: Record<string, unknown>;
  prev_hash?: string;
  entry_hash: string;
}

export interface AuditPage {
  count: number;
  signing_key: string | null;
  items: AuditEntry[];
}

export interface AuditHead {
  seq: number;
  entry_hash: string;
  ts: number | null;
  kind: string | null;
}

export interface AuditVerifyResult {
  ok: boolean;
  entries: number;
  head: AuditHead;
  signing_key: string | null;
  errors: { seq: number; reason: string }[];
}

/* ---------- correlation graph (Module 7) ---------- */

export interface GraphNode {
  id: string;
  type: string;
  label: string;
  sector?: string | null;
  flows?: number;
  bytes?: number;
  detections?: number;
  domains?: string[];
  first_ts?: number | null;
  last_ts?: number | null;
}

export interface GraphEdge {
  source: string;
  target: string;
  type: string;
  weight: number;
}

export interface GraphSummary {
  nodes: number;
  edges: number;
  by_type: Record<string, number>;
  by_sector: Record<string, number>;
  shared_infrastructure: number;
  shared_ip_nodes: string[];
}

export interface GraphSnapshot {
  summary: GraphSummary;
  nodes: GraphNode[];
  edges: GraphEdge[];
}

/* ---------- persisted history ---------- */

export interface HistoryStats {
  flows: number;
  detections: number;
  anomaly_rate: number;
  avg_score: number | null;
  first_ts: number | null;
  last_ts: number | null;
  by_proto: Record<string, number>;
  top_sni: { sni: string; flows: number }[];
}

/** One training run (lineage). `metrics` arrives as a JSON *string*. */
export interface ModelRun {
  id: number;
  trained_at: number;
  pcap: string | null;
  n_train: number | null;
  contamination: number | null;
  metrics: string | Record<string, unknown>;
}

export interface HistoryEvent {
  id: number;
  ts: number;
  type: string;
  data: Record<string, unknown>;
}

/* ---------- drift (Module 3) ---------- */

export interface DriftFeature {
  feature: string;
  psi: number;
  constant?: boolean;
}

export interface DriftReport {
  available: boolean;
  reason?: string;
  n?: number;
  psi?: number;
  level?: string;
  window?: number;
  features?: DriftFeature[];
}

/* ---------- model registry (Prompt 14) ---------- */

export type RegistryStatus =
  | "CANDIDATE"
  | "VALIDATED"
  | "ACTIVE"
  | "FAILED"
  | "RETIRED";

export interface RegistryCheck {
  name: string;
  ok: boolean;
  detail: string;
}

export interface RegistryMetrics {
  passed?: boolean;
  checks?: RegistryCheck[];
  failed?: string[];
  validated_at?: number;
}

export interface RegistryRow {
  id: number;
  model_id: string;
  created_at: number;
  source: string;
  artifact: string;
  artifact_sha256: string;
  status: RegistryStatus;
  trained_at: number | null;
  n_train: number | null;
  contamination: number | null;
  n_features: number | null;
  feature_schema: string | null;
  model_version: string | null;
  threshold: number | null;
  metrics: RegistryMetrics | null;
  error: string | null;
  activated_count: number;
  last_activated_at: number | null;
  retired_at: number | null;
  /** Activation responses: session side effects were applied. */
  applied?: boolean;
}

export interface RegistryList {
  enabled: boolean;
  count: number;
  offset: number;
  active: RegistryRow | null;
  items: RegistryRow[];
}

export interface RegistryCompare {
  a: RegistryRow;
  b: RegistryRow;
  diff: {
    same_artifact?: boolean;
    same_feature_schema?: boolean;
    status?: { a: string; b: string };
    n_train?: { a?: number | null; b?: number | null; delta?: number | null };
    [k: string]: unknown;
  };
}

/** POST /api/model/train — registry present when persistence is on. */
export interface TrainResult {
  n_train: number;
  model_path: string;
  pcap?: string;
  contamination?: number;
  n_features?: number;
  registry?: {
    model_id: string;
    status: RegistryStatus;
    activated: boolean;
    applied?: boolean;
    error?: string;
  };
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

/** Build a query string, dropping empty/undefined values. */
function qs(params: Record<string, string | number | boolean | undefined | null>): string {
  const out: string[] = [];
  for (const [key, value] of Object.entries(params)) {
    if (value === undefined || value === null || value === "") continue;
    out.push(`${encodeURIComponent(key)}=${encodeURIComponent(String(value))}`);
  }
  return out.length ? `?${out.join("&")}` : "";
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
  /** PSI drift of recent traffic against the training baseline (ANALYST+). */
  modelDrift: () => request<DriftReport>("/api/model/drift"),
  interfaces: () =>
    request<{ interfaces: string[]; details?: IfaceDetail[]; error?: string }>("/api/interfaces"),
  /** Live capture only — file-based starts were replaced by importCapture. */
  startCapture: (body: { mode: "live"; iface?: string; bpf_filter?: string }) =>
    request<CaptureStatus>("/api/capture/start", { method: "POST", body: JSON.stringify(body) }),
  stopCapture: () => request<CaptureStatus>("/api/capture/stop", { method: "POST" }),
  /**
   * Train on a stored capture's benign baseline (model:manage).
   * `activate: false` registers a registry CANDIDATE only — the running
   * session model stays untouched until an explicit activation.
   */
  train: (captureId: number, contamination: number, activate = true) =>
    request<TrainResult>("/api/model/train", {
      method: "POST",
      body: JSON.stringify({ capture_id: captureId, contamination, activate }),
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

  // -- SOC surface: incidents --------------------------------------------------
  incidents: (params: {
    status?: IncidentStatus;
    severity?: string;
    threat_type?: string;
    since?: number;
    until?: number;
    limit?: number;
    offset?: number;
  } = {}) =>
    request<{ count: number; offset: number; items: IncidentRow[] }>(
      `/api/incidents${qs(params)}`,
    ),
  incident: (id: number) => request<IncidentDetail>(`/api/incidents/${id}`),
  /** Cluster unassigned related alerts into incidents (incidents:manage). */
  correlateIncidents: () =>
    request<CorrelateResult>("/api/incidents/correlate", {
      method: "POST",
      body: JSON.stringify({}),
    }),
  incidentAction: (
    id: number,
    action:
      | "investigate"
      | "acknowledge"
      | "resolve"
      | "reopen"
      | "false-positive",
  ) => request<IncidentRow>(`/api/incidents/${id}/${action}`, { method: "POST" }),
  incidentNote: (id: number, body: string) =>
    request<IncidentNote>(`/api/incidents/${id}/notes`, {
      method: "POST",
      body: JSON.stringify({ body }),
    }),

  // -- SOC surface: investigation + search -------------------------------------
  /** One bundle: incident, evidence, flows, TLS, graph, modules, audit refs. */
  investigation: (id: number) =>
    request<InvestigationBundle>(`/api/investigations/${id}`),
  search: (q: string, limit?: number) =>
    request<SearchResults>(`/api/search${qs({ q, limit })}`),

  // -- SOC surface: audit trail -------------------------------------------------
  auditEntries: (params: {
    limit?: number;
    offset?: number;
    kind?: string;
    actor?: string;
    since?: number;
    until?: number;
  } = {}) => request<AuditPage>(`/api/audit/entries${qs(params)}`),
  auditHead: () => request<AuditHead>("/api/audit/head"),
  auditVerify: () => request<AuditVerifyResult>("/api/audit/verify"),

  // -- SOC surface: correlation graph -------------------------------------------
  graphSnapshot: (params: { ntype?: string; sector?: string; limit?: number } = {}) =>
    request<GraphSnapshot>(`/api/graph${qs(params)}`),
  graphSummary: () => request<GraphSummary>("/api/graph/summary"),
  /** One node plus its in/out edges (404 when the id is unknown). */
  graphNode: (id: string) =>
    request<{
      node: GraphNode;
      in: { source: string; type: string; weight: number }[];
      out: { target: string; type: string; weight: number }[];
    }>(`/api/graph/node${qs({ id })}`),

  // -- SOC surface: persisted history --------------------------------------------
  historyFlows: (params: {
    limit?: number;
    offset?: number;
    since?: number;
    until?: number;
    sni?: string;
    proto?: string;
    src?: string;
    dst?: string;
    min_score?: number;
    max_score?: number;
    capture_id?: number;
  } = {}) =>
    request<{ count: number; offset: number; items: FlowRecord[] }>(
      `/api/history/flows${qs(params)}`,
    ),
  historyDetections: (params: {
    limit?: number;
    offset?: number;
    since?: number;
    until?: number;
    proto?: string;
    src?: string;
    dst?: string;
    min_score?: number;
    max_score?: number;
  } = {}) =>
    request<{ count: number; offset: number; items: FlowRecord[] }>(
      `/api/history/detections${qs(params)}`,
    ),
  historyStats: () => request<HistoryStats>("/api/history/stats"),
  historyCaptures: (params: { limit?: number; offset?: number } = {}) =>
    request<{ count: number; offset: number; items: CaptureRow[] }>(
      `/api/history/captures${qs(params)}`,
    ),
  historyModelRuns: (params: { limit?: number; offset?: number } = {}) =>
    request<{ count: number; offset: number; items: ModelRun[] }>(
      `/api/history/model-runs${qs(params)}`,
    ),
  historyEvents: (params: {
    limit?: number;
    offset?: number;
    type?: string;
    since?: number;
    until?: number;
  } = {}) =>
    request<{ count: number; offset: number; items: HistoryEvent[] }>(
      `/api/history/events${qs(params)}`,
    ),

  // -- model registry (Prompt 14) --------------------------------------------------
  /** Rows newest-first + the ACTIVE model; `enabled: false` = persistence off. */
  registryList: () => request<RegistryList>("/api/model/registry"),
  registryGet: (modelId: string) =>
    request<RegistryRow>(`/api/model/registry/${modelId}`),
  registryCompare: (a: string, b: string) =>
    request<RegistryCompare>(`/api/model/registry/compare${qs({ a, b })}`),
  /** CANDIDATE -> VALIDATED (or FAILED with the failing checks recorded). */
  registryValidate: (modelId: string) =>
    request<RegistryRow>(`/api/model/registry/${modelId}/validate`, {
      method: "POST",
    }),
  /** VALIDATED/RETIRED -> ACTIVE: swaps the running session model. */
  registryActivate: (modelId: string) =>
    request<RegistryRow>(`/api/model/registry/${modelId}/activate`, {
      method: "POST",
    }),
  registryRetire: (modelId: string) =>
    request<RegistryRow>(`/api/model/registry/${modelId}/retire`, {
      method: "POST",
    }),
  /** Re-activate the most recently superseded model. */
  registryRollback: () =>
    request<RegistryRow>("/api/model/registry/rollback", { method: "POST" }),
};
