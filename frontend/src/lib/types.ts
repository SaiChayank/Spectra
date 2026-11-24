/**
 * Hand-written response types read from the recorded contract fixtures
 * (frontend/contract/fixtures/), for routes whose OpenAPI response is an
 * untyped `object`. Replace with generated types as the backend adds models.
 */

/** GET /api/users item (public projection: never hashes or secrets). */
export interface ManagedUser {
  id: number;
  username: string;
  role: "ADMIN" | "ANALYST" | "VIEWER";
  created_at: number;
  updated_at: number;
  last_login_at: number | null;
}

export interface UserList {
  count: number;
  items: ManagedUser[];
}

/** POST /api/auth/totp/setup: shown once, never stored by the UI. */
export interface TotpSetup {
  issuer: string;
  secret: string;
  otpauth_uri: string;
}

/** POST /api/auth/totp/enable: single-use recovery codes, shown once. */
export interface TotpEnabled {
  recovery_codes: string[];
}

/** POST /api/auth/password (contract fixture POST_api_auth_password): every session, this one included, is revoked. */
export interface PasswordChanged {
  ok: boolean;
  sign_in_required: boolean;
}

/* -- host triage (GET /api/hosts, GET /api/hosts/{host}/evidence, POST /api/hosts/{host}/verdict) -- */

export type HostVerdictValue = "true" | "expected" | "false";

export interface HostVerdict {
  verdict: HostVerdictValue;
  note: string | null;
  actor: string;
  created_at: number;
}

export interface HostSummary {
  host: string;
  rank: number;
  /** Ranking confidence 0-1. NOT a calibrated probability (backend services.hosts). */
  confidence: number;
  evidence_count: number;
  top_evidence: { detector: string; technique: string | null; destination: string; strength: number };
  first_seen: number;
  last_seen: number;
  verdict: HostVerdict | null;
}

export interface HostList {
  count: number;
  offset: number;
  items: HostSummary[];
}

export interface HostEvidenceItem {
  detector: string;
  threat_type: string;
  technique: string | null;
  first_seen: number;
  time: number;
  destination: string;
  strength: number;
  occurrences: number;
  alert_id: string;
  flow_ids: number[];
}

export interface HostEvidence {
  host: string;
  count: number;
  items: HostEvidenceItem[];
  verdict: HostVerdict | null;
}

/* -- own sessions (GET /api/auth/sessions, DELETE /api/auth/sessions/{id}) -- */

export interface SessionInfo {
  id: number;
  created_at: number;
  last_seen_at: number;
  expires_at: number;
  /** The session this browser is using. */
  current: boolean;
}

export interface SessionList {
  count: number;
  items: SessionInfo[];
}

export interface SessionRevoked {
  ok: boolean;
  revoked: number;
  current: boolean;
}
