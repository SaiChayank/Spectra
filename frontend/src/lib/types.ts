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
  totp_enabled?: boolean;
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

/** PROPOSED POST /api/auth/password (frontend/contract/proposed/). */
export interface PasswordChanged {
  ok: boolean;
  sessions_revoked: boolean;
}
