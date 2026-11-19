/**
 * Dev-only mock backend: picks a recorded contract fixture for a request.
 *
 * Pure (no fetch, no storage) so it is unit-tested. Fixtures come from
 * `frontend/contract/fixtures/` and are never edited by hand; when the mock
 * has to invent a response (generic 401/403/404, scenario overrides) it says
 * so in the body's `detail` or with an `x-mock` header.
 */

export interface Fixture {
  name: string;
  status: number;
  headers: Record<string, string | string[]>;
  body: unknown;
  request: { method: string; path: string; query: Record<string, unknown>; body: unknown };
}

export type Role = "ADMIN" | "ANALYST" | "VIEWER";

export type Scenario =
  | "normal"
  | "empty" // no data, no model
  | "storage-503" // writes fail with 503 + Retry-After, health shows busy
  | "login-429" // login throttled with Retry-After
  | "session-expiry"; // the session dies after SESSION_TTL_MS

export const SCENARIOS: { id: Scenario; label: string }[] = [
  { id: "normal", label: "Demo data (normal)" },
  { id: "empty", label: "Empty database, no model" },
  { id: "storage-503", label: "Storage unavailable (503 on writes)" },
  { id: "login-429", label: "Login throttled (429)" },
  { id: "session-expiry", label: "Session expires after 60 s" },
];

export const SESSION_TTL_MS = 60_000;
export const RETRY_AFTER_S = 10;

export interface MockState {
  scenario: Scenario;
  /** Signed-in role, or null when signed out. */
  role: Role | null;
  /** Fixture name of the login response (carries the user object). */
  loginFixture: string | null;
  /** When the session started (ms), for the session-expiry scenario. */
  since: number;
}

export interface MockRequest {
  method: string;
  path: string;
  query: Record<string, string>;
  body: unknown;
}

export interface MockResponse {
  status: number;
  headers: Record<string, string>;
  body: unknown;
  /** State change to apply (login/logout). */
  next?: Partial<MockState>;
}

const PUBLIC = [/^\/api\/auth\/login$/, /^\/api\/health$/];

/** Permission the backend checks for a route (approximation of authz.py, used only when no fixture covers it). */
export function requiredPermission(method: string, path: string): string {
  if (path.startsWith("/api/users")) return "users:manage";
  if (method === "GET") return "read";
  if (path.startsWith("/api/auth/")) return "read";
  if (path.startsWith("/api/model")) return "model:manage";
  if (path.startsWith("/api/captures") || path.startsWith("/api/capture/")) return "capture:manage";
  if (path.startsWith("/api/audit/rotate-key")) return "config:manage";
  if (path.startsWith("/api/alerts") || path.startsWith("/api/incidents")) return "incidents:manage";
  return "investigate";
}

const ID_SEGMENT = /^(\d+|alrt_[0-9a-z]+|mdl_[0-9a-z]+|cap_[0-9a-z]+)$/;

function pathPattern(path: string): string {
  return path
    .split("/")
    .map((seg) => (ID_SEGMENT.test(seg) ? ":id" : seg))
    .join("/");
}

function variantOf(f: Fixture): string {
  const i = f.name.indexOf("__");
  return i === -1 ? "" : f.name.slice(i + 2);
}

function sameQuery(a: Record<string, unknown>, b: Record<string, string>): boolean {
  const ka = Object.keys(a);
  return ka.length === Object.keys(b).length && ka.every((k) => String(a[k]) === b[k]);
}

function json(status: number, body: unknown, headers: Record<string, string> = {}): MockResponse {
  return { status, body, headers: { "content-type": "application/json", ...headers } };
}

function flatHeaders(h: Fixture["headers"], retryAfter: number): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [k, v] of Object.entries(h)) {
    if (k === "set-cookie-names") continue;
    out[k] = Array.isArray(v) ? v.join(", ") : v === "<seconds>" ? String(retryAfter) : v;
  }
  return out;
}

function fromFixture(f: Fixture, extra: Partial<MockResponse> = {}): MockResponse {
  return { status: f.status, headers: flatHeaders(f.headers, RETRY_AFTER_S), body: f.body, ...extra };
}

export class FixtureIndex {
  private byKey = new Map<string, Fixture[]>();
  private byPattern = new Map<string, Fixture[]>();
  readonly all: Fixture[];

  constructor(fixtures: Fixture[]) {
    this.all = fixtures;
    for (const f of fixtures) {
      const m = f.request.method.toUpperCase();
      push(this.byKey, `${m} ${f.request.path}`, f);
      push(this.byPattern, `${m} ${pathPattern(f.request.path)}`, f);
    }
  }

  named(name: string): Fixture | undefined {
    return this.all.find((f) => f.name === name);
  }

  /** Recorded fixtures for this exact path, else for the same path shape (another id). */
  candidates(method: string, path: string): Fixture[] {
    const m = method.toUpperCase();
    return this.byKey.get(`${m} ${path}`) ?? this.byPattern.get(`${m} ${pathPattern(path)}`) ?? [];
  }
}

function push<K, V>(map: Map<K, V[]>, key: K, value: V) {
  const list = map.get(key);
  if (list) list.push(value);
  else map.set(key, [value]);
}

function pickSuccess(cands: Fixture[], req: MockRequest, preferVariant?: string): Fixture | undefined {
  const ok = cands.filter((f) => f.status < 300);
  if (preferVariant) {
    const v = ok.find((f) => variantOf(f) === preferVariant);
    if (v) return v;
  }
  return (
    ok.find((f) => sameQuery(f.request.query, req.query) && variantOf(f) === "") ??
    ok.find((f) => sameQuery(f.request.query, req.query) && variantOf(f) !== "empty") ??
    ok.find((f) => variantOf(f) === "") ??
    ok.find((f) => variantOf(f) !== "empty") ??
    ok[0]
  );
}

function loginFixtureFor(username: string): string {
  const u = username.toLowerCase();
  if (u.includes("viewer")) return "POST_api_auth_login__viewer";
  if (u.includes("analyst")) return "POST_api_auth_login__analyst";
  if (u.includes("totp")) return "POST_api_auth_login__totp_user";
  return "POST_api_auth_login";
}

function roleOf(f: Fixture | undefined): Role {
  const user = (f?.body as { user?: { role?: Role } } | undefined)?.user;
  return user?.role ?? "ADMIN";
}

function permissionsOf(index: FixtureIndex, state: MockState): string[] {
  const f = state.loginFixture ? index.named(state.loginFixture) : undefined;
  const perms = (f?.body as { user?: { permissions?: string[] } } | undefined)?.user?.permissions;
  return perms ?? [];
}

export function resolve(index: FixtureIndex, state: MockState, req: MockRequest, now: number): MockResponse {
  const method = req.method.toUpperCase();
  const { path } = req;

  // --- login / logout ---------------------------------------------------
  if (method === "POST" && path === "/api/auth/login") {
    if (state.scenario === "login-429") return fromFixture(index.named("POST_api_auth_login__429_throttled")!);
    const body = (req.body ?? {}) as { username?: string; password?: string };
    if (!body.username || !body.password) return fromFixture(index.named("POST_api_auth_login__422")!);
    if (body.password === "wrong") return fromFixture(index.named("POST_api_auth_login__401_bad_password")!);
    const name = loginFixtureFor(body.username);
    const f = index.named(name)!;
    return fromFixture(f, { next: { role: roleOf(f), loginFixture: name, since: now } });
  }
  if (method === "POST" && path === "/api/auth/logout") {
    return fromFixture(index.named("POST_api_auth_logout")!, { next: { role: null, loginFixture: null } });
  }

  // --- authentication ---------------------------------------------------
  const expired = state.scenario === "session-expiry" && state.role !== null && now - state.since > SESSION_TTL_MS;
  if (!PUBLIC.some((re) => re.test(path)) && (state.role === null || expired)) {
    return json(401, { detail: "not authenticated" }, { "x-mock": expired ? "session expired (scenario)" : "signed out" });
  }

  // --- current user -----------------------------------------------------
  if (method === "GET" && path === "/api/auth/me") {
    const login = index.named(state.loginFixture ?? "POST_api_auth_login")!;
    return json(200, { ...(login.body as object) });
  }

  // --- scenario: storage unavailable -------------------------------------
  if (state.scenario === "storage-503") {
    if (path === "/api/health") return fromFixture(index.named("GET_api_health__database_busy")!);
    if (method !== "GET") return fromFixture(index.named("POST_api_users__503_storage_locked")!);
  }

  const cands = index.candidates(method, path);

  // --- authorisation ----------------------------------------------------
  const role = state.role!;
  const perm = requiredPermission(method, path);
  if (role && !permissionsOf(index, state).includes(perm)) {
    const recorded = cands.find((f) => f.status === 403 && variantOf(f).endsWith(role.toLowerCase()));
    if (recorded) return fromFixture(recorded);
    return json(403, { detail: `role ${role} lacks the '${perm}' permission` }, { "x-mock": "generic 403" });
  }

  // --- data -------------------------------------------------------------
  const prefer = state.scenario === "empty" ? "empty" : role === "ANALYST" ? "analyst" : undefined;
  const hit = pickSuccess(cands, req, prefer);
  if (hit) return fromFixture(hit);

  const notFound = cands.find((f) => f.status === 404);
  if (notFound) return fromFixture(notFound);
  return json(404, { detail: `mock: no fixture recorded for ${method} ${path}` }, { "x-mock": "no fixture" });
}
