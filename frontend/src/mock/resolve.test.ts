import { describe, expect, it } from "vitest";
import { FixtureIndex, SESSION_TTL_MS, resolve, type Fixture, type MockRequest, type MockState } from "./resolve";

const raw = import.meta.glob("../../contract/fixtures/*.json", { eager: true, import: "default" }) as Record<
  string,
  Omit<Fixture, "name">
>;
const fixtures: Fixture[] = Object.entries(raw)
  .map(([file, data]) => ({ ...data, name: file.split("/").pop()!.replace(/\.json$/, "") }))
  .filter((f) => f.name !== "ws_events");
const index = new FixtureIndex(fixtures);

const signedOut: MockState = { scenario: "normal", role: null, loginFixture: null, since: 0 };
const req = (method: string, path: string, query: Record<string, string> = {}, body: unknown = null): MockRequest => ({
  method,
  path,
  query,
  body,
});

function signIn(username: string, scenario: MockState["scenario"] = "normal"): MockState {
  const res = resolve(index, { ...signedOut, scenario }, req("POST", "/api/auth/login", {}, { username, password: "x" }), 0);
  expect(res.status).toBe(200);
  return { ...signedOut, scenario, ...res.next } as MockState;
}

describe("mock resolver", () => {
  it("requires a session for API calls but not for health", () => {
    expect(resolve(index, signedOut, req("GET", "/api/alerts"), 0).status).toBe(401);
    expect(resolve(index, signedOut, req("GET", "/api/health"), 0).status).toBe(200);
  });

  it("signs in each demo role and reports it from /api/auth/me", () => {
    for (const [name, role] of [["admin", "ADMIN"], ["analyst", "ANALYST"], ["viewer", "VIEWER"]] as const) {
      const me = resolve(index, signIn(name), req("GET", "/api/auth/me"), 1);
      expect((me.body as { user: { role: string } }).user.role).toBe(role);
    }
  });

  it("fails a wrong password and throttles in the login-429 scenario with a numeric Retry-After", () => {
    expect(resolve(index, signedOut, req("POST", "/api/auth/login", {}, { username: "admin", password: "wrong" }), 0).status).toBe(401);
    const r = resolve(index, { ...signedOut, scenario: "login-429" }, req("POST", "/api/auth/login", {}, { username: "admin", password: "x" }), 0);
    expect(r.status).toBe(429);
    expect(Number(r.headers["retry-after"])).toBeGreaterThan(0);
  });

  it("serves the recorded list, the query-matched variant, and another id's detail by path shape", () => {
    const s = signIn("admin");
    expect(resolve(index, s, req("GET", "/api/alerts"), 1).body).toEqual(index.named("GET_api_alerts")!.body);
    expect(resolve(index, s, req("GET", "/api/alerts", { limit: "2", status: "OPEN" }), 1).body).toEqual(
      index.named("GET_api_alerts__filtered")!.body,
    );
    expect(resolve(index, s, req("GET", "/api/incidents/7"), 1).status).toBe(200);
  });

  it("uses the recorded 403 for a viewer and a generic 403 where none was recorded", () => {
    const v = signIn("viewer");
    const ack = resolve(index, v, req("POST", "/api/alerts/alrt_9de57ae832fd/acknowledge"), 1);
    expect(ack.status).toBe(403);
    expect(ack.body).toEqual(index.named("POST_api_alerts_alrt_9de57ae832fd_acknowledge__403_viewer")!.body);
    expect(resolve(index, v, req("DELETE", "/api/captures/1"), 1).status).toBe(403);
    expect(resolve(index, v, req("GET", "/api/users"), 1).status).toBe(403);
  });

  it("serves empty variants in the empty scenario", () => {
    const s = signIn("admin", "empty");
    expect(resolve(index, s, req("GET", "/api/model"), 1).body).toEqual(index.named("GET_api_model__empty")!.body);
  });

  it("fails writes with 503 + Retry-After and reports a busy database in the storage scenario", () => {
    const s = signIn("admin", "storage-503");
    const w = resolve(index, s, req("POST", "/api/incidents"), 1);
    expect(w.status).toBe(503);
    expect(Number(w.headers["retry-after"])).toBeGreaterThan(0);
    const h = resolve(index, s, req("GET", "/api/health"), 1);
    expect((h.body as { writable: { database: string } }).writable.database).toBe("busy");
  });

  it("expires the session in the session-expiry scenario", () => {
    const s = signIn("admin", "session-expiry");
    expect(resolve(index, s, req("GET", "/api/alerts"), SESSION_TTL_MS - 1).status).toBe(200);
    expect(resolve(index, s, req("GET", "/api/alerts"), SESSION_TTL_MS + 1).status).toBe(401);
  });

  it("returns a labelled 404 for routes without a fixture", () => {
    const r = resolve(index, signIn("admin"), req("GET", "/api/nothing-here"), 1);
    expect(r.status).toBe(404);
    expect(r.headers["x-mock"]).toBe("no fixture");
  });

  it("never serves an unredacted secret from a fixture", () => {
    const text = JSON.stringify(fixtures);
    expect(text).not.toMatch(/"password":\s*"(?!<redacted>)[^"]+"/);
  });
});
