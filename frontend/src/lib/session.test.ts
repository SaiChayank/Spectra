import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { Identity } from "./api";
import { resetStartupForTests, startPage, startupSession } from "./session";

const json = (status: number, body: unknown) => new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
const me: Identity = { expires_at: 1, user: { id: 1, username: "admin", role: "ADMIN", permissions: ["read", "users:manage"] } };

beforeEach(() => {
  sessionStorage.clear();
  resetStartupForTests();
});
afterEach(() => vi.unstubAllGlobals());

describe("startupSession", () => {
  it("a fresh visit signs out first and starts signed out, without reporting a dead session", async () => {
    const fetchMock = vi.fn().mockResolvedValue(json(200, { ok: true }));
    vi.stubGlobal("fetch", fetchMock);
    const ended = vi.fn();
    window.addEventListener("spectra:unauthorized", ended);
    expect(await startupSession()).toBeNull();
    window.removeEventListener("spectra:unauthorized", ended);
    expect(String(fetchMock.mock.calls[0][0])).toMatch(/\/api\/auth\/logout$/);
    expect(fetchMock).toHaveBeenCalledTimes(1); // never asks /me on a fresh visit
    expect(ended).not.toHaveBeenCalled();
  });

  it("a reload in the same tab restores the session", async () => {
    sessionStorage.setItem("spectra-ui-visit", "1");
    const fetchMock = vi.fn().mockResolvedValue(json(200, me));
    vi.stubGlobal("fetch", fetchMock);
    expect(await startupSession()).toEqual(me);
    expect(String(fetchMock.mock.calls[0][0])).toMatch(/\/api\/auth\/me$/);
  });

  it("decides once per page load even if called twice (React dev effects)", async () => {
    const fetchMock = vi.fn().mockResolvedValue(json(200, { ok: true }));
    vi.stubGlobal("fetch", fetchMock);
    const [a, b] = await Promise.all([startupSession(), startupSession()]);
    expect(a).toBeNull();
    expect(b).toBeNull();
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it("stays signed out when the server is unreachable", async () => {
    vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new TypeError("Failed to fetch")));
    expect(await startupSession()).toBeNull();
  });
});

describe("startPage", () => {
  const who = (permissions: string[]): Identity => ({ expires_at: 1, user: { id: 1, username: "u", role: "VIEWER", permissions } });
  it("sends analysts to the alert queue, admins and viewers to the overview", () => {
    expect(startPage(who(["read", "investigate", "incidents:manage"]))).toBe("#/incidents");
    expect(startPage(who(["read", "investigate", "incidents:manage", "users:manage"]))).toBe("#/overview");
    expect(startPage(who(["read"]))).toBe("#/overview");
  });
});
