import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import "@testing-library/jest-dom/vitest";
import { afterEach, describe, expect, it, vi } from "vitest";
import hostsFixture from "../../contract/fixtures/GET_api_hosts.json";
import evidenceFixture from "../../contract/fixtures/GET_api_hosts_10.0.0.7_evidence.json";
import verdictFixture from "../../contract/fixtures/POST_api_hosts_10.0.0.7_verdict.json";
import HostsPage from "./HostsPage";

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

const json = (status: number, body: unknown) =>
  new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });

/** fetch stub routed by "METHOD path" (query ignored); records every call. */
function stubFetch(routes: Record<string, () => Response>) {
  const calls: { key: string; query: string; body: unknown }[] = [];
  vi.stubGlobal("fetch", vi.fn((url: string, init?: RequestInit) => {
    const u = new URL(url, "http://x");
    const key = `${(init?.method ?? "GET").toUpperCase()} ${u.pathname}`;
    calls.push({ key, query: u.search, body: init?.body ? JSON.parse(String(init.body)) : null });
    const route = routes[key];
    return Promise.resolve(route ? route() : json(404, { detail: "Not Found" }));
  }));
  return calls;
}

const recorded = {
  "GET /api/hosts": () => json(200, hostsFixture.body),
  "GET /api/hosts/10.0.0.7/evidence": () => json(200, evidenceFixture.body),
};

describe("hosts page (recorded contract)", () => {
  it("lists hosts by risk and explains the confidence is not a probability", async () => {
    const calls = stubFetch(recorded);
    render(<HostsPage canTriage={false} />);
    expect(await screen.findByText("10.0.0.7")).toBeInTheDocument();
    expect(screen.getByText("100%")).toBeInTheDocument();
    expect(screen.getByText(/not a\s+probability/)).toBeInTheDocument();
    expect(calls[0].query).toContain("sort=risk");
  });

  it("re-queries when the order changes", async () => {
    const calls = stubFetch(recorded);
    render(<HostsPage canTriage={false} />);
    await screen.findByText("10.0.0.7");
    fireEvent.click(screen.getByRole("tab", { name: "Most recent" }));
    await waitFor(() => expect(calls.some((c) => c.query.includes("sort=last_seen"))).toBe(true));
  });

  it("shows the evidence timeline of a selected host; a viewer cannot record a verdict", async () => {
    stubFetch(recorded);
    render(<HostsPage canTriage={false} />);
    fireEvent.click(await screen.findByText("10.0.0.7"));
    expect(await screen.findByText(/Beaconing: c2 beaconing/)).toBeInTheDocument();
    expect(screen.getByText(/Anomaly model: unknown anomaly/)).toBeInTheDocument();
    expect(screen.getByText(/not record verdicts/)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Record verdict" })).not.toBeInTheDocument();
  });

  it("an analyst records a verdict with a note", async () => {
    const calls = stubFetch({ ...recorded, "POST /api/hosts/10.0.0.7/verdict": () => json(200, verdictFixture.body) });
    render(<HostsPage canTriage />);
    fireEvent.click(await screen.findByText("10.0.0.7"));
    fireEvent.change(await screen.findByLabelText("Verdict"), { target: { value: "expected" } });
    fireEvent.change(screen.getByLabelText("Note (optional)"), { target: { value: "known scanner" } });
    fireEvent.click(screen.getByRole("button", { name: "Record verdict" }));
    expect(await screen.findByText("Verdict saved")).toBeInTheDocument();
    expect(calls.find((c) => c.key.startsWith("POST"))!.body).toEqual({ verdict: "expected", note: "known scanner" });
  });

  it("a refused verdict (403) is explained, not swallowed", async () => {
    stubFetch({ ...recorded, "POST /api/hosts/10.0.0.7/verdict": () => json(403, { detail: "role lacks incidents:manage" }) });
    render(<HostsPage canTriage />);
    fireEvent.click(await screen.findByText("10.0.0.7"));
    fireEvent.click(await screen.findByRole("button", { name: "Record verdict" }));
    expect(await screen.findByText("Your role cannot record verdicts.")).toBeInTheDocument();
  });

  it("empty and error states", async () => {
    stubFetch({ "GET /api/hosts": () => json(200, { count: 0, offset: 0, items: [] }) });
    render(<HostsPage canTriage={false} />);
    expect(await screen.findByText("No host has evidence yet")).toBeInTheDocument();
    cleanup();
    stubFetch({ "GET /api/hosts": () => json(500, { detail: "internal server error" }) });
    render(<HostsPage canTriage={false} />);
    expect(await screen.findByText(/internal server error/)).toBeInTheDocument();
  });
});
