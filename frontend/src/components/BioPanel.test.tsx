import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, render, screen, waitFor } from "@testing-library/react";
import "@testing-library/jest-dom/vitest";
import BioPanel from "./BioPanel";

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

describe("BioPanel", () => {
  it("shows the loading state until the first status arrives", () => {
    vi.stubGlobal("fetch", vi.fn(() => new Promise<Response>(() => {})));
    render(<BioPanel onError={() => {}} />);
    expect(screen.getByText("Loading immune layer…")).toBeInTheDocument();
  });

  it("shows the empty state when the bio layer is unavailable", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(jsonResponse({ available: false })));
    render(<BioPanel onError={() => {}} />);
    expect(await screen.findByText(/Bio layer unavailable/)).toBeInTheDocument();
  });

  it("reports a failed load through onError and keeps the loading state", async () => {
    vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new Error("Backend unreachable")));
    const onError = vi.fn();
    render(<BioPanel onError={onError} />);
    await waitFor(() => expect(onError).toHaveBeenCalledWith("Backend unreachable"));
    expect(screen.getByText("Loading immune layer…")).toBeInTheDocument();
  });
});
