import { act, cleanup, fireEvent, render, renderHook, screen, within } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { ApiError, NetworkError, api, parseRetryAfter, type Identity } from "../lib/api";
import { parseHash } from "../lib/router";
import Shell from "./Shell";
import { useConnection } from "./useConnection";

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

const viewer: Identity = {
  expires_at: 1800043200,
  user: { id: 2, username: "viewer", role: "VIEWER", permissions: ["read"] },
};

function renderShell(identity = viewer, section: Parameters<typeof Shell>[0]["section"] = "overview") {
  const can = (p: string) => identity.user.permissions.includes(p);
  const onSignOut = vi.fn();
  render(
    <Shell
      identity={identity}
      section={section}
      module={null}
      title="Overview"
      can={can}
      capture={undefined}
      model={{ trained: false } as never}
      live="reconnecting"
      onSignOut={onSignOut}
    >
      <p>page body</p>
    </Shell>,
  );
  return { onSignOut };
}

describe("router", () => {
  it("parses sections, incident deep links and experimental modules", () => {
    expect(parseHash("")).toEqual({ kind: "landing" });
    expect(parseHash("#/login")).toEqual({ kind: "login" });
    expect(parseHash("#/incidents/12")).toMatchObject({ section: "incidents", incidentId: 12 });
    expect(parseHash("#/experimental/tee")).toMatchObject({ section: "experimental", module: "tee" });
    expect(parseHash("#/modules")).toMatchObject({ section: "experimental", module: null });
    expect(parseHash("#/hosts")).toMatchObject({ section: "hosts" });
    expect(parseHash("#/nope")).toEqual({ kind: "landing" });
  });
});

describe("api client signals", () => {
  it("parses Retry-After seconds and ignores junk", () => {
    expect(parseRetryAfter("10")).toBe(10);
    expect(parseRetryAfter(" 2.5 ")).toBe(3);
    expect(parseRetryAfter("Wed, 21 Oct 2026 07:28:00 GMT")).toBeNull();
    expect(parseRetryAfter(null)).toBeNull();
  });

  it("raises ApiError with status and Retry-After, and signals a storage outage on 503", async () => {
    vi.spyOn(window, "fetch").mockResolvedValue(
      new Response(JSON.stringify({ detail: "storage temporarily unavailable" }), {
        status: 503,
        headers: { "content-type": "application/json", "retry-after": "7" },
      }),
    );
    const seen = vi.fn();
    window.addEventListener("spectra:storage", seen);
    const err = await api.stats().catch((e: unknown) => e);
    window.removeEventListener("spectra:storage", seen);
    expect(err).toBeInstanceOf(ApiError);
    expect((err as ApiError).status).toBe(503);
    expect((err as ApiError).retryAfter).toBe(7);
    expect((err as ApiError).message).toBe("storage temporarily unavailable");
    expect((seen.mock.calls[0][0] as CustomEvent).detail).toBe(7);
  });

  it("raises NetworkError and signals offline when the server cannot be reached", async () => {
    vi.spyOn(window, "fetch").mockRejectedValue(new TypeError("Failed to fetch"));
    const seen = vi.fn();
    window.addEventListener("spectra:offline", seen);
    const err = await api.stats().catch((e: unknown) => e);
    window.removeEventListener("spectra:offline", seen);
    expect(err).toBeInstanceOf(NetworkError);
    expect(seen).toHaveBeenCalledOnce();
  });

  it("keeps 403 as an ApiError the page can show inline", async () => {
    vi.spyOn(window, "fetch").mockResolvedValue(
      new Response(JSON.stringify({ detail: "role VIEWER lacks the 'users:manage' permission" }), { status: 403 }),
    );
    const err = (await api.stats().catch((e: unknown) => e)) as ApiError;
    expect(err.status).toBe(403);
    expect(err.retryAfter).toBeNull();
  });
});

describe("useConnection", () => {
  it("tracks offline/online and one storage countdown per outage", () => {
    const { result } = renderHook(() => useConnection());
    act(() => {
      window.dispatchEvent(new CustomEvent("spectra:offline"));
    });
    expect(result.current[0].offline).toBe(true);
    act(() => {
      window.dispatchEvent(new CustomEvent("spectra:online"));
    });
    expect(result.current[0].offline).toBe(false);

    act(() => {
      window.dispatchEvent(new CustomEvent("spectra:storage", { detail: 5 }));
    });
    const first = result.current[0].storage;
    expect(first?.retryAfter).toBe(5);
    act(() => {
      window.dispatchEvent(new CustomEvent("spectra:storage", { detail: 30 }));
    });
    expect(result.current[0].storage).toBe(first); // a running countdown is not restarted
    act(() => result.current[1]());
    expect(result.current[0].storage).toBeNull();
  });
});

describe("Shell", () => {
  it("marks the current page, restricted sections and planned ones", () => {
    renderShell(viewer, "overview");
    const nav = screen.getAllByRole("navigation", { name: "Console sections" })[0];
    expect(within(nav).getByRole("link", { name: /Overview/ }).getAttribute("aria-current")).toBe("page");
    // a viewer lacks `investigate`: gated sections say so in text
    expect(within(nav).getByRole("link", { name: /Alerts & Incidents.*restricted/i })).toBeTruthy();
    expect(within(nav).getByRole("link", { name: /Hosts.*planned/i })).toBeTruthy();
    expect(within(nav).getAllByRole("link", { name: /simulated/i })).toHaveLength(5);
  });

  it("shows status as text, the role, and signs out", () => {
    const { onSignOut } = renderShell();
    expect(screen.getByText("No model")).toBeTruthy();
    expect(screen.getByText("Reconnecting")).toBeTruthy();
    expect(screen.getByText("VIEWER")).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Sign out" }));
    expect(onSignOut).toHaveBeenCalled();
  });

  it("collapses the sidebar and remembers it as a UI preference", () => {
    renderShell();
    fireEvent.click(screen.getByRole("button", { name: "Collapse sidebar" }));
    expect(screen.getByRole("button", { name: "Expand sidebar" })).toBeTruthy();
    expect(localStorage.getItem("spectra-ui-sidebar-collapsed")).toBe("1");
    localStorage.removeItem("spectra-ui-sidebar-collapsed");
  });

  it("has a skip link to the main content", () => {
    renderShell();
    expect(screen.getByRole("link", { name: "Skip to content" }).getAttribute("href")).toBe("#sx-main");
  });
});
