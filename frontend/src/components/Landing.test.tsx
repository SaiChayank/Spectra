import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import capabilityExport from "../../contract/fixtures/GET_api_capabilities.json";
import Landing from "./Landing";

// jsdom has no IntersectionObserver (used by scroll-reveal); report everything as visible
beforeEach(() => {
  class IO {
    cb: IntersectionObserverCallback;
    constructor(cb: IntersectionObserverCallback) {
      this.cb = cb;
    }
    observe(el: Element) {
      this.cb([{ isIntersecting: true, target: el, intersectionRatio: 1 } as IntersectionObserverEntry], this as unknown as IntersectionObserver);
    }
    unobserve() {}
    disconnect() {}
    takeRecords() {
      return [];
    }
  }
  vi.stubGlobal("IntersectionObserver", IO);
});

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

describe("Landing", () => {
  it("makes no API calls (signed-out pages stay silent)", () => {
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);
    render(<Landing />);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("shows every module with its real maturity from the contract export", () => {
    render(<Landing />);
    const modules = Object.values(capabilityExport.body.modules) as { title: string; status: string }[];
    for (const m of modules) {
      // the strip repeats its tiles for a seamless marquee; the visible (first) copy carries the status
      const tile = screen.getAllByText(m.title)[0].closest("li")!;
      expect(tile.textContent).toContain(m.status.replace("_", " "));
    }
  });

  it("is honest: states detector weakness, no marketing claims, never calls traffic malicious", () => {
    const { container } = render(<Landing />);
    const text = container.textContent!.toLowerCase();
    expect(text).toContain("not a reliable attack detector yet");
    expect(text).toContain("unusual for this network");
    for (const banned of ["malicious", "book a demo", "ai-powered", "100 %", "100%", "threat blocked"]) {
      expect(text).not.toContain(banned);
    }
  });

  it("has a single h1 and a sign-in action", () => {
    render(<Landing />);
    expect(screen.getAllByRole("heading", { level: 1 })).toHaveLength(1);
    expect(screen.getAllByRole("button", { name: /Sign in/ }).length).toBeGreaterThan(0);
  });
});
