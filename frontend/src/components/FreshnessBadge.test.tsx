import { afterEach, describe, expect, it } from "vitest";
import { cleanup, render, screen } from "@testing-library/react";
import "@testing-library/jest-dom/vitest";
import FreshnessBadge, { describeFreshness, formatLag } from "./FreshnessBadge";

afterEach(cleanup);

describe("FreshnessBadge", () => {
  it("formats lag coarsely", () => {
    expect(formatLag(45)).toBe("45 s");
    expect(formatLag(600)).toBe("10 min");
    expect(formatLag(7200)).toBe("2.0 h");
  });

  it("calls a lagging graph stale and says how to refresh it", () => {
    const f = { hydrated_at: 1_700_000_000, flow_lag: 900, stale: true };
    expect(describeFreshness(f).tone).toBe("high");
    render(<FreshnessBadge freshness={f} />);
    expect(screen.getByRole("status")).toHaveTextContent("stale · 15 min behind");
    expect(screen.getByRole("status").parentElement).toHaveAttribute(
      "title",
      expect.stringContaining("re-reads stored history"),
    );
  });

  it("distinguishes up to date, slightly behind, and unknown", () => {
    expect(describeFreshness({ hydrated_at: 1, flow_lag: 0, stale: false }).label).toBe(
      "up to date",
    );
    expect(describeFreshness({ hydrated_at: 1, flow_lag: 30, stale: false }).tone).toBe(
      "mid",
    );
    const unknown = describeFreshness({ hydrated_at: null, flow_lag: null, stale: false });
    expect(unknown.label).toBe("freshness unknown");
    render(<FreshnessBadge freshness={{ hydrated_at: null, flow_lag: null, stale: false }} />);
    expect(screen.queryByText(/loaded from history/)).not.toBeInTheDocument();
  });
});
