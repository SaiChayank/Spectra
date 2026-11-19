import { act, cleanup, fireEvent, render, screen, within } from "@testing-library/react";
import { useState } from "react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { contrast } from "../../lib/contrast";
import { compareValues, DataTable, type Column } from "./DataTable";
import { PasswordInput, SkewButton, SkewTabs, Toggle } from "./controls";
import { ScoreMeter, SeverityBadge, TimeValue, formatUtc } from "./display";
import { EmptyState, PermissionDenied, StorageBanner, UntrainedBanner } from "./feedback";
import { ConfirmDialog } from "./overlays";

afterEach(() => {
  cleanup(); // no vitest globals, so Testing Library cannot register this itself
  vi.useRealTimers();
});

interface Row {
  id: number;
  name: string;
  score: number | null;
}
const rows: Row[] = Array.from({ length: 60 }, (_, i) => ({ id: i + 1, name: `host-${i + 1}`, score: i % 10 === 0 ? null : i }));
const cols: Column<Row>[] = [
  { key: "name", header: "Name", sort: (r) => r.name },
  { key: "score", header: "Score", sort: (r) => r.score, render: (r) => String(r.score ?? "—") },
];

describe("DataTable", () => {
  it("paginates, sorts by header and reports aria-sort", () => {
    render(<DataTable caption="Hosts" columns={cols} rows={rows} rowKey={(r) => r.id} pageSize={10} />);
    expect(screen.getAllByRole("row")).toHaveLength(11); // header + 10
    expect(screen.getByText("1 / 6")).toBeTruthy();

    fireEvent.click(screen.getByRole("button", { name: /Score/ }));
    const header = screen.getByRole("columnheader", { name: /Score/ });
    expect(header.getAttribute("aria-sort")).toBe("ascending");
    const firstCell = within(screen.getAllByRole("row")[1]).getAllByRole("cell")[1];
    expect(firstCell.textContent).toBe("1");

    fireEvent.click(screen.getByRole("button", { name: /Score/ }));
    expect(header.getAttribute("aria-sort")).toBe("descending");
    fireEvent.click(screen.getByRole("button", { name: "Next" }));
    expect(screen.getByText("2 / 6")).toBeTruthy();
  });

  it("windows long lists in virtual mode", () => {
    const many = Array.from({ length: 5000 }, (_, i) => ({ id: i, name: `h${i}`, score: i }));
    render(<DataTable caption="Many" columns={cols} rows={many} rowKey={(r) => r.id} virtual maxHeight={380} />);
    expect(screen.getAllByRole("row").length).toBeLessThan(60);
    expect(screen.getByText("5,000 rows")).toBeTruthy();
  });

  it("shows empty, loading and error states", () => {
    const { rerender } = render(<DataTable caption="Alerts" columns={cols} rows={[]} rowKey={(r) => r.id} empty={{ title: "No alerts yet" }} />);
    expect(screen.getByText("No alerts yet")).toBeTruthy();
    rerender(<DataTable caption="Alerts" columns={cols} rows={null} loading rowKey={(r) => r.id} />);
    expect(screen.getByText("Loading Alerts…")).toBeTruthy();
    rerender(<DataTable caption="Alerts" columns={cols} rows={null} error="boom" rowKey={(r) => r.id} />);
    expect(screen.getByRole("alert").textContent).toContain("boom");
  });

  it("opens a row with the keyboard", () => {
    const onRow = vi.fn();
    render(<DataTable caption="Hosts" columns={cols} rows={rows.slice(0, 3)} rowKey={(r) => r.id} onRowClick={onRow} />);
    fireEvent.keyDown(screen.getAllByRole("row")[1], { key: "Enter" });
    expect(onRow).toHaveBeenCalledWith(rows[0]);
  });

  it("sorts blanks last and numbers numerically", () => {
    expect([3, null, 10, 2].sort(compareValues)).toEqual([2, 3, 10, null]);
    expect(["a10", "a2"].sort(compareValues)).toEqual(["a2", "a10"]);
  });
});

describe("controls", () => {
  it("moves between tabs with arrow keys and skips disabled tabs", () => {
    function Harness() {
      const [v, setV] = useState<"a" | "b" | "c">("a");
      return (
        <SkewTabs
          label="t"
          value={v}
          onChange={setV}
          items={[
            { id: "a", label: "A" },
            { id: "b", label: "B", disabled: true },
            { id: "c", label: "C" },
          ]}
        />
      );
    }
    render(<Harness />);
    fireEvent.keyDown(screen.getByRole("tab", { name: "A" }), { key: "ArrowRight" });
    expect(screen.getByRole("tab", { name: "C" }).getAttribute("aria-selected")).toBe("true");
  });

  it("reveals and hides the password", () => {
    render(<PasswordInput label="Password" />);
    const input = screen.getByLabelText("Password") as HTMLInputElement;
    expect(input.type).toBe("password");
    fireEvent.click(screen.getByRole("button", { name: /show password/i }));
    expect(input.type).toBe("text");
  });

  it("disables a loading button and marks it busy", () => {
    render(<SkewButton loading>Save</SkewButton>);
    const b = screen.getByRole("button", { name: "Save" });
    expect(b).toHaveProperty("disabled", true);
    expect(b.getAttribute("aria-busy")).toBe("true");
  });

  it("toggle is a switch with state", () => {
    const fn = vi.fn();
    render(<Toggle label="Beacon" checked={false} onChange={fn} />);
    fireEvent.click(screen.getByRole("switch", { name: "Beacon" }));
    expect(fn).toHaveBeenCalledWith(true);
  });
});

describe("honest display", () => {
  it("always states the threshold and never calls a flow malicious", () => {
    const { container } = render(<ScoreMeter score={97} threshold={90} />);
    expect(container.textContent).toContain("threshold 90");
    expect(container.textContent).toContain("unusual for this network");
    expect(container.textContent?.toLowerCase()).not.toContain("malicious");
    expect(screen.getByRole("meter").getAttribute("aria-valuetext")).toContain("above threshold");
  });

  it("shows unscored instead of a number when there is no score", () => {
    render(<ScoreMeter score={null} threshold={90} />);
    expect(screen.getByText("Unscored")).toBeTruthy();
  });

  it("severity badge carries text, not only colour", () => {
    render(<SeverityBadge level="high" />);
    expect(screen.getByText("HIGH")).toBeTruthy();
  });

  it("time shows local and exposes UTC", () => {
    render(<TimeValue ts={1800000000} />);
    expect(screen.getByRole("tooltip", { hidden: true }).textContent).toBe(formatUtc(1800000000));
    expect(formatUtc(1800000000)).toBe("2027-01-15 08:00:00 UTC");
  });

  it("untrained banner offers training only with the permission", () => {
    const { rerender } = render(<UntrainedBanner canTrain onTrain={() => {}} />);
    expect(screen.getByRole("button", { name: "Train a baseline" })).toBeTruthy();
    rerender(<UntrainedBanner canTrain={false} />);
    expect(screen.queryByRole("button")).toBeNull();
    expect(screen.getByText(/Ask an administrator/)).toBeTruthy();
  });

  it("permission denied names the permission", () => {
    render(<PermissionDenied permission="incidents:manage" what="acknowledge alerts" />);
    expect(screen.getByText("incidents:manage")).toBeTruthy();
  });

  it("empty state renders its title", () => {
    render(<EmptyState title="No flows yet" />);
    expect(screen.getByText("No flows yet")).toBeTruthy();
  });
});

describe("feedback timing", () => {
  it("storage banner counts down from Retry-After and retries once", () => {
    vi.useFakeTimers();
    const retry = vi.fn();
    render(<StorageBanner retryAfter={3} onRetry={retry} />);
    expect(screen.getByText(/Retrying in 3 s/)).toBeTruthy();
    act(() => vi.advanceTimersByTime(1000));
    expect(screen.getByText(/Retrying in 2 s/)).toBeTruthy();
    // one second per step: each tick is scheduled by an effect after the previous render
    act(() => vi.advanceTimersByTime(1000));
    act(() => vi.advanceTimersByTime(1000));
    expect(screen.getByText(/Retrying now/)).toBeTruthy();
    expect(retry).toHaveBeenCalledTimes(1);
  });
});

describe("ConfirmDialog", () => {
  it("spells out the consequence, focuses Cancel and closes on Escape", () => {
    const cancel = vi.fn();
    render(
      <div className="sx">
        <ConfirmDialog open title="Rotate the audit key?" consequence="Old proofs stay valid." confirmLabel="Rotate" onConfirm={() => {}} onCancel={cancel} />
      </div>,
    );
    expect(screen.getByRole("dialog").textContent).toContain("What happens: Old proofs stay valid.");
    expect(document.activeElement?.textContent).toBe("Cancel");
    fireEvent.keyDown(document, { key: "Escape" });
    expect(cancel).toHaveBeenCalled();
  });
});

describe("contrast tokens", () => {
  it("text tokens meet AA on every surface", () => {
    // measured tokens (src/styles/tokens.css): bg-0, bg-1, surface-1..3 x text-1..3, blue-400, gold
    for (const surface of ["#000000", "#0A0B0D", "#111214", "#17181D", "#202227"]) {
      for (const text of ["#F5F5F5", "#A3A3A6", "#8E8E93", "#5DA2F7", "#D2A970"]) {
        expect(contrast(text, surface)).toBeGreaterThanOrEqual(4.5);
      }
    }
  });
});
