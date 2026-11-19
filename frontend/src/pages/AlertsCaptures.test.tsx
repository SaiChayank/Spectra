import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import "@testing-library/jest-dom/vitest";
import { afterEach, describe, expect, it, vi } from "vitest";
import alertsFixture from "../../contract/fixtures/GET_api_alerts.json";
import capturesFixture from "../../contract/fixtures/GET_api_captures.json";
import { ApiError, type ModelInfo, type ThreatAlert } from "../lib/api";
import AlertsPage, { scoreThreshold } from "./AlertsPage";
import CapturesPage from "./CapturesPage";

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

const model = { trained: true, contamination: 0.02, n_train: 42, n_features: 39, trained_at: "2027-01-15", threshold: 0.19 } as ModelInfo;
const alerts = alertsFixture.body.items as unknown as ThreatAlert[];
const json = (status: number, body: unknown) => new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });

describe("scoreThreshold", () => {
  it("is the 100·(1−contamination) percentile, and absent without a trained model", () => {
    expect(scoreThreshold(model)).toBe(98);
    expect(scoreThreshold({ ...model, trained: false })).toBeNull();
  });
});

describe("AlertsPage", () => {
  it("opens an alert and explains why, with score against the threshold", () => {
    render(<div className="sx"><AlertsPage alerts={alerts} loading={false} model={model} canTriage triage={vi.fn()} /></div>);
    const first = alerts.find((a) => a.status === "OPEN")!;
    fireEvent.click(screen.getAllByText(first.destination)[0].closest("tr")!);
    const drawer = screen.getByRole("dialog");
    expect(drawer.textContent).toContain(first.evidence.summary);
    expect(drawer.textContent).toContain("threshold 98");
    expect(drawer.textContent).toContain("unusual for this network");
    expect(drawer.textContent?.toLowerCase()).not.toContain("malicious");
    expect(within(drawer).getByRole("button", { name: "Acknowledge" })).toBeInTheDocument();
  });

  it("labels beacon alerts as a ranking aid", () => {
    const beacon = alerts.find((a) => a.threat_type === "C2_BEACONING")!;
    render(<div className="sx"><AlertsPage alerts={alerts} loading={false} model={model} canTriage triage={vi.fn()} /></div>);
    fireEvent.change(screen.getByLabelText("Status"), { target: { value: "any" } });
    fireEvent.click(screen.getAllByText(beacon.destination).map((e) => e.closest("tr")!).find((tr) => tr.textContent?.includes("ranking aid"))!);
    expect(within(screen.getByRole("dialog")).getByText("Ranking aid, not a proven detector")).toBeInTheDocument();
  });

  it("is read-only without incidents:manage and explains a 409", async () => {
    const triage = vi.fn().mockRejectedValue(new ApiError("alert is already resolved", 409, null));
    const { rerender } = render(<div className="sx"><AlertsPage alerts={alerts} loading={false} model={model} canTriage={false} triage={triage} /></div>);
    const first = alerts.find((a) => a.status === "OPEN")!;
    fireEvent.click(screen.getAllByText(first.destination)[0].closest("tr")!);
    expect(screen.getByText(/Read only/)).toBeInTheDocument();
    rerender(<div className="sx"><AlertsPage alerts={alerts} loading={false} model={model} canTriage triage={triage} /></div>);
    fireEvent.click(screen.getByRole("button", { name: "Acknowledge" }));
    expect(await screen.findByText(/Someone may have changed it already/)).toBeInTheDocument();
  });

  it("explains an empty list when no model is trained", () => {
    render(<div className="sx"><AlertsPage alerts={[]} loading={false} model={{ ...model, trained: false }} canTriage triage={vi.fn()} /></div>);
    expect(screen.getByText(/No model is trained/)).toBeInTheDocument();
  });
});

describe("CapturesPage", () => {
  const routes = (extra: Record<string, () => Response> = {}) => {
    const fn = vi.fn((url: string, init?: RequestInit) => {
      const key = `${(init?.method ?? "GET").toUpperCase()} ${new URL(url, "http://x").pathname}`;
      const r = extra[key] ?? ({ "GET /api/captures": () => json(200, capturesFixture.body), "GET /api/interfaces": () => json(200, { interfaces: ["eth0"] }) } as Record<string, () => Response>)[key];
      return Promise.resolve(r ? r() : json(404, { detail: "Not Found" }));
    });
    vi.stubGlobal("fetch", fn);
    return fn;
  };
  const can = (perms: string[]) => (p: string) => perms.includes(p);

  it("lists captures and offers actions only with capture:manage", async () => {
    routes();
    render(<div className="sx"><CapturesPage can={can(["read"])} capture={undefined} model={model} onChanged={vi.fn()} /></div>);
    expect(await screen.findByText("suspicious3.pcap")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /Delete capture/ })).toBeNull();
    expect(screen.getAllByText(/You do not have permission/).length).toBeGreaterThan(0);
  });

  it("warns that an unscored capture's zero detections mean nothing", async () => {
    routes({
      "POST /api/captures/4/process": () => json(200, { ...capturesFixture.body.items[0], unscored_flows: 13, detections: 0 }),
    });
    const onChanged = vi.fn();
    render(<div className="sx"><CapturesPage can={can(["read", "capture:manage", "model:manage"])} capture={undefined} model={{ ...model, trained: false }} onChanged={onChanged} /></div>);
    fireEvent.click(await screen.findByRole("button", { name: "Process capture 4" }));
    expect(await screen.findByText(/13 are unscored because no model is trained/)).toBeInTheDocument();
    await waitFor(() => expect(onChanged).toHaveBeenCalled());
  });

  it("waits for background processing before reporting counts (real backend answers PROCESSING first)", async () => {
    let polls = 0;
    routes({
      "POST /api/captures/4/process": () => json(200, { ...capturesFixture.body.items[0], status: "PROCESSING", running: true, flows: 0, detections: 0 }),
      "GET /api/captures/4": () =>
        json(200, ++polls < 2 ? { ...capturesFixture.body.items[0], status: "PROCESSING", running: true, flows: 5 } : { ...capturesFixture.body.items[0], status: "COMPLETED", running: false, flows: 13, detections: 1 }),
    });
    render(<div className="sx"><CapturesPage can={can(["read", "capture:manage"])} capture={undefined} model={model} onChanged={vi.fn()} /></div>);
    fireEvent.click(await screen.findByRole("button", { name: "Process capture 4" }));
    expect(await screen.findByText(/Processed #4: 13 flows, 1 above the threshold/, undefined, { timeout: 5000 })).toBeInTheDocument();
  });

  it("shows a live capture error prominently", async () => {
    routes();
    render(
      <div className="sx">
        <CapturesPage can={can(["read", "capture:manage"])} capture={{ running: false, mode: "live", source: "eth0", packets: 0, flows: 0, detections: 0, started_at: null, error: "permission denied: eth0", model_trained: true }} model={model} onChanged={vi.fn()} />
      </div>,
    );
    expect(await screen.findByText(/permission denied: eth0/)).toBeInTheDocument();
  });
});
