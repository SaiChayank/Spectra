/**
 * Mock mode (`npm run dev:mock`): serves the recorded contract fixtures in
 * place of the backend by patching `fetch` and `WebSocket`. Imported only
 * behind `import.meta.env.DEV && VITE_MOCK`, so it never reaches a build.
 */
import { useState } from "react";
import { createRoot } from "react-dom/client";
import { FixtureIndex, SCENARIOS, resolve, type Fixture, type MockState, type Scenario } from "./resolve";
import { MockWebSocket, configureSocket, dropAllSockets } from "./socket";

const raw = import.meta.glob("../../contract/fixtures/*.json", { eager: true, import: "default" }) as Record<
  string,
  Omit<Fixture, "name"> & { messages?: unknown[] }
>;

const fixtures: Fixture[] = [];
let wsFrames: unknown[] = [];
for (const [file, data] of Object.entries(raw)) {
  const name = file.split("/").pop()!.replace(/\.json$/, "");
  if (name === "ws_events") wsFrames = data.messages ?? [];
  else fixtures.push({ ...data, name });
}
const index = new FixtureIndex(fixtures);

// Mock state is dev-only UI state (scenario + which demo role is signed in), never flow data.
const KEY = "spectra-mock-state";
function load(): MockState {
  try {
    const s = JSON.parse(sessionStorage.getItem(KEY) ?? "");
    if (s && typeof s.scenario === "string") return s;
  } catch {
    /* first run */
  }
  return { scenario: "normal", role: null, loginFixture: null, since: 0 };
}
let state = load();
const listeners = new Set<() => void>();
function setState(patch: Partial<MockState>) {
  state = { ...state, ...patch };
  try {
    sessionStorage.setItem(KEY, JSON.stringify(state));
  } catch {
    /* storage blocked: state lives for this page only */
  }
  listeners.forEach((l) => l());
}

async function readBody(init?: RequestInit): Promise<unknown> {
  const body = init?.body;
  if (body == null) return null;
  if (typeof body === "string") {
    try {
      return JSON.parse(body);
    } catch {
      return body;
    }
  }
  return "<binary>"; // multipart uploads: the mock never reads file contents
}

export function installMocks() {
  const realFetch = window.fetch.bind(window);

  window.fetch = async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = new URL(input instanceof Request ? input.url : String(input), window.location.href);
    if (!url.pathname.startsWith("/api/")) return realFetch(input, init);
    const method = (init?.method ?? (input instanceof Request ? input.method : "GET")).toUpperCase();
    const query = Object.fromEntries(url.searchParams.entries());
    const res = resolve(index, state, { method, path: url.pathname, query, body: await readBody(init) }, Date.now());
    if (res.next) setState(res.next);
    if (res.status >= 400) console.info(`[mock] ${method} ${url.pathname} -> ${res.status}`, res.body);
    await new Promise((r) => setTimeout(r, 120)); // let loading states render
    return new Response(JSON.stringify(res.body), { status: res.status, headers: res.headers });
  };

  configureSocket({ signedIn: () => state.role !== null, frames: wsFrames, intervalMs: 1500 });
  window.WebSocket = MockWebSocket as unknown as typeof WebSocket;

  const host = document.createElement("div");
  host.id = "mock-panel";
  document.body.appendChild(host);
  createRoot(host).render(<MockPanel />);
  console.info(`[mock] mock mode: ${fixtures.length} fixtures, ${wsFrames.length} WebSocket frames`);
}

function MockPanel() {
  const [, force] = useState(0);
  const [open, setOpen] = useState(false);
  useState(() => listeners.add(() => force((n) => n + 1)));

  const box: React.CSSProperties = {
    position: "fixed",
    right: 12,
    bottom: 12,
    zIndex: 9999,
    font: "12px system-ui, sans-serif",
    background: "#1d1d1f",
    color: "#f5f5f7",
    border: "1px solid #444",
    borderRadius: 8,
    padding: open ? 12 : 0,
    maxWidth: 300,
  };
  if (!open) {
    return (
      <div style={box}>
        <button type="button" onClick={() => setOpen(true)} style={{ padding: "6px 10px" }}>
          Mock: {state.scenario}
        </button>
      </div>
    );
  }
  return (
    <div style={box} role="region" aria-label="Mock backend controls">
      <strong>Mock backend</strong> (fixtures, not a real server)
      <label style={{ display: "block", marginTop: 8 }}>
        Scenario
        <select
          value={state.scenario}
          onChange={(e) => setState({ scenario: e.target.value as Scenario, since: Date.now() })}
          style={{ display: "block", width: "100%" }}
        >
          {SCENARIOS.map((s) => (
            <option key={s.id} value={s.id}>
              {s.label}
            </option>
          ))}
        </select>
      </label>
      <p style={{ margin: "8px 0" }}>
        Signed in: {state.role ?? "nobody"}. Sign in with any password as <code>admin</code>, <code>analyst</code> or{" "}
        <code>viewer</code>; the password <code>wrong</code> fails.
      </p>
      <button type="button" onClick={dropAllSockets}>
        Drop WebSocket
      </button>{" "}
      <button type="button" onClick={() => location.reload()}>
        Reload
      </button>{" "}
      <button type="button" onClick={() => setOpen(false)}>
        Hide
      </button>
    </div>
  );
}
