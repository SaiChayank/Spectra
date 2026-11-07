import { describe, expect, it } from "vitest";
import { resolveEndpoints } from "./endpoints";

const page = (protocol: string, host: string) => ({ protocol, host });

describe("resolveEndpoints", () => {
  it("dev server (Vite on :5173) talks to the API on :8787", () => {
    expect(resolveEndpoints({ DEV: true }, page("http:", "localhost:5173"))).toEqual({
      apiBase: "http://localhost:8787",
      wsUrl: "ws://localhost:8787/ws/events",
    });
  });

  it("a production build served by the API uses its own origin", () => {
    expect(resolveEndpoints({ DEV: false }, page("http:", "10.0.0.5:8787"))).toEqual({
      apiBase: "",
      wsUrl: "ws://10.0.0.5:8787/ws/events",
    });
  });

  it("uses wss behind HTTPS and keeps the host a proxy presented", () => {
    expect(resolveEndpoints({ DEV: false }, page("https:", "spectra.example.org"))).toEqual({
      apiBase: "",
      wsUrl: "wss://spectra.example.org/ws/events",
    });
  });

  it("explicit VITE_ overrides win in both modes", () => {
    const env = { DEV: false, VITE_API_BASE: "https://api.example", VITE_WS_URL: "wss://api.example/ws/events" };
    expect(resolveEndpoints(env, page("http:", "x:1"))).toEqual({
      apiBase: "https://api.example",
      wsUrl: "wss://api.example/ws/events",
    });
    expect(resolveEndpoints({ ...env, DEV: true }, page("http:", "x:1")).apiBase).toBe("https://api.example");
  });

  it("an empty override is treated as unset, not as a base URL", () => {
    expect(resolveEndpoints({ DEV: false, VITE_API_BASE: "" }, page("http:", "h:1")).apiBase).toBe("");
    expect(resolveEndpoints({ DEV: true, VITE_API_BASE: "" }, page("http:", "h:1")).apiBase).toBe(
      "http://localhost:8787",
    );
  });
});
