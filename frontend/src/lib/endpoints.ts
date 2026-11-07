/**
 * Where the dashboard finds the API and its event WebSocket.
 *
 * - `vite dev` serves the page on :5173, so the API is cross-origin on :8787.
 * - A production build is served by the API itself (`spectra serve`), so it
 *   uses its own origin: relative REST paths and a WebSocket on the same host,
 *   `wss` when the page is HTTPS (e.g. behind a TLS terminator).
 * - `VITE_API_BASE` / `VITE_WS_URL` override either default (empty = unset).
 */
export interface EndpointEnv {
  DEV: boolean;
  VITE_API_BASE?: string;
  VITE_WS_URL?: string;
}

export function resolveEndpoints(
  env: EndpointEnv,
  page: { protocol: string; host: string },
): { apiBase: string; wsUrl: string } {
  const apiBase = env.VITE_API_BASE || (env.DEV ? "http://localhost:8787" : "");
  const sameOriginWs = `${page.protocol === "https:" ? "wss" : "ws"}://${page.host}/ws/events`;
  const wsUrl = env.VITE_WS_URL || (env.DEV ? "ws://localhost:8787/ws/events" : sameOriginWs);
  return { apiBase, wsUrl };
}
