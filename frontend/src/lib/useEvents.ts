import { useEffect, useRef, useState } from "react";
import { WS_URL, type WsEvent } from "../lib/api";

/**
 * Connects to the backend event stream; reconnects if the API restarts.
 * The handshake rides the HttpOnly session cookie — only connects while
 * signed in (`enabled`), so an expired session never spin-retries.
 */
export function useEvents(onEvent: (event: WsEvent) => void, enabled = true) {
  const handler = useRef(onEvent);
  handler.current = onEvent;
  const [connected, setConnected] = useState(false);

  useEffect(() => {
    if (!enabled) {
      setConnected(false);
      return;
    }
    let ws: WebSocket | null = null;
    let closed = false;
    let retry: ReturnType<typeof setTimeout>;

    const connect = () => {
      ws = new WebSocket(WS_URL);
      ws.onopen = () => setConnected(true);
      ws.onclose = () => {
        setConnected(false);
        if (!closed) retry = setTimeout(connect, 1500);
      };
      ws.onerror = () => ws?.close();
      ws.onmessage = (msg) => {
        try {
          handler.current(JSON.parse(msg.data) as WsEvent);
        } catch {
          /* ignore malformed frames */
        }
      };
    };

    connect();
    return () => {
      closed = true;
      clearTimeout(retry);
      ws?.close();
    };
  }, [enabled]);

  return connected;
}
