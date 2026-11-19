/**
 * Dev-only stand-in for the browser WebSocket on `/ws/events`: replays the
 * recorded `ws_events.json` frames on a timer and can be dropped on demand
 * so the reconnect logic in `useEvents` is exercised.
 */

type Listener = (ev: Event) => void;

export interface SocketControl {
  /** Is anyone signed in? The real server refuses the handshake otherwise. */
  signedIn: () => boolean;
  frames: unknown[];
  intervalMs: number;
}

const open = new Set<MockWebSocket>();
let control: SocketControl = { signedIn: () => false, frames: [], intervalMs: 1500 };

export function configureSocket(c: SocketControl) {
  control = c;
}

/** Close every open mock socket (as if the server restarted). */
export function dropAllSockets() {
  for (const s of [...open]) s.serverClose(1012, "mock: simulated disconnect");
}

export class MockWebSocket extends EventTarget {
  static readonly CONNECTING = 0;
  static readonly OPEN = 1;
  static readonly CLOSING = 2;
  static readonly CLOSED = 3;

  readonly url: string;
  readyState = MockWebSocket.CONNECTING;
  onopen: Listener | null = null;
  onclose: ((ev: CloseEvent) => void) | null = null;
  onerror: Listener | null = null;
  onmessage: ((ev: MessageEvent) => void) | null = null;
  private timer: ReturnType<typeof setInterval> | undefined;
  private cursor = 0;

  constructor(url: string | URL) {
    super();
    this.url = String(url);
    setTimeout(() => {
      if (this.readyState !== MockWebSocket.CONNECTING) return;
      if (!control.signedIn()) {
        this.fire("error", new Event("error"));
        this.serverClose(1008, "not authenticated");
        return;
      }
      this.readyState = MockWebSocket.OPEN;
      open.add(this);
      this.fire("open", new Event("open"));
      this.timer = setInterval(() => this.tick(), control.intervalMs);
    }, 150);
  }

  private tick() {
    if (!control.signedIn()) return this.serverClose(1008, "session ended");
    if (control.frames.length === 0) return;
    const frame = control.frames[this.cursor % control.frames.length];
    this.cursor += 1;
    this.fire("message", new MessageEvent("message", { data: JSON.stringify(frame) }));
  }

  private fire(type: "open" | "error" | "message" | "close", ev: Event) {
    const handler = (this as unknown as Record<string, ((e: Event) => void) | null>)[`on${type}`];
    handler?.call(this, ev);
    this.dispatchEvent(ev);
  }

  serverClose(code: number, reason: string) {
    if (this.readyState === MockWebSocket.CLOSED) return;
    clearInterval(this.timer);
    open.delete(this);
    this.readyState = MockWebSocket.CLOSED;
    this.fire("close", new CloseEvent("close", { code, reason, wasClean: code === 1000 }));
  }

  send() {
    /* the events socket is server-to-client only */
  }

  close(code = 1000, reason = "") {
    this.serverClose(code, reason);
  }
}
