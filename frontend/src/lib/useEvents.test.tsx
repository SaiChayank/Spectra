import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { act, cleanup, renderHook } from "@testing-library/react";
import "@testing-library/jest-dom/vitest";
import { WS_URL } from "./api";
import { useEvents } from "./useEvents";

/** Minimal stand-in for the browser WebSocket: the test drives open/close. */
class FakeSocket {
  static instances: FakeSocket[] = [];
  url: string;
  closed = false;
  onopen: (() => void) | null = null;
  onclose: (() => void) | null = null;
  onerror: (() => void) | null = null;
  onmessage: ((msg: { data: string }) => void) | null = null;

  constructor(url: string) {
    this.url = url;
    FakeSocket.instances.push(this);
  }

  close() {
    this.closed = true;
    this.onclose?.();
  }
}

beforeEach(() => {
  FakeSocket.instances = [];
  vi.useFakeTimers();
  vi.stubGlobal("WebSocket", FakeSocket);
});

afterEach(() => {
  cleanup();
  vi.useRealTimers();
  vi.unstubAllGlobals();
});

describe("useEvents", () => {
  it("connects to the event stream when enabled", () => {
    const { result } = renderHook(() => useEvents(() => {}, true));
    expect(FakeSocket.instances).toHaveLength(1);
    expect(FakeSocket.instances[0].url).toBe(WS_URL);
    expect(result.current).toBe(false);

    act(() => FakeSocket.instances[0].onopen?.());
    expect(result.current).toBe(true);
  });

  it("does not connect while disabled", () => {
    renderHook(() => useEvents(() => {}, false));
    expect(FakeSocket.instances).toHaveLength(0);
  });

  it("reconnects 1.5 s after the server closes the socket", () => {
    const { result } = renderHook(() => useEvents(() => {}, true));
    act(() => FakeSocket.instances[0].onopen?.());
    expect(result.current).toBe(true);

    // The server drops the connection (not our own close).
    act(() => FakeSocket.instances[0].onclose?.());
    expect(result.current).toBe(false);
    expect(FakeSocket.instances).toHaveLength(1);

    act(() => vi.advanceTimersByTime(1499));
    expect(FakeSocket.instances).toHaveLength(1);

    act(() => vi.advanceTimersByTime(1));
    expect(FakeSocket.instances).toHaveLength(2);
  });

  it("cleanup closes the socket and stops retrying", () => {
    const { unmount } = renderHook(() => useEvents(() => {}, true));
    const first = FakeSocket.instances[0];

    unmount();
    expect(first.closed).toBe(true);

    act(() => vi.advanceTimersByTime(10_000));
    expect(FakeSocket.instances).toHaveLength(1);
  });
});
