import { useEffect, useState } from "react";

export interface ConnectionState {
  /** Seconds to wait from the last 503 (Retry-After), with a key that changes per outage. */
  storage: { retryAfter: number; key: number } | null;
  /** The last request could not reach the server at all. */
  offline: boolean;
}

/**
 * Listens for the app-wide signals `request()` in lib/api.ts dispatches and
 * turns them into banner state. Any successful answer clears "offline";
 * a storage outage clears when its countdown ends and the retry succeeds.
 */
export function useConnection(): [ConnectionState, () => void] {
  const [state, setState] = useState<ConnectionState>({ storage: null, offline: false });

  useEffect(() => {
    const onStorage = (e: Event) => {
      const retryAfter = Number((e as CustomEvent).detail) || 10;
      // keep one countdown per outage: repeated 503s while it runs do not restart it
      setState((s) => (s.storage ? s : { ...s, storage: { retryAfter, key: Date.now() } }));
    };
    const onOffline = () => setState((s) => (s.offline ? s : { ...s, offline: true }));
    const onOnline = () => setState((s) => (s.offline ? { ...s, offline: false } : s));
    window.addEventListener("spectra:storage", onStorage);
    window.addEventListener("spectra:offline", onOffline);
    window.addEventListener("spectra:online", onOnline);
    return () => {
      window.removeEventListener("spectra:storage", onStorage);
      window.removeEventListener("spectra:offline", onOffline);
      window.removeEventListener("spectra:online", onOnline);
    };
  }, []);

  const clearStorage = () => setState((s) => ({ ...s, storage: null }));
  return [state, clearStorage];
}
