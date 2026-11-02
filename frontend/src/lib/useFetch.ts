import { useCallback, useEffect, useRef, useState } from "react";

interface Options {
  /** Skip the fetch entirely (e.g. permission gate known client-side). */
  enabled?: boolean;
  /** Poll interval in ms (0 = fetch once; reload() always works). */
  intervalMs?: number;
}

/**
 * One fetch lifecycle per dependency set: `loading` on the first load,
 * `error` instead of stale data on failure, `reload()` to refetch.
 *
 * `deps` are the query inputs — changing one refetches; `intervalMs`
 * keeps a section fresh without re-running every render.
 */
export function useFetch<T>(
  fetcher: () => Promise<T>,
  deps: readonly unknown[],
  { enabled = true, intervalMs = 0 }: Options = {},
): {
  data: T | null;
  error: string | null;
  loading: boolean;
  reload: () => void;
} {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(enabled);
  const [nonce, setNonce] = useState(0);
  const fetcherRef = useRef(fetcher);
  fetcherRef.current = fetcher;

  useEffect(() => {
    if (!enabled) {
      setLoading(false);
      return;
    }
    let cancelled = false;
    setLoading(true);

    const run = () =>
      fetcherRef
        .current()
        .then((value) => {
          if (!cancelled) {
            setData(value);
            setError(null);
          }
        })
        .catch((err: unknown) => {
          if (!cancelled) {
            setError(err instanceof Error ? err.message : String(err));
          }
        })
        .finally(() => {
          if (!cancelled) setLoading(false);
        });

    run();
    const timer = intervalMs > 0 ? setInterval(run, intervalMs) : null;
    return () => {
      cancelled = true;
      if (timer) clearInterval(timer);
    };
    // deps + nonce are the declared inputs; fetcher rides a ref.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [...deps, nonce, enabled, intervalMs]);

  const reload = useCallback(() => setNonce((n) => n + 1), []);
  return { data, error, loading, reload };
}
