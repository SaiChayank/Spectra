import { useEffect, useState, type CSSProperties, type ReactNode } from "react";
import { SignalField } from "./art";
import { SkewButton } from "./controls";

/* -- Banner ---------------------------------------------------------------------- */

export type BannerTone = "info" | "warn" | "error" | "untrained" | "storage";

const BANNER_COLOUR: Record<BannerTone, string> = {
  info: "var(--blue-400)",
  warn: "var(--warn)",
  error: "var(--error)",
  untrained: "var(--warn)",
  storage: "var(--warn)",
};

export function Banner({
  tone = "info",
  title,
  children,
  action,
}: {
  tone?: BannerTone;
  title: ReactNode;
  children?: ReactNode;
  action?: ReactNode;
}) {
  return (
    <div
      className="sx-banner"
      role={tone === "error" ? "alert" : "status"}
      style={{ "--c": BANNER_COLOUR[tone] } as CSSProperties}
    >
      <span className="sx-banner-title">{title}</span>
      {children ? <span className="sx-banner-body">{children}</span> : null}
      {action}
    </div>
  );
}

/** Counts down from `seconds` (Retry-After), then calls onDone once. */
export function useCountdown(seconds: number | null, onDone?: () => void): number | null {
  const [left, setLeft] = useState(seconds);
  const [from, setFrom] = useState(seconds);
  if (from !== seconds) {
    // a new Retry-After restarts the countdown (state adjusted during render)
    setFrom(seconds);
    setLeft(seconds);
  }
  useEffect(() => {
    if (left === null) return;
    if (left <= 0) {
      onDone?.();
      return;
    }
    const t = setTimeout(() => setLeft((n) => (n === null ? null : n - 1)), 1000);
    return () => clearTimeout(t);
    // onDone is intentionally not a dependency: it fires once per countdown
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [left]);
  return left;
}

/** Non-blocking 503 banner: "Storage temporarily unavailable — retrying in N s". */
export function StorageBanner({ retryAfter, onRetry }: { retryAfter: number; onRetry: () => void }) {
  const left = useCountdown(retryAfter, onRetry);
  return (
    <Banner tone="storage" title="Storage temporarily unavailable">
      {left && left > 0 ? `Retrying in ${left} s.` : "Retrying now…"} Your last change was not saved.
    </Banner>
  );
}

export function UntrainedBanner({ canTrain, onTrain }: { canTrain: boolean; onTrain?: () => void }) {
  return (
    <Banner
      tone="untrained"
      title="No trained model"
      action={
        canTrain && onTrain ? (
          <SkewButton size="sm" onClick={onTrain}>
            Train a baseline
          </SkewButton>
        ) : null
      }
    >
      Flows are parsed and stored but not scored, so captures show no detections. Zero detections here means nothing.
      {canTrain ? "" : " Ask an administrator to train a baseline."}
    </Banner>
  );
}

/* -- Toasts ------------------------------------------------------------------------- */

export interface ToastItem {
  id: number;
  tone: "info" | "ok" | "warn" | "error";
  text: ReactNode;
}

export function Toasts({ items, onDismiss }: { items: ToastItem[]; onDismiss: (id: number) => void }) {
  const c = { info: "var(--blue-400)", ok: "var(--ok)", warn: "var(--warn)", error: "var(--error)" };
  return (
    <div className="sx-toasts" aria-live="polite">
      {items.map((t) => (
        <div key={t.id} className="sx-toast" role={t.tone === "error" ? "alert" : "status"} style={{ "--c": c[t.tone] } as CSSProperties}>
          <span style={{ flex: 1 }}>{t.text}</span>
          <button type="button" className="sx-close" style={{ width: 24, height: 24, fontSize: 14 }} aria-label="Dismiss" onClick={() => onDismiss(t.id)}>
            ×
          </button>
        </div>
      ))}
    </div>
  );
}

/* -- Skeleton ------------------------------------------------------------------------- */

export function Skeleton({ width = "100%", height = 14, lines = 1 }: { width?: number | string; height?: number; lines?: number }) {
  return (
    <span style={{ display: "grid", gap: 8 }} aria-hidden>
      {Array.from({ length: lines }, (_, i) => (
        <span key={i} className="sx-skeleton" style={{ width: i === lines - 1 && lines > 1 ? "60%" : width, height }} />
      ))}
    </span>
  );
}

/** Wraps a loading region so screen readers hear "Loading" once. */
export function Loading({ label = "Loading", lines = 3 }: { label?: string; lines?: number }) {
  return (
    <div role="status" aria-live="polite">
      <span className="sx-visually-hidden">{label}…</span>
      <Skeleton lines={lines} />
    </div>
  );
}

/* -- States ----------------------------------------------------------------------------- */

export function EmptyState({ title, children, action }: { title: string; children?: ReactNode; action?: ReactNode }) {
  return (
    <div className="sx-state sx-state--empty">
      <SignalField size={140} />
      <h3 className="sx-state-title">{title}</h3>
      {children ? <p className="sx-state-body">{children}</p> : null}
      {action}
    </div>
  );
}

export function ErrorState({ title = "Could not load this", detail, onRetry }: { title?: string; detail?: string; onRetry?: () => void }) {
  return (
    <div className="sx-state" role="alert">
      <span className="sx-badge" style={{ "--c": "var(--error)" } as CSSProperties}>
        Error
      </span>
      <h3 className="sx-state-title">{title}</h3>
      {detail ? <p className="sx-state-body sx-mono">{detail}</p> : null}
      {onRetry ? (
        <SkewButton variant="ghost" size="sm" onClick={onRetry}>
          Try again
        </SkewButton>
      ) : null}
    </div>
  );
}

export function PermissionDenied({ permission, what }: { permission: string; what?: string }) {
  return (
    <div className="sx-state" role="status">
      <span className="sx-badge" style={{ "--c": "var(--sev-info)" } as CSSProperties}>
        No permission
      </span>
      <h3 className="sx-state-title">You do not have permission{what ? ` to ${what}` : ""}</h3>
      <p className="sx-state-body">
        This needs the <code>{permission}</code> permission. Ask an administrator if you need it.
      </p>
    </div>
  );
}
