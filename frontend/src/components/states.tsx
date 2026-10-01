import type { ReactNode } from "react";

/** Loading skeleton for a section that is fetching its first page. */
export function Loading({ label = "Loading…" }: { label?: string }) {
  return (
    <div className="state-block loading" role="status" aria-live="polite">
      <span className="state-spinner" aria-hidden="true" />
      <span>{label}</span>
    </div>
  );
}

/**
 * Fetch failure. Distinguishes "backend unreachable" (the App-level banner
 * already says so) from API errors so a page never renders stale lies.
 */
export function ErrorBox({
  message,
  onRetry,
}: {
  message: string;
  onRetry?: () => void;
}) {
  return (
    <div className="state-block error" role="alert">
      <span className="state-title">Request failed</span>
      <span className="state-detail">{message}</span>
      {onRetry && (
        <button className="ghost" onClick={onRetry}>
          Retry
        </button>
      )}
    </div>
  );
}

/** Empty result: valid query, nothing to show (never an error). */
export function Empty({
  message,
  hint,
}: {
  message: string;
  hint?: string;
}) {
  return (
    <div className="state-block empty-state">
      <span className="state-title">{message}</span>
      {hint && <span className="state-detail">{hint}</span>}
    </div>
  );
}

/**
 * Permission gate: the server would answer 403 — the UI says so up front
 * instead of firing a request it knows will be rejected. The route stays
 * visible so the operator can see *why* a section is unavailable.
 */
export function Locked({
  permission,
  title = "Restricted section",
  note,
}: {
  permission: string;
  title?: string;
  note?: string;
}) {
  return (
    <div className="state-block locked">
      <span className="state-title">
        <span className="lock-glyph" aria-hidden="true">
          ▲
        </span>
        {title}
      </span>
      <span className="state-detail">
        {note ??
          `This section requires the “${permission}” permission. Ask an administrator to upgrade your role.`}
      </span>
      <span className="state-detail dim">
        Your role can browse Overview, Monitor, Traffic, Models and System.
      </span>
    </div>
  );
}

/** Section heading: title + one-line purpose + optional right-hand controls. */
export function PageHeader({
  title,
  subtitle,
  actions,
}: {
  title: string;
  subtitle?: string;
  actions?: ReactNode;
}) {
  return (
    <div className="page-header">
      <div>
        <h2 className="page-title">{title}</h2>
        {subtitle && <p className="page-subtitle">{subtitle}</p>}
      </div>
      {actions && <div className="page-actions">{actions}</div>}
    </div>
  );
}

/** A labelled value row used across detail panes. */
export function KV({
  k,
  children,
  verdict,
}: {
  k: string;
  children: ReactNode;
  verdict?: "ok" | "bad";
}) {
  return (
    <div className={`kv${verdict ? ` verdict ${verdict}` : ""}`}>
      <span className="k">{k}</span>
      <span className="v">{children}</span>
    </div>
  );
}

/** Horizontal pagination footer: "n of total" + prev/next. */
export function Pager({
  shown,
  total,
  offset,
  limit,
  onChange,
}: {
  shown: number;
  total: number;
  offset: number;
  limit: number;
  onChange: (offset: number) => void;
}) {
  if (total <= limit && offset === 0) {
    return (
      <p className="note">
        {shown} of {total}
      </p>
    );
  }
  return (
    <div className="pager">
      <span className="note">
        {offset + 1}–{offset + shown} of {total}
      </span>
      <div className="controls">
        <button
          className="ghost"
          disabled={offset === 0}
          onClick={() => onChange(Math.max(0, offset - limit))}
        >
          ← Prev
        </button>
        <button
          className="ghost"
          disabled={offset + limit >= total}
          onClick={() => onChange(offset + limit)}
        >
          Next →
        </button>
      </div>
    </div>
  );
}
