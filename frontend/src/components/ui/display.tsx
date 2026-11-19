import { useId, useState, type CSSProperties, type ReactNode } from "react";

/* -- Eyebrow ------------------------------------------------------------------ */

export function Eyebrow({ children, as: Tag = "span" }: { children: ReactNode; as?: "span" | "p" | "h2" | "h3" }) {
  return <Tag className="sx-eyebrow">{children}</Tag>;
}

/* -- Severity badge: text + colour + icon, never colour alone --------------------- */

export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";

const SEV_COLOUR: Record<Severity, string> = {
  CRITICAL: "var(--sev-critical)",
  HIGH: "var(--sev-high)",
  MEDIUM: "var(--sev-medium)",
  LOW: "var(--sev-low)",
  INFO: "var(--sev-info)",
};

function SevIcon({ level }: { level: Severity }) {
  // distinct shapes per level, so colour is not the only signal
  const p = { width: 10, height: 10, viewBox: "0 0 10 10", "aria-hidden": true } as const;
  switch (level) {
    case "CRITICAL":
      return (
        <svg {...p}>
          <path d="M5 0 10 10H0Z" fill="currentColor" />
        </svg>
      );
    case "HIGH":
      return (
        <svg {...p}>
          <path d="M5 0 10 5 5 10 0 5Z" fill="currentColor" />
        </svg>
      );
    case "MEDIUM":
      return (
        <svg {...p}>
          <rect x="1" y="1" width="8" height="8" fill="currentColor" />
        </svg>
      );
    case "LOW":
      return (
        <svg {...p}>
          <circle cx="5" cy="5" r="4" fill="currentColor" />
        </svg>
      );
    default:
      return (
        <svg {...p}>
          <circle cx="5" cy="5" r="3.5" fill="none" stroke="currentColor" strokeWidth="1.5" />
        </svg>
      );
  }
}

export function SeverityBadge({ level }: { level: string }) {
  const sev = (level.toUpperCase() in SEV_COLOUR ? level.toUpperCase() : "INFO") as Severity;
  return (
    <span className="sx-badge" style={{ "--c": SEV_COLOUR[sev] } as CSSProperties}>
      <SevIcon level={sev} />
      {sev}
    </span>
  );
}

/** Neutral or tone badge (e.g. "unscored", "simulated", "ranking aid"). */
export function Badge({
  children,
  tone = "neutral",
  title,
}: {
  children: ReactNode;
  tone?: "neutral" | "blue" | "ok" | "warn" | "error";
  title?: string;
}) {
  const c = { neutral: "var(--sev-info)", blue: "var(--blue-400)", ok: "var(--ok)", warn: "var(--warn)", error: "var(--error)" }[tone];
  return (
    <span className="sx-badge" style={{ "--c": c } as CSSProperties} title={title}>
      {children}
    </span>
  );
}

/* -- StatusPill: dot + text label ------------------------------------------------------ */

export type Status = "live" | "reconnecting" | "offline" | "ok" | "warn" | "error" | "idle";

const STATUS_COLOUR: Record<Status, string> = {
  live: "var(--blue-400)",
  reconnecting: "var(--warn)",
  offline: "var(--sev-info)",
  ok: "var(--ok)",
  warn: "var(--warn)",
  error: "var(--error)",
  idle: "var(--sev-info)",
};

export function StatusPill({ status, children }: { status: Status; children: ReactNode }) {
  return (
    <span className="sx-pill" style={{ "--c": STATUS_COLOUR[status] } as CSSProperties}>
      <span className={`sx-dot ${status === "live" ? "sx-dot--pulse" : ""}`} aria-hidden />
      {children}
    </span>
  );
}

export function RoleChip({ role }: { role: string }) {
  return (
    <span className="sx-role" title={`Role: ${role}`}>
      {role}
    </span>
  );
}

/* -- Cards ----------------------------------------------------------------------------- */

export function Card({
  children,
  raised,
  crosshair,
  title,
  eyebrow,
  actions,
  className = "",
  style,
}: {
  children?: ReactNode;
  raised?: boolean;
  crosshair?: boolean;
  title?: ReactNode;
  eyebrow?: ReactNode;
  actions?: ReactNode;
  className?: string;
  style?: CSSProperties;
}) {
  return (
    <section className={`sx-card ${raised ? "sx-card--raised" : ""} ${crosshair ? "sx-crosshair" : ""} ${className}`} style={style}>
      {title || eyebrow || actions ? (
        <header className="sx-card-head">
          <div style={{ display: "grid", gap: 4 }}>
            {eyebrow ? <Eyebrow>{eyebrow}</Eyebrow> : null}
            {title ? <h3 className="sx-card-title">{title}</h3> : null}
          </div>
          {actions}
        </header>
      ) : null}
      {children}
    </section>
  );
}

/** Numbered card with corner "+" marks and an icon square (landing features, modules). */
export function CrosshairCard({
  index,
  icon,
  title,
  children,
}: {
  index: string;
  icon?: ReactNode;
  title: ReactNode;
  children?: ReactNode;
}) {
  return (
    <section className="sx-card sx-crosshair" style={{ display: "grid", gap: 12, padding: 20 }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
        <span className="sx-card-icon" aria-hidden>
          {icon ?? "◇"}
        </span>
        <span className="sx-index">{index}</span>
      </div>
      <h3 className="sx-card-title">{title}</h3>
      {children ? <p className="sx-card-desc">{children}</p> : null}
    </section>
  );
}

/** Mini sparkline (inline SVG, no chart library). */
export function Sparkline({ values, label }: { values: number[]; label: string }) {
  if (values.length < 2) return null;
  const w = 96;
  const h = 28;
  const min = Math.min(...values);
  const max = Math.max(...values);
  const span = max - min || 1;
  const pts = values.map((v, i) => `${(i / (values.length - 1)) * w},${h - 2 - ((v - min) / span) * (h - 4)}`).join(" ");
  return (
    <svg width={w} height={h} viewBox={`0 0 ${w} ${h}`} role="img" aria-label={label}>
      <polyline points={pts} fill="none" stroke="var(--blue-400)" strokeWidth="1.5" />
    </svg>
  );
}

export function StatCard({
  label,
  value,
  unit,
  delta,
  caption,
  trend,
  index,
  focal,
}: {
  label: string;
  value: ReactNode;
  unit?: string;
  /** e.g. "+12 %" with a direction for colour; the sign stays in the text. */
  delta?: { text: string; direction: "up" | "down" | "flat" };
  caption?: ReactNode;
  trend?: number[];
  index?: string;
  /** The one focal element per screen: bracketed. */
  focal?: boolean;
}) {
  const body = (
    <section className="sx-card sx-crosshair" style={{ display: "grid", gap: 8, minWidth: 0 }}>
      <div style={{ display: "flex", justifyContent: "space-between", gap: 8 }}>
        <Eyebrow>{label}</Eyebrow>
        {index ? <span className="sx-index">{index}</span> : null}
      </div>
      <div style={{ display: "flex", alignItems: "baseline", gap: 6, flexWrap: "wrap" }}>
        <span className="sx-stat-value">{value}</span>
        {unit ? <span className="sx-hint">{unit}</span> : null}
        {delta ? (
          <span
            className="sx-stat-delta"
            style={{ color: delta.direction === "flat" ? "var(--text-3)" : "var(--text-2)" }}
          >
            {delta.direction === "up" ? "▲" : delta.direction === "down" ? "▼" : "■"} {delta.text}
          </span>
        ) : null}
      </div>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-end", gap: 8 }}>
        {caption ? <span className="sx-hint">{caption}</span> : <span />}
        {trend ? <Sparkline values={trend} label={`${label} trend`} /> : null}
      </div>
    </section>
  );
  return focal ? <Viewfinder>{body}</Viewfinder> : body;
}

/* -- Viewfinder brackets ------------------------------------------------------------------- */

export function Viewfinder({
  children,
  size = 14,
  padding = 8,
  colour,
}: {
  children: ReactNode;
  size?: number;
  padding?: number;
  colour?: string;
}) {
  return (
    <div className="sx-viewfinder" style={{ "--vf": `${size}px`, "--vf-pad": `${padding}px`, ...(colour ? { "--vfc": colour } : {}) } as CSSProperties}>
      <span className="sx-vf-corner tl" aria-hidden />
      <span className="sx-vf-corner tr" aria-hidden />
      <span className="sx-vf-corner bl" aria-hidden />
      <span className="sx-vf-corner br" aria-hidden />
      {children}
    </div>
  );
}

/* -- ScoreMeter: score always with its threshold ---------------------------------------- */

export function ScoreMeter({ score, threshold, label = "Anomaly score" }: { score: number | null; threshold: number; label?: string }) {
  const id = useId();
  if (score === null) {
    return (
      <div className="sx-meter">
        <span className="sx-label">{label}</span>
        <Badge tone="warn">Unscored</Badge>
        <span className="sx-hint">No trained model scored this flow, so there is no score to compare.</span>
      </div>
    );
  }
  const over = score >= threshold;
  const pct = Math.max(0, Math.min(100, score));
  return (
    <div className="sx-meter">
      <div className="sx-meter-row">
        <span id={id} className="sx-label">
          {label}
        </span>
        <span className="sx-mono" style={{ color: "var(--text-1)" }}>
          {score.toFixed(1)} <span style={{ color: "var(--text-3)" }}>/ 100 · threshold {threshold}</span>
        </span>
      </div>
      <div
        className="sx-meter-track"
        role="meter"
        aria-labelledby={id}
        aria-valuemin={0}
        aria-valuemax={100}
        aria-valuenow={score}
        aria-valuetext={`${score.toFixed(1)} of 100, threshold ${threshold}, ${over ? "above" : "below"} threshold`}
      >
        <span className="sx-meter-fill" data-over={over} style={{ width: `${pct}%` }} />
        <span className="sx-meter-threshold" style={{ left: `calc(${threshold}% - 1px)` }} title={`Threshold ${threshold}`} />
      </div>
      <span className="sx-hint">
        {over
          ? "Above threshold: unusual for this network. Not proof of an attack."
          : "Below threshold: within the range of the baseline."}{" "}
        Percentile against the training flows, not a probability.
      </span>
    </div>
  );
}

/* -- EvidenceList ----------------------------------------------------------------------- */

export interface EvidenceItem {
  label: string;
  value?: ReactNode;
  unit?: string;
  detail?: ReactNode;
  /** 0.3 weak, 0.4 moderate, 0.5 strong (backend weights). */
  weight?: number;
}

export function EvidenceList({
  supporting,
  contradicting = [],
}: {
  supporting: EvidenceItem[];
  contradicting?: EvidenceItem[];
}) {
  const strength = (w?: number) => (w === undefined ? null : w >= 0.5 ? "strong" : w >= 0.4 ? "moderate" : "weak");
  const render = (items: EvidenceItem[], kind: "for" | "against") =>
    items.length === 0 ? (
      <p className="sx-hint">{kind === "for" ? "No supporting signals." : "No contradicting signals."}</p>
    ) : (
      <ul className="sx-evidence">
        {items.map((e, i) => (
          <li key={i} style={{ "--c": kind === "for" ? "var(--blue-400)" : "var(--sev-info)" } as CSSProperties}>
            <span className="sx-evidence-label">{e.label}</span>
            <span className="sx-evidence-value">
              {e.value}
              {e.unit ? <span style={{ color: "var(--text-3)" }}> {e.unit}</span> : null}
            </span>
            {strength(e.weight) ? <span className="sx-hint">{strength(e.weight)}</span> : <span />}
            {e.detail ? <span className="sx-evidence-detail">{e.detail}</span> : null}
          </li>
        ))}
      </ul>
    );
  return (
    <div style={{ display: "grid", gap: 14 }}>
      <div style={{ display: "grid", gap: 8 }}>
        <Eyebrow>Supporting</Eyebrow>
        {render(supporting, "for")}
      </div>
      <div style={{ display: "grid", gap: 8 }}>
        <Eyebrow>Contradicting</Eyebrow>
        {render(contradicting, "against")}
      </div>
    </div>
  );
}

/* -- KeyValue, CodeValue, Timeline ------------------------------------------------------------ */

export function KeyValue({ rows }: { rows: [ReactNode, ReactNode][] }) {
  return (
    <dl className="sx-kv">
      {rows.map(([k, v], i) => (
        <div key={i} style={{ display: "contents" }}>
          <dt>{k}</dt>
          <dd>{v ?? <span style={{ color: "var(--text-3)" }}>—</span>}</dd>
        </div>
      ))}
    </dl>
  );
}

/** Mono technical value (IP, JA3/JA4, hash) with a copy button. */
export function CodeValue({ value, label }: { value: string; label?: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <span className="sx-code">
      <span title={value}>{value}</span>
      <button
        type="button"
        className="sx-copy"
        aria-label={`Copy ${label ?? value}`}
        onClick={async (e) => {
          e.stopPropagation();
          try {
            await navigator.clipboard.writeText(value);
            setCopied(true);
            setTimeout(() => setCopied(false), 1200);
          } catch {
            /* clipboard blocked: the value is still selectable */
          }
        }}
      >
        {copied ? "Copied" : "Copy"}
      </button>
      <span className="sx-visually-hidden" aria-live="polite">
        {copied ? "Copied" : ""}
      </span>
    </span>
  );
}

export interface TimelineItem {
  ts: number; // unix seconds
  title: ReactNode;
  detail?: ReactNode;
  colour?: string;
}

export function Timeline({ items }: { items: TimelineItem[] }) {
  return (
    <ol className="sx-timeline">
      {items.map((it, i) => (
        <li key={i} style={it.colour ? ({ "--c": it.colour } as CSSProperties) : undefined}>
          <TimeValue ts={it.ts} />
          <div style={{ color: "var(--text-1)" }}>{it.title}</div>
          {it.detail ? <div className="sx-hint">{it.detail}</div> : null}
        </li>
      ))}
    </ol>
  );
}

/* -- Tooltip and TimeValue (local time, UTC on hover/focus) ------------------------------------ */

export function Tooltip({ tip, children }: { tip: ReactNode; children: ReactNode }) {
  const id = useId();
  const [open, setOpen] = useState(false);
  return (
    <span
      className="sx-tip"
      onMouseEnter={() => setOpen(true)}
      onMouseLeave={() => setOpen(false)}
      onFocus={() => setOpen(true)}
      onBlur={() => setOpen(false)}
      onKeyDown={(e) => e.key === "Escape" && setOpen(false)}
    >
      <span aria-describedby={id} tabIndex={0}>
        {children}
      </span>
      <span id={id} role="tooltip" className="sx-tip-bubble" hidden={!open}>
        {tip}
      </span>
    </span>
  );
}

const pad = (n: number) => String(n).padStart(2, "0");

export function formatLocal(ts: number): string {
  const d = new Date(ts * 1000);
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
}

export function formatUtc(ts: number): string {
  return `${new Date(ts * 1000).toISOString().replace("T", " ").slice(0, 19)} UTC`;
}

export function TimeValue({ ts }: { ts: number }) {
  return (
    <Tooltip tip={formatUtc(ts)}>
      <time className="sx-time" dateTime={new Date(ts * 1000).toISOString()}>
        {formatLocal(ts)}
      </time>
    </Tooltip>
  );
}
