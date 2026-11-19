import { useId, useRef, useState, type ButtonHTMLAttributes, type InputHTMLAttributes, type ReactNode, type SelectHTMLAttributes, type TextareaHTMLAttributes } from "react";

/* -- SkewButton ------------------------------------------------------------- */

export type ButtonVariant = "primary" | "secondary" | "ghost" | "danger";

export interface SkewButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: ButtonVariant;
  size?: "sm" | "md" | "lg";
  loading?: boolean;
  /** Leading icon (decorative). */
  icon?: ReactNode;
  /** Trailing icon (decorative), e.g. the secondary "↗". */
  trailing?: ReactNode;
}

export function SkewButton({
  variant = "primary",
  size = "md",
  loading = false,
  icon,
  trailing,
  children,
  disabled,
  type = "button",
  className = "",
  ...rest
}: SkewButtonProps) {
  return (
    <span className={`sx-btn-wrap sx-btn-wrap--${variant}`}>
      <button
        type={type}
        className={`sx-btn sx-btn--${variant} ${size !== "md" ? `sx-btn--${size}` : ""} ${className}`}
        disabled={disabled || loading}
        aria-busy={loading || undefined}
        {...rest}
      >
        {loading ? <span className="sx-spinner" aria-hidden /> : icon ? <span aria-hidden>{icon}</span> : null}
        {children}
        {trailing ? <span aria-hidden>{trailing}</span> : null}
      </button>
    </span>
  );
}

/* -- SkewTabs ---------------------------------------------------------------- */

export interface TabItem<T extends string> {
  id: T;
  label: ReactNode;
  disabled?: boolean;
}

/** In-page tab bar (WAI-ARIA tabs: arrow keys move, Home/End jump). */
export function SkewTabs<T extends string>({
  items,
  value,
  onChange,
  label,
}: {
  items: TabItem<T>[];
  value: T;
  onChange: (id: T) => void;
  label: string;
}) {
  const refs = useRef<(HTMLButtonElement | null)[]>([]);
  const enabled = items.filter((i) => !i.disabled);
  const move = (from: T, delta: number | "home" | "end") => {
    const at = enabled.findIndex((i) => i.id === from);
    const next =
      delta === "home" ? 0 : delta === "end" ? enabled.length - 1 : (at + delta + enabled.length) % enabled.length;
    const id = enabled[next].id;
    onChange(id);
    refs.current[items.findIndex((i) => i.id === id)]?.focus();
  };
  return (
    <div className="sx-tabs" role="tablist" aria-label={label}>
      {items.map((item, i) => (
        <button
          key={item.id}
          ref={(el) => {
            refs.current[i] = el;
          }}
          type="button"
          role="tab"
          className="sx-tab"
          aria-selected={item.id === value}
          tabIndex={item.id === value ? 0 : -1}
          disabled={item.disabled}
          onClick={() => onChange(item.id)}
          onKeyDown={(e) => {
            const k = { ArrowRight: 1, ArrowLeft: -1, Home: "home", End: "end" } as const;
            const d = k[e.key as keyof typeof k];
            if (d !== undefined) {
              e.preventDefault();
              move(item.id, d);
            }
          }}
        >
          {item.label}
        </button>
      ))}
    </div>
  );
}

/* -- Field wrapper ------------------------------------------------------------ */

interface FieldProps {
  label: string;
  hint?: ReactNode;
  error?: string;
  /** Visually hide the label (it stays for screen readers). */
  hideLabel?: boolean;
}

function Field({
  id,
  label,
  hint,
  error,
  hideLabel,
  children,
}: FieldProps & { id: string; children: ReactNode }) {
  return (
    <div className="sx-field">
      <label htmlFor={id} className={hideLabel ? "sx-visually-hidden" : "sx-label"}>
        {label}
      </label>
      {children}
      {hint && !error ? (
        <span id={`${id}-hint`} className="sx-hint">
          {hint}
        </span>
      ) : null}
      {error ? (
        <span id={`${id}-err`} className="sx-error-text" role="alert">
          {error}
        </span>
      ) : null}
    </div>
  );
}

function describedBy(id: string, hint: unknown, error: unknown) {
  return error ? `${id}-err` : hint ? `${id}-hint` : undefined;
}

export function Input({ label, hint, error, hideLabel, id, ...rest }: FieldProps & InputHTMLAttributes<HTMLInputElement>) {
  const auto = useId();
  const fid = id ?? auto;
  return (
    <Field id={fid} label={label} hint={hint} error={error} hideLabel={hideLabel}>
      <input
        id={fid}
        className="sx-input"
        aria-invalid={error ? true : undefined}
        aria-describedby={describedBy(fid, hint, error)}
        {...rest}
      />
    </Field>
  );
}

export function PasswordInput({
  label,
  hint,
  error,
  id,
  ...rest
}: FieldProps & Omit<InputHTMLAttributes<HTMLInputElement>, "type">) {
  const auto = useId();
  const fid = id ?? auto;
  const [shown, setShown] = useState(false);
  return (
    <Field id={fid} label={label} hint={hint} error={error}>
      <div className="sx-password">
        <input
          id={fid}
          type={shown ? "text" : "password"}
          className="sx-input"
          aria-invalid={error ? true : undefined}
          aria-describedby={describedBy(fid, hint, error)}
          {...rest}
        />
        <button
          type="button"
          className="sx-password-toggle"
          aria-pressed={shown}
          aria-controls={fid}
          aria-label={shown ? "Hide password" : "Show password"}
          onClick={() => setShown((s) => !s)}
        >
          {shown ? "Hide" : "Show"}
        </button>
      </div>
    </Field>
  );
}

export function Select({
  label,
  hint,
  error,
  hideLabel,
  id,
  options,
  ...rest
}: FieldProps & SelectHTMLAttributes<HTMLSelectElement> & { options: { value: string; label: string }[] }) {
  const auto = useId();
  const fid = id ?? auto;
  return (
    <Field id={fid} label={label} hint={hint} error={error} hideLabel={hideLabel}>
      <select
        id={fid}
        className="sx-select"
        aria-invalid={error ? true : undefined}
        aria-describedby={describedBy(fid, hint, error)}
        {...rest}
      >
        {options.map((o) => (
          <option key={o.value} value={o.value}>
            {o.label}
          </option>
        ))}
      </select>
    </Field>
  );
}

export function Textarea({ label, hint, error, id, ...rest }: FieldProps & TextareaHTMLAttributes<HTMLTextAreaElement>) {
  const auto = useId();
  const fid = id ?? auto;
  return (
    <Field id={fid} label={label} hint={hint} error={error}>
      <textarea
        id={fid}
        className="sx-textarea"
        aria-invalid={error ? true : undefined}
        aria-describedby={describedBy(fid, hint, error)}
        {...rest}
      />
    </Field>
  );
}

export function Checkbox({ label, ...rest }: { label: ReactNode } & Omit<InputHTMLAttributes<HTMLInputElement>, "type">) {
  return (
    <label className="sx-check">
      <input type="checkbox" {...rest} />
      {label}
    </label>
  );
}

export function Toggle({
  label,
  checked,
  onChange,
  disabled,
}: {
  label: string;
  checked: boolean;
  onChange: (next: boolean) => void;
  disabled?: boolean;
}) {
  return (
    <button
      type="button"
      role="switch"
      aria-checked={checked}
      className="sx-toggle"
      disabled={disabled}
      onClick={() => onChange(!checked)}
    >
      <span className="sx-toggle-track" aria-hidden />
      {label}
    </button>
  );
}

/* -- FileDrop ------------------------------------------------------------------ */

export function FileDrop({
  accept = ".pcap,.pcapng",
  onFile,
  progress,
  disabled,
  label = "Drop a capture here, or choose a file",
  hint = "PCAP or PCAPNG. Payload bytes are stripped on upload; only headers and handshake metadata are kept.",
}: {
  accept?: string;
  onFile: (file: File) => void;
  /** 0-100 while uploading; undefined when idle. */
  progress?: number;
  disabled?: boolean;
  label?: string;
  hint?: string;
}) {
  const input = useRef<HTMLInputElement>(null);
  const [over, setOver] = useState(false);
  const busy = progress !== undefined;
  const pick = () => !disabled && !busy && input.current?.click();
  return (
    <div
      className="sx-filedrop"
      role="button"
      tabIndex={disabled ? -1 : 0}
      aria-disabled={disabled || busy || undefined}
      data-over={over}
      onClick={pick}
      onKeyDown={(e) => {
        if (e.key === "Enter" || e.key === " ") {
          e.preventDefault();
          pick();
        }
      }}
      onDragOver={(e) => {
        e.preventDefault();
        if (!disabled) setOver(true);
      }}
      onDragLeave={() => setOver(false)}
      onDrop={(e) => {
        e.preventDefault();
        setOver(false);
        const f = e.dataTransfer.files[0];
        if (f && !disabled && !busy) onFile(f);
      }}
    >
      <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.4" aria-hidden>
        <path d="M12 16V4m0 0-4 4m4-4 4 4M4 16v3a1 1 0 0 0 1 1h14a1 1 0 0 0 1-1v-3" />
      </svg>
      <span style={{ color: "var(--text-1)" }}>{busy ? `Uploading… ${Math.round(progress!)} %` : label}</span>
      <span className="sx-hint">{hint}</span>
      {busy ? (
        <div className="sx-progress" role="progressbar" aria-valuenow={Math.round(progress!)} aria-valuemin={0} aria-valuemax={100} aria-label="Upload progress">
          <span style={{ width: `${progress}%` }} />
        </div>
      ) : null}
      <input
        ref={input}
        type="file"
        accept={accept}
        hidden
        onChange={(e) => {
          const f = e.target.files?.[0];
          if (f) onFile(f);
          e.target.value = "";
        }}
      />
    </div>
  );
}
