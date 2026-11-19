import { useState, type FormEvent, type ReactNode } from "react";
import { ApiError, api, type Identity } from "../lib/api";
import {
  Banner,
  Input,
  PasswordInput,
  SkewButton,
  Viewfinder,
  Wordmark,
  useCountdown,
  type BannerTone,
} from "./ui";
import HeroScene from "./HeroScene";
import "./landing.css";

export interface LoginNotice {
  tone: BannerTone;
  title: string;
  body?: ReactNode;
}

interface Props {
  onLogin: (identity: Identity) => void;
}

/**
 * Local sign-in card. No external identity provider: the form posts to
 * /api/auth/login and the HttpOnly session cookie does the rest. A 429
 * (too many failed attempts) disables the form for Retry-After seconds.
 */
export default function LoginPanel({ onLogin }: Props) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [code, setCode] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [throttle, setThrottle] = useState<number | null>(null);
  const wait = useCountdown(throttle, () => {
    setThrottle(null);
    setError(null);
  });
  const throttled = wait !== null && wait > 0;

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    if (busy || throttled) return;
    setBusy(true);
    setError(null);
    try {
      const identity = await api.login(username.trim(), password, code.trim() || undefined);
      onLogin(identity);
    } catch (err) {
      if (err instanceof ApiError && err.status === 429) {
        setThrottle(err.retryAfter ?? 60);
        setError("Too many failed sign-in attempts.");
      } else {
        setError(err instanceof Error ? err.message : String(err));
      }
    } finally {
      setBusy(false);
    }
  };

  return (
    <section className="sx-login-card" aria-labelledby="login-title">
      <div className="sx-login-brand">
        <Wordmark size={15} />
      </div>
      <h1 id="login-title" className="sx-eyebrow" style={{ justifyContent: "center" }}>
        Sign in to Spectra
      </h1>
      <form onSubmit={submit} noValidate>
        <Input label="Username" value={username} onChange={(e) => setUsername(e.target.value)} autoComplete="username" autoFocus required />
        <PasswordInput label="Password" value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="current-password" required />
        <Input
          label="Authenticator or recovery code (only if you enabled two-factor)"
          value={code}
          onChange={(e) => setCode(e.target.value)}
          autoComplete="one-time-code"
          inputMode="text"
          maxLength={32}
        />
        {error ? (
          <div role="alert" className="sx-banner" style={{ ["--c" as string]: throttled ? "var(--warn)" : "var(--error)" }}>
            <span className="sx-banner-body" style={{ color: "var(--text-1)" }}>
              {error}
              {throttled ? ` Try again in ${wait} s.` : ""}
            </span>
          </div>
        ) : null}
        <SkewButton type="submit" size="lg" icon="⚡" loading={busy} disabled={throttled || !username || !password} style={{ width: "100%" }}>
          {busy ? "Signing in…" : "Sign in"}
        </SkewButton>
      </form>
      <p className="sx-hint">
        Local accounts only. Passwords are checked against a scrypt hash and never stored or shown in the clear. Sessions expire, and
        are revoked when a password changes.
      </p>
      <p className="sx-hint">
        First run: the initial admin password is in <code>backend/data/admin_bootstrap.txt</code>, or set{" "}
        <code>SPECTRA_ADMIN_PASSWORD</code> before starting the server. Delete the file after your first sign-in.
      </p>
    </section>
  );
}

/** Full-screen sign-in: hero backdrop, the card inside viewfinder brackets. */
export function LoginScreen({ onLogin, notice }: Props & { notice?: LoginNotice | null }) {
  return (
    <div className="sx sx-login-page">
      <HeroScene />
      <div className="sx-login-col">
        {notice ? (
          <Banner tone={notice.tone} title={notice.title}>
            {notice.body}
          </Banner>
        ) : null}
        <Viewfinder size={18} padding={14}>
          <LoginPanel onLogin={onLogin} />
        </Viewfinder>
        <a href="#/" className="sx-hint" style={{ justifySelf: "center" }}>
          ← Back to the overview page
        </a>
      </div>
    </div>
  );
}
