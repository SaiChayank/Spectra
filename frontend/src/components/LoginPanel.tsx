import { useState, type FormEvent } from "react";
import { api, type Identity } from "../lib/api";

interface Props {
  onLogin: (identity: Identity) => void;
}

/**
 * Full-screen local sign-in. No external identity provider: the form posts
 * to /api/auth/login and the HttpOnly session cookie does the rest.
 */
export default function LoginPanel({ onLogin }: Props) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    if (busy) return;
    setBusy(true);
    setError(null);
    try {
      const identity = await api.login(username.trim(), password);
      onLogin(identity);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="login-shell">
      <section className="panel login-card">
        <h2>Sign in to Spectra</h2>
        <form className="controls" onSubmit={submit}>
          <label>
            Username
            <input
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              autoComplete="username"
              autoFocus
              required
            />
          </label>
          <label>
            Password
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              autoComplete="current-password"
              required
            />
          </label>
          <button type="submit" disabled={busy || !username || !password}>
            {busy ? "Signing in…" : "Sign in"}
          </button>
        </form>
        {error && <div className="error-banner">{error}</div>}
        <p className="note">
          Local accounts only — passwords are checked against a scrypt hash and
          never stored or displayed in the clear. Sessions expire and are
          revoked when a password changes.
        </p>
        <p className="note">
          First run: the initial admin password is in{" "}
          <code>backend/data/admin_bootstrap.txt</code>, or set{" "}
          <code>SPECTRA_ADMIN_PASSWORD</code> before starting the server.
          Delete the file after your first sign-in.
        </p>
      </section>
    </div>
  );
}
