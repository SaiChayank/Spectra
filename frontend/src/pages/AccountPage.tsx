import { useState, type FormEvent } from "react";
import {
  Banner,
  Card,
  Checkbox,
  CodeValue,
  Input,
  KeyValue,
  PasswordInput,
  RoleChip,
  SkewButton,
  SkewTabs,
  StatusPill,
  TimeValue,
} from "../components/ui";
import { ApiError, api, type Identity } from "../lib/api";
import type { TotpSetup } from "../lib/types";
import UsersAdmin from "./UsersAdmin";

const MIN_PASSWORD = 8; // backend UserCreate/UserUpdate policy

interface Props {
  identity: Identity;
  can: (permission: string) => boolean;
  /** The server revoked this session (password changed): back to sign-in with a message. */
  onSignedOut: (message: string) => void;
  /** Re-read /api/auth/me after a change to the account (e.g. two-factor). */
  onIdentityChanged: () => void;
}

function message(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

/* -- change own password ---------------------------------------------------------- */

function ChangePassword({ identity, onSignedOut }: Pick<Props, "identity" | "onSignedOut">) {
  const needsCode = identity.user.totp_enabled === true; // the server asks for the second factor too
  const [current, setCurrent] = useState("");
  const [code, setCode] = useState("");
  const [next, setNext] = useState("");
  const [confirm, setConfirm] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const tooShort = next.length > 0 && next.length < MIN_PASSWORD;
  const mismatch = confirm.length > 0 && confirm !== next;
  const ready = current && next.length >= MIN_PASSWORD && confirm === next && (!needsCode || code.trim()) && !busy;

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    if (!ready) return;
    setBusy(true);
    setError(null);
    try {
      const res = await api.changeOwnPassword(current, next, needsCode ? code.trim() : undefined);
      if (res.sign_in_required) onSignedOut("Password changed. Every session was signed out; sign in with your new password.");
    } catch (err) {
      if (err instanceof ApiError && err.status === 429) setError(`Too many attempts. Try again in ${err.retryAfter ?? 60} s.`);
      else if (err instanceof ApiError && err.status === 403) {
        setError(identity.user.totp_enabled ? "Current password or two-factor code is incorrect." : "Current password is incorrect.");
      } else setError(message(err));
    } finally {
      setBusy(false);
    }
  };

  return (
    <Card title="Change password" eyebrow="Sign-in">
        <form onSubmit={submit} style={{ display: "grid", gap: 12, maxWidth: 420 }} noValidate>
          <PasswordInput label="Current password" value={current} onChange={(e) => setCurrent(e.target.value)} autoComplete="current-password" />
          <PasswordInput
            label="New password"
            value={next}
            onChange={(e) => setNext(e.target.value)}
            autoComplete="new-password"
            hint={`At least ${MIN_PASSWORD} characters.`}
            error={tooShort ? `Use at least ${MIN_PASSWORD} characters.` : undefined}
          />
          <PasswordInput
            label="Confirm new password"
            value={confirm}
            onChange={(e) => setConfirm(e.target.value)}
            autoComplete="new-password"
            error={mismatch ? "The two passwords differ." : undefined}
          />
          {needsCode ? (
            <Input label="Two-factor code" value={code} onChange={(e) => setCode(e.target.value)}
              autoComplete="one-time-code" maxLength={32} hint="Two-factor is on for your account, so the server asks for a code too." />
          ) : null}
          {error ? (
            <Banner tone="error" title="Password not changed">
              {error}
            </Banner>
          ) : null}
          <p className="sx-hint">Changing it signs you out everywhere, including this browser.</p>
          <div>
            <SkewButton type="submit" loading={busy} disabled={!ready}>
              Change password
            </SkewButton>
          </div>
        </form>
    </Card>
  );
}

/* -- two-factor (TOTP) ---------------------------------------------------------------- */

type TwoFactorStep =
  | { kind: "idle" }
  | { kind: "password" } // asked before setup
  | { kind: "enrol"; setup: TotpSetup }
  | { kind: "recovery"; codes: string[] }
  | { kind: "disable" };

function TwoFactor({ identity, onIdentityChanged }: Pick<Props, "identity" | "onIdentityChanged">) {
  const enabled = identity.user.totp_enabled === true;
  const [step, setStep] = useState<TwoFactorStep>({ kind: "idle" });
  const [password, setPassword] = useState("");
  const [code, setCode] = useState("");
  const [saved, setSaved] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // secrets live only in this component's state and are dropped on every exit
  const reset = () => {
    setStep({ kind: "idle" });
    setPassword("");
    setCode("");
    setSaved(false);
    setError(null);
  };

  const run = async (fn: () => Promise<void>) => {
    setBusy(true);
    setError(null);
    try {
      await fn();
    } catch (err) {
      if (err instanceof ApiError && err.status === 429) setError(`Too many attempts. Try again in ${err.retryAfter ?? 60} s.`);
      else if (err instanceof Error && err.name === "AuthError") setError("That code or password is not correct.");
      else setError(message(err));
    } finally {
      setBusy(false);
    }
  };

  const errorBox = error ? (
    <Banner tone="error" title="Not done">
      {error}
    </Banner>
  ) : null;

  return (
    <Card
      title="Two-factor sign-in"
      eyebrow="Authenticator app"
      actions={<StatusPill status={enabled ? "ok" : "idle"}>{enabled ? "Enabled" : "Not enabled"}</StatusPill>}
    >
      {step.kind === "idle" ? (
        <div style={{ display: "grid", gap: 12, justifyItems: "start" }}>
          <p>
            {enabled
              ? "Sign-in asks for a code from your authenticator app. If you lose the device, use a recovery code or ask an administrator to remove two-factor."
              : "Add a time-based code from an authenticator app to your sign-in."}
          </p>
          {enabled ? (
            <SkewButton variant="ghost" onClick={() => setStep({ kind: "disable" })}>
              Turn off two-factor
            </SkewButton>
          ) : (
            <SkewButton onClick={() => setStep({ kind: "password" })}>Set up two-factor</SkewButton>
          )}
        </div>
      ) : null}

      {step.kind === "password" ? (
        <form
          style={{ display: "grid", gap: 12, maxWidth: 420 }}
          onSubmit={(e) => {
            e.preventDefault();
            void run(async () => {
              const setup = await api.totpSetup(password);
              setPassword("");
              setStep({ kind: "enrol", setup });
            });
          }}
        >
          <PasswordInput label="Confirm your password" value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="current-password" />
          {errorBox}
          <div style={{ display: "flex", gap: 10 }}>
            <SkewButton type="submit" loading={busy} disabled={!password}>
              Continue
            </SkewButton>
            <SkewButton variant="ghost" onClick={reset}>
              Cancel
            </SkewButton>
          </div>
        </form>
      ) : null}

      {step.kind === "enrol" ? (
        <form
          style={{ display: "grid", gap: 14 }}
          onSubmit={(e) => {
            e.preventDefault();
            void run(async () => {
              const out = await api.totpEnable(code.trim());
              setCode("");
              setStep({ kind: "recovery", codes: out.recovery_codes });
            });
          }}
        >
          <Banner tone="warn" title="Shown once">
            Add this key to your authenticator app now. Spectra will not show it again.
          </Banner>
          <KeyValue
            rows={[
              ["Issuer", step.setup.issuer],
              ["Secret key", <CodeValue value={step.setup.secret} label="secret key" />],
              ["Setup link", <CodeValue value={step.setup.otpauth_uri} label="otpauth setup link" />],
            ]}
          />
          <p className="sx-hint">Most apps accept the secret key typed in, or the setup link pasted. (A QR code is not shown yet.)</p>
          <div style={{ maxWidth: 260 }}>
            <Input label="Code from the app" value={code} onChange={(e) => setCode(e.target.value)} inputMode="numeric" autoComplete="one-time-code" maxLength={32} />
          </div>
          {errorBox}
          <div style={{ display: "flex", gap: 10 }}>
            <SkewButton type="submit" loading={busy} disabled={!code.trim()}>
              Turn on
            </SkewButton>
            <SkewButton variant="ghost" onClick={reset}>
              Cancel
            </SkewButton>
          </div>
        </form>
      ) : null}

      {step.kind === "recovery" ? (
        <div style={{ display: "grid", gap: 14 }}>
          <Banner tone="warn" title="Save your recovery codes">
            Each code signs you in once if you lose the device. They are shown only now.
          </Banner>
          <ol className="sx-mono" style={{ margin: 0, paddingLeft: 22, columns: 2, color: "var(--text-1)" }} aria-label="Recovery codes">
            {step.codes.map((c) => (
              <li key={c}>{c}</li>
            ))}
          </ol>
          <div>
            <CodeValue value={step.codes.join("\n")} label="all recovery codes" />
          </div>
          <Checkbox label="I have saved these codes somewhere safe" checked={saved} onChange={(e) => setSaved(e.target.checked)} />
          <div>
            <SkewButton
              disabled={!saved}
              onClick={() => {
                reset();
                onIdentityChanged();
              }}
            >
              Done
            </SkewButton>
          </div>
        </div>
      ) : null}

      {step.kind === "disable" ? (
        <form
          style={{ display: "grid", gap: 12, maxWidth: 420 }}
          onSubmit={(e) => {
            e.preventDefault();
            void run(async () => {
              await api.totpDisable(password, code.trim());
              reset();
              onIdentityChanged();
            });
          }}
        >
          <PasswordInput label="Password" value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="current-password" />
          <Input label="Authenticator or recovery code" value={code} onChange={(e) => setCode(e.target.value)} autoComplete="one-time-code" maxLength={32} />
          {errorBox}
          <div style={{ display: "flex", gap: 10 }}>
            <SkewButton type="submit" variant="danger" loading={busy} disabled={!password || !code.trim()}>
              Turn off two-factor
            </SkewButton>
            <SkewButton variant="ghost" onClick={reset}>
              Cancel
            </SkewButton>
          </div>
        </form>
      ) : null}
    </Card>
  );
}

/* -- page ----------------------------------------------------------------------------------- */

export default function AccountPage({ identity, can, onSignedOut, onIdentityChanged }: Props) {
  const admin = can("users:manage");
  const [tab, setTab] = useState<"me" | "users">("me");

  return (
    <div style={{ display: "grid", gap: 18 }}>
      {admin ? (
        <SkewTabs
          label="Account sections"
          value={tab}
          onChange={setTab}
          items={[
            { id: "me", label: "My account" },
            { id: "users", label: "Users" },
          ]}
        />
      ) : null}

      {tab === "users" && admin ? (
        <UsersAdmin me={identity.user.id} />
      ) : (
        <div style={{ display: "grid", gap: 18, gridTemplateColumns: "repeat(auto-fit, minmax(min(100%, 420px), 1fr))", alignItems: "start" }}>
          <Card title={identity.user.username} eyebrow="Signed in as">
            <KeyValue
              rows={[
                ["Role", <RoleChip role={identity.user.role} />],
                ["Permissions", <span className="sx-mono">{identity.user.permissions.join(", ")}</span>],
                ["Session expires", <TimeValue ts={identity.expires_at} />],
              ]}
            />
          </Card>
          <ChangePassword identity={identity} onSignedOut={onSignedOut} />
          <TwoFactor identity={identity} onIdentityChanged={onIdentityChanged} />
        </div>
      )}
    </div>
  );
}
