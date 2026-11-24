/**
 * Compile-time contract check (gap G-06): recorded API responses (frontend/contract/fixtures, exported from the real
 * backend by scripts/export_frontend_contract.py) must match the hand-written types the UI uses.
 *
 * Nothing here runs. `tsc` (npm run build, CI) fails when a type drifts from the backend:
 *   - `ok(...)` assigns the recorded body to the type: a missing, renamed or mistyped field is an error;
 *   - `SameKeys` compares the key sets both ways: a field the server added or stopped sending is an error too.
 * Gap G-03 (password change expected `sessions_revoked`, the server sends `sign_in_required`) fails here.
 * Add a line when the UI starts using another endpoint.
 */
import alerts from "../../contract/fixtures/GET_api_alerts.json";
import me from "../../contract/fixtures/GET_api_auth_me.json";
import hostEvidence from "../../contract/fixtures/GET_api_hosts_10.0.0.7_evidence.json";
import hosts from "../../contract/fixtures/GET_api_hosts.json";
import users from "../../contract/fixtures/GET_api_users.json";
import sessions from "../../contract/fixtures/GET_api_auth_sessions__2.json";
import password from "../../contract/fixtures/POST_api_auth_password.json";
import totpSetup from "../../contract/fixtures/POST_api_auth_totp_setup.json";
import verdict from "../../contract/fixtures/POST_api_hosts_10.0.0.7_verdict.json";
import type { Identity, ThreatAlert } from "./api";
import type { HostEvidence, HostEvidenceItem, HostList, HostSummary, HostVerdict, ManagedUser, PasswordChanged, SessionInfo, SessionList, TotpSetup, UserList } from "./types";

/** true when A and B have exactly the same keys (optional keys count), else a readable error type. */
type SameKeys<A, B> = [Exclude<keyof A, keyof B>, Exclude<keyof B, keyof A>] extends [never, never]
  ? true
  : { recorded_only: Exclude<keyof A, keyof B>; type_only: Exclude<keyof B, keyof A> };

function ok<T>(value: T): T {
  return value;
}
const same = <A, B>(check: SameKeys<A, B>) => check;
type Item<L> = L extends { items: (infer I)[] } ? I : never;

// whole bodies: recorded value assignable to the type
export const contract = [
  ok<PasswordChanged>(password.body),
  ok<HostList>(hosts.body as HostList),
  ok<HostEvidence>(hostEvidence.body as HostEvidence),
  ok<TotpSetup>(totpSetup.body),
  ok<SessionList>(sessions.body),
  ok<UserList>(users.body as UserList), // JSON imports widen the role literal to string; keys are checked below
  ok<Omit<Identity, "user">>({ expires_at: me.body.expires_at }),
] as const;

// key sets, both directions (top level and list items)
export const keys = [
  same<typeof password.body, PasswordChanged>(true),
  same<typeof totpSetup.body, TotpSetup>(true),
  same<typeof hosts.body, HostList>(true),
  same<Item<typeof hosts.body>, HostSummary>(true),
  same<typeof hostEvidence.body, HostEvidence>(true),
  same<Item<typeof hostEvidence.body>, HostEvidenceItem>(true),
  same<Omit<typeof verdict.body, "host">, HostVerdict>(true),
  same<Item<typeof users.body>, ManagedUser>(true),
  same<typeof me.body, Identity>(true),
  same<Item<typeof alerts.body>, ThreatAlert>(true),
  same<typeof sessions.body, SessionList>(true),
  same<Item<typeof sessions.body>, SessionInfo>(true),
] as const;
