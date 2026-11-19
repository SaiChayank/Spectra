import { api, type Identity } from "./api";

/**
 * Visit tracking: a new tab or window starts signed out on the landing page;
 * a reload in the same tab keeps the session. The flag is a UI marker only
 * (no token or user data) in sessionStorage, which the browser clears when
 * the tab closes.
 */
const VISIT_KEY = "spectra-ui-visit";

export function isFreshVisit(): boolean {
  try {
    return sessionStorage.getItem(VISIT_KEY) === null;
  } catch {
    return true; // storage blocked: treat every load as a new visit (safe default: signed out)
  }
}

export function markVisit(): void {
  try {
    sessionStorage.setItem(VISIT_KEY, "1");
  } catch {
    /* storage blocked */
  }
}

/** Where each kind of user starts after signing in, from permissions (never role names). */
export function startPage(identity: Identity): string {
  const p = identity.user.permissions;
  // analysts work the queue; admins and viewers start on the overview
  if (p.includes("incidents:manage") && !p.includes("users:manage")) return "#/incidents";
  return "#/overview";
}

let startup: Promise<Identity | null> | null = null;

/**
 * The session to start with, decided once per page load (React may run
 * effects twice in development): a fresh visit signs out first and starts
 * signed out; a reload restores the session from the cookie.
 */
export function startupSession(): Promise<Identity | null> {
  if (!startup) {
    if (isFreshVisit()) {
      markVisit();
      startup = api
        .logout()
        .catch(() => undefined) // nobody was signed in, or the server is down
        .then(() => null);
    } else {
      startup = api.me().catch(() => null);
    }
  }
  return startup;
}

/** Tests only: forget the decision for this page load. */
export function resetStartupForTests(): void {
  startup = null;
}
