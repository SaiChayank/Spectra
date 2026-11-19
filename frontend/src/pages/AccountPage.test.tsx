import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import "@testing-library/jest-dom/vitest";
import { afterEach, describe, expect, it, vi } from "vitest";
import { formatDetail, type Identity } from "../lib/api";
import AccountPage from "./AccountPage";

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

const json = (status: number, body: unknown, headers: Record<string, string> = {}) =>
  new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json", ...headers } });

/** fetch stub routed by "METHOD path"; records every call. */
function stubFetch(routes: Record<string, () => Response>) {
  const calls: { key: string; body: unknown }[] = [];
  const fn = vi.fn((url: string, init?: RequestInit) => {
    const path = new URL(url, "http://x").pathname;
    const key = `${(init?.method ?? "GET").toUpperCase()} ${path}`;
    calls.push({ key, body: init?.body ? JSON.parse(String(init.body)) : null });
    const route = routes[key];
    return Promise.resolve(route ? route() : json(404, { detail: "Not Found" }));
  });
  vi.stubGlobal("fetch", fn);
  return calls;
}

const user = (role: "ADMIN" | "ANALYST" | "VIEWER", perms: string[], totp = false): Identity => ({
  expires_at: 1800043200,
  user: { id: 2, username: role.toLowerCase(), role, permissions: perms, totp_enabled: totp },
});
const viewer = user("VIEWER", ["read"]);
const admin = user("ADMIN", ["read", "investigate", "incidents:manage", "users:manage"]);

function renderPage(identity: Identity) {
  const onSignedOut = vi.fn();
  const onIdentityChanged = vi.fn();
  const can = (p: string) => identity.user.permissions.includes(p);
  render(
    <div className="sx">
      <AccountPage identity={identity} can={can} onSignedOut={onSignedOut} onIdentityChanged={onIdentityChanged} />
    </div>,
  );
  return { onSignedOut, onIdentityChanged };
}

function fillPassword(current: string, next: string, confirm = next) {
  fireEvent.change(screen.getByLabelText("Current password"), { target: { value: current } });
  fireEvent.change(screen.getByLabelText("New password"), { target: { value: next } });
  fireEvent.change(screen.getByLabelText("Confirm new password"), { target: { value: confirm } });
}

describe("formatDetail", () => {
  it("turns 422 validation lists into one readable line without values", () => {
    expect(
      formatDetail([
        { loc: ["body", "username"], msg: "String should have at least 3 characters" },
        { loc: ["body", "password"], msg: "String should have at least 8 characters" },
      ]),
    ).toBe("username: String should have at least 3 characters; password: String should have at least 8 characters");
    expect(formatDetail("username already exists")).toBe("username already exists");
  });
});

describe("change own password", () => {
  it("uses the proposed endpoint and returns to sign-in on success", async () => {
    const calls = stubFetch({ "POST /api/auth/password": () => json(200, { ok: true, sessions_revoked: true }) });
    const { onSignedOut } = renderPage(viewer);
    fillPassword("old-pass-1", "new-pass-123");
    fireEvent.click(screen.getByRole("button", { name: "Change password" }));
    await waitFor(() => expect(onSignedOut).toHaveBeenCalled());
    expect(calls[0].body).toEqual({ current_password: "old-pass-1", new_password: "new-pass-123" });
  });

  it("blocks short or mismatched passwords before sending", () => {
    const calls = stubFetch({});
    renderPage(viewer);
    fillPassword("old", "short");
    expect(screen.getByText("Use at least 8 characters.")).toBeInTheDocument();
    fillPassword("old", "long-enough-1", "long-enough-2");
    expect(screen.getByText("The two passwords differ.")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Change password" })).toBeDisabled();
    expect(calls).toHaveLength(0);
  });

  it("tells a non-admin honestly when the server lacks the route (404)", async () => {
    stubFetch({});
    const { onSignedOut } = renderPage(viewer);
    fillPassword("old-pass-1", "new-pass-123");
    fireEvent.click(screen.getByRole("button", { name: "Change password" }));
    expect(await screen.findByText("Not available on this server yet")).toBeInTheDocument();
    expect(onSignedOut).not.toHaveBeenCalled();
  });

  it("lets an admin fall back to PATCH /api/users/{id} when the route is missing", async () => {
    const calls = stubFetch({ "PATCH /api/users/2": () => json(200, { id: 2 }) });
    const { onSignedOut } = renderPage(admin);
    fillPassword("old-pass-1", "new-pass-123");
    fireEvent.click(screen.getByRole("button", { name: "Change password" }));
    await waitFor(() => expect(onSignedOut).toHaveBeenCalled());
    expect(calls.map((c) => c.key)).toEqual(["POST /api/auth/password", "PATCH /api/users/2"]);
    expect(calls[1].body).toEqual({ password: "new-pass-123" });
  });

  it("a wrong current password (401) is a form error, not a dead session", async () => {
    stubFetch({ "POST /api/auth/password": () => json(401, { detail: "current password is incorrect" }) });
    const ended = vi.fn();
    window.addEventListener("spectra:unauthorized", ended);
    const { onSignedOut } = renderPage(viewer);
    fillPassword("wrong", "new-pass-123");
    fireEvent.click(screen.getByRole("button", { name: "Change password" }));
    expect(await screen.findByText("Current password is incorrect.")).toBeInTheDocument();
    window.removeEventListener("spectra:unauthorized", ended);
    expect(ended).not.toHaveBeenCalled();
    expect(onSignedOut).not.toHaveBeenCalled();
  });
});

describe("two-factor", () => {
  it("enrols: secret shown once, wrong code keeps the session, recovery codes need acknowledging", async () => {
    let enableAttempts = 0;
    stubFetch({
      "POST /api/auth/totp/setup": () => json(200, { issuer: "Spectra", secret: "TESTSECRET", otpauth_uri: "otpauth://totp/x?secret=TESTSECRET" }),
      "POST /api/auth/totp/enable": () =>
        ++enableAttempts === 1 ? json(401, { detail: "invalid code" }) : json(200, { recovery_codes: ["r-1", "r-2"] }),
    });
    const ended = vi.fn();
    window.addEventListener("spectra:unauthorized", ended);
    const { onIdentityChanged } = renderPage(viewer);

    fireEvent.click(screen.getByRole("button", { name: "Set up two-factor" }));
    fireEvent.change(screen.getByLabelText("Confirm your password"), { target: { value: "pw" } });
    fireEvent.click(screen.getByRole("button", { name: "Continue" }));
    expect(await screen.findByText("TESTSECRET")).toBeInTheDocument();
    expect(screen.getByText("Shown once")).toBeInTheDocument();

    fireEvent.change(screen.getByLabelText("Code from the app"), { target: { value: "000000" } });
    fireEvent.click(screen.getByRole("button", { name: "Turn on" }));
    expect(await screen.findByText("That code or password is not correct.")).toBeInTheDocument();
    expect(ended).not.toHaveBeenCalled(); // a typo must not sign the user out

    fireEvent.click(screen.getByRole("button", { name: "Turn on" }));
    const list = await screen.findByRole("list", { name: "Recovery codes" });
    expect(within(list).getAllByRole("listitem")).toHaveLength(2);
    expect(screen.queryByText("TESTSECRET")).toBeNull(); // the secret is gone once enrolled
    const done = screen.getByRole("button", { name: "Done" });
    expect(done).toBeDisabled();
    fireEvent.click(screen.getByLabelText("I have saved these codes somewhere safe"));
    fireEvent.click(done);
    expect(onIdentityChanged).toHaveBeenCalled();
    expect(screen.queryByText("r-1")).toBeNull();
    window.removeEventListener("spectra:unauthorized", ended);
  });

  it("turns off with password and code", async () => {
    const calls = stubFetch({ "POST /api/auth/totp/disable": () => json(200, { totp_enabled: false }) });
    const { onIdentityChanged } = renderPage(user("VIEWER", ["read"], true));
    expect(screen.getByText("Enabled")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Turn off two-factor" }));
    fireEvent.change(screen.getByLabelText("Password"), { target: { value: "pw" } });
    fireEvent.change(screen.getByLabelText("Authenticator or recovery code"), { target: { value: "123456" } });
    fireEvent.click(screen.getByRole("button", { name: "Turn off two-factor" }));
    await waitFor(() => expect(onIdentityChanged).toHaveBeenCalled());
    expect(calls[0].body).toEqual({ password: "pw", code: "123456" });
  });
});

describe("users admin", () => {
  const list = {
    count: 2,
    items: [
      { id: 1, username: "admin", role: "ADMIN", created_at: 1800000000, updated_at: 1800000000, last_login_at: 1800000000 },
      { id: 2, username: "admin-2", role: "ADMIN", created_at: 1800000000, updated_at: 1800000000, last_login_at: null },
    ],
  };

  it("is a tab only for users:manage", () => {
    stubFetch({});
    renderPage(viewer);
    expect(screen.queryByRole("tab", { name: "Users" })).toBeNull();
  });

  it("lists users, marks you, and will not offer to delete yourself", async () => {
    stubFetch({ "GET /api/users": () => json(200, list) });
    renderPage(admin);
    fireEvent.click(screen.getByRole("tab", { name: "Users" }));
    expect(await screen.findByText("(you)")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Delete admin-2" })).toBeDisabled(); // id 2 is the signed-in user
    expect(screen.getByRole("button", { name: "Delete admin" })).not.toBeDisabled();
    expect(screen.getByText("never")).toBeInTheDocument();
  });

  it("shows the server's 409 when creating a duplicate", async () => {
    stubFetch({
      "GET /api/users": () => json(200, list),
      "POST /api/users": () => json(409, { detail: "username already exists" }),
    });
    renderPage(admin);
    fireEvent.click(screen.getByRole("tab", { name: "Users" }));
    fireEvent.click(await screen.findByRole("button", { name: "New user" }));
    const dialog = screen.getByRole("dialog");
    fireEvent.change(within(dialog).getByLabelText("Username"), { target: { value: "admin" } });
    fireEvent.change(within(dialog).getByLabelText("Initial password"), { target: { value: "long-enough" } });
    fireEvent.click(within(dialog).getByRole("button", { name: "Create" }));
    expect(await within(dialog).findByText("username already exists")).toBeInTheDocument();
  });

  it("spells out the consequence before deleting", async () => {
    stubFetch({ "GET /api/users": () => json(200, list) });
    renderPage(admin);
    fireEvent.click(screen.getByRole("tab", { name: "Users" }));
    fireEvent.click(await screen.findByRole("button", { name: "Delete admin" }));
    expect(screen.getByRole("dialog").textContent).toContain("cannot be restored");
  });
});
