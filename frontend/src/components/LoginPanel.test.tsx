import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import "@testing-library/jest-dom/vitest";
import LoginPanel from "./LoginPanel";

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

describe("LoginPanel", () => {
  it("posts the credentials and shows the server message on 401", async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(JSON.stringify({ detail: "invalid username or password" }), {
        status: 401,
        headers: { "Content-Type": "application/json" },
      }),
    );
    vi.stubGlobal("fetch", fetchMock);
    const onLogin = vi.fn();

    render(<LoginPanel onLogin={onLogin} />);
    fireEvent.change(screen.getByLabelText("Username"), { target: { value: "alice" } });
    fireEvent.change(screen.getByLabelText("Password"), { target: { value: "wrong" } });
    fireEvent.click(screen.getByRole("button", { name: "Sign in" }));

    expect(await screen.findByText("invalid username or password")).toBeInTheDocument();
    const [url, init] = fetchMock.mock.calls[0];
    expect(String(url)).toMatch(/\/api\/auth\/login$/);
    expect(JSON.parse(init.body)).toEqual({ username: "alice", password: "wrong" });
    expect(onLogin).not.toHaveBeenCalled();
  });

  it("sends the authenticator code in the same request, only when typed", async () => {
    const identity = { user: { id: 1, username: "alice", role: "ADMIN", permissions: [] }, expires_at: 1 };
    const fetchMock = vi.fn().mockImplementation(() =>
      Promise.resolve(new Response(JSON.stringify(identity), {
        status: 200, headers: { "Content-Type": "application/json" } })));
    vi.stubGlobal("fetch", fetchMock);
    const onLogin = vi.fn();

    render(<LoginPanel onLogin={onLogin} />);
    fireEvent.change(screen.getByLabelText("Username"), { target: { value: "alice" } });
    fireEvent.change(screen.getByLabelText("Password"), { target: { value: "pw-123456" } });
    fireEvent.click(screen.getByRole("button", { name: "Sign in" }));
    await screen.findByRole("button", { name: "Sign in" });
    expect(JSON.parse(fetchMock.mock.calls[0][1].body)).toEqual({ username: "alice", password: "pw-123456" });

    fireEvent.change(screen.getByLabelText(/Authenticator or recovery code/), { target: { value: " 123456 " } });
    fireEvent.click(screen.getByRole("button", { name: "Sign in" }));
    await vi.waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(2));
    expect(JSON.parse(fetchMock.mock.calls[1][1].body)).toEqual(
      { username: "alice", password: "pw-123456", totp_code: "123456" });
    await vi.waitFor(() => expect(onLogin).toHaveBeenCalledTimes(2));
  });
});
