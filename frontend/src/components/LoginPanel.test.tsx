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
});
