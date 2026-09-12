// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// Login.form.test.tsx — the sign-in form's own behaviour, pinned after the
// 2026-09-12 redesign.
//
// Only the things the redesign CHANGED are asserted here; the locator and
// provider behaviour is covered by Login.locator.test.tsx and is untouched.
//
// What is pinned:
//   - the submit button is disabled ONLY while a request is in flight. It used
//     to be disabled until both fields had content, which is silent: a
//     keyboard or screen-reader user got a dead button and no reason for it;
//   - an empty field produces a NAMED error, programmatically associated with
//     the field, and moves focus to it;
//   - a second submit while one is in flight does not fire a second request;
//   - the password toggle keeps its accessible name in both states;
//   - the heading names the product, and the username field is not called an
//     email — nothing in the auth path accepts an address.

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { act, cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";

// fireEvent, not user-event: @testing-library/user-event is not a dependency
// of this app and §6 of CLAUDE.md forbids adding one for a test convenience.
const type = (el: HTMLElement, value: string) => fireEvent.change(el, { target: { value } });
import Login from "./Login";

function stubAuth(login: ReturnType<typeof vi.fn>) {
  vi.stubGlobal("fetch", vi.fn(async (url: string, init?: RequestInit) => {
    if (url.startsWith("/api/auth/locator")) {
      return new Response(JSON.stringify({ locator: null }), { status: 200, headers: { "Content-Type": "application/json" } });
    }
    if (url.startsWith("/api/auth/methods")) {
      return new Response(JSON.stringify({
        local: true,
        ldap: { enabled: false, name: "LDAP" },
        tacacs: { enabled: false, name: "TACACS+" },
        sso: { enabled: false, providers: [] },
      }), { status: 200, headers: { "Content-Type": "application/json" } });
    }
    if (url.startsWith("/api/auth/login")) return login(url, init);
    return new Response("{}", { status: 200, headers: { "Content-Type": "application/json" } });
  }));
}

beforeEach(() => { localStorage.clear(); sessionStorage.clear(); });
afterEach(() => { cleanup(); vi.unstubAllGlobals(); vi.restoreAllMocks(); });

describe("the sign-in form", () => {
  it("names the product in the heading and does not ask for an email", async () => {
    stubAuth(vi.fn());
    render(<Login onLoggedIn={() => {}} />);
    expect(await screen.findByRole("heading", { name: "Sign in to Correlix" })).toBeTruthy();
    expect(screen.getByLabelText("Username")).toBeTruthy();
    expect(screen.queryByLabelText(/e-?mail/i)).toBeNull();
  });

  it("keeps Sign in operable when the fields are empty, and says what is missing", async () => {
    const login = vi.fn();
    stubAuth(login);
    render(<Login onLoggedIn={() => {}} />);

    const btn = await screen.findByRole("button", { name: "Sign in" });
    // The whole point: reachable, not dead.
    expect((btn as HTMLButtonElement).disabled).toBe(false);

    fireEvent.click(btn);

    const err = await screen.findByText("Enter your username.");
    expect(err).toBeTruthy();
    // Programmatically associated, not merely adjacent.
    const userInput = screen.getByLabelText("Username");
    expect(userInput.getAttribute("aria-invalid")).toBe("true");
    expect(userInput.getAttribute("aria-describedby")).toBe(err.id);
    expect(document.activeElement).toBe(userInput);
    // Nothing was sent.
    expect(login).not.toHaveBeenCalled();
  });

  it("reports a missing password once the username is present", async () => {
    const login = vi.fn();
    stubAuth(login);
    render(<Login onLoggedIn={() => {}} />);

    type(await screen.findByLabelText("Username"), "rao");
    fireEvent.click(screen.getByRole("button", { name: "Sign in" }));

    const err = await screen.findByText("Enter your password.");
    const pw = screen.getByLabelText("Password");
    expect(pw.getAttribute("aria-describedby")).toBe(err.id);
    expect(document.activeElement).toBe(pw);
    expect(login).not.toHaveBeenCalled();
  });

  it("clears a field error as soon as the operator types", async () => {
    stubAuth(vi.fn());
    render(<Login onLoggedIn={() => {}} />);

    fireEvent.click(await screen.findByRole("button", { name: "Sign in" }));
    expect(await screen.findByText("Enter your username.")).toBeTruthy();

    type(screen.getByLabelText("Username"), "r");
    await waitFor(() => expect(screen.queryByText("Enter your username.")).toBeNull());
  });

  it("does not fire a second request while one is in flight", async () => {
    let release: (v: Response) => void = () => {};
    const login = vi.fn(() => new Promise<Response>((res) => { release = res; }));
    stubAuth(login as never);
    render(<Login onLoggedIn={() => {}} />);

    type(await screen.findByLabelText("Username"), "rao");
    type(screen.getByLabelText("Password"), "hunter2");
    const btn = screen.getByRole("button", { name: "Sign in" });
    fireEvent.click(btn);

    // Busy: the label changes and the control is disabled.
    const busy = await screen.findByRole("button", { name: "Signing in…" });
    expect((busy as HTMLButtonElement).disabled).toBe(true);
    expect(login).toHaveBeenCalledTimes(1);

    release(new Response(JSON.stringify({ token: "t" }), { status: 200, headers: { "Content-Type": "application/json" } }));
    await waitFor(() => expect(login).toHaveBeenCalledTimes(1));
  });

  it("gives the password toggle an accessible name in both states", async () => {
    stubAuth(vi.fn());
    render(<Login onLoggedIn={() => {}} />);

    const show = await screen.findByRole("button", { name: "Show password" });
    expect(screen.getByLabelText("Password").getAttribute("type")).toBe("password");
    fireEvent.click(show);
    expect(await screen.findByRole("button", { name: "Hide password" })).toBeTruthy();
    expect(screen.getByLabelText("Password").getAttribute("type")).toBe("text");
  });

  it("offers change-password by its accurate name, not a recovery promise", async () => {
    stubAuth(vi.fn());
    render(<Login onLoggedIn={() => {}} />);
    // The flow behind it asks for the CURRENT password, so it is a change.
    expect(await screen.findByRole("button", { name: "Change password" })).toBeTruthy();
    expect(screen.queryByText(/forgot password/i)).toBeNull();
  });
});
