// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// Login.busy.test.tsx — tracker 322, the frontend half.
//
// On 2026-09-15 a login on a box at 94 % disk took 26 s and came back 500,
// while the same credentials worked three seconds later. The backend now
// answers 503 + Retry-After for a store that ran out of time; this file pins
// what the SIGN-IN FORM does with that:
//
//   - it retries ONCE, by itself, after the delay the server advertised, so the
//     operator never sees a failure the server said was temporary;
//   - if the second attempt is refused too it says the system is busy, in
//     plain language — never "503 Service Unavailable", which reads as a broken
//     product;
//   - a 503 is the ONLY thing it retries: a wrong password is still one
//     request and still the server's own message.
//
// The fetch layer is stubbed, not the api module, so the real request()
// classification (ServiceBusyError + the Retry-After clamp) is under test too.

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { act, cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import Login from "./Login";
import { retryAfterSecondsFrom } from "../services/api";

const type = (el: HTMLElement, value: string) => fireEvent.change(el, { target: { value } });

const json = (body: unknown, status: number, headers: Record<string, string> = {}) =>
  new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json", ...headers } });

/** The backend's real 503: a plain sentence, and a delay. */
const busyResponse = (retryAfter = "0") =>
  json({ error: "the system is busy right now — please try again in a few seconds" }, 503, { "Retry-After": retryAfter });

const okResponse = () =>
  json({ token: "tok", refresh_token: "ref", expires_in: 900, user: { username: "rao", role: "admin" } }, 200);

/** Stubs the pre-auth endpoints; `login` answers /api/auth/login. */
function stubAuth(login: ReturnType<typeof vi.fn>) {
  vi.stubGlobal("fetch", vi.fn(async (url: string, init?: RequestInit) => {
    if (url.startsWith("/api/auth/locator")) return json({ locator: null }, 200);
    if (url.startsWith("/api/auth/methods")) {
      return json({
        local: true,
        ldap: { enabled: false, name: "LDAP" },
        tacacs: { enabled: false, name: "TACACS+" },
        sso: { enabled: false, providers: [] },
      }, 200);
    }
    if (url.startsWith("/api/auth/login")) return login(url, init);
    return json({}, 200);
  }));
  return login;
}

async function signIn() {
  type(await screen.findByLabelText("Username"), "rao");
  type(screen.getByLabelText("Password"), "hunter2");
  fireEvent.click(screen.getByRole("button", { name: "Sign in" }));
}

beforeEach(() => { localStorage.clear(); sessionStorage.clear(); });
afterEach(() => { cleanup(); vi.useRealTimers(); vi.unstubAllGlobals(); vi.restoreAllMocks(); });

describe("sign-in when the server is busy (503)", () => {
  it("retries once on its own and signs the operator in", async () => {
    const login = stubAuth(vi.fn()
      .mockImplementationOnce(async () => busyResponse())
      .mockImplementationOnce(async () => okResponse()));
    const onLoggedIn = vi.fn();
    render(<Login onLoggedIn={onLoggedIn} />);

    await signIn();

    await waitFor(() => expect(onLoggedIn).toHaveBeenCalledTimes(1));
    expect(login).toHaveBeenCalledTimes(2);
    // The operator is never shown the refusal the client already handled.
    expect(screen.queryByRole("alert")).toBeNull();
  });

  it("waits the advertised delay before retrying, rather than hammering", async () => {
    vi.useFakeTimers();
    const login = stubAuth(vi.fn()
      .mockImplementationOnce(async () => busyResponse("2"))
      .mockImplementationOnce(async () => okResponse()));
    render(<Login onLoggedIn={vi.fn()} />);

    // findBy* drives its own timers, so the fake-clock half of this test does
    // its waiting explicitly.
    await act(async () => { await vi.advanceTimersByTimeAsync(0); });
    type(screen.getByLabelText("Username"), "rao");
    type(screen.getByLabelText("Password"), "hunter2");
    fireEvent.click(screen.getByRole("button", { name: "Sign in" }));

    await act(async () => { await vi.advanceTimersByTimeAsync(0); });
    expect(login).toHaveBeenCalledTimes(1);

    await act(async () => { await vi.advanceTimersByTimeAsync(1_900); });
    expect(login, "retried before the advertised delay elapsed").toHaveBeenCalledTimes(1);

    await act(async () => { await vi.advanceTimersByTimeAsync(200); });
    expect(login).toHaveBeenCalledTimes(2);
  });

  it("stays visibly busy across the retry instead of flashing an error", async () => {
    stubAuth(vi.fn()
      .mockImplementationOnce(async () => busyResponse())
      .mockImplementationOnce(async () => okResponse()));
    const onLoggedIn = vi.fn();
    render(<Login onLoggedIn={onLoggedIn} />);

    await signIn();

    // Between the refusal and the retry the button must still read "Signing in…".
    const btn = screen.getByRole("button", { name: /Signing in|Sign in/ }) as HTMLButtonElement;
    expect(btn.disabled).toBe(true);
    expect(btn.textContent).toBe("Signing in…");

    // Let the retry finish before the test ends. A sign-in left in flight
    // outlives cleanup() — its pending retry lands on the NEXT test's fetch
    // stub and shows up there as a phantom third request.
    await waitFor(() => expect(onLoggedIn).toHaveBeenCalled());
  });

  it("says the system is busy — never the raw 503 — when the retry is refused too", async () => {
    const login = stubAuth(vi.fn(async () => busyResponse()));
    const onLoggedIn = vi.fn();
    render(<Login onLoggedIn={onLoggedIn} />);

    await signIn();

    const alert = await screen.findByRole("alert");
    expect(alert.textContent).toContain("The system is busy — try again shortly.");
    expect(alert.textContent).not.toContain("503");
    expect(alert.textContent).not.toContain("Service Unavailable");
    expect(login).toHaveBeenCalledTimes(2); // one retry, not a loop
    expect(onLoggedIn).not.toHaveBeenCalled();
    // The form is usable again — a busy server must not leave a dead button.
    expect((screen.getByRole("button", { name: "Sign in" }) as HTMLButtonElement).disabled).toBe(false);
  });

  it("does not retry a wrong password, and keeps the server's own message", async () => {
    const login = stubAuth(vi.fn(async () =>
      json({ error: "invalid username or password" }, 401)));
    render(<Login onLoggedIn={vi.fn()} />);

    await signIn();

    const alert = await screen.findByRole("alert");
    expect(alert.textContent).toContain("invalid username or password");
    expect(alert.textContent).not.toContain("busy");
    expect(login, "a failed sign-in must be ONE request — a retry doubles every brute-force attempt")
      .toHaveBeenCalledTimes(1);
  });

  it("does not retry a 500 either — a defect is not a delay", async () => {
    const login = stubAuth(vi.fn(async () => json({ error: "sign-in could not be completed" }, 500)));
    render(<Login onLoggedIn={vi.fn()} />);

    await signIn();

    await screen.findByRole("alert");
    expect(login).toHaveBeenCalledTimes(1);
  });
});

describe("the advertised delay", () => {
  const withRetryAfter = (v: string | null) =>
    new Response("{}", { status: 503, headers: v === null ? {} : { "Retry-After": v } });

  it("is honoured, capped, and falls back when it is not a number of seconds", () => {
    expect(retryAfterSecondsFrom(withRetryAfter("0"))).toBe(0);
    expect(retryAfterSecondsFrom(withRetryAfter("5"))).toBe(5);
    // A server may advertise minutes; a spinner that honours it literally hangs.
    expect(retryAfterSecondsFrom(withRetryAfter("600"))).toBe(10);
    // The HTTP-date form is not guessed at.
    expect(retryAfterSecondsFrom(withRetryAfter("Wed, 21 Oct 2026 07:28:00 GMT"))).toBe(3);
    expect(retryAfterSecondsFrom(withRetryAfter("-4"))).toBe(3);
    expect(retryAfterSecondsFrom(withRetryAfter(null))).toBe(3);
  });
});
