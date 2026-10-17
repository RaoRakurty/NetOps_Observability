// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// api.activityKeepAlive.test.ts — an operator who is working is never signed
// out "for inactivity".
//
// The server counts a session as active only when the client calls
// /api/auth/refresh. The client used to refresh only when its 1 h access token
// expired, so with the 30 min idle default every session was idle-expired at its
// first refresh (lab, 2026-10-08..10: SESSION_IDLE_EXPIRED an hour apart while
// the operator was using the console). These pin the fix: real input refreshes
// at most once per window, a refused refresh signs out, a lost one does not.

import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import {
  ACTIVITY_REFRESH_MS, ACTIVITY_RETRY_MS, clearSession, getRefresh, getToken,
  noteUserActivity, onAuthChange, setRefresh, setToken, startActivityKeepAlive,
  takeSessionEndMessage,
} from "./api";

let fetchMock: ReturnType<typeof vi.fn>;
const okRefresh = () => new Response(JSON.stringify({ token: "new-access", refresh_token: "new-refresh" }), { status: 200 });

beforeEach(() => {
  localStorage.clear();
  sessionStorage.clear();
  setToken("access");
  setRefresh("refresh-1"); // stamps "last activity" = now
  fetchMock = vi.fn(async () => okRefresh());
  vi.stubGlobal("fetch", fetchMock);
});

afterEach(() => {
  vi.unstubAllGlobals();
  clearSession();
});

const refreshCalls = () => fetchMock.mock.calls.filter((c) => c[0] === "/api/auth/refresh").length;

describe("activity keep-alive", () => {
  it("does not refresh inside the window — input alone is not a request storm", async () => {
    const now = Date.now();
    expect(noteUserActivity(now + 1_000)).toBeNull();
    expect(noteUserActivity(now + ACTIVITY_REFRESH_MS - 1_000)).toBeNull();
    expect(refreshCalls()).toBe(0);
  });

  it("refreshes once the window has passed, and a burst makes exactly one call", async () => {
    const t = Date.now() + ACTIVITY_REFRESH_MS + 1;
    const p = noteUserActivity(t);
    expect(p).not.toBeNull();
    expect(noteUserActivity(t + 5)).toBeNull(); // in flight
    await expect(p).resolves.toBe(true);
    // The new token re-stamps "last activity" to now, so the next window starts over.
    expect(noteUserActivity(Date.now() + 10)).toBeNull();
    expect(refreshCalls()).toBe(1);
    expect(getToken()).toBe("new-access");
    expect(getRefresh()).toBe("new-refresh");
  });

  it("an operator active for over an hour keeps refreshing inside every idle window", async () => {
    vi.useFakeTimers({ toFake: ["Date"] });
    const start = Date.now();
    setRefresh("refresh-1"); // re-stamp under the fake clock
    const refreshedAt: number[] = [];
    // Input every minute for 70 min; the server's idle limit is 30 min.
    for (let m = 1; m <= 70; m++) {
      vi.setSystemTime(start + m * 60_000);
      const p = noteUserActivity();
      if (p) {
        await p;
        refreshedAt.push(Date.now());
      }
    }
    vi.useRealTimers();
    expect(refreshedAt.length).toBe(Math.floor(70 / (ACTIVITY_REFRESH_MS / 60_000)));
    expect(refreshedAt[0] - start).toBeLessThanOrEqual(ACTIVITY_REFRESH_MS + 60_000);
    for (let i = 1; i < refreshedAt.length; i++) {
      expect(refreshedAt[i] - refreshedAt[i - 1]).toBeLessThan(30 * 60_000);
    }
  });

  it("a refused refresh (session ended) signs out and says why", async () => {
    fetchMock.mockImplementation(async () =>
      new Response(JSON.stringify({ error: "idle", code: "SESSION_IDLE_TIMEOUT" }), { status: 401 }));
    const signedOut = vi.fn();
    const off = onAuthChange((s) => { if (!s) signedOut(); });
    await expect(noteUserActivity(Date.now() + ACTIVITY_REFRESH_MS + 1)).resolves.toBe(false);
    off();
    expect(signedOut).toHaveBeenCalledTimes(1);
    expect(getToken()).toBeNull();
    expect(getRefresh()).toBeNull();
    expect(takeSessionEndMessage()).toBe("You were signed out due to inactivity.");
  });

  it("a refresh that gets no answer keeps the session and retries soon", async () => {
    fetchMock.mockImplementation(async () => { throw new TypeError("Failed to fetch"); });
    const signedOut = vi.fn();
    const off = onAuthChange((s) => { if (!s) signedOut(); });
    const t = Date.now() + ACTIVITY_REFRESH_MS + 1;
    await expect(noteUserActivity(t)).resolves.toBe(false);
    off();
    expect(signedOut).not.toHaveBeenCalled();
    expect(getRefresh()).toBe("refresh-1");
    expect(noteUserActivity(t + ACTIVITY_RETRY_MS - 1)).toBeNull();
    fetchMock.mockImplementation(async () => okRefresh());
    await expect(noteUserActivity(t + ACTIVITY_RETRY_MS + 1)).resolves.toBe(true);
  });

  it("does nothing when signed out", () => {
    clearSession();
    expect(noteUserActivity(Date.now() + 10 * ACTIVITY_REFRESH_MS)).toBeNull();
    expect(refreshCalls()).toBe(0);
  });

  it("listens to real input only, and the remover detaches it", async () => {
    vi.useFakeTimers({ toFake: ["Date"] });
    vi.setSystemTime(Date.now() + ACTIVITY_REFRESH_MS + 1);
    const stop = startActivityKeepAlive();
    window.dispatchEvent(new Event("mousemove")); // hover is not activity
    expect(refreshCalls()).toBe(0);
    window.dispatchEvent(new KeyboardEvent("keydown", { key: "a" }));
    await Promise.resolve();
    expect(refreshCalls()).toBe(1);
    stop();
    vi.setSystemTime(Date.now() + 10 * ACTIVITY_REFRESH_MS);
    window.dispatchEvent(new KeyboardEvent("keydown", { key: "b" }));
    expect(refreshCalls()).toBe(1);
    vi.useRealTimers();
  });
});
