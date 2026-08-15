// api.session.test.ts — session-edge state-sweep regression (M21, wave-3
// second pass). logout() swept the netops.fp.kpihist* family and the active
// scope, but the 401/refresh-failure clear path dropped ONLY the tokens — an
// expired session on a shared browser left the previous tenant's KPI history
// behind to seed the next user's sparklines. Both paths now share
// clearSession(), and every successful login sweeps BEFORE first render.

import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import {
  api,
  clearSession,
  sessionTenantKey,
  setToken,
  setRefresh,
  getToken,
} from "./api";

function b64url(o: unknown): string {
  return btoa(JSON.stringify(o)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function fakeJwt(claims: Record<string, unknown>): string {
  return `${b64url({ alg: "HS256", typ: "JWT" })}.${b64url(claims)}.sig`;
}

beforeEach(() => {
  localStorage.clear();
  sessionStorage.clear();
});
afterEach(() => {
  vi.unstubAllGlobals();
});

describe("M21 — clearSession sweeps scoped UI state on every session edge", () => {
  it("clearSession removes tokens, the whole kpihist family, and the active scope", () => {
    setToken("t");
    setRefresh("r");
    localStorage.setItem("netops.fp.kpihist", "[1]"); // legacy unscoped key too
    localStorage.setItem("netops.fp.kpihist.tenant-a", "[1]");
    localStorage.setItem("netops.fp.kpihist.tenant-b", "[2]");
    localStorage.setItem("netops.activeScope", "tenant-a");
    localStorage.setItem("netops.unrelated", "keep");
    clearSession();
    expect(getToken()).toBeNull();
    expect(localStorage.getItem("netops.fp.kpihist")).toBeNull();
    expect(localStorage.getItem("netops.fp.kpihist.tenant-a")).toBeNull();
    expect(localStorage.getItem("netops.fp.kpihist.tenant-b")).toBeNull();
    expect(localStorage.getItem("netops.activeScope")).toBeNull();
    expect(localStorage.getItem("netops.unrelated")).toBe("keep");
  });

  it("the 401/refresh-failure path sweeps kpihist like logout does", async () => {
    setToken(fakeJwt({ sub: "alice", tenant: "tenant-a" }));
    localStorage.setItem("netops.fp.kpihist.tenant-a", "[1,2,3]");
    localStorage.setItem("netops.activeScope", "tenant-a");
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => new Response("expired", { status: 401, statusText: "Unauthorized" })),
    );
    await expect(api.authMethods()).rejects.toThrow(/401/);
    expect(getToken()).toBeNull();
    expect(localStorage.getItem("netops.fp.kpihist.tenant-a")).toBeNull();
    expect(localStorage.getItem("netops.activeScope")).toBeNull();
  });

  it("a successful login sweeps the previous principal's state before first render", async () => {
    localStorage.setItem("netops.fp.kpihist.tenant-a", "[9,9,9]");
    localStorage.setItem("netops.activeScope", "tenant-a");
    vi.stubGlobal(
      "fetch",
      vi.fn(
        async () =>
          new Response(JSON.stringify({ token: "new-token", refresh_token: "new-refresh" }), {
            status: 200,
            headers: { "Content-Type": "application/json" },
          }),
      ),
    );
    const r = await api.login("bob", "pw");
    expect(r.mfaRequired).toBe(false);
    expect(getToken()).toBe("new-token");
    expect(localStorage.getItem("netops.fp.kpihist.tenant-a")).toBeNull();
    expect(localStorage.getItem("netops.activeScope")).toBeNull();
  });
});

describe("M21 — sessionTenantKey discriminates principals", () => {
  it("returns the tenant claim for tenant-bound sessions", () => {
    setToken(fakeJwt({ sub: "alice", tenant: "tenant-a" }));
    expect(sessionTenantKey()).toBe("tenant-a");
  });

  it("falls back to the subject for the cross-tenant platform owner", () => {
    setToken(fakeJwt({ sub: "root" }));
    expect(sessionTenantKey()).toBe("u.root");
  });

  it("two different tenants never share a key", () => {
    setToken(fakeJwt({ sub: "alice", tenant: "tenant-a" }));
    const a = sessionTenantKey();
    setToken(fakeJwt({ sub: "carol", tenant: "tenant-b" }));
    const b = sessionTenantKey();
    expect(a).not.toBe(b);
    expect(a).toBeTruthy();
    expect(b).toBeTruthy();
  });

  it("is empty (not throwing) with no or a malformed token", () => {
    expect(sessionTenantKey()).toBe("");
    setToken("not-a-jwt");
    expect(sessionTenantKey()).toBe("");
  });
});
