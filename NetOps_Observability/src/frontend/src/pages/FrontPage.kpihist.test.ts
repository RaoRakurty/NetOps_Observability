// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// FrontPage.kpihist.test.ts — KPI-history key isolation (M21, wave-3 second
// pass). kpiHistKey() fell back to the BARE prefix for every non-cross user
// (getActiveScope() is only set by the platform owner's scope selector), so
// two tenants on a shared browser read/wrote the SAME localStorage key. The
// key now derives from the session token's tenant claim when no explicit
// scope is active.

import { describe, it, expect, beforeEach } from "vitest";
import { kpiHistKey } from "./FrontPage";
import { setToken, setActiveScope } from "../services/api";

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

describe("M21 — kpiHistKey never shares a key across tenants", () => {
  it("keys by the session's tenant when no active scope is selected", () => {
    setToken(fakeJwt({ sub: "alice", tenant: "tenant-a" }));
    const a = kpiHistKey();
    setToken(fakeJwt({ sub: "carol", tenant: "tenant-b" }));
    const b = kpiHistKey();
    expect(a).toBe("netops.fp.kpihist.tenant-a");
    expect(b).toBe("netops.fp.kpihist.tenant-b");
    expect(a).not.toBe(b);
  });

  it("a signed-in tenant user never lands on the bare shared prefix", () => {
    setToken(fakeJwt({ sub: "alice", tenant: "tenant-a" }));
    expect(kpiHistKey()).not.toBe("netops.fp.kpihist");
  });

  it("an explicitly selected scope still wins (platform owner viewing a tenant)", () => {
    setToken(fakeJwt({ sub: "root" }));
    setActiveScope("tenant-z");
    expect(kpiHistKey()).toBe("netops.fp.kpihist.tenant-z");
  });

  it("the cross-tenant owner gets a per-user key, not the shared prefix", () => {
    setToken(fakeJwt({ sub: "root" }));
    setActiveScope("");
    expect(kpiHistKey()).toBe("netops.fp.kpihist.u.root");
  });
});
