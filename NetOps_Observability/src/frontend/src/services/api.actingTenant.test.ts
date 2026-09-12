// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// api.actingTenant.test.ts — every call to our api carries the tenant the
// operator is acting in.
//
// Most calls go through `request`, which has always added the header. A
// download or a text body has to hand-roll its fetch, and four of those (plus
// the Knowledge export the audit found) assembled their own headers and carried
// the token WITHOUT the acting tenant. That is not cosmetic: the call then acts
// in the caller's home tenant while the list beside it shows the tenant they
// picked, and the platform owner — who has no home tenant to fall back on — is
// refused outright.
//
// The last test walks the source, so a NEW hand-rolled fetch that skips the
// shared header builder fails here rather than in a customer's export.

import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { api, authHeaders, setToken, setActiveScope, clearSession } from "./api";

const SCOPE = "tenant-beta";

function headersOf(call: unknown[]): Record<string, string> {
  const init = call[1] as RequestInit | undefined;
  return (init?.headers ?? {}) as Record<string, string>;
}

let fetchMock: ReturnType<typeof vi.fn>;

beforeEach(() => {
  localStorage.clear();
  setToken("test-token");
  setActiveScope(SCOPE);
  fetchMock = vi.fn(async () => new Response("ok", { status: 200 }));
  vi.stubGlobal("fetch", fetchMock);
  // Downloads reach for the DOM; the calls under test only need it not to throw.
  vi.stubGlobal("URL", Object.assign(URL, { createObjectURL: () => "blob:x", revokeObjectURL: () => {} }));
});

afterEach(() => {
  vi.unstubAllGlobals();
  clearSession();
});

describe("the acting tenant travels on every hand-rolled call", () => {
  it("the Knowledge export sends it, so it exports the tenant the operator is looking at", async () => {
    await api.tacCandidateExport("ios-xe");
    expect(fetchMock).toHaveBeenCalledTimes(1);
    const h = headersOf(fetchMock.mock.calls[0]);
    expect(h["X-Acting-Tenant"]).toBe(SCOPE);
    expect(h.Authorization).toBe("Bearer test-token");
  });

  it("the report preview and the stored-artifact download send it", async () => {
    await api.reportPreview("weekly", { sections: [] } as never, "html");
    expect(headersOf(fetchMock.mock.calls[0])["X-Acting-Tenant"]).toBe(SCOPE);
    fetchMock.mockClear();
    await api.downloadArtifact("exec-1", "html").catch(() => {});
    expect(headersOf(fetchMock.mock.calls[0])["X-Acting-Tenant"]).toBe(SCOPE);
  });

  it("both log exports send it", async () => {
    await api.exportLogRows("csv", ["a"], [["1"]]).catch(() => {});
    expect(headersOf(fetchMock.mock.calls[0])["X-Acting-Tenant"]).toBe(SCOPE);
    fetchMock.mockClear();
    await api.exportLogQuery({ format: "csv" } as never).catch(() => {});
    expect(headersOf(fetchMock.mock.calls[0])["X-Acting-Tenant"]).toBe(SCOPE);
  });

  it("no scope selected means no header, not an empty one", () => {
    setActiveScope("");
    expect(authHeaders()["X-Acting-Tenant"]).toBeUndefined();
    expect(authHeaders().Authorization).toBe("Bearer test-token");
  });

  it("an explicit scope on a call is not overwritten", () => {
    expect(authHeaders({ "X-Acting-Tenant": "tenant-gamma" })["X-Acting-Tenant"]).toBe("tenant-gamma");
  });

  // The structural guard. Two auth endpoints are about the session and not
  // about a tenant, so they are named here rather than silently allowed.
  it("every fetch in api.ts builds its headers through the one path", () => {
    const src = readFileSync(join(dirname(fileURLToPath(import.meta.url)), "api.ts"), "utf8");
    const lines = src.split("\n");
    const AUTH_ONLY = ["/api/auth/refresh", "/api/auth/logout"];
    const offenders: string[] = [];
    lines.forEach((line, i) => {
      if (!/\bfetch\(/.test(line) || /authHeaders/.test(line)) return;
      if (AUTH_ONLY.some((p) => line.includes(p))) return;
      // The call's headers are either on this line or within the next few.
      const block = lines.slice(i, i + 8).join("\n");
      const upto = block.slice(0, block.indexOf("});") + 3 || block.length);
      if (/Authorization:\s*`Bearer/.test(upto) && !/authHeaders/.test(upto)) {
        offenders.push(`api.ts:${i + 1}  ${line.trim()}`);
      }
    });
    expect(offenders).toEqual([]);
    // The walk has teeth: the file really does hold fetches to find.
    expect(src.match(/\bfetch\(/g)!.length).toBeGreaterThan(5);
  });
});
