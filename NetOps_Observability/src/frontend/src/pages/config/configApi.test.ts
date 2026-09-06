// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// configApi.test.ts — the WIRE contract of the config-backup client methods.
//
// The component tests mock services/api, so they cannot catch a wrong verb,
// path or body. These tests stub fetch and assert exactly what leaves the
// browser: the golden promotion carries {sha} to the device golden endpoint,
// the drift list sends only the three contracted params, and every id/sha is
// URL-encoded (never interpolated raw into a path).

import { describe, it, expect, afterEach, vi } from "vitest";
import { api, configDriftParams } from "../../services/api";

type Call = { url: string; init: RequestInit | undefined };

function stubFetch(body: unknown, status = 200): Call[] {
  const calls: Call[] = [];
  vi.stubGlobal("fetch", vi.fn(async (url: string, init?: RequestInit) => {
    calls.push({ url, init });
    return new Response(JSON.stringify(body), { status, statusText: status === 200 ? "OK" : "Error" });
  }));
  return calls;
}

afterEach(() => vi.unstubAllGlobals());

describe("config client — wire contract", () => {
  it("configSetGolden POSTs {sha} to the device golden endpoint", async () => {
    const calls = stubFetch({ device_id: "leaf1", golden_sha: "abc123" });
    await api.configSetGolden("leaf1", "abc123");
    expect(calls).toHaveLength(1);
    expect(calls[0].url).toBe("/api/devices/leaf1/config/golden");
    expect(calls[0].init?.method).toBe("POST");
    expect(JSON.parse(String(calls[0].init?.body))).toEqual({ sha: "abc123" });
  });

  it("configBackup POSTs to the backup endpoint with no body", async () => {
    const calls = stubFetch({ job_id: "j1", status: "queued" });
    await api.configBackup("leaf1");
    expect(calls[0].url).toBe("/api/devices/leaf1/config/backup");
    expect(calls[0].init?.method).toBe("POST");
    expect(calls[0].init?.body).toBeUndefined();
  });

  it("encodes the device id and sha into the path rather than interpolating raw", async () => {
    const calls = stubFetch({ device_id: "a/b", sha: "s", captured_at: "", size_bytes: 0, golden: false, text: "" });
    await api.configVersion("a/b", "s p");
    expect(calls[0].url).toBe("/api/devices/a%2Fb/config/versions/s%20p");
  });

  it("configDiff sends from/to as query params", async () => {
    const calls = stubFetch({ device_id: "leaf1", from: "a", to: "b", added: 0, removed: 0, unified: "", truncated: false });
    await api.configDiff("leaf1", "a a", "b");
    expect(calls[0].url).toBe("/api/devices/leaf1/config/diff?from=a+a&to=b");
  });

  it("configDriftList sends ONLY the contracted params", async () => {
    const calls = stubFetch({ items: [], next_cursor: null, total: 0 });
    await api.configDriftList({ state: "drifted", cursor: "c1", limit: 50 });
    expect(calls[0].url).toBe("/api/config/drift?state=drifted&cursor=c1&limit=50");
    await api.configDriftList();
    expect(calls[1].url).toBe("/api/config/drift");
  });

  it("configDriftParams omits every absent param", () => {
    expect(configDriftParams()).toBe("");
    expect(configDriftParams({ state: "unknown" })).toBe("state=unknown");
    expect(configDriftParams({ limit: 10 })).toBe("limit=10");
    // No tenant is ever sent from the client (§3a is a server guarantee).
    expect(configDriftParams({ state: "in_sync", cursor: "c", limit: 1 })).not.toContain("tenant");
  });

  it("surfaces a 404 as a 404-prefixed error so the UI can read it as feature-off", async () => {
    stubFetch({}, 404);
    await expect(api.configStatus("leaf1")).rejects.toThrow(/^404/);
  });
});
