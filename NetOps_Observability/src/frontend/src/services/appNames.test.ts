// appNames helper — the client-side batch enrichment primitive (#81 P3G):
// one debounced POST for all visible IPs, module-level TTL cache (positive AND
// negative), non-IP keys never leave the browser, and a failing backend is
// silent (rows render as plain IPs) with a brief back-off.

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

const appIdResolveBatch = vi.fn();
vi.mock("./api", () => ({
  api: { appIdResolveBatch: (...a: unknown[]) => appIdResolveBatch(...a) },
}));

import { looksLikeIp, requestAppNames, cachedAppName, _resetAppNamesForTest } from "./appNames";

beforeEach(() => {
  vi.useFakeTimers();
  appIdResolveBatch.mockReset();
  _resetAppNamesForTest();
});
afterEach(() => {
  vi.useRealTimers();
});

describe("looksLikeIp", () => {
  it("accepts IPv4/IPv6 shapes and rejects everything else", () => {
    expect(looksLikeIp("10.0.1.10")).toBe(true);
    expect(looksLikeIp("2001:db8::1")).toBe(true);
    expect(looksLikeIp("leaf1")).toBe(false); // device name
    expect(looksLikeIp("443")).toBe(false); // bare port
    expect(looksLikeIp("US")).toBe(false); // country
    expect(looksLikeIp("")).toBe(false);
    expect(looksLikeIp("1.2.3.4; DROP")).toBe(false); // charset
    expect(looksLikeIp("a".repeat(46))).toBe(false); // length bound
  });
});

describe("requestAppNames batching + cache", () => {
  it("coalesces requests into one debounced call, IP keys only", async () => {
    appIdResolveBatch.mockResolvedValue({ "10.0.1.10": { app: "billing", source: "cloud_tag", confidence: 0.95 } });

    requestAppNames(["10.0.1.10", "leaf1", "443"]);
    requestAppNames(["10.0.1.10", "8.8.8.8"]); // within the debounce window
    expect(appIdResolveBatch).not.toHaveBeenCalled(); // debounced, not eager

    await vi.advanceTimersByTimeAsync(300);
    expect(appIdResolveBatch).toHaveBeenCalledTimes(1);
    expect(appIdResolveBatch.mock.calls[0][0]).toEqual(["10.0.1.10", "8.8.8.8"]);

    // resolved key cached; unresolved key negative-cached (asked → null)
    expect(cachedAppName("10.0.1.10")).toEqual({ app: "billing", source: "cloud_tag", confidence: 0.95 });
    expect(cachedAppName("8.8.8.8")).toBeNull();
    expect(cachedAppName("192.0.2.99")).toBeUndefined(); // never asked

    // cache hit: a re-request issues NO new call
    requestAppNames(["10.0.1.10", "8.8.8.8"]);
    await vi.advanceTimersByTimeAsync(300);
    expect(appIdResolveBatch).toHaveBeenCalledTimes(1);
  });

  it("expires entries after the TTL and re-asks", async () => {
    appIdResolveBatch.mockResolvedValue({});
    requestAppNames(["8.8.8.8"]);
    await vi.advanceTimersByTimeAsync(300);
    expect(appIdResolveBatch).toHaveBeenCalledTimes(1);

    await vi.advanceTimersByTimeAsync(5 * 60_000 + 1); // past TTL
    expect(cachedAppName("8.8.8.8")).toBeUndefined();
    requestAppNames(["8.8.8.8"]);
    await vi.advanceTimersByTimeAsync(300);
    expect(appIdResolveBatch).toHaveBeenCalledTimes(2);
  });

  it("swallows backend failures and backs off briefly (no user-facing error)", async () => {
    appIdResolveBatch.mockRejectedValue(new Error("502"));
    requestAppNames(["10.0.1.10"]);
    await vi.advanceTimersByTimeAsync(300);
    expect(appIdResolveBatch).toHaveBeenCalledTimes(1);
    expect(cachedAppName("10.0.1.10")).toBeNull(); // negative-cached

    // within the error back-off: no hammering
    requestAppNames(["10.0.1.10"]);
    await vi.advanceTimersByTimeAsync(300);
    expect(appIdResolveBatch).toHaveBeenCalledTimes(1);
  });

  it("splits oversized batches across calls (server cap 200)", async () => {
    appIdResolveBatch.mockResolvedValue({});
    const keys = Array.from({ length: 205 }, (_, i) => `10.0.${Math.floor(i / 250)}.${i % 250}`);
    requestAppNames(keys);
    await vi.advanceTimersByTimeAsync(700); // first flush + follow-up flush
    expect(appIdResolveBatch).toHaveBeenCalledTimes(2);
    expect(appIdResolveBatch.mock.calls[0][0]).toHaveLength(200);
    expect(appIdResolveBatch.mock.calls[1][0]).toHaveLength(5);
  });
});
