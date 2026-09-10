// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// correlixRum.test.ts — the shipped browser beacon (public/correlix-rum.js).
//
// The snippet is plain ES5 in a public/ file, so it is loaded from disk and
// evaluated here rather than imported. That is deliberate: the thing under test
// has to be the exact bytes a customer pastes into their page.
//
// What is proven: a POST that fails for a reason that can clear is retried with
// backoff and keeps its batch; a POST that fails for a reason that cannot clear
// says so on the console once, names what the installer has to change, and
// stops. The old snippet handled 503 alone, so a 400 (which a custom cohort key
// produces, because the API decodes the cohort with DisallowUnknownFields) or a
// 401 destroyed the already-spliced batch in silence, forever.

import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const SNIPPET = readFileSync(resolve(__dirname, "../../public/correlix-rum.js"), "utf8");

type Call = { url: string; body: unknown };

interface RumHandle {
  track: (partial: Record<string, unknown>) => void;
  business: (partial: Record<string, unknown>) => void;
  flush: () => void;
  sessionId: string;
}

function loadRum(respond: () => Promise<Response> | Response): {
  rum: RumHandle;
  calls: Call[];
  warn: ReturnType<typeof vi.fn>;
  error: ReturnType<typeof vi.fn>;
} {
  const calls: Call[] = [];
  const fetchMock = vi.fn((url: string, init: RequestInit) => {
    calls.push({ url, body: JSON.parse(String(init.body)) });
    return Promise.resolve(respond());
  });
  vi.stubGlobal("fetch", fetchMock);

  const warn = vi.fn();
  const error = vi.fn();
  vi.stubGlobal("console", { ...console, warn, error, info: vi.fn() });

  (window as unknown as { CorrelixRUM: unknown }).CorrelixRUM = {
    endpoint: "https://correlix.example.com",
    key: "cx_test",
    app: "checkout",
  };
  new Function(SNIPPET)();
  const rum = (window as unknown as { correlixRum: RumHandle }).correlixRum;
  return { rum, calls, warn, error };
}

function ok(status: number): Response {
  return { status, ok: status >= 200 && status < 300 } as Response;
}

// settle lets the fetch promise chain run.
const settle = () => new Promise((r) => setTimeout(r, 0));

beforeEach(() => {
  vi.useRealTimers();
});

afterEach(() => {
  vi.unstubAllGlobals();
  delete (window as unknown as { correlixRum?: unknown }).correlixRum;
  delete (window as unknown as { CorrelixRUM?: unknown }).CorrelixRUM;
});

describe("correlix-rum delivery health", () => {
  it("says what a 400 means and stops, instead of discarding the batch in silence", async () => {
    const { rum, calls, warn, error } = loadRum(() => ok(400));
    rum.track({ type: "interaction", action: "click" });
    rum.flush();
    await settle();

    expect(calls.length).toBe(1);
    const said = [...warn.mock.calls, ...error.mock.calls].map((c) => String(c[0])).join(" ");
    expect(said).toContain("correlix-rum:");
    expect(said).toContain("400");
    // It names the thing the installer can actually change.
    expect(said).toContain("cohort");
    expect(said).toContain("STOPPED");

    // And it does not keep POSTing a body the API will refuse the same way.
    rum.track({ type: "interaction", action: "click again" });
    rum.flush();
    await settle();
    expect(calls.length).toBe(1);
  });

  it("names the key on a 401 and stops", async () => {
    const { rum, calls, warn, error } = loadRum(() => ok(401));
    rum.track({ type: "interaction", action: "click" });
    rum.flush();
    await settle();

    const said = [...warn.mock.calls, ...error.mock.calls].map((c) => String(c[0])).join(" ");
    expect(said).toContain("401");
    expect(said).toContain("ingest:experience");

    rum.track({ type: "interaction", action: "again" });
    rum.flush();
    await settle();
    expect(calls.length).toBe(1);
  });

  it("keeps the batch and backs off on a 503 rather than hammering the API", async () => {
    const { rum, calls, warn } = loadRum(() => ok(503));
    rum.track({ type: "interaction", action: "click" });
    rum.flush();
    await settle();
    expect(calls.length).toBe(1);

    // The batch is back in the queue, and the backoff holds the next flush.
    rum.flush();
    await settle();
    expect(calls.length).toBe(1);

    const said = warn.mock.calls.map((c) => String(c[0])).join(" ");
    expect(said).toContain("503");
    expect(said).toContain("retried");
  });

  it("keeps the batch when the request never lands at all", async () => {
    const calls: Call[] = [];
    const fetchMock = vi.fn((url: string, init: RequestInit) => {
      calls.push({ url, body: JSON.parse(String(init.body)) });
      return Promise.reject(new TypeError("Failed to fetch"));
    });
    vi.stubGlobal("fetch", fetchMock);
    const warn = vi.fn();
    vi.stubGlobal("console", { ...console, warn, error: vi.fn(), info: vi.fn() });
    (window as unknown as { CorrelixRUM: unknown }).CorrelixRUM = {
      endpoint: "https://correlix.example.com",
      key: "cx_test",
      app: "checkout",
    };
    new Function(SNIPPET)();
    const rum = (window as unknown as { correlixRum: RumHandle }).correlixRum;

    rum.track({ type: "interaction", action: "click" });
    rum.flush();
    await settle();
    expect(calls.length).toBe(1);

    const said = warn.mock.calls.map((c) => String(c[0])).join(" ");
    expect(said).toContain("CORS_ALLOWED_ORIGINS");
    // The event was not thrown away: it is queued for the next window.
    rum.flush();
    await settle();
    expect(calls.length).toBe(1);
  });

  it("sends on a 202 and keeps sending", async () => {
    const { rum, calls, warn, error } = loadRum(() => ok(202));
    rum.track({ type: "interaction", action: "one" });
    rum.flush();
    await settle();
    rum.track({ type: "interaction", action: "two" });
    rum.flush();
    await settle();
    expect(calls.length).toBe(2);
    expect(warn).not.toHaveBeenCalled();
    expect(error).not.toHaveBeenCalled();
  });
});
