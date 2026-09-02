// assign.test.ts — the pure core of the bulk service-assignment workflow
// (2026-07 review imp #5). Validation must mirror the backend bounds
// (business_service_handlers.go): 1..5000 ids, exactly one target, name ≤128
// printable chars — a request that would 400 never leaves the client.

import { describe, it, expect } from "vitest";
import {
  buildAssignRequest, validServiceName, toggleSelection, toggleAllVisible,
  assignErrorMessage, ASSIGN_MAX_RESOURCES,
} from "./assign";

describe("validServiceName", () => {
  it("accepts realistic names and rejects the backend's rejects", () => {
    expect(validServiceName("payments")).toBe(true);
    expect(validServiceName("Trade Capture 2.0 - EU")).toBe(true);
    expect(validServiceName("")).toBe(false);
    expect(validServiceName("   ")).toBe(false);
    expect(validServiceName("a".repeat(129))).toBe(false);
    expect(validServiceName("bad\x00name")).toBe(false);
    expect(validServiceName("bad\nname")).toBe(false);
  });
});

describe("buildAssignRequest", () => {
  it("builds a name-target body, deduped and trimmed", () => {
    const r = buildAssignRequest([" i-1 ", "i-1", "i-2", ""], { serviceName: " payments " });
    expect(r).toEqual({ ok: true, body: { service_name: "payments", resource_ids: ["i-1", "i-2"] } });
  });

  it("builds an existing-service body", () => {
    const r = buildAssignRequest(["i-1"], { businessServiceId: "3f2a" });
    expect(r).toEqual({ ok: true, body: { business_service_id: "3f2a", resource_ids: ["i-1"] } });
  });

  it("rejects empty selections, both-targets, no-target and oversize", () => {
    expect(buildAssignRequest([], { serviceName: "x" }).ok).toBe(false);
    expect(buildAssignRequest(["i-1"], { businessServiceId: "a", serviceName: "b" }).ok).toBe(false);
    expect(buildAssignRequest(["i-1"], {}).ok).toBe(false);
    const many = Array.from({ length: ASSIGN_MAX_RESOURCES + 1 }, (_, i) => `i-${i}`);
    expect(buildAssignRequest(many, { serviceName: "x" }).ok).toBe(false);
  });

  it("rejects an invalid free-text name with the exact reason", () => {
    const r = buildAssignRequest(["i-1"], { serviceName: "bad\x07name" });
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error).toContain("printable");
  });
});

describe("selection helpers", () => {
  it("toggleSelection adds and removes without mutating the input", () => {
    const base = new Set(["a"]);
    const plus = toggleSelection(base, "b");
    expect([...plus].sort()).toEqual(["a", "b"]);
    const minus = toggleSelection(plus, "a");
    expect([...minus]).toEqual(["b"]);
    expect([...base]).toEqual(["a"]); // untouched
  });

  it("toggleAllVisible selects all visible, then unselects ONLY the visible", () => {
    const sel = new Set(["hidden-1"]);
    const all = toggleAllVisible(sel, ["v1", "v2"]);
    expect([...all].sort()).toEqual(["hidden-1", "v1", "v2"]);
    const cleared = toggleAllVisible(all, ["v1", "v2"]);
    expect([...cleared]).toEqual(["hidden-1"]); // off-screen selection survives
    expect(toggleAllVisible(new Set(), []).size).toBe(0); // no rows → no-op
  });
});

describe("assignErrorMessage", () => {
  it("maps 501 to the honest store-off message, 404 to a refresh hint", () => {
    expect(assignErrorMessage(new Error("501 Not Implemented: store off"))).toContain("not enabled on this deployment");
    expect(assignErrorMessage(new Error("404 Not Found: x"))).toContain("no longer exists");
    expect(assignErrorMessage(new Error("500 boom"))).toContain("failed");
  });
});
