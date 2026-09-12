// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// Wave 4 #11 — governance Settings editors: pure-helper contracts.
import { describe, expect, it } from "vitest";
import { describeGovernanceChange, moveItem, normalizeTagKey } from "./GovernanceSettings";
import type { GovernanceAuditEvent } from "../../services/api";
import { missingTags, DEFAULT_REQUIRED_TAGS } from "./api";

describe("normalizeTagKey (mirror of tenant_governance.go validation)", () => {
  it("lowercases and trims valid keys", () => {
    expect(normalizeTagKey(" Cost_Center ")).toBe("cost_center");
    expect(normalizeTagKey("team/unit")).toBe("team/unit");
    expect(normalizeTagKey("a.b:c-d")).toBe("a.b:c-d");
  });
  it("rejects blank, oversize, and off-charset keys", () => {
    expect(normalizeTagKey("")).toBeNull();
    expect(normalizeTagKey("   ")).toBeNull();
    expect(normalizeTagKey("has space")).toBeNull();
    expect(normalizeTagKey("quote'")).toBeNull();
    expect(normalizeTagKey("x".repeat(65))).toBeNull();
  });
});

describe("moveItem (precedence up/down reorder)", () => {
  const abc = ["a", "b", "c"];
  it("swaps neighbours immutably", () => {
    expect(moveItem(abc, 1, -1)).toEqual(["b", "a", "c"]);
    expect(moveItem(abc, 1, +1)).toEqual(["a", "c", "b"]);
    expect(abc).toEqual(["a", "b", "c"]); // untouched
  });
  it("returns the same array at the edges (no-op)", () => {
    expect(moveItem(abc, 0, -1)).toBe(abc);
    expect(moveItem(abc, 2, +1)).toBe(abc);
    expect(moveItem(abc, 5, +1)).toBe(abc);
  });
});

describe("describeGovernanceChange (audit view rows)", () => {
  const ev = (detail: Record<string, unknown>): GovernanceAuditEvent => ({
    id: "1", time: "2026-07-18T00:00:00Z", actor: "adm", method: "PUT",
    path: "/api/settings/x", status: 200, decision: "allow", detail,
  });
  it("renders each settings action readably", () => {
    expect(describeGovernanceChange(ev({ action: "set_required_tags", required_tags: ["app", "cost_center"] })))
      .toEqual({ setting: "Required tags", change: "app, cost_center" });
    expect(describeGovernanceChange(ev({ action: "set_rca_window", rca_window_hours: 72 })))
      .toEqual({ setting: "RCA window", change: "72 hours" });
    expect(describeGovernanceChange(ev({ action: "set_attribution_precedence", attribution_precedence: ["firewall_appid", "operator"] })))
      .toEqual({ setting: "Attribution precedence", change: "firewall_appid → operator" });
    expect(describeGovernanceChange(ev({ action: "set_time_display", time_display: "utc" })))
      .toEqual({ setting: "Time display", change: "utc" });
  });
  it("labels resets and never invents a change", () => {
    expect(describeGovernanceChange(ev({ action: "set_required_tags", reset: true })).change).toBe("reset to default");
    expect(describeGovernanceChange(ev({ action: "set_rca_window", rca_window_hours: 0, reset: true })).change).toBe("reset to default");
    expect(describeGovernanceChange(ev({ action: "something_else" })).change).toBe("");
  });
});

describe("missingTags with a tenant-governed list", () => {
  it("defaults to app/owner/env with alias keys honored", () => {
    expect(missingTags({ Application: "billing", TEAM: "pay", stage: "prod" })).toEqual([]);
    // backend parity: app_id / component / awsapplication count as app
    expect(missingTags({ app_id: "x", owner: "y", env: "z" })).toEqual([]);
    expect(missingTags({})).toEqual(DEFAULT_REQUIRED_TAGS);
  });
  it("honors a custom required list (exact match for custom keys)", () => {
    const req = ["app", "cost_center"];
    expect(missingTags({ service: "api", Cost_Center: "cc-42" }, req)).toEqual([]);
    expect(missingTags({ service: "api" }, req)).toEqual(["cost_center"]);
    expect(missingTags({ cost_center: "cc" }, req)).toEqual(["app"]);
  });
  it("ignores whitespace-only tag values", () => {
    expect(missingTags({ app: "  " }, ["app"])).toEqual(["app"]);
  });
});
