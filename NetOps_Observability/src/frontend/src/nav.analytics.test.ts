// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// nav.analytics.test.ts — Analytics opens each page exactly once (owner,
// 2026-11-22: "under Analytics we have duplicate items — merge them into one, no
// duplications"). The Dashboard List leaf only re-linked pages that already have
// leaves (Device Metrics and Bandwidth Utilization were the SAME page; WAN
// circuits lives in Investigate › Paths) and hosted the builder that moved to
// Overview → My dashboards. The Demo Showcase repeats Overview's panels as a
// sales surface, so tenants no longer see it.

import { describe, it, expect } from "vitest";
import { NAV, filteredNav, resolveRoute } from "./nav";

const analytics = (nav = NAV) => {
  const s = nav.find((x) => x.id === "analytics");
  if (!s?.children) throw new Error("no Analytics section");
  return s.children;
};

describe("Analytics — no duplicates", () => {
  it("no longer has the Dashboard List directory", () => {
    expect(analytics().map((l) => l.id)).not.toContain("dashboards");
    expect(analytics().map((l) => l.label)).not.toContain("Dashboard List");
  });

  it("has no sub-item that re-links another page", () => {
    const relinks = analytics().flatMap((l) => (l.subItems ?? []).filter((s) => s.route).map((s) => `${l.id} → ${s.route}`));
    expect(relinks).toEqual([]);
  });

  it("gives every leaf a distinct label", () => {
    const labels = analytics().map((l) => l.label);
    expect(new Set(labels).size).toBe(labels.length);
  });

  it("shows the Demo Showcase to the platform owner only", () => {
    expect(analytics(filteredNav(true, true)).map((l) => l.id)).toContain("demo");
    expect(analytics(filteredNav(false, true)).map((l) => l.id)).not.toContain("demo");
  });

  it("folds BGP Operations into Protocol Monitoring's BGP tab", () => {
    const ids = analytics().map((l) => l.id);
    expect(ids).toContain("protocols");
    expect(ids).not.toContain("bgp-ops");
    const r = resolveRoute("#/analytics/bgp-ops", NAV);
    expect([r.section?.id, r.leaf?.id]).toEqual(["analytics", "protocols"]);
  });

  it("sends the old Dashboard List address to My dashboards", () => {
    const r = resolveRoute("#/analytics/dashboards", NAV);
    expect([r.section?.id, r.leaf?.id]).toEqual(["overview", "dashboards"]);
  });
});
