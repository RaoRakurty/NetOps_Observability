// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// nav.overview.test.ts — the Overview section's shape.
//
// 2026-11-22 (owner): Operations Overview and My Dashboard merged into ONE
// default page, "Overview". The leaf id stays `operations` so saved landings,
// the landing choices and every existing link keep resolving; My Dashboard's
// old addresses land on it.

import { describe, it, expect } from "vitest";
import { NAV, resolveRoute, canonicalHash } from "./nav";

const overview = () => {
  const s = NAV.find((x) => x.id === "overview");
  if (!s?.children) throw new Error("no Overview section");
  return s.children;
};

describe("Overview section", () => {
  it("keeps Home first and has one default Overview leaf", () => {
    const leaves = overview().map((l) => [l.id, l.label]);
    expect(leaves[0]).toEqual(["home", "Home"]);
    expect(leaves).toContainEqual(["operations", "Overview"]);
  });

  it("hosts the tenant's own dashboards as My dashboards, after the default", () => {
    const ids = overview().map((l) => l.id);
    expect(ids).toEqual(["home", "operations", "dashboards"]);
    expect(overview().find((l) => l.id === "dashboards")?.label).toBe("My dashboards");
  });

  it.each([
    ["#/overview/dashboards"],
    ["#/overview/dashboards/new?template=default"],
    ["#/overview/dashboards/0f1e2d3c4b5a69788796a5b4c3d2e1f0"],
  ])("%s opens My dashboards (the page reads the rest of the address)", (hash) => {
    const r = resolveRoute(hash, NAV);
    expect(r.section?.id).toBe("overview");
    expect(r.leaf?.id).toBe("dashboards");
  });

  it("no longer lists My Dashboard as its own leaf", () => {
    const ids = overview().map((l) => l.id);
    expect(ids).not.toContain("board");
    expect(overview().map((l) => l.label)).not.toContain("My Dashboard");
    expect(overview().map((l) => l.label)).not.toContain("Operations Overview");
  });

  it.each([
    ["#/overview/operations"],
    ["#/overview/board"],
    ["#/dashboards/board"],
    ["#/dashboards/operations"],
  ])("%s lands on the merged Overview", (hash) => {
    const r = resolveRoute(hash, NAV);
    expect(r.section?.id).toBe("overview");
    expect(r.leaf?.id).toBe("operations");
    // An old address is rewritten straight to the live one (aliases never chain);
    // the live address itself needs no rewrite.
    const canon = canonicalHash(hash);
    expect(canon === null ? hash : canon).toBe("#/overview/operations");
  });
});
