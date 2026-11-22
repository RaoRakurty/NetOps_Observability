// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// nav.paths.test.ts — the Paths section's shape.
//
// P0 (2026-11-20): Troubleshooting sat after the three Paths leaves with no
// group and so read as a fourth "path" page; it is the case workbench and sits
// beside RCA. P5 (2026-11-21): the three Paths leaves became ONE leaf, "Paths",
// with three tabs (#/investigate/paths/<tab>); every old address lands on its tab.
// 2026-11-22: the Measured paths tab was retired (each measured path is on the
// WAN circuit or tunnel row it measures); its old addresses open WAN circuits.

import { describe, it, expect } from "vitest";
import { NAV, resolveRoute, canonicalHash, navDestinations } from "./nav";
import { tabFromHash } from "./pages/paths/pathsModel";

const investigate = () => {
  const s = NAV.find((x) => x.id === "investigate");
  if (!s?.children) throw new Error("no Investigate section");
  return s.children;
};

describe("Investigate → Paths", () => {
  it("is one leaf with the two measurement tabs, in order", () => {
    const leaf = investigate().find((l) => l.id === "paths");
    expect(leaf?.label).toBe("Paths");
    expect(leaf?.subItems?.map((x) => [x.id, x.label])).toEqual([
      ["tunnels", "Tunnels"],
      ["wan-circuits", "WAN circuits"],
    ]);
    // No sub-item routes elsewhere: each one is a tab of this page.
    expect(leaf?.subItems?.every((x) => !x.route)).toBe(true);
  });

  it("no longer lists the three pages as separate leaves", () => {
    const ids = investigate().map((l) => l.id);
    for (const old of ["flowtrace", "tunnels", "wan-paths"]) expect(ids).not.toContain(old);
    expect(investigate().filter((l) => l.group === "Paths")).toEqual([]);
  });

  it("puts Troubleshooting beside RCA, outside Paths", () => {
    const ids = investigate().map((l) => l.id);
    expect(ids.indexOf("troubleshooting")).toBe(ids.indexOf("rca") + 1);
    expect(investigate().find((l) => l.id === "troubleshooting")?.group).toBeUndefined();
  });

  it("no ungrouped Investigate leaf follows a grouped run (it would inherit that header)", () => {
    const bad: string[] = [];
    let inGroup = "";
    for (const l of investigate()) {
      if (l.group) inGroup = l.group;
      else if (inGroup) bad.push(`investigate/${l.id} renders under "${inGroup}"`);
    }
    expect(bad).toEqual([]);
  });

  it("every old address lands on the Paths leaf AND on its own tab", () => {
    const cases: [string, string][] = [
      ["#/investigate/flowtrace", "wan-circuits"],
      ["#/investigate/paths/measured", "wan-circuits"],
      ["#/investigate/tunnels", "tunnels"],
      ["#/investigate/wan-paths", "wan-circuits"],
      ["#/infrastructure/flowtrace", "wan-circuits"],
      ["#/infrastructure/tunnels", "tunnels"],
      ["#/infrastructure/wan-circuits", "wan-circuits"],
      ["#/topology/tunnels", "tunnels"],
    ];
    for (const [hash, tab] of cases) {
      const r = resolveRoute(hash);
      expect(`${hash} → ${r.section.id}/${r.leaf?.id}`).toBe(`${hash} → investigate/paths`);
      const canon = canonicalHash(hash);
      expect(canon, hash).toBe(`#/investigate/paths/${tab}`);
      expect(tabFromHash(canon ?? "")).toBe(tab);
    }
    expect(resolveRoute("#/investigate/troubleshooting").leaf?.id).toBe("troubleshooting");
  });

  it("keeps a query string through the rewrite", () => {
    expect(canonicalHash("#/investigate/tunnels?q=hq")).toBe("#/investigate/paths/tunnels?q=hq");
  });

  it("the canonical tab addresses are already canonical and resolve to the leaf", () => {
    for (const tab of ["tunnels", "wan-circuits"]) {
      const hash = `#/investigate/paths/${tab}`;
      expect(canonicalHash(hash)).toBeNull();
      expect(resolveRoute(hash).leaf?.id).toBe("paths");
    }
  });

  it("⌘K offers each tab as its own destination", () => {
    const routes = navDestinations().map((d) => d.route);
    for (const tab of ["tunnels", "wan-circuits"]) expect(routes).toContain(`investigate/paths/${tab}`);
    expect(routes).not.toContain("investigate/paths/measured");
  });
});
