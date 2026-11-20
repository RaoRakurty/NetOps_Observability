// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// nav.paths.test.ts — the Paths section's shape (Paths redesign P0, 2026-11-20).
//
// The nav prints a group header only when the group CHANGES to a non-empty one
// (SubNav / NavFlyout / Sidebar), so an ungrouped leaf placed after a grouped
// run renders under that run's header. Troubleshooting sat after the three
// Paths leaves with no group and so read as a fourth "path" page. It is the
// case workbench and now sits beside RCA.

import { describe, it, expect } from "vitest";
import { NAV, resolveRoute, canonicalHash } from "./nav";

const investigate = () => {
  const s = NAV.find((x) => x.id === "investigate");
  if (!s?.children) throw new Error("no Investigate section");
  return s.children;
};

describe("Investigate → Paths", () => {
  it("groups exactly the three measurement pages, under their new names", () => {
    const paths = investigate().filter((l) => l.group === "Paths").map((l) => [l.id, l.label]);
    expect(paths).toEqual([
      ["flowtrace", "Measured paths"],
      ["tunnels", "Tunnels"],
      ["wan-paths", "WAN circuits"],
    ]);
  });

  it("puts Troubleshooting beside RCA, outside the Paths group", () => {
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

  it("keeps every old address: the route ids did not change", () => {
    for (const [hash, leaf] of [
      ["#/investigate/flowtrace", "flowtrace"],
      ["#/investigate/wan-paths", "wan-paths"],
      ["#/investigate/tunnels", "tunnels"],
      ["#/investigate/troubleshooting", "troubleshooting"],
    ] as const) {
      expect(resolveRoute(hash).leaf?.id).toBe(leaf);
    }
    expect(canonicalHash("#/infrastructure/flowtrace")).toBe("#/investigate/flowtrace");
    expect(canonicalHash("#/infrastructure/wan-circuits")).toBe("#/investigate/wan-paths");
  });
});
