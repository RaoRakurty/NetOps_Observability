// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// The layout cache must key on the GROUP structure, not only on the node and
// edge ids: two views with the same devices and links but different grouping
// (the site lens on vs off, a device moved to another site) used to share one
// cached layout, so the boxes were drawn around positions computed for the
// other grouping.

import { describe, it, expect } from "vitest";
import type { TopologyView } from "../api/topologyTypes";
import { groupSignature, layoutView, viewSignature } from "./elkLayout";

type G = { id: string; label?: string; children: string[]; parent_id?: string; collapsed?: boolean; health?: string };

function view(groups: G[] | null, layout_type = "wan_overlay"): TopologyView {
  const nodes = ["wan:x:inet", "a1", "a2", "b1", "b2"].map((id) => ({
    id, label: id, kind: id.startsWith("wan:") ? "wan" : "router", health: "ok", confidence: 1, resolved: true, evidence: [],
  }));
  return {
    view_id: "v", mode: "explore", layout_type, generated_at: "", nodes, edges: [], overlays: [],
    groups: (groups ?? []).map((g) => ({
      id: g.id, label: g.label ?? g.id, group_type: "site", children: g.children,
      health: g.health ?? "ok", collapsed: g.collapsed ?? false, parent_id: g.parent_id,
    })),
  } as unknown as TopologyView;
}

const twoSites: G[] = [{ id: "site:a", children: ["a1", "a2"] }, { id: "site:b", children: ["b1", "b2"] }];

describe("groupSignature — what about the boxes moves the geometry", () => {
  it("is the same for an identical grouping, whatever the group or member order", () => {
    const reordered: G[] = [{ id: "site:b", children: ["b2", "b1"] }, { id: "site:a", children: ["a2", "a1"] }];
    expect(groupSignature(view(reordered))).toBe(groupSignature(view(twoSites)));
  });

  it("differs when grouping is on vs off, though the node and edge ids are equal", () => {
    expect(viewSignature(view(null))).toBe(viewSignature(view(twoSites)));
    expect(groupSignature(view(null))).not.toBe(groupSignature(view(twoSites)));
  });

  it("differs when a device moves to another site", () => {
    const moved: G[] = [{ id: "site:a", children: ["a1"] }, { id: "site:b", children: ["a2", "b1", "b2"] }];
    expect(groupSignature(view(moved))).not.toBe(groupSignature(view(twoSites)));
  });

  it("differs on a label, a parent or a collapsed box — each changes a box's size or place", () => {
    const base = groupSignature(view(twoSites));
    expect(groupSignature(view([{ ...twoSites[0], label: "Site 50 · from vManage" }, twoSites[1]]))).not.toBe(base);
    expect(groupSignature(view([{ ...twoSites[0], parent_id: "region:1" }, twoSites[1]]))).not.toBe(base);
    expect(groupSignature(view([{ ...twoSites[0], collapsed: true }, twoSites[1]]))).not.toBe(base);
  });

  it("ignores health, so a status change never throws a layout away", () => {
    expect(groupSignature(view([{ ...twoSites[0], health: "critical" }, twoSites[1]])))
      .toBe(groupSignature(view(twoSites)));
  });
});

describe("layoutView — the cache keys on the grouping", () => {
  it("reuses the layout for the same grouping and recomputes it for a different one", async () => {
    const first = await layoutView(view(twoSites));
    expect(await layoutView(view(twoSites))).toBe(first); // an unrelated re-render hits
    const moved: G[] = [{ id: "site:a", children: ["a1"] }, { id: "site:b", children: ["a2", "b1", "b2"] }];
    const regrouped = await layoutView(view(moved));
    expect(regrouped).not.toBe(first);
    // The regrouped layout puts a2 inside site:b's box, not where site:a had it.
    const b = regrouped["site:b"] as { x: number; y: number; w?: number; h?: number };
    const a2 = regrouped["a2"];
    expect(a2.x).toBeGreaterThanOrEqual(b.x);
    expect(a2.x).toBeLessThan(b.x + (b.w ?? 0));
  });
});
