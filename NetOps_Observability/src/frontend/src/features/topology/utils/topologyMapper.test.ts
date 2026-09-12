// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// normalizeView — the ONE place a renderer-bound TopologyView is made safe.
//
// The rule these tests pin: after normalizeView, the type's promises are TRUE.
// Every consumer downstream (topologyToReactFlow, elkLayout, topologyDomains,
// topologyFilters, the side drawer, …) iterates `groups[].children` and spreads
// `nodes`/`edges` without a guard, because the contract says they are arrays. So
// a producer that breaks the contract must be corrected HERE, once — not caught
// ten times, and never left to throw mid-render.

import { describe, it, expect } from "vitest";
import { normalizeView } from "./topologyMapper";
import type { TopologyView } from "../api/topologyTypes";

// A view exactly as the API can deliver it — including fields the contract calls
// required. `as unknown as TopologyView` is the point: TypeScript cannot police
// what arrives over the wire, which is why this normalization exists.
function wireView(overrides: Record<string, unknown> = {}): TopologyView {
  return {
    view_id: "v", mode: "explore", scope: { tenant_id: "t" },
    layout_type: "cloud_grouped", generated_at: "2026-08-02T00:00:00Z",
    nodes: [], edges: [], groups: [], overlays: ["health"],
    ...overrides,
  } as unknown as TopologyView;
}

describe("normalizeView", () => {
  // THE CLOUD-TAB BLANK-SCREEN DEFECT. A Go nil slice marshals to `null`, and the
  // cloud projection left a REGION group's children nil (a region parents VPC
  // groups via parent_id and owns no member nodes). The SPA threw
  // "g.children is not iterable" on the first group, React unmounted to the root,
  // and the operator saw an empty page — with a 200 and 15 nodes on the wire.
  it("coerces a group's null children to an empty array (the blank Cloud tab)", () => {
    const v = normalizeView(wireView({
      groups: [
        { id: "region:aws:us-west-2", label: "aws · us-west-2", group_type: "region", children: null, health: "unknown", collapsed: false },
        { id: "vpc-1", label: "VPC · vpc-1", group_type: "vpc", parent_id: "region:aws:us-west-2", children: ["n1"], health: "unknown", collapsed: false },
      ],
    }));

    expect(v.groups[0].children).toEqual([]);
    expect(v.groups[1].children).toEqual(["n1"]);
    // The property that actually matters: every consumer can iterate, always.
    expect(() => v.groups.flatMap((g) => [...g.children])).not.toThrow();
  });

  it("coerces a missing children field too, and keeps the rest of the group intact", () => {
    const v = normalizeView(wireView({
      groups: [{ id: "g1", label: "G", group_type: "vpc", parent_id: "r1", health: "critical", collapsed: true }],
    }));

    expect(v.groups[0].children).toEqual([]);
    expect(v.groups[0].parent_id).toBe("r1");
    expect(v.groups[0].health).toBe("critical");
    expect(v.groups[0].collapsed).toBe(true);
  });

  it("survives groups/nodes/edges/overlays arriving as null", () => {
    const v = normalizeView(wireView({ nodes: null, edges: null, groups: null, overlays: null }));
    expect(v.nodes).toEqual([]);
    expect(v.edges).toEqual([]);
    expect(v.groups).toEqual([]);
    expect(v.overlays).toEqual([]);
  });

  it("does not mutate the input view", () => {
    const raw = wireView({
      groups: [{ id: "g1", label: "G", group_type: "region", children: null, health: "unknown", collapsed: false }],
    });
    const before = JSON.stringify(raw);
    normalizeView(raw);
    expect(JSON.stringify(raw)).toBe(before);
  });
});
