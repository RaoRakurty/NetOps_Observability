// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

import { describe, expect, it } from "vitest";
import { detectArchetype, circularLayout, archetypeLayout, autoArchetype } from "./topologyArchetype";
import { zoneOfNode } from "./topologyDomains";
import type { TopologyView, TopologyNode } from "../api/topologyTypes";

function mkView(
  nodes: Array<Partial<TopologyNode> & { id: string }>,
  edges: Array<[string, string]>,
): TopologyView {
  return {
    view_id: "t", mode: "explore", scope: { tenant_id: "t" }, layout_type: "spine_leaf",
    generated_at: new Date().toISOString(),
    nodes: nodes.map((n) => ({
      label: n.id, kind: "switch", health: "ok", confidence: 1, resolved: true, ...n,
    })) as TopologyNode[],
    edges: edges.map(([s, t], i) => ({
      id: `e${i}`, source: s, target: t, relationship: "connected_to", status: "up",
    })),
    groups: [], overlays: [],
  } as unknown as TopologyView;
}

describe("detectArchetype", () => {
  it("recognizes a ring (every device degree 2, one loop)", () => {
    const v = mkView(
      ["a", "b", "c", "d", "e"].map((id) => ({ id })),
      [["a", "b"], ["b", "c"], ["c", "d"], ["d", "e"], ["e", "a"]],
    );
    const r = detectArchetype(v);
    expect(r.archetype).toBe("ring");
    expect(r.confidence).toBe(1);
  });

  it("recognizes a bus (a chained line with two ends)", () => {
    const v = mkView(
      ["a", "b", "c", "d"].map((id) => ({ id })),
      [["a", "b"], ["b", "c"], ["c", "d"]],
    );
    expect(detectArchetype(v).archetype).toBe("bus");
  });

  it("recognizes a star (one hub, single-homed spokes)", () => {
    const v = mkView(
      ["hub", "s1", "s2", "s3", "s4", "s5"].map((id) => ({ id })),
      [["hub", "s1"], ["hub", "s2"], ["hub", "s3"], ["hub", "s4"], ["hub", "s5"]],
    );
    const r = detectArchetype(v);
    expect(r.archetype).toBe("star");
    expect(r.confidence).toBe(1);
  });

  it("recognizes leaf-spine from roles + crossing links", () => {
    const v = mkView(
      [
        { id: "sp1", role: "spine" }, { id: "sp2", role: "spine" },
        { id: "lf1", role: "leaf" }, { id: "lf2", role: "leaf" }, { id: "lf3", role: "leaf" },
      ],
      [["sp1", "lf1"], ["sp1", "lf2"], ["sp1", "lf3"], ["sp2", "lf1"], ["sp2", "lf2"], ["sp2", "lf3"]],
    );
    expect(detectArchetype(v).archetype).toBe("leaf_spine");
  });

  it("recognizes a full mesh", () => {
    const ids = ["a", "b", "c", "d", "e"];
    const edges: Array<[string, string]> = [];
    for (let i = 0; i < ids.length; i++) for (let j = i + 1; j < ids.length; j++) edges.push([ids[i], ids[j]]);
    const r = detectArchetype(mkView(ids.map((id) => ({ id })), edges));
    expect(r.archetype).toBe("mesh");
    expect(r.confidence).toBe(1);
  });

  it("stays honest on shapeless graphs and excludes boundary nodes", () => {
    const v = mkView(
      [{ id: "a" }, { id: "b" }, { id: "c" }, { id: "ext", kind: "unresolved" }],
      [["a", "b"], ["a", "c"], ["a", "ext"]],
    );
    // a/b/c alone form a star-of-3; the unresolved node must not distort degrees.
    const r = detectArchetype(v);
    expect(r.archetype).not.toBe("irregular");
    expect(r.reason.length).toBeGreaterThan(0);
  });
});

describe("archetype layouts", () => {
  it("ring layout places every node (boundary nodes parked, never hidden)", () => {
    const v = mkView(
      [...["a", "b", "c", "d"].map((id) => ({ id })), { id: "ext", kind: "unresolved" as const }],
      [["a", "b"], ["b", "c"], ["c", "d"], ["d", "a"]],
    );
    const pos = circularLayout(v, true);
    for (const n of v.nodes) expect(pos[n.id]).toBeDefined();
    // deterministic: same input → same output (no physics).
    expect(circularLayout(v, true)).toEqual(pos);
  });

  it("returns null for ELK-handled archetypes", () => {
    const v = mkView([{ id: "a" }, { id: "b" }, { id: "c" }], [["a", "b"]]);
    expect(archetypeLayout(v, "leaf_spine")).toBeNull();
    expect(archetypeLayout(v, "irregular")).toBeNull();
  });
});

describe("zoneOfNode (seam vocabulary §4.0)", () => {
  const n = (p: Partial<TopologyNode> & { id: string }): TopologyNode =>
    ({ label: p.id, kind: "switch", ...p }) as TopologyNode;

  it("segregates by ownership border", () => {
    expect(zoneOfNode(n({ id: "vpc-1", kind: "cloud" }))).toBe("Cloud");
    expect(zoneOfNode(n({ id: "dx-edge-1", label: "dx-edge-1" }))).toBe("AWS Direct Connect");
    expect(zoneOfNode(n({ id: "gw", label: "expressroute-gw" }))).toBe("Azure ExpressRoute");
    expect(zoneOfNode(n({ id: "t1", label: "isp-transit-1" }))).toBe("ISP");
    expect(zoneOfNode(n({ id: "sp1", label: "spine-1", role: "spine" }))).toBe("Data Center");
    expect(zoneOfNode(n({ id: "sw1", label: "access-sw-1", role: "access" }))).toBe("LAN");
  });

  it("never asserts an owner for an unresolved boundary", () => {
    expect(zoneOfNode(n({ id: "x", kind: "unresolved" }))).toBe("");
  });
});

// The lab's SD-WAN estate as the api serves it (2026-11-23): 8 branch edges at
// 7 controller-reported site ids, two transports every edge attaches to, and a
// full mesh of overlay tunnels. Auto used to detect it as a dense mesh (0.9)
// and draw a name-sorted circle, so the site boxes the api sent meant nothing.
function labSdwanView(layout: TopologyView["layout_type"]): TopologyView {
  const edges: Array<[string, string]> = [];
  const sites: Record<string, string> = {
    "vedge-20": "20", "cedge-40": "40", "vedge-51": "50", "vedge-52": "50",
    "cedge-60": "60", "cedge-80": "80", "cedge-81": "81", "vedge-100": "100",
  };
  const ids = Object.keys(sites);
  for (let i = 0; i < ids.length; i++) {
    for (let j = i + 1; j < ids.length; j++) edges.push([ids[i], ids[j]]);
    edges.push([ids[i], "wan:internet"], [ids[i], "wan:mpls"]);
  }
  const v = mkView(
    [...ids.map((id) => ({ id, kind: "router" as const, site: `discovered:t1:sdwan:${sites[id]}` })),
      { id: "wan:internet", kind: "wan" as const }, { id: "wan:mpls", kind: "wan" as const }],
    edges,
  );
  const bySite = new Map<string, string[]>();
  for (const id of ids) bySite.set(sites[id], [...(bySite.get(sites[id]) ?? []), id]);
  v.groups = [...bySite.entries()].map(([sid, children]) => ({
    id: `site:discovered:t1:sdwan:${sid}`, label: `Site ${sid} · from vManage`, group_type: "site",
    children, health: "ok", collapsed: false,
  })) as TopologyView["groups"];
  v.layout_type = layout;
  return v;
}

describe("autoArchetype (Shape: Auto)", () => {
  it("the lab estate really does detect as a confident mesh — the trap", () => {
    const r = detectArchetype(labSdwanView("hierarchical"));
    expect(r.archetype).toBe("mesh");
    expect(r.confidence).toBeGreaterThanOrEqual(0.8);
  });

  it("never arranges a site-grouped view by a shape", () => {
    const v = labSdwanView("hierarchical");
    expect(autoArchetype(v, detectArchetype(v))).toBeNull();
  });

  it("never replaces the WAN picture, grouped or not", () => {
    const v = { ...labSdwanView("wan_overlay"), groups: [] };
    expect(autoArchetype(v, detectArchetype(v))).toBeNull();
  });

  it("still arranges an ungrouped campus by its shape, and one container is not 'grouped'", () => {
    const ring = mkView(
      ["a", "b", "c", "d", "e"].map((id) => ({ id })),
      [["a", "b"], ["b", "c"], ["c", "d"], ["d", "e"], ["e", "a"]],
    );
    expect(autoArchetype(ring, detectArchetype(ring))).toBe("ring");
    ring.groups = [{ id: "site:hq", label: "HQ", group_type: "site", children: ["a", "b", "c", "d", "e"], health: "ok", collapsed: false }] as TopologyView["groups"];
    expect(autoArchetype(ring, detectArchetype(ring))).toBe("ring");
  });

  it("an empty container does not count as a site", () => {
    const ring = mkView(
      ["a", "b", "c", "d", "e"].map((id) => ({ id })),
      [["a", "b"], ["b", "c"], ["c", "d"], ["d", "e"], ["e", "a"]],
    );
    ring.groups = [
      { id: "site:x", label: "x", group_type: "site", children: ["gone"], health: "ok", collapsed: false },
      { id: "site:y", label: "y", group_type: "site", children: ["a"], health: "ok", collapsed: false },
    ] as TopologyView["groups"];
    expect(autoArchetype(ring, detectArchetype(ring))).toBe("ring");
  });

  it("a weak or shapeless verdict picks nothing", () => {
    const v = labSdwanView("hierarchical");
    expect(autoArchetype({ ...v, groups: [] }, { archetype: "mesh", confidence: 0.5, reason: "" })).toBeNull();
    expect(autoArchetype({ ...v, groups: [] }, { archetype: "irregular", confidence: 1, reason: "" })).toBeNull();
    expect(autoArchetype({ ...v, groups: [] }, null)).toBeNull();
  });
});
