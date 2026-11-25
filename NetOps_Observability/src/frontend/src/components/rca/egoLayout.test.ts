// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// egoLayout.test.ts — P-7EE84E: "network causal topology is crammed on screen
// but fine in the PDF". The ego-graph geometry is text-aware: every node's
// footprint (circle + mark + label + role) is measured at the SCREEN's text
// size, nothing overlaps, the picture stays 760 wide, and the positions match
// the server document's twin (rca_report_topology_layout.go) through the
// shared golden it writes.

import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { egoGeometry, egoFootprint, egoMarkText, egoBox, egoBoxesOverlap, deriveContextModel } from "./pathModel";
import { readTopologyContext, type TopologyContext } from "./topologyContext";

const here = dirname(fileURLToPath(import.meta.url));
const GOLDEN = resolve(here, "../../../../backend/internal/rca/testdata/topoctx/ego_layout.golden.json");

interface GoldenCase { name: string; context: unknown; w: number; h: number; pos: Record<string, [number, number]> }

const read = (v: unknown): TopologyContext => {
  const tc = readTopologyContext(v);
  if (!tc) throw new Error("context did not validate");
  return tc;
};

function role(n: TopologyContext["nodes"][number]): string {
  const sub = (n.role ?? "").replace(/_/g, " ");
  return !n.managed && !sub ? "not in inventory" : sub;
}

function assertClean(tc: TopologyContext, label: string) {
  const { w, h, pos } = egoGeometry(tc);
  expect(w, label).toBe(760);
  const boxes = tc.nodes.map((n) => {
    const p = pos.get(n.id);
    expect(p, `${label}: ${n.id} placed`).toBeDefined();
    return { id: n.id, b: egoBox(p![0], p![1], egoFootprint(n.label, role(n), egoMarkText(tc, n.id), n.anchor)) };
  });
  for (const { id, b } of boxes) {
    expect(b.x0 >= -0.01 && b.y0 >= -0.01 && b.x1 <= w + 0.01 && b.y1 <= h + 0.01, `${label}: ${id} inside ${w}x${h}`).toBe(true);
  }
  for (let i = 0; i < boxes.length; i++) {
    for (let j = i + 1; j < boxes.length; j++) {
      expect(egoBoxesOverlap(boxes[i].b, boxes[j].b), `${label}: ${boxes[i].id} × ${boxes[j].id}`).toBe(false);
    }
  }
}

// Same shape as the Go test's genEgoContext: long labels/roles, every anchor
// linked to every neighbour, anomalous interfaces on anchors and every third
// neighbour.
function gen(anchors: number, neigh: number, marks: boolean): TopologyContext {
  const nodes: unknown[] = [], edges: unknown[] = [], faults: unknown[] = [];
  for (let i = 0; i < anchors; i++) {
    const id = `anchor-${i}`;
    nodes.push({ id, label: `core-router-${String(i).padStart(2, "0")}-very-long-hostname`, role: "dc_spine_border_router_x", source: "inventory", anchor: true, managed: true });
    if (marks) {
      faults.push({ target_type: "interface", target_id: `${id}:GigabitEthernet0/0/1`, device: id, port: "GigabitEthernet0/0/1", kinds: ["link_down"], peak_severity: "crit" });
      faults.push({ target_type: "interface", target_id: `${id}:TenGigE0/1/0/3`, device: id, port: "TenGigE0/1/0/3", kinds: ["if_errors"], peak_severity: "warn" });
    }
  }
  for (let i = 0; i < neigh; i++) {
    const id = `n-${i}`;
    const managed = i % 5 !== 0;
    nodes.push({ id, label: `branch-site-${String(i).padStart(2, "0")}-edge-router`, role: managed ? "wan_edge_router_branch_x" : undefined, source: "lldp", managed });
    if (marks && i % 3 === 0) faults.push({ target_type: "interface", target_id: `${id}:Tunnel100`, device: id, port: "Tunnel100", kinds: ["tunnel_down"], peak_severity: "high" });
  }
  for (let a = 0; a < anchors; a++) for (let i = 0; i < neigh; i++) edges.push({ id: `e-${a}-${i}`, a: `anchor-${a}`, b: `n-${i}`, relationship: "l3", sources: ["lldp"], freshness: "current" });
  if (anchors === 0 && neigh > 1) edges.push({ id: "e-n", a: "n-0", b: "n-1", relationship: "l3", sources: ["lldp"], freshness: "current" });
  return read({ state: "topology_only", nodes, edges, faults, causal: [], sources: [] });
}

// The full grid is 7 × 30 × 2 = 420 topologies, each an O(n²) pairwise overlap
// check. It is deterministic CPU work, not a race: measured 2.25 s at host load 16
// and over vitest's 5 s default at load ~21 (2026-11-25). The grid stays whole —
// thinning it would drop shapes the guarantee exists for — so this one test gets
// an explicit budget: ~13× the loaded measurement, still a hard stop on a hang.
const FULL_GRID_TIMEOUT_MS = 30_000;

describe("ego-graph geometry — P-7EE84E", () => {
  it("never overlaps at the screen's text size (0–6 anchors × 1–30 neighbours, with and without marks)", () => {
    for (let a = 0; a <= 6; a++) for (let n = 1; n <= 30; n++) for (const m of [false, true]) assertClean(gen(a, n, m), `a=${a} n=${n} marks=${m}`);
  }, FULL_GRID_TIMEOUT_MS);

  it("matches the server document's positions (shared golden written by the Go twin)", () => {
    const golden = JSON.parse(readFileSync(GOLDEN, "utf8")) as { cases: GoldenCase[] };
    expect(golden.cases.length).toBeGreaterThan(3);
    for (const c of golden.cases) {
      const tc = read(c.context);
      const { w, h, pos } = egoGeometry(tc);
      expect(w, c.name).toBeCloseTo(c.w, 1);
      expect(h, c.name).toBeCloseTo(c.h, 1);
      expect([...pos.keys()].sort(), c.name).toEqual(Object.keys(c.pos).sort());
      for (const [id, [x, y]] of Object.entries(c.pos)) {
        expect(pos.get(id)![0], `${c.name} ${id} x`).toBeCloseTo(x, 1);
        expect(pos.get(id)![1], `${c.name} ${id} y`).toBeCloseTo(y, 1);
      }
      assertClean(tc, c.name);
    }
  });

  it("the drawn ego view uses the geometry: edges join node centres", () => {
    const golden = JSON.parse(readFileSync(GOLDEN, "utf8")) as { cases: GoldenCase[] };
    const lab = golden.cases.find((c) => c.name === "lab-sdwan")!;
    const tc = read(lab.context);
    const ego = deriveContextModel(tc).ego!;
    const at = new Map(ego.nodes.map((n) => [n.node.id, [n.x, n.y]]));
    for (const e of ego.edges) {
      expect([e.x1, e.y1]).toEqual(at.get(e.edge.a));
      expect([e.x2, e.y2]).toEqual(at.get(e.edge.b));
    }
    expect(ego.h).toBeCloseTo(lab.h, 1);
  });

  it("a long device name fits its panel box at the screen size (240px, 24 chars of 14px bold)", () => {
    const golden = JSON.parse(readFileSync(GOLDEN, "utf8")) as { cases: GoldenCase[] };
    const tc = read(golden.cases[0].context);
    const p = deriveContextModel(tc).panels[0];
    expect(p.dev.w).toBe(240);
    expect(8.7 * 24 + 2 * 8).toBeLessThanOrEqual(p.dev.w);
  });
});
