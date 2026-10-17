// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

import { describe, it, expect } from "vitest";
import type { TopologyView } from "../api/topologyTypes";
import { wanOverlayLayout, gridCols } from "./wanOverlayLayout";
import { CARD_W, CARD_H } from "../renderers/react-flow/nodes/DeviceNode";

function estate(sites: number[], transports = ["biz-internet", "mpls"]): TopologyView {
  const nodes: TopologyView["nodes"] = [];
  const groups: NonNullable<TopologyView["groups"]> = [];
  transports.forEach((t) => nodes.push({ id: `wan:x:${t}`, label: `WAN transport · ${t}`, kind: "wan", health: "ok", confidence: 0.6, resolved: true, evidence: [] } as never));
  sites.forEach((n, s) => {
    const children: string[] = [];
    for (let i = 0; i < n; i++) {
      const id = `s${s}-e${i}`;
      children.push(id);
      nodes.push({ id, label: id, kind: "router", health: "ok", confidence: 1, resolved: true, evidence: [] } as never);
    }
    groups.push({ id: `site-${s}`, label: `SD-WAN site ${s}`, group_type: "site", children, health: "ok", collapsed: false } as never);
  });
  return { view_id: "v", mode: "explore", layout_type: "wan_overlay", generated_at: "", nodes, edges: [], groups, overlays: [] } as TopologyView;
}

type R = { x: number; y: number; w: number; h: number };
const rect = (p: { x: number; y: number; w?: number; h?: number }): R => ({ x: p.x, y: p.y, w: p.w ?? CARD_W, h: p.h ?? CARD_H });
const overlap = (a: R, b: R) => a.x < b.x + b.w && b.x < a.x + a.w && a.y < b.y + b.h && b.y < a.y + a.h;

describe("wanOverlayLayout — SD-WAN as sites around shared transports", () => {
  it("puts the transports in one row and the sites above and below it", () => {
    const view = estate([1, 2, 2, 1, 3, 1]);
    const r = wanOverlayLayout(view);
    const t = view.nodes.filter((n) => n.kind === "wan").map((n) => r[n.id]);
    expect(new Set(t.map((p) => p.y))).toEqual(new Set([0]));
    const ys = (view.groups ?? []).map((g) => r[g.id]);
    expect(ys.some((p) => p.y + (p.h ?? 0) <= 0)).toBe(true); // a shelf above
    expect(ys.some((p) => p.y >= CARD_H)).toBe(true); // a shelf below
  });

  it("never overlaps two site boxes, a box and a transport, or a member and its box edge", () => {
    const view = estate([1, 4, 9, 2, 16, 1, 3, 7, 2, 2, 5]);
    const r = wanOverlayLayout(view);
    const boxes = (view.groups ?? []).map((g) => rect(r[g.id]));
    const transports = view.nodes.filter((n) => n.kind === "wan").map((n) => rect(r[n.id]));
    for (let i = 0; i < boxes.length; i++) {
      for (let j = i + 1; j < boxes.length; j++) expect(overlap(boxes[i], boxes[j])).toBe(false);
      for (const t of transports) expect(overlap(boxes[i], t)).toBe(false);
    }
    for (const g of view.groups ?? []) {
      const b = rect(r[g.id]);
      for (const m of g.children ?? []) {
        const c = rect(r[m]);
        expect(c.x >= b.x && c.y >= b.y && c.x + c.w <= b.x + b.w && c.y + c.h <= b.y + b.h).toBe(true);
      }
    }
  });

  it("sizes each site box to its members, so a site grows as it grows", () => {
    const r = wanOverlayLayout(estate([1, 12]));
    const small = r["site-0"];
    const big = r["site-1"];
    expect((big.w ?? 0) * (big.h ?? 0)).toBeGreaterThan((small.w ?? 0) * (small.h ?? 0));
    expect(gridCols(12)).toBe(4);
    expect(gridCols(2)).toBe(2);
  });

  it("is deterministic: the same view always draws the same picture", () => {
    expect(wanOverlayLayout(estate([3, 1, 2]))).toEqual(wanOverlayLayout(estate([3, 1, 2])));
  });

  it("packs a large estate into a stage-shaped area, not a ribbon", () => {
    const view = estate(Array.from({ length: 1000 }, (_, i) => 1 + (i % 3)));
    const r = wanOverlayLayout(view);
    const all = Object.values(r).map(rect);
    const minX = Math.min(...all.map((p) => p.x));
    const maxX = Math.max(...all.map((p) => p.x + p.w));
    const minY = Math.min(...all.map((p) => p.y));
    const maxY = Math.max(...all.map((p) => p.y + p.h));
    const aspect = (maxX - minX) / (maxY - minY);
    expect(aspect).toBeGreaterThan(0.8);
    expect(aspect).toBeLessThan(4);
  });
});
