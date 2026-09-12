// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// floatingEdge.test.ts — the pure border-anchor geometry. Guards that links anchor
// to the side facing the neighbour (so they fan out, not stack), independent of
// React Flow. "no bugs at ground level": exercises the four sides + degenerate cases.

import { describe, it, expect } from "vitest";
import { Position } from "@xyflow/react";
import { getEdgeParams, nodeBorderPoint, sideFor } from "./floatingEdge";

// minimal InternalNode stub: top-left position + measured size (what the geometry uses)
function node(x: number, y: number, w = 100, h = 40) {
  return { internals: { positionAbsolute: { x, y } }, measured: { width: w, height: h } } as never;
}

describe("floatingEdge geometry", () => {
  it("anchors to the side of each node that faces the other", () => {
    const a = node(0, 0); // centre (50,20)
    const b = node(300, 0); // centre (350,20) — directly to the right
    const p = getEdgeParams(a, b);
    // a's anchor on its RIGHT border, b's on its LEFT border
    expect(p.sx).toBeCloseTo(100); // a right edge x = 0 + width
    expect(p.tx).toBeCloseTo(300); // b left edge x
    expect(p.sourcePos).toBe(Position.Right);
    expect(p.targetPos).toBe(Position.Left);
    // both anchors sit on the shared centre line (y of the centres)
    expect(p.sy).toBeCloseTo(20);
    expect(p.ty).toBeCloseTo(20);
  });

  it("anchors top/bottom for a vertical relationship (a tree parent above its child)", () => {
    const parent = node(0, 0); // centre (50,20)
    const child = node(0, 300); // centre (50,320) — directly below
    const p = getEdgeParams(parent, child);
    expect(p.sourcePos).toBe(Position.Bottom);
    expect(p.targetPos).toBe(Position.Top);
    expect(p.sy).toBeCloseTo(40); // parent bottom edge y = 0 + height
    expect(p.ty).toBeCloseTo(300); // child top edge y
  });

  it("two neighbours on different sides → different anchor points (fan-out, not stacked)", () => {
    const hub = node(0, 0);
    const right = node(300, 0);
    const below = node(0, 300);
    const toRight = getEdgeParams(hub, right);
    const toBelow = getEdgeParams(hub, below);
    // hub's anchor differs per neighbour — the whole point of floating edges
    expect(toRight.sourcePos).not.toBe(toBelow.sourcePos);
    expect([toRight.sx, toRight.sy]).not.toEqual([toBelow.sx, toBelow.sy]);
  });

  it("coincident nodes degrade to the centre without throwing", () => {
    const a = node(0, 0);
    const b = node(0, 0);
    expect(nodeBorderPoint(a, b)).toEqual({ x: 50, y: 20 });
  });

  it("sideFor classifies a point on each border", () => {
    const n = node(0, 0, 100, 40);
    expect(sideFor(n, { x: 0, y: 20 })).toBe(Position.Left);
    expect(sideFor(n, { x: 100, y: 20 })).toBe(Position.Right);
    expect(sideFor(n, { x: 50, y: 0 })).toBe(Position.Top);
    expect(sideFor(n, { x: 50, y: 40 })).toBe(Position.Bottom);
  });
});

// The badge tier draws a 36px glyph centred in the SAME 120×56 cell the card
// tier fills — the cell is fixed so changing zoom never reflows the layout.
// Anchoring to that cell left far-zoom edges hanging ~42px off the visible
// badge, which is exactly the tier used for the overview.
describe("badge-tier anchoring", () => {
  function badge(x: number, y: number) {
    return {
      internals: { positionAbsolute: { x, y } },
      measured: { width: 120, height: 56 },
      data: { tier: "badge" },
    } as never;
  }
  function card(x: number, y: number) {
    return {
      internals: { positionAbsolute: { x, y } },
      measured: { width: 120, height: 56 },
      data: { tier: "card" },
    } as never;
  }

  it("anchors a badge to the GLYPH, not the layout cell", () => {
    const a = badge(0, 0); // centre (60,28); glyph spans x 42..78
    const b = badge(400, 0); // directly to the right
    const p = getEdgeParams(a, b);
    // Right edge of the 36px glyph, not the 120px cell.
    expect(p.sx).toBeCloseTo(78);
    expect(p.tx).toBeCloseTo(442);
    // Still the correct sides — the inset must not confuse side classification.
    expect(p.sourcePos).toBe(Position.Right);
    expect(p.targetPos).toBe(Position.Left);
  });

  it("leaves the card tier anchored to its full cell", () => {
    const a = card(0, 0);
    const b = card(400, 0);
    const p = getEdgeParams(a, b);
    expect(p.sx).toBeCloseTo(120); // full cell width
    expect(p.tx).toBeCloseTo(400);
  });

  it("classifies all four sides correctly for a badge", () => {
    const c = badge(0, 0); // centre (60,28)
    for (const [ox, oy, want] of [
      [400, 0, Position.Right],
      [-400, 0, Position.Left],
      [0, -400, Position.Top],
      [0, 400, Position.Bottom],
    ] as const) {
      const other = badge(ox, oy);
      const pt = nodeBorderPoint(c, other);
      expect(sideFor(c, pt)).toBe(want);
    }
  });

  it("never anchors outside the layout cell", () => {
    const a = badge(0, 0);
    const b = badge(400, 300);
    const pt = nodeBorderPoint(a, b);
    expect(pt.x).toBeGreaterThanOrEqual(0);
    expect(pt.x).toBeLessThanOrEqual(120);
    expect(pt.y).toBeGreaterThanOrEqual(0);
    expect(pt.y).toBeLessThanOrEqual(56);
  });
});
