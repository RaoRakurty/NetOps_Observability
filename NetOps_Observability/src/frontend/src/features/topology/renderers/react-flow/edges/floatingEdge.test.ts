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
