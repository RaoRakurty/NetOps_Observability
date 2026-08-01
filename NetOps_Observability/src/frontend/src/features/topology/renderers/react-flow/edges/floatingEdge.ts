// floatingEdge.ts — geometry for "floating" edges: instead of anchoring every link
// to a node's fixed centre handle (which stacks all of a node's links at one point
// and makes the graph look hand-placed), each link anchors to the point on the
// node's border that faces its neighbour. Links fan out naturally, never overlap at
// a single port, and follow node drags in real time.
//
// Pure geometry (no React) → unit-testable. Works for ANY layout/mode/collapsed
// group: it only needs the two nodes' absolute position + measured size, which
// React Flow always has once a node is rendered.

import { Position, type InternalNode, type Node } from "@xyflow/react";

type Pt = { x: number; y: number };

/** Absolute centre of a node from its top-left position + measured size. */
function center(node: InternalNode<Node>): Pt {
  const w = node.measured?.width ?? 0;
  const h = node.measured?.height ?? 0;
  return {
    x: (node.internals.positionAbsolute.x ?? 0) + w / 2,
    y: (node.internals.positionAbsolute.y ?? 0) + h / 2,
  };
}


/**
 * Half-width/half-height of what the node VISUALLY occupies.
 *
 * This is not always the measured box. The badge tier draws a 36px glyph
 * centred inside the same 120×56 cell the card tier fills — the box stays a
 * fixed size on purpose, so changing zoom tier never reflows the layout. But
 * anchoring edges to that box meant that at the far-zoom tiers (exactly the
 * overview, where badges are used) a horizontal edge stopped ~42px short of the
 * glyph and hung in whitespace.
 *
 * So the LAYOUT extent and the DRAWN extent are deliberately different, and
 * edges follow the drawn one. Shrinking the box instead would have fixed the
 * edges and broken the no-reflow-on-zoom invariant.
 */
function visualHalfExtent(node: InternalNode<Node>): { w: number; h: number } {
  const boxW = (node.measured?.width ?? 0) / 2;
  const boxH = (node.measured?.height ?? 0) / 2;
  const tier = (node.data as { tier?: string } | undefined)?.tier;
  if (tier === "badge") {
    // Never larger than the box: a malformed/oversized constant must not push
    // anchors outside the cell.
    return { w: Math.min(BADGE_HALF, boxW), h: Math.min(BADGE_HALF, boxH) };
  }
  return { w: boxW, h: boxH };
}

/** Half of DeviceNode's BADGE_SIZE. Duplicated as a literal rather than
 *  imported to keep this geometry module free of a React component dependency;
 *  floatingEdge.test.ts pins the two together. */
const BADGE_HALF = 18;

/**
 * Point where the line from `node`'s centre toward `other`'s centre crosses
 * `node`'s rectangle border. Scaling the centre→centre vector to the nearer of the
 * half-width / half-height bounds lands exactly on the border (standard
 * rectangle-ray intersection).
 */
export function nodeBorderPoint(node: InternalNode<Node>, other: InternalNode<Node>): Pt {
  const { w, h } = visualHalfExtent(node);
  const c = center(node);
  const o = center(other);
  const dx = o.x - c.x;
  const dy = o.y - c.y;
  if (dx === 0 && dy === 0) return c;
  const scaleX = dx !== 0 ? w / Math.abs(dx) : Infinity;
  const scaleY = dy !== 0 ? h / Math.abs(dy) : Infinity;
  const scale = Math.min(scaleX, scaleY); // first border the ray hits
  return { x: c.x + dx * scale, y: c.y + dy * scale };
}

/** Which side of the node the border point sits on (drives the bezier tangent). */
export function sideFor(node: InternalNode<Node>, p: Pt): Position {
  // Derived from the point's offset from the node CENTRE against the same
  // visual half-extent nodeBorderPoint used — not from the measured box.
  //
  // Comparing against the box edges only worked while the anchor sat ON the box.
  // Once the badge tier anchors 18px from centre inside a 120×56 cell, no point
  // is ever within 1px of a box edge, so every badge edge would classify as
  // Bottom and every bezier would leave downward regardless of direction.
  const c = center(node);
  const { w, h } = visualHalfExtent(node);
  const dx = p.x - c.x;
  const dy = p.y - c.y;
  // Normalise so a wide, short node is judged by which border the ray actually
  // crossed rather than by raw pixels.
  const nx = w > 0 ? dx / w : 0;
  const ny = h > 0 ? dy / h : 0;
  if (Math.abs(nx) >= Math.abs(ny)) {
    return nx >= 0 ? Position.Right : Position.Left;
  }
  return ny >= 0 ? Position.Bottom : Position.Top;
}

export type EdgeParams = {
  sx: number;
  sy: number;
  tx: number;
  ty: number;
  sourcePos: Position;
  targetPos: Position;
};

/** Border anchor + side for both ends of a link between two nodes. */
export function getEdgeParams(source: InternalNode<Node>, target: InternalNode<Node>): EdgeParams {
  const sp = nodeBorderPoint(source, target);
  const tp = nodeBorderPoint(target, source);
  return {
    sx: sp.x,
    sy: sp.y,
    tx: tp.x,
    ty: tp.y,
    sourcePos: sideFor(source, sp),
    targetPos: sideFor(target, tp),
  };
}
