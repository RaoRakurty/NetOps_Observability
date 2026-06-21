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
 * Point where the line from `node`'s centre toward `other`'s centre crosses
 * `node`'s rectangle border. Scaling the centre→centre vector to the nearer of the
 * half-width / half-height bounds lands exactly on the border (standard
 * rectangle-ray intersection).
 */
export function nodeBorderPoint(node: InternalNode<Node>, other: InternalNode<Node>): Pt {
  const w = (node.measured?.width ?? 0) / 2;
  const h = (node.measured?.height ?? 0) / 2;
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
  const x = node.internals.positionAbsolute.x ?? 0;
  const y = node.internals.positionAbsolute.y ?? 0;
  const w = node.measured?.width ?? 0;
  if (p.x <= x + 1) return Position.Left;
  if (p.x >= x + w - 1) return Position.Right;
  if (p.y <= y + 1) return Position.Top;
  return Position.Bottom;
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
