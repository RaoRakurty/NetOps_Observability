// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// groupDrag.ts — moving a site box (owner, 2026-11-23: "I cannot drag a box
// separately from the devices — they are all glued together").
//
// A box is not a free-floating shape: it is DRAWN around its members. So
// dragging a box moves its members (every device below it, nested boxes
// included) by the drag delta, and the box is re-drawn around them where they
// landed. Each box moves on its own; a device can still be dragged on its own
// and its box re-fits around it.
//
// The one geometry rule this needs: a container's rectangle comes from the
// layout engine (ELK / wanOverlayLayout) only while NONE of its members has been
// moved by hand. Once one has, the solved rectangle describes a place the
// members no longer are, so it is dropped and the renderer draws the box around
// the members instead (topologyToReactFlow's fallback). Only device positions
// are ever persisted (savedLayoutStore) — never a box — so a reload re-derives
// every box from the same rule.
//
// Pure: no React, no storage.

import type { TopologyView } from "../api/topologyTypes";
import type { LayoutResult, NodePosition } from "./layoutTypes";

/** Every container below `groupId` (nested via parent_id), bounded against cycles. */
function childGroups(view: TopologyView): Map<string, string[]> {
  const out = new Map<string, string[]>();
  const ids = new Set(view.groups.map((g) => g.id));
  for (const g of view.groups) {
    const p = g.parent_id;
    if (!p || p === g.id || !ids.has(p)) continue;
    out.set(p, [...(out.get(p) ?? []), g.id]);
  }
  return out;
}

/** The devices and containers below `groupId`. */
export function groupDescendants(view: TopologyView, groupId: string): { nodes: string[]; groups: string[] } {
  const byId = new Map(view.groups.map((g) => [g.id, g]));
  const kids = childGroups(view);
  const nodes: string[] = [];
  const groups: string[] = [];
  const seen = new Set<string>([groupId]);
  const stack = [groupId];
  while (stack.length) {
    const cur = stack.pop() as string;
    for (const c of byId.get(cur)?.children ?? []) nodes.push(c);
    for (const k of kids.get(cur) ?? []) {
      if (seen.has(k)) continue;
      seen.add(k);
      groups.push(k);
      stack.push(k);
    }
  }
  return { nodes: [...new Set(nodes)], groups };
}

/** The containers a device sits in, innermost first. */
export function ancestorGroups(view: TopologyView, nodeId: string): string[] {
  const byId = new Map(view.groups.map((g) => [g.id, g]));
  const out: string[] = [];
  let cur = view.groups.find((g) => g.children.includes(nodeId))?.id;
  while (cur && !out.includes(cur) && out.length < 16) {
    out.push(cur);
    cur = byId.get(cur)?.parent_id;
  }
  return out;
}

/**
 * Drop the solved rectangle of every container that has a hand-placed member,
 * so it is drawn around where its members are. `pinned` = the device ids whose
 * positions came from the operator, not the layout engine.
 */
export function dropMovedGroupRects(view: TopologyView, positions: LayoutResult, pinned: Iterable<string>): LayoutResult {
  const out: LayoutResult = { ...positions };
  for (const id of pinned) {
    for (const g of ancestorGroups(view, id)) delete out[g];
  }
  return out;
}

/**
 * Move a container by (dx, dy): every device below it moves by the delta and the
 * container (and every container inside it) loses its solved rectangle, so all
 * of them are re-drawn around the moved devices. Returns the new positions and
 * the devices that moved — exactly the positions to persist.
 */
export function moveGroup(
  view: TopologyView,
  positions: LayoutResult,
  groupId: string,
  dx: number,
  dy: number,
): { positions: LayoutResult; moved: Record<string, NodePosition> } {
  const out: LayoutResult = { ...positions };
  const moved: Record<string, NodePosition> = {};
  if (!Number.isFinite(dx) || !Number.isFinite(dy)) return { positions: out, moved };
  const desc = groupDescendants(view, groupId);
  for (const id of desc.nodes) {
    const p = positions[id];
    if (!p) continue;
    const np = { x: p.x + dx, y: p.y + dy };
    out[id] = np;
    moved[id] = np;
  }
  // The box itself, every box inside it, and every box it sits in (their member
  // moved too) are re-drawn around the devices.
  const byId = new Map(view.groups.map((g) => [g.id, g]));
  const outer: string[] = [];
  let cur = byId.get(groupId)?.parent_id;
  while (cur && cur !== groupId && !outer.includes(cur) && outer.length < 16) {
    outer.push(cur);
    cur = byId.get(cur)?.parent_id;
  }
  for (const g of [groupId, ...desc.groups, ...outer]) delete out[g];
  return { positions: out, moved };
}
