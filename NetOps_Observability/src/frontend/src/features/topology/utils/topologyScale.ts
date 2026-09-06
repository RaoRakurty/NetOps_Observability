// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// topologyScale.ts — the interactive-canvas scale policy, as PURE functions.
//
// The React Flow canvas draws every node as a live HTML card, so past a ceiling
// (MAX_CANVAS_NODES) a raw fabric is unusable — it used to hit a dead-end "N nodes
// — too many for the interactive canvas" card. The real fix is to AGGREGATE: a
// large graph is shown as its GROUPS (auto-collapsed via the existing collapse
// mechanism), which is a few dozen aggregate cards — interactive and well under
// the ceiling — and the operator drills in by expanding a group.
//
// The number that actually matters for the canvas is NOT view.nodes.length but the
// count of nodes React Flow RENDERS given which groups are collapsed. These helpers
// compute that, decide whether a view can be shown as a sub-ceiling aggregate, and
// guard a drill-down expansion from blowing the ceiling with one huge group. Kept
// pure (no React) so the policy is unit-testable in isolation.

import type { TopologyView } from "../api/topologyTypes";

/**
 * The number of React Flow nodes a view renders for a given collapse state:
 * one node per group (a container when expanded, an aggregate card when
 * collapsed) PLUS every device that is NOT hidden inside a collapsed group.
 * This — not the raw node count — is what the interactive canvas has to draw.
 *
 * A device counted as hidden only if its group is collapsed; ungrouped devices
 * are always visible. `Math.max(0, …)` guards the (malformed) case of a node
 * listed as a child of more than one collapsed group.
 */
export function renderedNodeCount(view: TopologyView, collapsed: ReadonlySet<string>): number {
  let hidden = 0;
  for (const g of view.groups) if (collapsed.has(g.id)) hidden += g.children.length;
  const visibleDevices = Math.max(0, view.nodes.length - hidden);
  return view.groups.length + visibleDevices;
}

/** Every group id — i.e. the fully-collapsed (maximally-aggregated) set. */
export function allGroupIds(view: TopologyView): Set<string> {
  return new Set(view.groups.map((g) => g.id));
}

/**
 * Can an over-ceiling view be shown as an interactive AGGREGATE (group cards)
 * that fits under `max`? It needs a grouping dimension (≥1 group) AND a
 * fully-collapsed render count within budget. When this is false — no groups,
 * or even fully collapsed the group + ungrouped-device count still exceeds the
 * ceiling — the last-resort "too many nodes" card applies instead.
 */
export function canAggregateUnderCeiling(view: TopologyView, max: number): boolean {
  if (view.groups.length === 0) return false;
  return renderedNodeCount(view, allGroupIds(view)) <= max;
}

/**
 * Would EXPANDING `groupId` (revealing its devices) push the rendered node count
 * over `max`? Used to keep a single huge group collapsed — a group whose devices
 * alone blow the ceiling can never be drawn inline; the operator is steered to
 * the WebGL overview / search for it instead.
 */
export function expansionWouldExceed(
  view: TopologyView,
  collapsed: ReadonlySet<string>,
  groupId: string,
  max: number,
): boolean {
  const next = new Set(collapsed);
  next.delete(groupId);
  return renderedNodeCount(view, next) > max;
}
