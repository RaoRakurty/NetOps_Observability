// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// carryMeasured.ts — keep React Flow's measurement on nodes the canvas re-derives.
//
// The canvas rebuilds its node array from the domain view on every UI change that
// touches a node (zoom-level bucket, hover spotlight, selection, overlay, the cloud
// half landing on its own read). Those are FRESH objects, and a fresh object has no
// `measured` field. @xyflow/react 12 reads a user node without `measured` as "this
// node was re-initialised": it throws away the node's handle bounds and waits for a
// ResizeObserver pass to measure it again. Until then every edge touching the node
// is not drawn at all (getEdgePosition → null), so each re-derive blanked EVERY
// link on the canvas for a frame or ten — and when a second re-derive landed in the
// same React commit as that measurement pass, the node stayed unmeasured for good
// (its size never changes, so the observer never fires again): nodes on screen, no
// links, which is what the cloudDomain e2e caught in CI.
//
// Carrying the last `measured` onto the re-derived node keeps React Flow's stored
// handle bounds (it keeps them whenever the incoming node has `measured`), so the
// links never blink. A node whose SIZE really changes is still re-measured: the
// ResizeObserver stays attached to every node element and reports the new size.

import type { Node } from "@xyflow/react";

/**
 * Return `next` with each node's `measured` copied from the node of the same id in
 * `prev` when that node has been measured (both dimensions present) and the
 * incoming node does not carry its own measurement. Nodes are copied only when
 * something is carried; everything else is returned as-is. Pure.
 */
export function carryMeasured<T extends Node>(next: readonly T[], prev: readonly T[]): T[] {
  const measuredById = new Map<string, NonNullable<Node["measured"]>>();
  for (const n of prev) {
    const m = n.measured;
    if (m && typeof m.width === "number" && typeof m.height === "number") measuredById.set(n.id, m);
  }
  if (measuredById.size === 0) return [...next];
  return next.map((n) => {
    if (n.measured) return n;
    const m = measuredById.get(n.id);
    return m ? { ...n, measured: { width: m.width, height: m.height } } : n;
  });
}
