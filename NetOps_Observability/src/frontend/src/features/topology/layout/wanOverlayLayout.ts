// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// wanOverlayLayout.ts — the SD-WAN / WAN-overlay picture (owner, 2026-10-10):
// the shared transports (Internet, MPLS, LTE …) in the middle, every branch
// SITE as its own box around them, each box sized to what is in it so it grows
// as the site grows. Spine/leaf tiering is the wrong model for a WAN: there is
// no tier between two branches, only the transports they share.
//
// Deterministic and pure (no ELK): the same view always draws the same picture,
// so a 30 s refresh never shuffles the sites.
//
//   1. each site box = a grid of its members (≈ square), padded like every
//      other container (groupGeometry) — a 1-device site is a small box, a
//      20-device site a large one;
//   2. transports in one centred row;
//   3. site boxes shelf-packed to a screen-shaped width, shelves ALTERNATING
//      above and below the transport row, so every site sits close to the
//      transports it attaches to and the canvas fills both directions instead
//      of growing into one long ribbon.

import type { TopologyView } from "../api/topologyTypes";
import type { LayoutResult } from "./layoutTypes";
import { CARD_W, CARD_H } from "../renderers/react-flow/nodes/DeviceNode";
import { GROUP_GAP, GROUP_PAD, LABEL_BAND, GROUP_MIN_W, GROUP_MIN_H } from "./groupGeometry";

const CELL_GAP_X = 28; // between cards inside a site box
const CELL_GAP_Y = 24;
const TRANSPORT_GAP_X = 120; // between transport nodes
const BAND_GAP = 90; // between the transport row and the nearest shelf
const TARGET_ASPECT = 2.0; // ≈ the shape of the stage

type Box = { id: string; w: number; h: number; container: boolean; members: string[] };

const natural = new Intl.Collator(undefined, { numeric: true, sensitivity: "base" });

/** Grid columns for n members: near-square, never wider than it is useful. */
export function gridCols(n: number): number {
  if (n <= 2) return Math.max(1, n);
  return Math.ceil(Math.sqrt(n));
}

export function wanOverlayLayout(view: TopologyView): LayoutResult {
  const out: LayoutResult = {};
  const transports = view.nodes.filter((n) => n.kind === "wan");
  const transportIds = new Set(transports.map((n) => n.id));

  // ── site boxes (containers) + loose nodes ─────────────────────────────────
  const claimed = new Set<string>();
  const nodeIds = new Set(view.nodes.map((n) => n.id));
  const boxes: Box[] = [];
  const groups = [...(view.groups ?? [])].sort((a, b) => natural.compare(a.label || a.id, b.label || b.id));
  for (const g of groups) {
    const members = (g.children ?? []).filter((id) => nodeIds.has(id) && !transportIds.has(id) && !claimed.has(id));
    if (members.length === 0) continue;
    members.sort((a, b) => natural.compare(a, b));
    members.forEach((m) => claimed.add(m));
    const cols = gridCols(members.length);
    const rows = Math.ceil(members.length / cols);
    const w = Math.max(GROUP_MIN_W, 2 * GROUP_PAD + cols * CARD_W + (cols - 1) * CELL_GAP_X);
    const h = Math.max(GROUP_MIN_H, LABEL_BAND + 2 * GROUP_PAD + rows * CARD_H + (rows - 1) * CELL_GAP_Y);
    boxes.push({ id: g.id, w, h, container: true, members });
  }
  const loose = view.nodes
    .filter((n) => !transportIds.has(n.id) && !claimed.has(n.id))
    .sort((a, b) => natural.compare(a.label || a.id, b.label || b.id));
  for (const n of loose) boxes.push({ id: n.id, w: CARD_W, h: CARD_H, container: false, members: [] });

  // ── transport row, centred on x = 0 ───────────────────────────────────────
  const rowW = transports.length * CARD_W + Math.max(0, transports.length - 1) * TRANSPORT_GAP_X;
  transports
    .sort((a, b) => natural.compare(a.label || a.id, b.label || b.id))
    .forEach((t, i) => {
      out[t.id] = { x: -rowW / 2 + i * (CARD_W + TRANSPORT_GAP_X), y: 0 };
    });

  // ── shelf-pack the boxes to a screen-shaped width ─────────────────────────
  const area = boxes.reduce((s, b) => s + (b.w + GROUP_GAP) * (b.h + GROUP_GAP), 0);
  const widest = boxes.reduce((m, b) => Math.max(m, b.w), 0);
  const targetW = Math.max(rowW, widest, Math.sqrt(area * TARGET_ASPECT));
  type Shelf = { items: Box[]; w: number; h: number };
  const shelves: Shelf[] = [];
  let cur: Shelf = { items: [], w: 0, h: 0 };
  for (const b of boxes) {
    const add = (cur.items.length ? GROUP_GAP : 0) + b.w;
    if (cur.items.length && cur.w + add > targetW) {
      shelves.push(cur);
      cur = { items: [], w: 0, h: 0 };
    }
    cur.w += (cur.items.length ? GROUP_GAP : 0) + b.w;
    cur.h = Math.max(cur.h, b.h);
    cur.items.push(b);
  }
  if (cur.items.length) shelves.push(cur);

  // Alternate: shelf 0 above, shelf 1 below, shelf 2 above (further out), …
  let aboveY = -BAND_GAP; // bottom edge of the next shelf above
  let belowY = CARD_H + BAND_GAP; // top edge of the next shelf below
  shelves.forEach((s, i) => {
    const above = i % 2 === 0;
    const top = above ? aboveY - s.h : belowY;
    let x = -s.w / 2;
    for (const b of s.items) {
      // Boxes in a shelf align to the side facing the transports.
      const y = above ? top + (s.h - b.h) : top;
      place(b, x, y);
      x += b.w + GROUP_GAP;
    }
    if (above) aboveY = top - GROUP_GAP;
    else belowY = top + s.h + GROUP_GAP;
  });

  function place(b: Box, x: number, y: number) {
    if (!b.container) {
      out[b.id] = { x, y };
      return;
    }
    out[b.id] = { x, y, w: b.w, h: b.h };
    const cols = gridCols(b.members.length);
    const rows = Math.ceil(b.members.length / cols);
    const innerW = cols * CARD_W + (cols - 1) * CELL_GAP_X;
    const innerH = rows * CARD_H + (rows - 1) * CELL_GAP_Y;
    // Centre the grid in the box (a box may be wider/taller than its grid
    // because of the minimum size).
    const ox = x + (b.w - innerW) / 2;
    const oy = y + LABEL_BAND + GROUP_PAD + (b.h - LABEL_BAND - 2 * GROUP_PAD - innerH) / 2;
    b.members.forEach((m, k) => {
      out[m] = { x: ox + (k % cols) * (CARD_W + CELL_GAP_X), y: oy + Math.floor(k / cols) * (CARD_H + CELL_GAP_Y) };
    });
  }
  return out;
}
