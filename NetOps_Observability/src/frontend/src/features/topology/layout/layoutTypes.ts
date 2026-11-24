// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// layoutTypes.ts — layout vocabulary shared by the ELK service, presets and the
// saved-layout store. Layout is computed from view.layout_type; operators may pin
// positions, but pins live OUTSIDE the domain graph (PDF §12 "saved layout rule").

import type { LayoutType } from "../api/topologyTypes";

export type Direction = "DOWN" | "RIGHT";

/** A computed position for one node — and, for a CONTAINER, the rectangle ELK
 *  solved for it.
 *
 *  Containers carry w/h because the renderer must DRAW THE RECT ELK LAID OUT.
 *  Re-deriving it from member positions (what the adapter used to do) produced
 *  a different rectangle from the one the layout reserved space for, which is
 *  how sibling boxes ended up nearly touching and padding ended up asymmetric. */
export type NodePosition = { x: number; y: number; w?: number; h?: number };

/** Result of a layout pass: node id → position. Edge routing is left to React Flow. */
export type LayoutResult = Record<string, NodePosition>;

/** Per-layout-type ELK tuning. */
export type LayoutPreset = {
  intent: LayoutType;
  direction: Direction;
  /** elk.layered.spacing.nodeNodeBetweenLayers */
  layerSpacing: number;
  /** elk.spacing.nodeNode */
  nodeSpacing: number;
  /** Pin nodes into role tiers (wan→spine→leaf→access) so a DC/campus graph reads
   *  as a proper top-down tree instead of letting ELK infer layers from the
   *  undirected mesh (which can place leaves above spines). */
  partitionByRole?: boolean;
};

/** Default layout cell for a node. The card renders 120×56 (adaptive 3-tier);
 *  the cell keeps a 30×8 margin for edge routing. History: 200×88 left 32px of
 *  phantom VERTICAL slack per row (fixed 2026-07-31), then the card shrank to
 *  120 wide while the cell stayed 200 — 80px of phantom HORIZONTAL slack, the
 *  same "sparse and banded" defect on the other axis (re-audit A2). */
//
//  2026-08-01: the cell now equals the CARD. A layout cell larger than the thing
//  drawn in it is phantom slack by definition — and when a group rect is
//  computed from cells while the eye measures from cards, the box looks
//  mis-padded on every side by the difference. See layout/groupGeometry.ts.
export const NODE_SIZE = { width: 120, height: 56 };

/** Longest hostname a card shows in full; beyond it the name ellipsizes and the
 *  full name stays in the card's tooltip and the side drawer. */
export const CARD_LABEL_MAX = 24;

/**
 * A node's FOOTPRINT width: wide enough for its hostname at 14px (owner,
 * 2026-11-24: "keep hostname as it is", shown in full — "cEDGE-40", not
 * "cEDG…"), never below NODE_SIZE.width, capped at CARD_LABEL_MAX characters.
 *
 * Still a FIXED size per node — it depends only on the label, so hover,
 * spotlight and the zoom tier never change it (a card that resized on hover
 * shook; see DeviceNode). Every layout and the renderer read THIS, so a cell,
 * a box and the card drawn in it cannot disagree. Deliberately a little
 * generous per character (mixed-case hostnames with digits at 14px/500 run
 * ~7.4–8.6px a glyph): a card a few pixels wide is fine, a clipped name is not.
 */
export function cardWidth(label?: string): number {
  const chars = Math.min((label ?? "").length, CARD_LABEL_MAX);
  // 76 = padding 10+10, accent border 3, border 1.5, icon 18, two 6px gaps,
  //      health ring 16, rounding.
  return Math.max(NODE_SIZE.width, Math.round(76 + chars * 8.4));
}

/**
 * The footprint width of ANY node on the canvas — the one function the card,
 * the adapter and every layout use. A DEVICE (router, switch, firewall, server,
 * unresolved neighbour, …) is as wide as its hostname (cardWidth). A cloud
 * resource or WAN transport (kind `cloud` / `wan`) keeps the base card: its
 * label is a resource descriptor ("Subnet · subnet-0dc1… · 172.31.48.0/20"),
 * not a hostname, and widening every cloud card would re-shape the cloud
 * layout for a request that was about hostnames.
 */
export function nodeWidth(n: { label?: string; kind?: string }): number {
  return n.kind === "cloud" || n.kind === "wan" ? NODE_SIZE.width : cardWidth(n.label);
}
export const GROUP_PAD = 28;
