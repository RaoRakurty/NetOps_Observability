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
export const GROUP_PAD = 28;
