// layoutTypes.ts — layout vocabulary shared by the ELK service, presets and the
// saved-layout store. Layout is computed from view.layout_type; operators may pin
// positions, but pins live OUTSIDE the domain graph (PDF §12 "saved layout rule").

import type { LayoutType } from "../api/topologyTypes";

export type Direction = "DOWN" | "RIGHT";

/** A computed position for one node. */
export type NodePosition = { x: number; y: number };

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
export const NODE_SIZE = { width: 150, height: 64 };
export const GROUP_PAD = 28;
