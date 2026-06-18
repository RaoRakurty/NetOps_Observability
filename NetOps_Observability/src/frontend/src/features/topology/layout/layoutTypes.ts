// layoutTypes.ts — layout vocabulary shared by the ELK service, presets and the
// saved-layout store. Layout is computed from layout_intent; operators may pin
// positions, but pins live OUTSIDE the domain graph (PDF §12 "saved layout rule").

import type { LayoutIntent } from "../api/topologyTypes";

export type Direction = "DOWN" | "RIGHT";

/** A computed position for one node. */
export type NodePosition = { x: number; y: number };

/** Result of a layout pass: node id → position. Edge routing is left to React Flow. */
export type LayoutResult = Record<string, NodePosition>;

/** Per-intent ELK tuning. */
export type LayoutPreset = {
  intent: LayoutIntent;
  direction: Direction;
  /** elk.layered.spacing.nodeNodeBetweenLayers */
  layerSpacing: number;
  /** elk.spacing.nodeNode */
  nodeSpacing: number;
};

/** Default rendered card size used for ELK sizing and React Flow node dimensions. */
export const NODE_SIZE = { width: 200, height: 88 };
export const GROUP_PAD = 28;
