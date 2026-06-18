// workflowTypes.ts — a workflow is a thin DESCRIPTOR that configures the one
// React Flow canvas: which mock/view to load, and how to compute the spotlight set
// from the current selection. The canvas is the renderer; workflows steer it.
// (PDF §9 "map workflows"). Phase-1 implements Explore/Investigate/Path Trace;
// the rest are honest placeholders.

import type { TopologyView, TopologySelection, WorkflowMode } from "../api/topologyTypes";

export type SpotlightResult = {
  /** node ids to brighten; empty => calm default (nothing dimmed). */
  nodes: Set<string>;
  /** edge ids to force strong (path edges). */
  edges: Set<string>;
};

export type WorkflowDef = {
  id: WorkflowMode;
  label: string;
  /** One-line operator description for the selector tooltip. */
  blurb: string;
  /** Phase-1 implemented vs placeholder (renders a "coming in a later phase" note). */
  implemented: boolean;
  /** The mock TopologyView this workflow opens with (undefined for placeholders). */
  view?: TopologyView;
  /**
   * Given the active view and the current selection, return the spotlight. The
   * default (no selection) should usually be empty so the map stays calm — except
   * Investigate (pre-spotlights the RCA path) and Path Trace (pre-spotlights path).
   */
  computeSpotlight?: (view: TopologyView, selection: TopologySelection) => SpotlightResult;
};

export const EMPTY_SPOTLIGHT: SpotlightResult = { nodes: new Set(), edges: new Set() };
