// layoutPresets.ts — map each layout_type to ELK tuning. Deterministic layered
// layouts only; NEVER force layout for physical/routed topology (PDF §12).

import type { LayoutType } from "../api/topologyTypes";
import type { LayoutPreset } from "./layoutTypes";

const PRESETS: Record<LayoutType, LayoutPreset> = {
  // spine/leaf reads best top-to-bottom with generous layer spacing for bundles.
  spine_leaf: { intent: "spine_leaf", direction: "DOWN", layerSpacing: 120, nodeSpacing: 70, partitionByRole: true },
  campus: { intent: "campus", direction: "DOWN", layerSpacing: 110, nodeSpacing: 64, partitionByRole: true },
  // path views are a left-to-right ribbon.
  path_first: { intent: "path_first", direction: "RIGHT", layerSpacing: 150, nodeSpacing: 56 },
  // incident: root cause → affected path → blast radius, left to right.
  incident: { intent: "incident", direction: "RIGHT", layerSpacing: 140, nodeSpacing: 64 },
  dependency: { intent: "dependency", direction: "RIGHT", layerSpacing: 130, nodeSpacing: 60 },
  cloud_grouped: { intent: "cloud_grouped", direction: "DOWN", layerSpacing: 110, nodeSpacing: 72 },
  // geo is positioned by coordinates, not ELK; fall back to a calm layered grid.
  wan_geo: { intent: "wan_geo", direction: "DOWN", layerSpacing: 120, nodeSpacing: 80 },
  // The persisted graph's declared type (audit S6): plain layered flow WITHOUT
  // role partitioning — the mode-agnostic whole-tenant graph never asked for
  // DC spine/leaf tiering.
  layered: { intent: "layered", direction: "DOWN", layerSpacing: 110, nodeSpacing: 70 },
};

export function presetFor(layoutType: LayoutType): LayoutPreset {
  return PRESETS[layoutType] ?? PRESETS.spine_leaf;
}
