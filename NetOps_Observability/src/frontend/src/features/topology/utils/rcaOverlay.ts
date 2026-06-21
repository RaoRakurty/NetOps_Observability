// rcaOverlay.ts — the single source of truth for how an RCA Layer-3 overlay state
// (RcaOverlayState) maps to visual treatment on the canvas. Parallel to
// topologyHealth.ts's HEALTH_* maps, but for the engine's *grounded verdict* —
// kept SEPARATE from health so the canvas can say "suspected" differently from
// "confirmed" instead of collapsing both into the same red.
//
// Honesty rule (design doc §"Overlay states" + netops-rca-wording-templates):
// suspected is dashed + ⚠ (NOT certain); confirmed is solid + ✕ (independently
// confirmed); missing-evidence is a HOLLOW ○ (we don't have the proof); internal
// monitoring is customer-hidden. Colour is never the only signal — every state
// carries a distinct glyph and line style.

import type { RcaOverlayState } from "../api/topologyTypes";

export type RcaOverlayStyle = {
  /** Operator-facing label (legend / aria / drawer). */
  label: string;
  /** Stroke + glyph colour — drawn from the same calm NOC palette as HEALTH_COLOR. */
  color: string;
  /** Accessible symbol so the state reads without colour. */
  glyph: string;
  /** strokeDasharray for edges; undefined = solid line. */
  dash?: string;
  /** Draw the node marker as a HOLLOW ring (missing evidence — no fill). */
  hollow: boolean;
  /** Dash-flow animation hint (honoured only when motion is allowed — see CSS). */
  animate: boolean;
  /** internal_only — never rendered in the customer/operator view (decision #76). */
  customerHidden: boolean;
};

/**
 * The canonical state → treatment map. Colours match topologyHealth.HEALTH_COLOR
 * (green/amber/red/slate) so the two layers feel like one design system.
 */
export const RCA_OVERLAY: Record<RcaOverlayState, RcaOverlayStyle> = {
  observed: { label: "Observed", color: "#16a34a", glyph: "●", dash: undefined, hollow: false, animate: false, customerHidden: false },
  degraded: { label: "Degraded", color: "#d97706", glyph: "!", dash: "6 3 1 3", hollow: false, animate: true, customerHidden: false },
  suspected_down: { label: "Suspected fault", color: "#dc2626", glyph: "⚠", dash: "7 4", hollow: false, animate: true, customerHidden: false },
  confirmed_down: { label: "Confirmed fault", color: "#dc2626", glyph: "✕", dash: undefined, hollow: false, animate: false, customerHidden: false },
  insufficient_visibility: { label: "Insufficient visibility", color: "#64748b", glyph: "?", dash: "2 4", hollow: false, animate: false, customerHidden: false },
  missing_evidence: { label: "Missing evidence", color: "#64748b", glyph: "○", dash: "2 4", hollow: true, animate: false, customerHidden: false },
  internal_only: { label: "Internal monitoring", color: "#94a3b8", glyph: "·", dash: "2 4", hollow: false, animate: false, customerHidden: true },
};

/** Legend display order — worst-to-calm, customer-visible states only. */
export const RCA_OVERLAY_ORDER: RcaOverlayState[] = [
  "confirmed_down",
  "suspected_down",
  "degraded",
  "insufficient_visibility",
  "missing_evidence",
  "observed",
];

// Raw status/state strings the backend RCA overlay can emit (annotation.status,
// path node.status, path edge.state) → a canonical RcaOverlayState. Anything we
// don't recognise returns undefined (the node/edge then keeps its plain health
// ring — never a fabricated verdict).
const RCA_ALIASES: Record<string, RcaOverlayState> = {
  observed: "observed",
  healthy: "observed",
  up: "observed",
  ok: "observed",
  degraded: "degraded",
  warning: "degraded",
  suspected: "suspected_down",
  suspected_down: "suspected_down",
  confirmed: "confirmed_down",
  confirmed_down: "confirmed_down",
  down: "confirmed_down",
  insufficient_visibility: "insufficient_visibility",
  unknown: "insufficient_visibility",
  missing_evidence: "missing_evidence",
  internal_only: "internal_only",
  internal: "internal_only",
};

/** Normalise a raw RCA status/state string to a canonical state (or undefined). */
export function normalizeRcaState(raw?: string): RcaOverlayState | undefined {
  if (!raw) return undefined;
  return RCA_ALIASES[raw.trim().toLowerCase()];
}
