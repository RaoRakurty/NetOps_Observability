// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// topologyOverlays.ts — overlay catalogue + availability derivation. An overlay is
// descriptive metadata (PDF §16); the overlay renderer turns graph attributes into
// visual state WITHOUT mutating the domain graph. Here we only describe overlays and
// decide which ones a given view actually carries the data for.

import type { TopologyView, TopologyOverlay, OverlayKind } from "../api/topologyTypes";

/** Human label + description for every overlay kind (all 10). */
export const OVERLAY_META: Record<OverlayKind, { label: string; description: string }> = {
  health: {
    label: "Health",
    description: "Node rings carry health.",
  },
  utilization: {
    label: "Utilization",
    description: "Edge width is link load.",
  },
  interface_errors: {
    label: "Interface errors",
    description: "Edge width is error rate.",
  },
  routing_changes: {
    label: "Routing changes",
    description: "Where routing moved in the window.",
  },
  config_drift: {
    label: "Config drift",
    description: "Devices whose config differs from intent.",
  },
  syslog: {
    label: "Syslog",
    description: "Devices that logged in the window.",
  },
  flow: {
    label: "Flow dependencies",
    description: "Dependencies observed in traffic, not on the wire.",
  },
  rca_evidence: {
    label: "RCA evidence",
    description: "What this root-cause verdict actually used.",
  },
  golden_path_delta: {
    label: "Golden-path delta",
    description: "The live path against the golden path.",
  },
  historical_diff: {
    label: "Historical diff",
    description: "What changed since the snapshot.",
  },
};

/** Stable display order for the overlay picker. */
const OVERLAY_ORDER: OverlayKind[] = [
  "health",
  "utilization",
  "interface_errors",
  "flow",
  "rca_evidence",
  "routing_changes",
  "config_drift",
  "syslog",
  "golden_path_delta",
  "historical_diff",
];

function meta(kind: OverlayKind): TopologyOverlay {
  const m = OVERLAY_META[kind];
  return { kind, label: m.label, available: false, description: m.description };
}

/**
 * Derive which overlays this view can actually render:
 *   - health           → always available,
 *   - utilization      → any edge has a non-null utilization_pct,
 *   - interface_errors → any edge has a truthy errors value,
 *   - flow             → any dependency edge exists,
 *   - rca_evidence     → any node/edge evidence is used_by_rca,
 *   - others           → availability passed through from view.overlays (the builder
 *                        lists the kind when it attached the data).
 * Returns the overlays in OVERLAY_ORDER.
 */
export function availableOverlays(view: TopologyView): TopologyOverlay[] {
  const edges = view.edges ?? [];
  const passthrough = new Set<OverlayKind>(view.overlays ?? []);

  const evidencePools = [
    ...edges.flatMap((e) => e.evidence ?? []),
    ...(view.nodes ?? []).flatMap((n) => n.evidence ?? []),
  ];

  const changed = (s: string | undefined) => !!s && s !== "unchanged" && s !== "unknown";
  const derived: Partial<Record<OverlayKind, boolean>> = {
    health: true,
    utilization: edges.some((e) => e.utilization_pct != null),
    interface_errors: edges.some((e) => e.errors != null && e.errors > 0),
    flow: edges.some((e) => e.relationship === "dependency"),
    rca_evidence: evidencePools.some((ev) => ev?.used_by_rca === true),
    // Available only when the window actually has change to show (added/removed/
    // changed/stale) — the tractable "what changed" slice of topology time-travel.
    historical_diff:
      (view.nodes ?? []).some((n) => changed(n.change_state)) || edges.some((e) => changed(e.change_state)),
  };

  return OVERLAY_ORDER.map((kind) => {
    const o = meta(kind);
    const available =
      derived[kind] !== undefined ? Boolean(derived[kind]) : passthrough.has(kind);
    return { ...o, available };
  });
}
