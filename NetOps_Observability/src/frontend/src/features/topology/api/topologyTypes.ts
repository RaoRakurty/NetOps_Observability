// topologyTypes.ts — the RESOLVED, renderer-agnostic topology graph contract.
//
// This is the moat (PDF §7): a time-aware, evidence-backed graph that can be drawn
// by many renderers. The Graph API returns a TopologyView; it NEVER returns React
// Flow nodes. Each renderer has its own adapter (topologyToReactFlow / topologyToSigma
// / topologyToDeckLayers) that maps THIS contract into renderer-specific objects.
//
// Nothing here imports @xyflow/react, sigma, or deck.gl. Keep it that way.

import type { EvidenceRef, TopologySource } from "../graph/topologyFactTypes";

export type { EvidenceRef, TopologySource };

// ── enums ───────────────────────────────────────────────────────────────────

/** Operator workflow the view was built for (PDF §9). */
export type WorkflowMode =
  | "explore"
  | "investigate"
  | "path_trace"
  | "change_review"
  | "capacity"
  | "dependency"
  | "executive_geo";

/** Layout intent the View Builder requests of the Layout Service (PDF §5, §12). */
export type LayoutIntent =
  | "spine_leaf"
  | "campus"
  | "wan_geo"
  | "path_first"
  | "incident"
  | "dependency"
  | "cloud_grouped";

/** Device/entity class — drives the node renderer + icon. */
export type NodeKind =
  | "switch"
  | "router"
  | "firewall"
  | "load_balancer"
  | "server"
  | "cloud"
  | "wan"
  | "site"
  | "group"
  | "unresolved";

/** Health band. Color is NEVER the only signal — pair with icon/label/text. */
export type Health = "ok" | "warning" | "critical" | "unknown";

/** Time-diff state of an object across the selected window (PDF §14). */
export type ChangeState = "added" | "removed" | "changed" | "unchanged";

/** Relationship an edge encodes. */
export type EdgeRelationship =
  | "l2_link" // LLDP/CDP physical adjacency
  | "routed_adjacency" // BGP-LS / IS-IS / OSPF
  | "path_hop" // a hop on a traced A→B path
  | "dependency" // flow/observed dependency (dashed, lower confidence)
  | "containment" // cloud/group membership
  | "inferred"; // derived, not directly observed

/** Visual treatment hint chosen by the adapter from relationship + confidence. */
export type EdgeVariant = "topology" | "path" | "inferred" | "degraded" | "bundled";

export type GroupType = "site" | "pod" | "rack" | "cluster" | "zone" | "region" | "vpc" | "app";

// ── shared sub-shapes ─────────────────────────────────────────────────────────

export type Ownership = {
  team?: string;
  owner?: string;
  business_service?: string;
  criticality?: "low" | "medium" | "high" | "critical";
};

/** first_seen / last_seen / valid window + diff context carried by node & edge. */
export type TimeMeta = {
  first_seen: string;
  last_seen: string;
  valid_from?: string;
  valid_to?: string;
  change_state: ChangeState;
};

// ── nodes ─────────────────────────────────────────────────────────────────────

export type TopologyNode = {
  id: string;
  label: string;
  kind: NodeKind;
  role?: string; // spine | leaf | core | distribution | access | border | edge …
  vendor?: string;
  model?: string;
  site?: string;
  zone?: string;
  /** Membership in a TopologyGroup (compound layout). */
  group_id?: string;
  ownership?: Ownership;
  health: Health;
  /** 0..1 — how confident we are this node exists / is correctly resolved. */
  confidence: number;
  /** False when the node is an unresolved remote neighbour (render muted). */
  resolved: boolean;
  evidence: EvidenceRef[];
  time: TimeMeta;
  /** Overlay inputs (cpu/mem/links/alerts/util…). Strings or numbers. */
  metrics: Record<string, number | string>;
  tags: Record<string, string>;
  /** Optional pinned coordinate (saved operator layout / geo). Layout fills the rest. */
  coordinates?: { x: number; y: number };
};

// ── edges ─────────────────────────────────────────────────────────────────────

export type TopologyEdge = {
  id: string;
  source: string; // TopologyNode.id
  target: string; // TopologyNode.id
  relationship: EdgeRelationship;
  /** The dominant source that established this edge. */
  protocol_source: TopologySource;
  source_port?: string;
  target_port?: string;
  status: Health;
  /** 0..1. Bidirectional LLDP/CDP high; one-way / flow-only lower. */
  confidence: number;
  /** REQUIRED & NON-EMPTY: never draw a link without evidence (PDF §3, rule 6). */
  evidence: EvidenceRef[];
  time: TimeMeta;
  /** 0..100 link utilization for the utilization overlay (edge width). */
  utilization?: number;
  /** error/discard rate for the errors overlay. */
  errors?: number;
  /** Bundles parallel links (2x100G / LAG-10) — collapsed until expanded. */
  bundle_id?: string;
  /** How many physical members a bundle represents. */
  bundle_count?: number;
  direction?: "uni" | "bi";
};

// ── groups ─────────────────────────────────────────────────────────────────────

export type TopologyGroup = {
  id: string;
  label: string;
  group_type: GroupType;
  children: string[]; // node ids
  health_rollup: Health;
  collapsed: boolean;
  layout_policy?: LayoutIntent;
  ownership?: Ownership;
  evidence: EvidenceRef[];
};

// ── overlays ────────────────────────────────────────────────────────────────────

export type OverlayKind =
  | "health"
  | "utilization"
  | "errors"
  | "routing_changes"
  | "config_drift"
  | "flow"
  | "rca_evidence"
  | "golden_path_delta"
  | "historical_diff";

/**
 * An overlay is descriptive metadata; the overlay renderer turns graph attributes
 * into visual state WITHOUT mutating the domain graph (PDF §16, Overlays rule).
 */
export type TopologyOverlay = {
  kind: OverlayKind;
  label: string;
  /** True if this view actually carries the data this overlay needs. */
  available: boolean;
  description?: string;
};

// ── the view ────────────────────────────────────────────────────────────────────

export type TopologyView = {
  view_id: string;
  topology_id: string;
  mode: WorkflowMode;
  scope: {
    tenant_id: string;
    site?: string;
    app?: string;
    path_id?: string;
    incident_id?: string;
  };
  generated_at: string;
  time_range: { from: string; to: string };
  layout_intent: LayoutIntent;
  nodes: TopologyNode[];
  edges: TopologyEdge[];
  groups: TopologyGroup[];
  overlays: TopologyOverlay[];
  /** Flat evidence index for the view (in addition to per-object evidence). */
  evidence: EvidenceRef[];
  renderer_hints: {
    preferred: "react_flow" | "sigma" | "deck_geo";
    max_detail_level: number;
  };
  /** For path_trace / investigate: the ordered node ids of the highlighted path. */
  path?: string[];
};

// ── selection (kept SEPARATE from node/edge arrays for rerender perf, PDF §13) ──

export type TopologySelection = {
  nodeId?: string;
  edgeId?: string;
};
