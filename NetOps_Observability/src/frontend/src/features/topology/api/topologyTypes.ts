// topologyTypes.ts — the CANONICAL, renderer-agnostic topology contract.
//
// SINGLE SOURCE OF TRUTH = the skill contract (.claude/skills/topology-ui/
// topology-contract.json). Field names are FLAT and match that schema exactly:
// node.{first_seen,last_seen,change_state,owner,rack,mgmt_ip,health,metrics},
// edge.{protocol,utilization_pct,status,first_seen,...}, view.layout_type,
// overlays as a string[]. There is intentionally NO competing nested model.
//
// Fields the UI needs but the wire contract doesn't define (path, per-evidence
// summary, bundle details, coordinates, resolved flag) are marked DERIVED/
// ENRICHMENT below — produced by adapters, never authored as canonical API data.
//
// Nothing here imports @xyflow/react, sigma, or deck.gl.

import type { EvidenceRef, TopologySource } from "../graph/topologyFactTypes";

export type { EvidenceRef, TopologySource };

// ── enums ───────────────────────────────────────────────────────────────────

export type WorkflowMode =
  | "explore"
  | "investigate"
  | "path_trace"
  | "change_review"
  | "capacity"
  | "dependency"
  | "executive_geo";

/** Value of view.layout_type (skill example: "spine_leaf"). */
export type LayoutType =
  | "spine_leaf"
  | "campus"
  | "wan_geo"
  | "path_first"
  | "incident"
  | "dependency"
  | "cloud_grouped";

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

/** Health — 5 states incl. `maintenance` (skill design-tokens.md / contract enum). */
export type Health = "ok" | "warning" | "critical" | "unknown" | "maintenance";

/** change_state — incl. `stale` (skill time-diff-golden-path.md). */
export type ChangeState = "added" | "removed" | "changed" | "unchanged" | "stale" | "unknown";

/**
 * RCA overlay state (Layer-3 — design doc "Overlay states"). DISTINCT from health:
 * it carries the engine's *grounded* verdict on a node/edge — crucially separating
 * `suspected_down` (evidence points here, NOT confirmed) from `confirmed_down`
 * (independently confirmed). Set ONLY on RCA path views (overlay-only, never on the
 * base topology); visual treatment lives in utils/rcaOverlay.ts.
 */
export type RcaOverlayState =
  | "observed"
  | "degraded"
  | "suspected_down"
  | "confirmed_down"
  | "insufficient_visibility"
  | "missing_evidence"
  | "internal_only";

/** Edge link status (skill example uses "up"). Mapped to Health for colour. */
export type EdgeStatus = "up" | "down" | "degraded" | "warning" | "maintenance" | "unknown";

/** Edge relationship (skill example: "connected_to"). */
export type EdgeRelationship =
  | "connected_to" // L2/physical adjacency (LLDP/CDP)
  | "routed_adjacency" // BGP-LS / IS-IS / OSPF
  | "path_hop" // a hop on a traced A→B path
  | "dependency" // flow/observed dependency
  | "containment" // cloud/group membership
  | "inferred"; // derived, not directly observed

/** Visual treatment hint chosen by the adapter (not a wire field). */
export type EdgeVariant = "topology" | "path" | "inferred" | "degraded" | "bundled" | "rca";

/** Overlay kinds (skill topology-context.md). Note `interface_errors`, `syslog`. */
export type OverlayKind =
  | "health"
  | "utilization"
  | "interface_errors"
  | "routing_changes"
  | "config_drift"
  | "syslog"
  | "flow"
  | "rca_evidence"
  | "golden_path_delta"
  | "historical_diff";

export type GroupType = "site" | "pod" | "rack" | "cluster" | "zone" | "region" | "vpc" | "app";

// ── node ──────────────────────────────────────────────────────────────────────

export type TopologyNode = {
  // ── canonical (flat, skill contract) ──
  id: string;
  label: string;
  kind: NodeKind;
  role?: string;
  vendor?: string;
  model?: string;
  site?: string;
  rack?: string;
  mgmt_ip?: string;
  health: Health;
  owner?: string;
  confidence: number;
  first_seen?: string;
  last_seen?: string;
  change_state?: ChangeState;
  /** Skill metric keys: cpu_pct, mem_pct, link_count, alert_count, … */
  metrics?: Record<string, number | string>;
  evidence: EvidenceRef[];
  /** Active alerts DRIVING this node's health — the inspector's "why is this
   * critical/warning" answer. Worst-first, capped. Empty/absent when healthy. */
  issues?: { severity: string; summary: string; since?: string }[];
  // ── derived / UI enrichment (not canonical API) ──
  zone?: string;
  group_id?: string;
  /** Derived: false for unresolved remote neighbours (render muted). */
  resolved?: boolean;
  criticality?: "low" | "medium" | "high" | "critical";
  tags?: Record<string, string>;
  /** Pinned coordinate (saved operator layout / geo). Layout fills the rest. */
  coordinates?: { x: number; y: number };
  /** RCA Layer-3 overlay state (only on RCA path views) — supersedes the health
   *  ring with the engine's grounded verdict (suspected vs confirmed, etc.). */
  rca_status?: RcaOverlayState;
};

// ── edge ──────────────────────────────────────────────────────────────────────

export type TopologyEdge = {
  // ── canonical (flat, skill contract) ──
  id: string;
  source: string;
  target: string;
  source_port?: string;
  target_port?: string;
  relationship: EdgeRelationship;
  protocol?: TopologySource;
  status?: EdgeStatus;
  utilization_pct?: number;
  // #85 per-hop path metrics (interface facts on the path edge; omitted when unsourced)
  bandwidth_mbps?: number;
  throughput_mbps?: number;
  reliability_pct?: number;
  mtu?: number;
  confidence: number;
  first_seen?: string;
  last_seen?: string;
  change_state?: ChangeState;
  /** REQUIRED & NON-EMPTY: never draw a link without evidence. */
  evidence: EvidenceRef[];
  // ── derived / UI enrichment (not canonical API) ──
  errors?: number; // interface_errors overlay input
  bundle_id?: string; // collapsed parallel links (LAG / "4x100G")
  bundle_count?: number;
  direction?: "uni" | "bi";
  /** RCA Layer-3 overlay state (only on RCA path views) — drives the distinct
   *  suspected/confirmed/insufficient edge treatment, overriding the health colour. */
  rca_status?: RcaOverlayState;
};

// ── group ──────────────────────────────────────────────────────────────────────

export type TopologyGroup = {
  id: string;
  label: string;
  group_type: GroupType;
  children: string[]; // node ids
  health: Health; // rollup
  collapsed: boolean;
  owner?: string;
};

// ── overlays ────────────────────────────────────────────────────────────────────

/** Rich overlay descriptor — DERIVED by availableOverlays() from the view; the
 *  canonical view.overlays is a plain OverlayKind[] (skill example). */
export type TopologyOverlay = {
  kind: OverlayKind;
  label: string;
  available: boolean;
  description?: string;
};

// ── view ────────────────────────────────────────────────────────────────────────

export type TopologyView = {
  // ── canonical (skill contract) ──
  view_id: string;
  mode: WorkflowMode;
  scope?: { tenant_id?: string; site?: string; app?: string; path_id?: string; incident_id?: string };
  layout_type: LayoutType;
  generated_at: string;
  nodes: TopologyNode[];
  edges: TopologyEdge[];
  groups: TopologyGroup[];
  /** Canonical overlays are a plain string list (skill example: ["health","utilization"]). */
  overlays: OverlayKind[];
  legend?: Record<string, unknown>;
  // ── derived / UI enrichment (allowed; not canonical API) ──
  topology_id?: string;
  time_range?: { from: string; to: string };
  /** Ordered node ids of the highlighted path (path_trace / investigate). */
  path?: string[];
  /**
   * Provenance of `path` — HONESTY guard. "measured" = traceroute/probe ground truth;
   * "computed" = an IGP-weighted shortest-path INFERENCE over inventory (a proxy, not
   * an observed forwarding path). The UI MUST NOT call a "computed" path "traced".
   */
  path_source?: "measured" | "computed";
  renderer_hints?: { preferred: "react_flow" | "sigma" | "deck_geo"; max_detail_level: number };
};

// ── selection (kept SEPARATE from node/edge arrays for rerender perf) ──

export type TopologySelection = {
  nodeId?: string;
  edgeId?: string;
  groupId?: string;
};
