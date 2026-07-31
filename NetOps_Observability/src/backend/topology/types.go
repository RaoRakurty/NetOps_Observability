package topology

import "time"

// types.go — the canonical, renderer-agnostic topology contract, in Go.
//
// The OUTPUT types (View/Node/Edge/Group/EvidenceRef) mirror the single source of
// truth — `.claude/skills/topology-ui/topology-contract.json` and its TypeScript
// twin `features/topology/api/topologyTypes.ts` — field-for-field, json tags
// included, so the frontend consumes the projection with no translation. Only the
// flat CANONICAL fields are emitted here; the UI's DERIVED/enrichment fields
// (per-evidence summary, bundle details, coordinates) are computed in the adapter,
// never authored by the backend.
//
// The INPUT types (Input/DeviceFact/LinkFact/AlertFact/PathFact) are the
// dependency-injected telemetry bundle. They are deliberately decoupled from the
// rest of the backend (no models.* import) so this package stays a pure,
// stdlib-only leaf that is fully unit-testable with mock telemetry. The package
// main handler does the gather + translate; the projection logic stays pure.

// ── enums (string-valued, matching the contract) ─────────────────────────────

// Health — 5 states incl. "maintenance" (contract enum).
const (
	HealthOK          = "ok"
	HealthWarning     = "warning"
	HealthCritical    = "critical"
	HealthUnknown     = "unknown"
	HealthMaintenance = "maintenance"
)

// change_state — incl. "stale" (skill time-diff-golden-path.md).
const (
	ChangeUnchanged = "unchanged"
	ChangeStale     = "stale"
	ChangeUnknown   = "unknown"
)

// Node kinds (contract NodeKind).
const (
	KindSwitch       = "switch"
	KindRouter       = "router"
	KindFirewall     = "firewall"
	KindLoadBalancer = "load_balancer"
	KindServer       = "server"
	KindCloud        = "cloud"
	KindSite         = "site" // a geographic site (executive_geo projection)
	KindUnresolved   = "unresolved"
)

// Edge relationships (contract EdgeRelationship).
const (
	RelConnectedTo     = "connected_to"     // L2/physical adjacency (LLDP/CDP)
	RelRoutedAdjacency = "routed_adjacency" // BGP-LS / IS-IS / OSPF
)

// Workflow modes (contract WorkflowMode).
const (
	ModeExplore      = "explore"
	ModeInvestigate  = "investigate"
	ModePathTrace    = "path_trace"
	ModeDependency   = "dependency"
	ModeCapacity     = "capacity"
	ModeExecutiveGeo = "executive_geo"
)

// Path provenance (contract PathSource) — HONESTY guard for path_trace mode. A
// "measured" path is ground truth from a traceroute/probe; a "computed" path is an
// IGP-weighted shortest-path INFERENCE over the inventory graph (a proxy, not an
// observed forwarding path). The UI MUST distinguish them — a computed path is never
// labeled "traced". Empty when no path is highlighted.
const (
	PathMeasured = "measured"
	PathComputed = "computed"
)

// Edge link status (contract EdgeStatus). "" → "unknown" at the boundary.
const (
	StatusUp          = "up"
	StatusDown        = "down"
	StatusDegraded    = "degraded"
	StatusWarning     = "warning"
	StatusMaintenance = "maintenance"
	StatusUnknown     = "unknown"
)

// ── output: evidence ─────────────────────────────────────────────────────────

// EvidenceRef is one piece of evidence backing a node or edge. CANONICAL fields
// per the contract are source + confidence (+ optional detail). No node/edge is
// rendered without at least one of these (the "no edge without evidence" rule).
type EvidenceRef struct {
	Source     string  `json:"source"`                // TopologySource: lldp|cdp|bgp_ls|snmp|trace|metric…
	Confidence float64 `json:"confidence"`            // 0..1
	Detail     string  `json:"detail,omitempty"`      // human-readable one-liner
	ObservedAt string  `json:"observed_at,omitempty"` // RFC3339 (derived, but cheap & useful)
}

// NodeIssue — one active alert behind a node's health. The inspector's "why is this
// critical" section. Mirrors AlertFact minus the device id (it's on the node).
type NodeIssue struct {
	Severity string `json:"severity"`        // critical|warning|info
	Summary  string `json:"summary"`         // the alert one-liner (what is wrong)
	Since    string `json:"since,omitempty"` // RFC3339 fired-at
}

// ── output: node ─────────────────────────────────────────────────────────────

type Node struct {
	ID    string `json:"id"`
	Label string `json:"label"`
	Kind  string `json:"kind"`
	Role  string `json:"role,omitempty"`
	// DeviceRole — discovery-driven canonical role (roles.go): access_switch |
	// distribution_switch | core_router | firewall | load_balancer | wan_edge |
	// carrier_hop | dc_wan_edge | dc_leaf | dc_spine | cloud_edge. Omitted when
	// the classifier could not establish one (unknown stays unknown). Additive:
	// existing consumers of Role/Kind are untouched.
	DeviceRole     string             `json:"device_role,omitempty"`
	RoleConfidence string             `json:"role_confidence,omitempty"` // strong|medium|weak (words)
	RoleEvidence   []string           `json:"role_evidence,omitempty"`   // "signal: detail" lines
	Vendor         string             `json:"vendor,omitempty"`
	Model          string             `json:"model,omitempty"`
	Site           string             `json:"site,omitempty"`
	Rack           string             `json:"rack,omitempty"`
	MgmtIP         string             `json:"mgmt_ip,omitempty"`
	Health         string             `json:"health"`
	Owner          string             `json:"owner,omitempty"`
	Confidence     float64            `json:"confidence"`
	FirstSeen      string             `json:"first_seen,omitempty"`
	LastSeen       string             `json:"last_seen,omitempty"`
	ChangeState    string             `json:"change_state,omitempty"`
	Metrics        map[string]float64 `json:"metrics,omitempty"`
	Evidence       []EvidenceRef      `json:"evidence"`
	// Issues are the active alerts DRIVING this node's health — surfaced so the
	// inspector can answer "why is this device critical/warning" with the actual
	// problem, not just a colour. Worst-first, capped. Empty when healthy.
	Issues []NodeIssue `json:"issues,omitempty"`
	// derived enrichment the backend can safely supply
	Resolved bool   `json:"resolved"`
	GroupID  string `json:"group_id,omitempty"`
	// Tags are free-form, provider-supplied labels (provider, cidr, az, service…).
	// DERIVED enrichment matching TopologyNode.tags on the TS side — used by the
	// Cloud tab's CloudResourceNode to pick the official provider mark and surface
	// the resource's network context (CIDR, AZ). Omitted (nil) for every other
	// projection, so no existing view's JSON changes.
	Tags map[string]string `json:"tags,omitempty"`
	// Coordinates is geographic placement {x:lng, y:lat} in decimal WGS-84. It is
	// normally a UI-derived field — EXCEPT for the executive_geo projection, where
	// the coordinate IS the intent data (it lives in the Source of Truth and cannot
	// be derived in the adapter), so the backend authors it here. Omitted (nil) for
	// every other mode. Matches TopologyNode.coordinates on the TS side.
	Coordinates *Coord `json:"coordinates,omitempty"`
}

// Coord is a geographic coordinate: X = longitude, Y = latitude (decimal WGS-84).
type Coord struct {
	X float64 `json:"x"`
	Y float64 `json:"y"`
}

// ── output: edge ─────────────────────────────────────────────────────────────

type Edge struct {
	ID           string  `json:"id"`
	Source       string  `json:"source"`
	Target       string  `json:"target"`
	SourcePort   string  `json:"source_port,omitempty"`
	TargetPort   string  `json:"target_port,omitempty"`
	Relationship string  `json:"relationship"`
	Protocol     string  `json:"protocol,omitempty"`
	Status       string  `json:"status,omitempty"`
	Utilization  float64 `json:"utilization_pct,omitempty"`
	// #85 per-hop path metrics — interface facts joined onto the path edge (same
	// (device, ifName) join as Utilization). Omitted when not sourced so the UI
	// renders an honest "—"; MTU stays unset until the ifMtu OID is polled.
	BandwidthMbps  float64       `json:"bandwidth_mbps,omitempty"`  // interface link speed (ifSpeed)
	ThroughputMbps float64       `json:"throughput_mbps,omitempty"` // busiest-direction octet rate
	Reliability    float64       `json:"reliability_pct,omitempty"` // oper-status × (1 − error/discard ratio)
	MTU            float64       `json:"mtu,omitempty"`             // interface MTU (ifMtu)
	Confidence     float64       `json:"confidence"`
	FirstSeen      string        `json:"first_seen,omitempty"`
	LastSeen       string        `json:"last_seen,omitempty"`
	ChangeState    string        `json:"change_state,omitempty"`
	Evidence       []EvidenceRef `json:"evidence"`
}

// ── output: group ────────────────────────────────────────────────────────────

type Group struct {
	ID        string   `json:"id"`
	Label     string   `json:"label"`
	GroupType string   `json:"group_type"` // site|pod|rack|cluster|zone|region|vpc|app
	Children  []string `json:"children"`
	Health    string   `json:"health"`
	Collapsed bool     `json:"collapsed"`
	Owner     string   `json:"owner,omitempty"`
}

// ── output: view ─────────────────────────────────────────────────────────────

type Scope struct {
	TenantID   string `json:"tenant_id,omitempty"`
	Site       string `json:"site,omitempty"`
	PathID     string `json:"path_id,omitempty"`
	IncidentID string `json:"incident_id,omitempty"`
}

type View struct {
	ViewID      string   `json:"view_id"`
	Mode        string   `json:"mode"`
	Scope       Scope    `json:"scope"`
	LayoutType  string   `json:"layout_type"`
	GeneratedAt string   `json:"generated_at"` // RFC3339
	Nodes       []Node   `json:"nodes"`
	Edges       []Edge   `json:"edges"`
	Groups      []Group  `json:"groups"`
	Overlays    []string `json:"overlays"`
	// derived enrichment: ordered node ids of the highlighted path (path_trace).
	Path []string `json:"path,omitempty"`
	// provenance of Path: PathMeasured (traceroute ground truth) vs PathComputed
	// (IGP-weighted SPF inference). HONESTY: the UI must not call a computed path
	// "traced". Empty when there is no path.
	PathSource string `json:"path_source,omitempty"`
}

// ── input: the DI'd telemetry bundle ─────────────────────────────────────────

// DeviceFact is one managed device, already tenant-scoped by the caller.
type DeviceFact struct {
	ID       string
	Name     string
	Vendor   string
	Model    string
	Type     string // router|switch|firewall|load-balancer|cloud-gw|generic (backend device type)
	Role     string
	Site     string
	Rack     string
	MgmtIP   string
	Owner    string
	LastSeen time.Time
	// Metrics — set Has* to distinguish "0%" from "unknown" (zero-trust honesty).
	CPUPct float64
	HasCPU bool
	MemPct float64
	HasMem bool
	// ── role-classifier facts (roles.go) — gathered tenant-scoped by the caller;
	// zero values mean "not collected", which the classifier treats as absence
	// of evidence (default-closed), never as a negative signal.
	SysDescr            string // raw SNMP sysDescr when discovery stored it
	NeighborCount       int    // distinct LLDP/CDP/BGP-LS neighbors
	SwitchNeighborCount int    // neighbors whose inferred type is switch
	RouterNeighborCount int    // neighbors whose inferred type is router
	HasIGPAdjacency     bool   // appears in the BGP-LS/IGP topology
	TunnelCount         int    // discovered tunnel interfaces terminating here
	HasCloudTunnel      bool   // ≥1 tunnel remote end in published cloud space
}

// LinkFact is one deduped, undirected adjacency (output of the link normalizer).
type LinkFact struct {
	Source     string // local managed device id
	Target     string // managed device id, or "ext:<sysname>" for an unresolved neighbour
	SourceName string
	TargetName string
	LocalPort  string
	RemotePort string
	Protocol   string // "lldp"|"cdp"|"bgp_ls"; "+"-joined when several confirm
	IGP        string // bgp_ls IGP origin
	Area       string
	Metric     uint32 // IGP/TE cost (0 = unknown → SPF treats as 1)
	// Utilization — set HasUtil to distinguish "0%" from "unmeasured".
	Utilization   float64
	HasUtil       bool
	Status        string // up|down|degraded|warning|maintenance|unknown ("" → unknown)
	Resolved      bool   // target is a managed device
	Bidirectional bool
	LastSeen      time.Time
}

// AlertFact is one active alert affecting a device (drives node health).
type AlertFact struct {
	DeviceID string
	Severity string // critical|warning|info…
	Summary  string
	FiredAt  time.Time
}

// PathFact is a measured A→B path (traceroute), as an ordered list of device ids.
type PathFact struct {
	ID   string
	Hops []string
}

// Input is everything the projection needs. All slices are tenant-scoped by the
// caller; the projection trusts the scoping but validates shape (zero-trust on
// content — empty/degenerate facts are dropped, never panicked on).
type Input struct {
	Mode     string
	TenantID string
	Now      time.Time
	Devices  []DeviceFact
	Links    []LinkFact
	Alerts   []AlertFact
	Paths    []PathFact
	// SrcID/DstID — optional path_trace endpoints; when set (and no measured path
	// is supplied) the projection computes the IGP-weighted shortest path.
	SrcID      string
	DstID      string
	StaleAfter time.Duration // a device unseen longer than this → change_state=stale (0 → 24h default)
	// MaintenanceDevices — device ids currently inside an active maintenance
	// window (item 121). Covered devices render HealthMaintenance instead of
	// ok/unknown; an active critical/warning alert still wins (planned work is
	// calm, never a blindfold).
	MaintenanceDevices map[string]bool
}
