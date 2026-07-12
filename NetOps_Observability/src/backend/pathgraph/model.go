// Package pathgraph implements the Service Path Graph frozen domain contract
// (docs/design/service-path-graph-contract.md, contract_version = 1).
//
// It is the PURE domain half: entities (§2), the ranked endpoint/hop resolver
// (§3), the observed/inferred split (§4), typed edges (§5), the join rules (§6)
// and the ordered-spine builder (§7). It performs NO I/O — storage and HTTP live
// in the main package — so every rule in the contract is unit-testable without a
// database, and the resolver cannot be short-circuited by a caller's convenience.
//
// The one structural invariant worth stating up front, because it is the whole
// point of the contract: a Resolution's EntityRef is populated ONLY by ranks 1–5
// (observed). Rank 6 (cloud route/UDR) lands in Supporting; rank 7 (shared token
// / rDNS / name similarity) lands in CandidateRef. Neither can ever become an
// authoritative graph edge, because the spine builder reads EntityRef and
// Authoritative — not CandidateRef. Token overlap is a coincidence detector, and
// the type system now says so.
package pathgraph

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"
)

// ContractVersion is stamped on every emitted path object (§11).
const ContractVersion = 1

// ── §1 provenance ────────────────────────────────────────────────────────────

// Data classes. Customer/default APIs return ONLY DataClassLive (§1).
const (
	DataClassLive      = "live"
	DataClassSynthetic = "synthetic"
	DataClassReplay    = "replay"
	DataClassLab       = "lab"
)

// ValidDataClass reports whether c is one of the four §1 classes.
func ValidDataClass(c string) bool {
	switch c {
	case DataClassLive, DataClassSynthetic, DataClassReplay, DataClassLab:
		return true
	}
	return false
}

// Provenance is the §1 block carried by EVERY object in this contract.
// Immutable: set at creation, never rewritten.
type Provenance struct {
	TenantID     string `json:"tenant_id"`
	DataClass    string `json:"data_class"`
	Environment  string `json:"environment"`
	ScenarioID   string `json:"scenario_id,omitempty"`
	RunID        string `json:"run_id,omitempty"`
	ProducerID   string `json:"producer_id"`
	ProvenanceID string `json:"provenance_id"`
}

// Validate enforces the non-negotiable provenance fields. An object that cannot
// state who produced it, for which tenant, in which data class, is not admissible
// evidence — it is rejected at the boundary rather than stored and later trusted.
func (p Provenance) Validate() error {
	if !ValidDataClass(p.DataClass) {
		return fmt.Errorf("invalid data_class %q", p.DataClass)
	}
	if strings.TrimSpace(p.ProducerID) == "" {
		return fmt.Errorf("producer_id is required")
	}
	if strings.TrimSpace(p.ProvenanceID) == "" {
		return fmt.Errorf("provenance_id is required")
	}
	if strings.TrimSpace(p.Environment) == "" {
		return fmt.Errorf("environment is required")
	}
	// TenantID "" is legal: it means platform/untagged, exactly as everywhere else
	// in the platform. It is still an EXACT match key — untagged never joins a
	// tenant's data, it is only visible to the platform (cross-tenant) principal.
	return nil
}

// IsLive reports whether this record may anchor a customer-facing verdict (§1).
func (p Provenance) IsLive() bool { return p.DataClass == DataClassLive }

// ── §2.1 Endpoint ────────────────────────────────────────────────────────────

// Endpoint kinds (§2.1).
const (
	KindClient          = "client"
	KindLANGateway      = "lan_gateway"
	KindWANEdge         = "wan_edge"
	KindNVA             = "nva"
	KindCloudEdge       = "cloud_edge"
	KindAppEndpoint     = "app_endpoint"
	KindServiceEndpoint = "service_endpoint"
	KindTransit         = "transit"
	KindUnknown         = "unknown"
	// KindApplication is the SERVICE tail of the spine (§10: "AWS application").
	// It is not an address-bearing Endpoint kind — it is the service the app
	// endpoint exposes, reached only through a rank 2/4 binding.
	KindApplication = "application"
)

// Confidence levels (§2.1).
const (
	ConfAuthoritative = "authoritative"
	ConfStrong        = "strong"
	ConfCandidate     = "candidate"
	ConfUnknown       = "unknown"
)

// Endpoint is a BINDING of an address to an entity, within a network context,
// over a time window (§2.1) — not merely an IP. The same address in two tenants
// is two Endpoints and they never join.
type Endpoint struct {
	EndpointID        string     `json:"endpoint_id"`
	Address           string     `json:"address"`
	AddressFamily     string     `json:"address_family"` // ipv4 | ipv6
	NetworkContext    string     `json:"network_context"`
	Kind              string     `json:"kind"`
	ResolvedEntityRef string     `json:"resolved_entity_ref,omitempty"`
	ResolutionMethod  string     `json:"resolution_method"`
	Confidence        string     `json:"confidence"`
	ValidFrom         time.Time  `json:"valid_from"`
	ValidTo           *time.Time `json:"valid_to,omitempty"`
	EvidenceRef       string     `json:"evidence_ref"`
	Provenance        `json:"provenance"`
}

// ── §2.2 PathDefinition ──────────────────────────────────────────────────────

// PathDefinition is the logical path being measured (§2.2). Path identity =
// (tenant, src, dst, direction, protocol, dst_port, vantage, network_context):
// any difference is a DIFFERENT path — TCP:443 and ICMP to the same destination
// are distinct objects and are allowed to disagree (§8).
type PathDefinition struct {
	PathID         string `json:"path_id"`
	SrcEndpointRef string `json:"src_endpoint_ref"`
	DstEndpointRef string `json:"dst_endpoint_ref"`
	SrcAddress     string `json:"src_address"`
	DstAddress     string `json:"dst_address"`
	Direction      string `json:"direction"` // forward | reverse
	Protocol       string `json:"protocol"`  // icmp | tcp | udp
	DstPort        int    `json:"dst_port,omitempty"`
	VantageID      string `json:"vantage_id"`
	NetworkContext string `json:"network_context"`
	Provenance     `json:"provenance"`
}

// PathID derives the deterministic identity of a path from ONLY the §2.2 identity
// fields. Two measurements agree on a path_id iff every identity field matches —
// which is what makes "asymmetric paths are distinct", "vantages are distinct" and
// "TCP ≠ ICMP" structural facts rather than conventions (§8).
func PathID(tenant, srcEP, dstEP, direction, protocol string, dstPort int, vantage, netCtx string) string {
	h := sha256.Sum256([]byte(strings.Join([]string{
		normalize(tenant), normalize(srcEP), normalize(dstEP), normalize(direction),
		normalize(protocol), fmt.Sprintf("%d", dstPort), normalize(vantage), normalize(netCtx),
	}, "|")))
	return "pd-" + hex.EncodeToString(h[:10])
}

// EndpointID derives the stable identity of an address→context binding within a
// tenant. The binding's VALIDITY is carried by valid_from/valid_to; the id keys
// the binding, so a re-observed endpoint updates a window instead of forking.
func EndpointID(tenant, address, netCtx string) string {
	h := sha256.Sum256([]byte(normalize(tenant) + "|" + normalize(address) + "|" + normalize(netCtx)))
	return "ep-" + hex.EncodeToString(h[:10])
}

func normalize(s string) string { return strings.ToLower(strings.TrimSpace(s)) }

// ── §2.3 PathObservation ─────────────────────────────────────────────────────

// Observation methods (§2.3).
const (
	MethodTracerouteICMP = "traceroute_icmp"
	MethodTracerouteTCP  = "traceroute_tcp"
	MethodSTAMP          = "stamp"
	MethodTransaction    = "transaction"
	MethodFlowStitch     = "flow_stitch"
)

// Observation status (§2.3).
const (
	StatusComplete = "complete"
	StatusPartial  = "partial"
	StatusFailed   = "failed"
)

// PathObservation is IMMUTABLE — one per measurement run (§2.3). Observations are
// never updated in place: history is the point (route changes, §8). "Current path"
// is a QUERY (latest observation per path_id), never a mutable row.
type PathObservation struct {
	ObservationID   string    `json:"observation_id"`
	PathID          string    `json:"path_id"`
	ObservedAt      time.Time `json:"observed_at"`
	Method          string    `json:"method"`
	VantageID       string    `json:"vantage_id"`
	Status          string    `json:"status"`
	HopCount        int       `json:"hop_count"`
	ContractVersion int       `json:"contract_version"`
	Provenance      `json:"provenance"`
}

// Validate enforces §2.3: run_id is REQUIRED on an observation (it is the handle
// that makes cleanup possible on tenant+run alone — never on IP/name patterns).
func (o PathObservation) Validate() error {
	if err := o.Provenance.Validate(); err != nil {
		return err
	}
	if strings.TrimSpace(o.RunID) == "" {
		return fmt.Errorf("observation %s: run_id is required (§2.3)", o.ObservationID)
	}
	if strings.TrimSpace(o.PathID) == "" {
		return fmt.Errorf("observation %s: path_id is required", o.ObservationID)
	}
	switch o.Method {
	case MethodTracerouteICMP, MethodTracerouteTCP, MethodSTAMP, MethodTransaction, MethodFlowStitch:
	default:
		return fmt.Errorf("observation %s: invalid method %q", o.ObservationID, o.Method)
	}
	switch o.Status {
	case StatusComplete, StatusPartial, StatusFailed:
	default:
		return fmt.Errorf("observation %s: invalid status %q", o.ObservationID, o.Status)
	}
	return nil
}

// Stale reports whether the observation is outside its freshness window (§8):
// a stale observation may be rendered as history, but it can NEVER anchor a live
// verdict — the API says so explicitly rather than letting the UI guess.
func (o PathObservation) Stale(now time.Time, freshness time.Duration) bool {
	if freshness <= 0 {
		return false
	}
	return now.Sub(o.ObservedAt) > freshness
}

// ── §2.4 PathHop ─────────────────────────────────────────────────────────────

// Hop states (§2.4). A non-responding hop is PRESERVED as `missing` — never
// dropped, never silently bridged.
const (
	HopResponding = "responding"
	HopMissing    = "missing"
	HopFiltered   = "filtered"
)

// Transformations (§2.4).
const (
	TransformNone          = "none"
	TransformNAT           = "nat"
	TransformProxy         = "proxy"
	TransformLoadBalancer  = "load_balancer"
	TransformTunnelIngress = "tunnel_ingress"
	TransformTunnelEgress  = "tunnel_egress"
)

// PathHop is one ordered hop of an observation (§2.4). hop_index is 1-based and
// ORDERED: the spine order is DATA, not layout. tenant_id is denormalized onto the
// hop for RLS.
type PathHop struct {
	ObservationID     string    `json:"observation_id"`
	HopIndex          int       `json:"hop_index"`
	State             string    `json:"state"`
	ObservedAddress   string    `json:"observed_address,omitempty"` // empty when state != responding
	ResolvedEntityRef string    `json:"resolved_entity_ref,omitempty"`
	ResolutionMethod  string    `json:"resolution_method"`
	Confidence        string    `json:"confidence"`
	SeamID            string    `json:"seam_id,omitempty"`
	RTTms             float64   `json:"rtt_ms,omitempty"`
	LossPct           float64   `json:"loss_pct,omitempty"`
	Transformation    string    `json:"transformation"`
	EvidenceRef       string    `json:"evidence_ref"`
	ObservedAt        time.Time `json:"observed_at"`
	NetworkContext    string    `json:"network_context"`
	Kind              string    `json:"kind"`
	TenantID          string    `json:"tenant_id"`
	DataClass         string    `json:"data_class"`
	// CandidateRef holds a rank-7 (token/rDNS/name) match. It is DELIBERATELY a
	// separate field from ResolvedEntityRef: nothing in the graph builder reads
	// it, so a name coincidence can be shown to an operator as a lead without ever
	// becoming an edge (§3 rank 7: never authoritative).
	CandidateRef string `json:"candidate_ref,omitempty"`
}

// Validate enforces the §2.4 invariants that the rest of the system relies on:
// a responding hop HAS an address; a missing/filtered hop does NOT (its absence
// is the fact being recorded).
func (h PathHop) Validate() error {
	switch h.State {
	case HopResponding:
		if strings.TrimSpace(h.ObservedAddress) == "" {
			return fmt.Errorf("hop %d: responding hop requires an observed_address", h.HopIndex)
		}
	case HopMissing, HopFiltered:
		if strings.TrimSpace(h.ObservedAddress) != "" {
			return fmt.Errorf("hop %d: %s hop must not carry an observed_address", h.HopIndex, h.State)
		}
	default:
		return fmt.Errorf("hop %d: invalid state %q", h.HopIndex, h.State)
	}
	if h.HopIndex < 1 {
		return fmt.Errorf("hop index %d: must be 1-based", h.HopIndex)
	}
	switch h.Transformation {
	case TransformNone, TransformNAT, TransformProxy, TransformLoadBalancer,
		TransformTunnelIngress, TransformTunnelEgress:
	default:
		return fmt.Errorf("hop %d: invalid transformation %q", h.HopIndex, h.Transformation)
	}
	return nil
}
