package appid

import "time"

// FusionEngineVersion is bumped whenever the fusion ALGORITHM changes in a way that
// can alter a verdict. A stored FusedIdentity records the version that produced it,
// so replay can detect drift and a catalog/engine update creates a NEW versioned
// result without rewriting history (mirrors the correlation engine's engine_version).
const FusionEngineVersion = "appfuse-1"

// ── confidence band ──────────────────────────────────────────────────────────
// ConfidenceBand is the operator-facing bucket for a fused identity. It is DERIVED
// from the verdict Tier + winning source strength (one source of truth) — never a
// separately re-derived number presented as a probability.
type ConfidenceBand string

const (
	BandUnresolved    ConfidenceBand = "unresolved"
	BandLow           ConfidenceBand = "low"
	BandMedium        ConfidenceBand = "medium"
	BandHigh          ConfidenceBand = "high"
	BandAuthoritative ConfidenceBand = "authoritative"
)

// rank orders bands worst→best (for comparisons/sorting).
func (b ConfidenceBand) rank() int {
	switch b {
	case BandAuthoritative:
		return 4
	case BandHigh:
		return 3
	case BandMedium:
		return 2
	case BandLow:
		return 1
	default:
		return 0
	}
}

// BandFor maps a verdict (tier + strongest backing strength) to a band. Authoritative
// only when an authoritative source (strength 4) carried a confirmed verdict.
func BandFor(tier Tier, strength int) ConfidenceBand {
	switch tier {
	case Confirmed:
		if strength >= 4 {
			return BandAuthoritative
		}
		return BandHigh
	case Suspected:
		if strength >= 2 {
			return BandMedium
		}
		return BandLow
	default:
		return BandUnresolved
	}
}

// ── resolution state ─────────────────────────────────────────────────────────
// ResolutionState is the lifecycle of an identity decision (extends the engine's
// unknown-first-class principle into the spec's 5 states).
type ResolutionState string

const (
	StateObserved   ResolutionState = "observed"   // a single source reported it; not yet corroborated/fused
	StateFused      ResolutionState = "fused"      // multiple corroborating sources were combined
	StateInferred   ResolutionState = "inferred"   // derived from weak/indirect evidence (ip/asn/port/dns-only)
	StateConflicted ResolutionState = "conflicted" // authoritative sources disagree — identity not asserted
	StateUnknown    ResolutionState = "unknown"    // no admissible evidence — FIRST CLASS, never a guess
)

// ── canonical application ────────────────────────────────────────────────────
// VendorAppID namespaces a vendor application id. A raw vendor id (numeric or string)
// is NEVER globally unique, so it is keyed by (vendor, product, catalog version).
type VendorAppID struct {
	Vendor         string `json:"vendor"`                    // paloalto | fortinet | cisco | ...
	Product        string `json:"product,omitempty"`         // e.g. panos | fortios | secure-firewall
	CatalogVersion string `json:"catalog_version,omitempty"` // the vendor content/app-db version, if known
	ID             string `json:"id"`                        // the raw vendor app-id / name (never discarded)
}

// CanonicalApplication is the Correlix-canonical identity an observation maps to.
// It is a SUPERSET projection of the `applications` table (#81 P0) plus alias/domain
// metadata; the business-app↔component hierarchy is expressed via ParentID.
type CanonicalApplication struct {
	ID             string        `json:"id"`                 // opaque immutable canonical id (UUID)
	TenantID       string        `json:"tenant_id"`          // "" = global scope (shared catalog)
	DisplayName    string        `json:"display_name"`       // "Microsoft Teams"
	Provider       string        `json:"provider,omitempty"` // "Microsoft"
	Family         string        `json:"family,omitempty"`   // "Microsoft 365"
	Category       string        `json:"category,omitempty"` // "Collaboration"
	Subcategory    string        `json:"subcategory,omitempty"`
	ParentID       string        `json:"parent_id,omitempty"`  // component → business-app link ("Teams Media" → "Microsoft Teams")
	Aliases        []string      `json:"aliases,omitempty"`    // known display aliases
	VendorIDs      []VendorAppID `json:"vendor_ids,omitempty"` // namespaced vendor app-ids that resolve here
	Domains        []string      `json:"domains,omitempty"`    // domains / domain patterns
	Lifecycle      string        `json:"lifecycle"`            // active | deprecated | retired
	CatalogVersion int           `json:"catalog_version"`
	Scope          string        `json:"scope"` // global | tenant
}

// ── fused identity ───────────────────────────────────────────────────────────
// IdentityScope binds a fused identity to what it is ABOUT (a flow/session/workload
// and/or a correlation object). At least one scope key should be set; dst-only scope
// is weaker than exact-session scope (the fusion engine weights this — P3).
type IdentityScope struct {
	FlowID        string `json:"flow_id,omitempty"`
	SessionID     string `json:"session_id,omitempty"`
	WorkloadID    string `json:"workload_id,omitempty"`
	CorrelationID string `json:"correlation_id,omitempty"`
	SrcIP         string `json:"src_ip,omitempty"`
	DstIP         string `json:"dst_ip,omitempty"`
	DstPort       int    `json:"dst_port,omitempty"`
	Proto         string `json:"proto,omitempty"`
}

// ExactSession reports whether the scope identifies a single session/flow (vs a
// destination-only scope) — exact-session evidence outranks dst-only in fusion.
func (s IdentityScope) ExactSession() bool {
	return s.SessionID != "" || s.FlowID != ""
}

// Candidate is an alternative application the evidence could support — surfaced for
// transparency (and the basis for the "conflicted" state).
type Candidate struct {
	App        string         `json:"app"`
	Confidence float64        `json:"confidence"`
	Band       ConfidenceBand `json:"band"`
	Sources    []Source       `json:"sources"`
}

// FusedIdentity is the durable, explainable result of fusing observations for a
// scope. It EMBEDS the existing Verdict (App/Tier/Confidence/Contradicted/Signals/
// EvidenceMissing stay backward-compatible) and adds the provenance, banding,
// alternatives, explanation codes and versioning the spec requires.
type FusedIdentity struct {
	FusionID          string            `json:"fusion_id"`
	TenantID          string            `json:"tenant_id"`
	Scope             IdentityScope     `json:"scope"`
	CanonicalAppID    string            `json:"canonical_app_id,omitempty"`
	Provider          string            `json:"provider,omitempty"`
	Component         string            `json:"component,omitempty"`
	AppProtocol       string            `json:"app_protocol,omitempty"`       // QUIC (a protocol, NOT the business app)
	TransportProtocol string            `json:"transport_protocol,omitempty"` // UDP
	EvidenceScore     int               `json:"evidence_score"`               // 0..100 (§G) — an evidence score, NOT a probability
	Band              ConfidenceBand    `json:"band"`
	State             ResolutionState   `json:"state"`
	Alternatives      []Candidate       `json:"alternatives,omitempty"`
	Explanations      []ExplanationCode `json:"explanations"`
	CatalogVersion    int               `json:"catalog_version"`
	FusionVersion     string            `json:"fusion_version"`
	FusedAt           time.Time         `json:"fused_at"`
	Verdict                             // App, Tier, Confidence, Contradicted, Signals, EvidenceMissing
}
