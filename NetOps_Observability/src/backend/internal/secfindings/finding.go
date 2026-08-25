// Package secfindings owns Correlix's NORMALIZED security-finding model — the
// stable core every evidence provider produces into and every consumer reads
// from. Per the provider principle (SECURITY_OBSERVABILITY_HLD §5h): Correlix
// OWNS this shape; OpenSCAP, CIS-CAT, Lynis, vendor advisory APIs and the
// Correlix network-rule engine are interchangeable providers behind it, so the
// model must NOT depend on any one external tool's shape.
//
// The Finding type is OCSF-aligned (targeting the OCSF compliance_finding class
// 2003 field names in its JSON tags where natural) and is a strict SUPERSET of
// the legacy internal/compliance.Finding, so the 9 existing framework-tagged
// checks convert in via FromComplianceFinding with zero rewrite. It carries the
// three cross-cutting properties the design requires: an OCSF-normalized verdict
// (Pass/Warning/Fail/NotApplicable/Error — never a false "clear"), evidence held
// BY REFERENCE (an immutable, version-pinned pointer, never an inlined copy —
// §5c), and §3a tenant isolation hygiene (TenantID is stamped from the
// authenticated principal and is NEVER serialized to a client).
//
// This package is model + normalization + converter ONLY. It wires to no HTTP
// handler, no correlation engine and no bus — those are later tasks (T2+). It
// deliberately depends only on internal/compliance (read-only, for the
// converter) and the standard library.
package secfindings

import "time"

// EvidenceClass is the correlation lane a finding belongs to (§5b). Security is
// added to the engine as a fourth evidence class purely by emitting objects that
// carry one of these; the engine grounds them generically.
const (
	EvidencePosture  = "posture"  // hardening / compliance / config-audit state
	EvidenceExposure = "exposure" // seam-aware reachability exposure (§5e)
	EvidenceSignal   = "signal"   // active security signal (threat heuristics)
)

// Source identifies the provider that produced a finding (§5h). Correlix owns
// the model; the source is which swappable provider filled it in.
const (
	SourceOpenSCAP   = "openscap"
	SourceCISCAT     = "cis-cat"
	SourceLynis      = "lynis"
	SourceNetRule    = "correlix-netrule"    // the network-rule engine (§5e)
	SourceVendorAPI  = "vendor-api"          // vendor advisory / PSIRT (§5g)
	SourceCompliance = "correlix-compliance" // the legacy 9-check evaluator
)

// Resource kinds — the subject a finding is about.
const (
	KindHost          = "host"
	KindNetworkDevice = "network-device"
	KindContainer     = "container"
)

// Severity levels (superset of the legacy high/medium/low).
const (
	SeverityCritical = "critical"
	SeverityHigh     = "high"
	SeverityMedium   = "medium"
	SeverityLow      = "low"
	SeverityInfo     = "info"
)

// Resource is the subject of a finding — the device or host it concerns. It is a
// sub-struct so the finding reads cleanly and so providers that know more about
// the subject (hostname, address, platform) can fill it without widening the
// finding's top level.
type Resource struct {
	DeviceID   string `json:"uid,omitempty"`
	DeviceName string `json:"name,omitempty"`
	Hostname   string `json:"hostname,omitempty"`
	Address    string `json:"ip,omitempty"`
	Kind       string `json:"type,omitempty"`     // host|network-device|container
	Platform   string `json:"platform,omitempty"` // e.g. "Cisco IOS-XE 17.9"
}

// EvidenceRef is a BY-REFERENCE, version-pinned pointer to the raw artifact a
// verdict was derived from — an OVAL result, a ClickHouse row, a config line, an
// OS document (§5c). It is a POINTER on the Finding (never a copy of the raw
// evidence) precisely so the auditor requirement holds: the finding names where
// the evidence lives and under which ruleset version, and any past verdict is
// replayable without the finding having duplicated (and risked mutating) the
// underlying data.
type EvidenceRef struct {
	// Locator is the immutable address of the raw artifact (a URI, an index +
	// doc id, a config-file line ref, an ARF result id — provider-defined).
	Locator string `json:"locator"`
	// Kind names what Locator points at (oval-result|ch-row|config-line|os-doc|arf).
	Kind string `json:"kind,omitempty"`
	// RulesetVersion is the pinned (control, check, ruleset) version stamp that
	// makes the verdict reproducible (§5c version-pinning).
	RulesetVersion string `json:"ruleset_version,omitempty"`
	// Digest is an optional content hash proving the referenced artifact is the
	// exact one the verdict was computed against (immutability proof).
	Digest string `json:"digest,omitempty"`
}

// SeamContext is the optional seam attribution that turns a generic hardening
// flag into a contextual exposure verdict (§5e). It is set only for the
// seam-aware exposure findings; posture findings leave it nil.
type SeamContext struct {
	SeamID         string `json:"seam_id,omitempty"`
	SeamType       string `json:"seam_type,omitempty"` // e.g. "ISP", "internet", "mgmt"
	InternetFacing bool   `json:"internet_facing,omitempty"`
}

// Finding is Correlix's owned, normalized security finding — one subject × one
// evaluated rule, with an OCSF-normalized verdict and by-reference evidence. It
// is the single shape every provider produces and every consumer (correlation,
// API, reports) reads.
type Finding struct {
	// ── identity / provenance ────────────────────────────────────────────────
	ID string `json:"uid,omitempty"`
	// TenantID is stamped from the authenticated principal (§3a) and is NEVER
	// serialized to a client — json:"-" is a hard isolation-hygiene guarantee,
	// not a convenience. Scoping/auth logic lives at the boundary, not here.
	TenantID      string    `json:"-"`
	Source        string    `json:"source,omitempty"`         // one of the Source* constants
	ScanID        string    `json:"scan_uid,omitempty"`       // the assessment run that produced it
	Time          time.Time `json:"time"`                     // when the verdict was reached
	EvidenceClass string    `json:"evidence_class,omitempty"` // posture|exposure|signal

	// ── OCSF compliance object (the normalized verdict) ──────────────────────
	Status       string   `json:"status,omitempty"` // canonical StatusID.String()
	StatusID     StatusID `json:"status_id"`        // 1=Pass 2=Warning 3=Fail 4=NotApplicable 5=Error
	Standards    []string `json:"standards,omitempty"`
	ControlID    string   `json:"control,omitempty"` // canonical control id (owned control layer)
	ControlTitle string   `json:"control_title,omitempty"`
	Category     string   `json:"category_name,omitempty"` // grouping (e.g. drift|policy)
	Severity     string   `json:"severity,omitempty"`      // one of the Severity* constants

	// ── subject ──────────────────────────────────────────────────────────────
	Resource Resource `json:"resource"`

	// ── narrative / correlation-ready ────────────────────────────────────────
	Observed    string       `json:"observed,omitempty"`
	Intended    string       `json:"intended,omitempty"`
	Detail      string       `json:"status_detail,omitempty"`
	Remediation string       `json:"remediation,omitempty"`  // the "what to configure" (§5e)
	EvidenceRef *EvidenceRef `json:"evidence_ref,omitempty"` // by-reference, never a copy
	RawRuleID   string       `json:"raw_rule_id,omitempty"`  // the provider's native rule id

	// ── optional seam attribution (§5e) ──────────────────────────────────────
	SeamContext *SeamContext `json:"seam,omitempty"`
}
