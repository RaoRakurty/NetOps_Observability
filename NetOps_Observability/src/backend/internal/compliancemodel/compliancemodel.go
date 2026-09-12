// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// Package compliancemodel owns Correlix's CANONICAL compliance model — the
// Control layer and the Check→Control Mapping — plus the abstract framework
// (crosswalk) provider seam. It is the "OWNED middle" of the compliance model
// (COMPLIANCE_MODEL_2026-08-25 / SECURITY_OBSERVABILITY_HLD §5d/§5h): Correlix
// owns the Control / Mapping / Finding shape; frameworks (NIST/PCI/CIS/ISO/HIPAA)
// are INTERCHANGEABLE providers behind an interface, added INDEPENDENTLY.
//
// This package layers the T1 owned finding model (internal/secfindings) onto the
// legacy compliance evaluator (internal/compliance) WITHOUT touching either —
// exactly as internal/advisory wrapped internal/vuln (T3). The dependency is
// strictly one-way: compliancemodel → {compliance (read-only), secfindings} +
// stdlib. It wires to no HTTP handler, no correlation engine and no bus.
//
// Q4 scope (owner, 2026-08-25 — SCOPE-TIGHTENING): v1 does NOT fund broad
// benchmark maintenance. So this package ships:
//   - the abstract Control + ControlMapping + FrameworkProvider SEAM (target
//     architecture, §5d/§5h), and
//   - a MINIMAL, in-code seed mapping covering ONLY the controls the existing 9
//     compliance checks already tag (NIST CSF / CIS / 800-53).
//
// It DELIBERATELY does NOT import or maintain the broad 800-53↔PCI/HIPAA/CSF/ISO
// crosswalk DATA — that realization is deferred until demand (Q4). Because the
// framework layer is a provider interface, adding that data later is "add a
// FrameworkProvider", no refactor of the owned core.
package compliancemodel

import "sort"

// Relationship names how strongly a check evidences a control (§5d honesty: a
// technical config check usually SUPPORTS a control without fully demonstrating
// it — admin/physical/process aspects are out of a config audit's reach).
type Relationship string

const (
	// RelSupports — the check contributes evidence toward the control but does
	// not fully demonstrate it (the honest default for a config-audit check).
	RelSupports Relationship = "supports"
	// RelSubsetOf — the check verifies a strict subset of the control.
	RelSubsetOf Relationship = "subset-of"
	// RelEquivalentTo — the check fully demonstrates the control.
	RelEquivalentTo Relationship = "equivalent-to"
)

// Valid reports whether r is a known relationship.
func (r Relationship) Valid() bool {
	switch r {
	case RelSupports, RelSubsetOf, RelEquivalentTo:
		return true
	default:
		return false
	}
}

// Control is a node in Correlix's OWNED, canonical control layer. The id space is
// the NIST 800-53 control family (the "rosetta stone" HUB every framework maps
// TO, §5d) so one control tag inherits many frameworks with no N² maps. It is
// VERSIONED so any past verdict is replayable against the catalog it was scored
// under (§5c).
type Control struct {
	ID      string `json:"id"`      // canonical 800-53-style id, e.g. "IA-5", "SC-8", "CM-8"
	Family  string `json:"family"`  // control family, e.g. "IA", "SC", "CM"
	Title   string `json:"title"`   // human title
	Version string `json:"version"` // catalog version the control is drawn from
}

// ControlRef binds one check to one control WITH the relationship strength. It is
// the element of the M:N Check↔Control mapping (a check satisfies MANY controls,
// a control is satisfied-by MANY checks).
type ControlRef struct {
	ControlID    string       `json:"control_id"`
	Relationship Relationship `json:"relationship"`
}

// ControlMapping is Correlix IP: which owned controls a single check evidences,
// and how strongly. It is the per-rule Check→Control[] mapping (§5d schema step
// "Mapping (check→controls, OUR IP, per-rule)").
type ControlMapping struct {
	Check    string       `json:"check"` // the compliance check id (== secfindings Finding.RawRuleID)
	Controls []ControlRef `json:"controls"`
}

// CatalogVersion is the pinned version stamp for the seed control catalog + the
// seed check→control mapping shipped in this package. It is stamped onto emitted
// findings' EvidenceRef so a verdict is replayable against the exact mapping it
// was scored under (§5c version-pinning).
const CatalogVersion = "correlix-controls-2026-08-25"

// controlCatalogVersion is the 800-53 revision the seed controls are drawn from.
const controlCatalogVersion = "NIST 800-53 Rev5"

// Catalog is the owned control layer + the check→control mapping. It is built
// fresh by DefaultCatalog (no mutable package-level state — §5 no-globals); a
// caller that needs custom controls composes its own via NewCatalog.
type Catalog struct {
	controls map[string]Control
	byCheck  map[string][]ControlRef
}

// NewCatalog builds a catalog from a control set and a check→control mapping. It
// copies its inputs so the returned catalog is immutable from the caller's side.
// A mapping referencing a control absent from controls is retained (the control
// is simply "known by id only"); callers that require full referential integrity
// can verify via Control.
func NewCatalog(controls []Control, mappings []ControlMapping) *Catalog {
	c := &Catalog{
		controls: make(map[string]Control, len(controls)),
		byCheck:  make(map[string][]ControlRef, len(mappings)),
	}
	for _, ctrl := range controls {
		c.controls[ctrl.ID] = ctrl
	}
	for _, m := range mappings {
		refs := make([]ControlRef, len(m.Controls))
		copy(refs, m.Controls)
		c.byCheck[m.Check] = refs
	}
	return c
}

// Control returns the canonical control by id.
func (c *Catalog) Control(id string) (Control, bool) {
	ctrl, ok := c.controls[id]
	return ctrl, ok
}

// Controls returns every canonical control, sorted by id (stable output).
func (c *Catalog) Controls() []Control {
	out := make([]Control, 0, len(c.controls))
	for _, ctrl := range c.controls {
		out = append(out, ctrl)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// ControlsForCheck returns the control refs a check evidences (M:N). A check with
// no mapping returns nil — an UNMAPPED finding contributes to no framework rather
// than being silently attributed somewhere.
func (c *Catalog) ControlsForCheck(check string) []ControlRef {
	refs, ok := c.byCheck[check]
	if !ok {
		return nil
	}
	out := make([]ControlRef, len(refs))
	copy(out, refs)
	return out
}

// HasCheckForControl reports whether ANY check in the mapping evidences the given
// control id. It is the coverage primitive: a framework control is "check-covered"
// when at least one owned check maps to it.
func (c *Catalog) HasCheckForControl(controlID string) bool {
	for _, refs := range c.byCheck {
		for _, r := range refs {
			if r.ControlID == controlID {
				return true
			}
		}
	}
	return false
}

// Owned control ids — the 800-53 Rev5 hub controls this platform can reason
// about. The first five are the ones the 9 legacy compliance checks tag and are
// the ONLY ones the seed check→control MAPPING covers; the rest are the controls
// the hardening catalog tags, declared here so a framework provider can put them
// in scope (and so a projection can report them as check-covered once a caller
// composes the hardening mappings in via Catalog.With).
//
// Declaring a control is NOT claiming a check for it: HasCheckForControl is the
// coverage primitive and answers from the MAPPING, never from this list.
const (
	ControlAC2  = "AC-2"  // Account Management
	ControlAC3  = "AC-3"  // Access Enforcement
	ControlAC4  = "AC-4"  // Information Flow Enforcement
	ControlAC17 = "AC-17" // Remote Access
	ControlAU2  = "AU-2"  // Event Logging
	ControlAU6  = "AU-6"  // Audit Record Review, Analysis and Reporting
	ControlAU8  = "AU-8"  // Time Stamps
	ControlCM2  = "CM-2"  // Baseline Configuration      (golden-version baseline)
	ControlCM7  = "CM-7"  // Least Functionality
	ControlCM8  = "CM-8"  // System Component Inventory  (asset inventory / drift)
	ControlIA2  = "IA-2"  // Identification and Authentication (Organizational Users)
	ControlIA3  = "IA-3"  // Device Identification and Authentication
	ControlIA5  = "IA-5"  // Authenticator Management    (SNMP community / credential)
	ControlSC5  = "SC-5"  // Denial-of-Service Protection
	ControlSC7  = "SC-7"  // Boundary Protection
	ControlSC8  = "SC-8"  // Transmission Confidentiality & Integrity (SNMPv3 crypto)
	ControlSI2  = "SI-2"  // Flaw Remediation            (known-exploited CVEs)
	ControlSI7  = "SI-7"  // Software, Firmware and Information Integrity
)

// Legacy compliance check ids (mirrored from internal/compliance's stable API
// surface — the same ids that land on secfindings.Finding.RawRuleID after
// conversion). Duplicated as our own constants rather than imported so this
// package owns its mapping keys and does not couple to unexported names.
const (
	checkSotRegistered = "sot-registered"
	checkSotName       = "sot-name"
	checkSotMgmtIP     = "sot-mgmt-ip"
	checkSotSerial     = "sot-serial"
	checkSotPlatform   = "sot-platform"
	checkSnmpVersion   = "snmp-version"
	checkSnmpV3Weak    = "snmp-v3-strength"
	checkOSConsensus   = "os-consensus"
	checkKEV           = "kev-exposure"
)

// seedControls returns the owned control layer: every 800-53 Rev5 control this
// platform's checks or framework projections reference, with its published
// family and title. Fresh slice per call (no shared mutable state).
func seedControls() []Control {
	v := controlCatalogVersion
	return []Control{
		{ID: ControlAC2, Family: "AC", Title: "Account Management", Version: v},
		{ID: ControlAC3, Family: "AC", Title: "Access Enforcement", Version: v},
		{ID: ControlAC4, Family: "AC", Title: "Information Flow Enforcement", Version: v},
		{ID: ControlAC17, Family: "AC", Title: "Remote Access", Version: v},
		{ID: ControlAU2, Family: "AU", Title: "Event Logging", Version: v},
		{ID: ControlAU6, Family: "AU", Title: "Audit Record Review, Analysis, and Reporting", Version: v},
		{ID: ControlAU8, Family: "AU", Title: "Time Stamps", Version: v},
		{ID: ControlCM2, Family: "CM", Title: "Baseline Configuration", Version: v},
		{ID: ControlCM7, Family: "CM", Title: "Least Functionality", Version: v},
		{ID: ControlCM8, Family: "CM", Title: "System Component Inventory", Version: v},
		{ID: ControlIA2, Family: "IA", Title: "Identification and Authentication (Organizational Users)", Version: v},
		{ID: ControlIA3, Family: "IA", Title: "Device Identification and Authentication", Version: v},
		{ID: ControlIA5, Family: "IA", Title: "Authenticator Management", Version: v},
		{ID: ControlSC5, Family: "SC", Title: "Denial-of-Service Protection", Version: v},
		{ID: ControlSC7, Family: "SC", Title: "Boundary Protection", Version: v},
		{ID: ControlSC8, Family: "SC", Title: "Transmission Confidentiality and Integrity", Version: v},
		{ID: ControlSI2, Family: "SI", Title: "Flaw Remediation", Version: v},
		{ID: ControlSI7, Family: "SI", Title: "Software, Firmware, and Information Integrity", Version: v},
	}
}

// seedMappings maps each of the 9 legacy compliance checks onto the owned hub
// control(s) it evidences. Relationship is "supports" throughout: a single
// config-audit check contributes evidence toward the control without fully
// demonstrating it (§5d honesty). This is the WHOLE broad-crosswalk surface v1
// ships — deliberately small and ours (Q4).
func seedMappings() []ControlMapping {
	supports := func(ids ...string) []ControlRef {
		refs := make([]ControlRef, 0, len(ids))
		for _, id := range ids {
			refs = append(refs, ControlRef{ControlID: id, Relationship: RelSupports})
		}
		return refs
	}
	return []ControlMapping{
		// SoT drift checks → asset/component inventory (NIST CSF ID.AM-1/-2 ≈ CM-8).
		{Check: checkSotRegistered, Controls: supports(ControlCM8)},
		{Check: checkSotName, Controls: supports(ControlCM8)},
		{Check: checkSotMgmtIP, Controls: supports(ControlCM8)},
		{Check: checkSotSerial, Controls: supports(ControlCM8)},
		{Check: checkSotPlatform, Controls: supports(ControlCM8)},
		// SNMP community in use → authenticator management (tagged IA-5).
		{Check: checkSnmpVersion, Controls: supports(ControlIA5)},
		// Weak SNMPv3 crypto → transmission confidentiality/integrity (tagged SC-8).
		{Check: checkSnmpV3Weak, Controls: supports(ControlSC8)},
		// OS off fleet baseline → baseline configuration (golden version).
		{Check: checkOSConsensus, Controls: supports(ControlCM2)},
		// Known-exploited CVE present → flaw remediation (CISA BOD 22-01 ≈ SI-2).
		{Check: checkKEV, Controls: supports(ControlSI2)},
	}
}

// DefaultCatalog builds the seed owned-control catalog + the seed check→control
// mapping for the 9 existing checks. Fresh instance per call (no globals).
func DefaultCatalog() *Catalog {
	return NewCatalog(seedControls(), seedMappings())
}

// With returns a NEW catalog carrying this catalog's controls and mappings plus
// the supplied ones. It is the composition seam for check→control mappings that
// live OUTSIDE this package: the hardening catalog owns its own rule ids and
// their 800-53 tags, and importing it here would invert the dependency (§2 — a
// domain package must not reach into another domain's catalog). A caller that
// has both composes them; this package stays a leaf.
//
// The receiver is not modified — a catalog is immutable once built — and a
// mapping for a check already present REPLACES the existing one, so a composed
// catalog has exactly one answer per check id.
func (c *Catalog) With(controls []Control, mappings []ControlMapping) *Catalog {
	out := &Catalog{
		controls: make(map[string]Control, len(c.controls)+len(controls)),
		byCheck:  make(map[string][]ControlRef, len(c.byCheck)+len(mappings)),
	}
	for id, ctrl := range c.controls {
		out.controls[id] = ctrl
	}
	for check, refs := range c.byCheck {
		cp := make([]ControlRef, len(refs))
		copy(cp, refs)
		out.byCheck[check] = cp
	}
	for _, ctrl := range controls {
		out.controls[ctrl.ID] = ctrl
	}
	for _, m := range mappings {
		refs := make([]ControlRef, len(m.Controls))
		copy(refs, m.Controls)
		out.byCheck[m.Check] = refs
	}
	return out
}
