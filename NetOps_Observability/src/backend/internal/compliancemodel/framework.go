package compliancemodel

import "sort"

// Framework identities the seed providers report. The version is part of the
// identity (§5d: frameworks are abstract AND versioned — added independently).
const (
	FrameworkNISTCSF = "NIST CSF 2.0"
	FrameworkCIS     = "CIS Controls v8"
	FrameworkHIPAA   = "HIPAA Security Rule"
	FrameworkPCIDSS  = "PCI-DSS v4.0"
)

// FrameworkRequirement is one requirement of a framework that a canonical
// control maps to (control → framework-requirement). This is the "crosswalk"
// edge — Correlix owns the Control; the FrameworkProvider owns the edge from a
// control to that framework's requirement text/id.
type FrameworkRequirement struct {
	Framework     string `json:"framework"`
	RequirementID string `json:"requirement_id"` // e.g. "164.312(e)(1)", "Req 4", "PR.DS-2"
	Title         string `json:"title,omitempty"`
}

// FrameworkProvider is the §5h ABSTRACT framework/crosswalk seam: it answers
// "which of this framework's requirements does canonical control X satisfy, and
// which controls are in this framework's technical scope?". PCI, CIS, ISO, HIPAA
// and others plug in INDEPENDENTLY behind it — the owned Control/Mapping core
// never changes when a framework is added (§5d/§5h). Per Q4 the seed impls are
// minimal in-code crosswalks over ONLY the seed controls; broad official
// crosswalk DATA (NIST 800-53↔PCI/HIPAA/CSF/ISO) is a LATER provider, deferred.
//
// It is deliberately vendor/framework-AGNOSTIC in shape: no framework specifics
// leak into the interface, so a licensed-content provider (which must not
// redistribute its data through the core) satisfies the same contract.
type FrameworkProvider interface {
	// Framework is the provider's stable framework identity (a Framework* value).
	Framework() string
	// Version is the framework revision this provider maps against.
	Version() string
	// ControlsInScope returns the canonical control ids that fall within this
	// framework's technical scope — INCLUDING controls the owned catalog has no
	// check for yet. That inclusion is what makes coverage % honest (§5d): the
	// denominator is "controls this framework expects", the numerator is "those
	// Correlix can actually evidence".
	ControlsInScope() []string
	// RequirementsFor returns the framework requirement(s) a canonical control
	// satisfies in this framework. An empty result means the control is out of
	// this framework's scope (so a check for it contributes NOTHING to this
	// framework — the basis of per-framework independence).
	RequirementsFor(controlID string) []FrameworkRequirement
}

// StaticFrameworkProvider is an in-code FrameworkProvider built from a fixed
// control→requirements crosswalk. It is the seed vehicle for the minimal v1
// frameworks; a future licensed/official crosswalk provider implements the same
// interface without touching this one.
type StaticFrameworkProvider struct {
	framework string
	version   string
	crosswalk map[string][]FrameworkRequirement
}

// NewStaticFrameworkProvider builds a provider from a control→requirements map.
// It copies the input so the provider is immutable from the caller's side. The
// crosswalk keys ARE the controls in scope.
func NewStaticFrameworkProvider(framework, version string, crosswalk map[string][]FrameworkRequirement) *StaticFrameworkProvider {
	cp := make(map[string][]FrameworkRequirement, len(crosswalk))
	for control, reqs := range crosswalk {
		rr := make([]FrameworkRequirement, len(reqs))
		copy(rr, reqs)
		cp[control] = rr
	}
	return &StaticFrameworkProvider{framework: framework, version: version, crosswalk: cp}
}

// Framework identifies the provider.
func (p *StaticFrameworkProvider) Framework() string { return p.framework }

// Version returns the framework revision.
func (p *StaticFrameworkProvider) Version() string { return p.version }

// ControlsInScope returns the in-scope control ids, sorted (stable output).
func (p *StaticFrameworkProvider) ControlsInScope() []string {
	out := make([]string, 0, len(p.crosswalk))
	for id := range p.crosswalk {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

// RequirementsFor returns a copy of the requirements a control satisfies here.
func (p *StaticFrameworkProvider) RequirementsFor(controlID string) []FrameworkRequirement {
	reqs, ok := p.crosswalk[controlID]
	if !ok {
		return nil
	}
	out := make([]FrameworkRequirement, len(reqs))
	copy(out, reqs)
	return out
}

// req is a small constructor to keep the seed crosswalks readable.
func req(framework, id, title string) FrameworkRequirement {
	return FrameworkRequirement{Framework: framework, RequirementID: id, Title: title}
}

// NewNISTCSFProvider seeds the NIST CSF 2.0 crosswalk over the seed controls.
// The existing checks tag CSF directly (ID.AM-1/-2), so every seed control maps
// (coverage over the mapped set is complete). Minimal, in-code (Q4).
func NewNISTCSFProvider() *StaticFrameworkProvider {
	f := FrameworkNISTCSF
	return NewStaticFrameworkProvider(f, "2.0", map[string][]FrameworkRequirement{
		ControlCM8: {req(f, "ID.AM-1", "Inventories of hardware managed")},
		ControlCM2: {req(f, "PR.IP-1", "Baseline configuration maintained")},
		ControlIA5: {req(f, "PR.AC-1", "Identities and credentials managed")},
		ControlSC8: {req(f, "PR.DS-2", "Data-in-transit is protected")},
		ControlSI2: {req(f, "ID.RA-1", "Asset vulnerabilities identified")},
	})
}

// NewCISProvider seeds the CIS Controls v8 crosswalk. The SNMP checks tag CIS
// directly; the rest of the seed controls map to their CIS Control. Minimal (Q4).
func NewCISProvider() *StaticFrameworkProvider {
	f := FrameworkCIS
	return NewStaticFrameworkProvider(f, "8.0", map[string][]FrameworkRequirement{
		ControlCM8: {req(f, "CIS-1", "Inventory and Control of Enterprise Assets")},
		ControlCM2: {req(f, "CIS-4", "Secure Configuration of Enterprise Assets")},
		ControlIA5: {req(f, "CIS-5", "Account Management")},
		ControlSC8: {req(f, "CIS-3", "Data Protection")},
		ControlSI2: {req(f, "CIS-7", "Continuous Vulnerability Management")},
	})
}

// NewHIPAAProvider seeds the HIPAA Security Rule crosswalk. HIPAA is a
// LEGAL/regulatory framework: only the §164.312 Technical Safeguards map to a
// device config audit at all (§5d), so its scope is DELIBERATELY narrow and
// INCLUDES technical-safeguard controls Correlix has no check for yet
// (AC-3/AU-2/SI-7) — that is what makes the coverage % honest, and what makes a
// HIPAA-only tenant's view genuinely different from a PCI tenant's.
//
// NOTE: this is control EVIDENCE for the technical slice, NEVER "certified HIPAA
// compliance" (§5d defensible-claim rule); the broad §164.308/.310 realization
// is out of a config audit's reach and out of Q4 scope.
func NewHIPAAProvider() *StaticFrameworkProvider {
	f := FrameworkHIPAA
	return NewStaticFrameworkProvider(f, "45 CFR 164.312", map[string][]FrameworkRequirement{
		// Check-covered technical safeguards:
		ControlSC8: {req(f, "164.312(e)(1)", "Transmission Security")},
		ControlIA5: {req(f, "164.312(d)", "Person or Entity Authentication")},
		// In-scope technical safeguards Correlix has NO check for (honest coverage):
		"AC-3": {req(f, "164.312(a)(1)", "Access Control")},
		"AU-2": {req(f, "164.312(b)", "Audit Controls")},
		"SI-7": {req(f, "164.312(c)(1)", "Integrity")},
	})
}

// NewPCIProvider seeds the PCI-DSS v4.0 crosswalk. PCI is also regulatory but its
// TECHNICAL reqs (1/2/4/6/8/10) cover more of the seed controls than HIPAA does,
// so a PCI tenant's scope is broader — proving the two frameworks are scored on
// DIFFERENT, INDEPENDENT scopes from the same shared findings. Includes in-scope
// reqs with no Correlix check (AC-3/AU-2) for honest coverage. Minimal (Q4).
func NewPCIProvider() *StaticFrameworkProvider {
	f := FrameworkPCIDSS
	return NewStaticFrameworkProvider(f, "4.0", map[string][]FrameworkRequirement{
		// Check-covered technical requirements:
		ControlSC8: {req(f, "Req 4", "Protect cardholder data with strong cryptography during transmission")},
		ControlIA5: {req(f, "Req 8", "Identify users and authenticate access")},
		ControlCM8: {req(f, "Req 2", "Apply secure configurations to all system components")},
		ControlCM2: {req(f, "Req 2", "Apply secure configurations to all system components")},
		ControlSI2: {req(f, "Req 6", "Develop and maintain secure systems and software")},
		// In-scope technical reqs Correlix has NO check for (honest coverage):
		"AC-3": {req(f, "Req 7", "Restrict access by business need to know")},
		"AU-2": {req(f, "Req 10", "Log and monitor all access")},
	})
}
