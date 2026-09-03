package compliancemodel

import "sort"

// Framework identities the seed providers report. The version is part of the
// identity (§5d: frameworks are abstract AND versioned — added independently).
//
// NIST 800-53 Rev5 is the BASE: it is the hub every other framework here is a
// PROJECTION of, so it is the one framework whose "requirement" for a control is
// the control itself. The other four are crosswalks THROUGH that hub.
const (
	FrameworkNIST80053 = "NIST SP 800-53 Rev5"
	FrameworkNISTCSF   = "NIST CSF 2.0"
	FrameworkCIS       = "CIS Controls v8.1"
	FrameworkHIPAA     = "HIPAA Security Rule"
	FrameworkPCIDSS    = "PCI DSS v4.0.1"
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

// ─────────────────────────────────────────────────────────────────────────────
// THE SEED CROSSWALKS.
//
// These are HAND-AUTHORED, MINIMAL crosswalk edges over the controls this
// platform's own checks actually tag — not the official licensed crosswalk data
// (NIST's 800-53↔CSF informative references, the PCI SSC's 800-53 mapping, the
// HHS/NIST 800-66 HIPAA mapping). Those are a LATER provider behind the same
// interface (§5h); nothing here redistributes benchmark or crosswalk text.
//
// Each edge is a defensible "this 800-53 control contributes evidence toward
// that framework requirement", and the §5d caption on every scorecard says the
// number is control EVIDENCE, never certified compliance.
//
// A framework's SCOPE deliberately includes controls Correlix has NO check for
// (AC-3, SI-7 …). That inclusion is what keeps the coverage % honest: the
// denominator is "controls this framework expects of a device configuration",
// the numerator is "the ones we can actually evidence".
// ─────────────────────────────────────────────────────────────────────────────

// NewNIST80053Provider is the BASE framework: the 800-53 Rev5 hub itself. Its
// scope is every owned control and each control's "requirement" is the control,
// so enabling it reports the catalog exactly as the platform models it — with no
// crosswalk hop in between, and therefore no crosswalk judgement to disagree
// with. It is the framework a tenant with no regulatory driver should run.
func NewNIST80053Provider() *StaticFrameworkProvider {
	f := FrameworkNIST80053
	crosswalk := map[string][]FrameworkRequirement{}
	for _, ctrl := range seedControls() {
		crosswalk[ctrl.ID] = []FrameworkRequirement{req(f, ctrl.ID, ctrl.Title)}
	}
	return NewStaticFrameworkProvider(f, "Rev 5 (Release 5.2.0)", crosswalk)
}

// NewNISTCSFProvider seeds the NIST CSF 2.0 crosswalk.
//
// CSF 2.0 (February 2024) RENUMBERED the subcategories CSF 1.1 used: PR.AC-*
// became PR.AA-* (Identity Management, Authentication and Access Control),
// PR.IP-* was replaced by PR.PS-* (Platform Security), and network protection
// moved to PR.IR-* (Technology Infrastructure Resilience). The ids below are the
// 2.0 ones — the previous seed carried 1.1 ids under a "2.0" label, which is the
// kind of quiet version drift a scorecard must never have.
func NewNISTCSFProvider() *StaticFrameworkProvider {
	f := FrameworkNISTCSF
	return NewStaticFrameworkProvider(f, "2.0", map[string][]FrameworkRequirement{
		ControlCM8:  {req(f, "ID.AM-01", "Inventories of hardware managed by the organization are maintained")},
		ControlSI2:  {req(f, "ID.RA-01", "Vulnerabilities in assets are identified, validated and recorded")},
		ControlAC2:  {req(f, "PR.AA-01", "Identities and credentials for authorized users and devices are managed")},
		ControlIA5:  {req(f, "PR.AA-01", "Identities and credentials for authorized users and devices are managed")},
		ControlIA2:  {req(f, "PR.AA-03", "Users, services and hardware are authenticated")},
		ControlIA3:  {req(f, "PR.AA-03", "Users, services and hardware are authenticated")},
		ControlAC3:  {req(f, "PR.AA-05", "Access permissions and authorizations are defined and enforced")},
		ControlAC17: {req(f, "PR.AA-05", "Access permissions and authorizations are defined and enforced")},
		ControlSC8:  {req(f, "PR.DS-02", "The confidentiality, integrity and availability of data in transit are protected")},
		ControlSI7:  {req(f, "PR.DS-01", "The confidentiality, integrity and availability of data at rest are protected")},
		ControlCM2:  {req(f, "PR.PS-01", "Configuration management practices are established and applied")},
		ControlCM7:  {req(f, "PR.PS-01", "Configuration management practices are established and applied")},
		ControlAU2:  {req(f, "PR.PS-04", "Log records are generated and made available for continuous monitoring")},
		ControlAU8:  {req(f, "PR.PS-04", "Log records are generated and made available for continuous monitoring")},
		ControlAC4:  {req(f, "PR.IR-01", "Networks and environments are protected from unauthorized logical access")},
		ControlSC7:  {req(f, "PR.IR-01", "Networks and environments are protected from unauthorized logical access")},
		ControlSC5:  {req(f, "PR.IR-04", "Adequate resource capacity to ensure availability is maintained")},
		ControlAU6:  {req(f, "DE.CM-01", "Networks and network services are monitored to find potentially adverse events")},
	})
}

// NewCISProvider seeds the CIS Critical Security Controls v8.1 crosswalk — the
// ENTERPRISE controls (CIS-1 … CIS-18), which are a different artefact from the
// per-platform CIS Benchmarks. Benchmark sections are NOT frameworks and are
// never listed as one; they hang off a finding (internal/hardening's Benchmark
// metadata) as a reference to the published device benchmark.
func NewCISProvider() *StaticFrameworkProvider {
	f := FrameworkCIS
	return NewStaticFrameworkProvider(f, "8.1", map[string][]FrameworkRequirement{
		ControlCM8:  {req(f, "CIS-1", "Inventory and Control of Enterprise Assets")},
		ControlSI7:  {req(f, "CIS-2", "Inventory and Control of Software Assets")},
		ControlSC8:  {req(f, "CIS-3", "Data Protection")},
		ControlCM2:  {req(f, "CIS-4", "Secure Configuration of Enterprise Assets and Software")},
		ControlCM7:  {req(f, "CIS-4", "Secure Configuration of Enterprise Assets and Software")},
		ControlAC2:  {req(f, "CIS-5", "Account Management")},
		ControlIA5:  {req(f, "CIS-5", "Account Management")},
		ControlIA2:  {req(f, "CIS-6", "Access Control Management")},
		ControlAC3:  {req(f, "CIS-6", "Access Control Management")},
		ControlSI2:  {req(f, "CIS-7", "Continuous Vulnerability Management")},
		ControlAU2:  {req(f, "CIS-8", "Audit Log Management")},
		ControlAU6:  {req(f, "CIS-8", "Audit Log Management")},
		ControlAU8:  {req(f, "CIS-8", "Audit Log Management")},
		ControlAC17: {req(f, "CIS-12", "Network Infrastructure Management")},
		ControlIA3:  {req(f, "CIS-12", "Network Infrastructure Management")},
		ControlAC4:  {req(f, "CIS-13", "Network Monitoring and Defense")},
		ControlSC7:  {req(f, "CIS-13", "Network Monitoring and Defense")},
		ControlSC5:  {req(f, "CIS-13", "Network Monitoring and Defense")},
	})
}

// NewHIPAAProvider seeds the HIPAA Security Rule crosswalk (45 CFR Part 164
// Subpart C as it stands in 2026 — the January 2025 NPRM was moved to HHS'
// long-term agenda with anticipated final action in 2027 and is NOT law, so
// nothing here codes against its proposed requirements). HIPAA is a
// LEGAL/regulatory framework: only the §164.312 Technical Safeguards map to a
// device config audit at all (§5d), so its scope is DELIBERATELY narrow and
// INCLUDES technical-safeguard controls Correlix has no check for yet — that is
// what makes the coverage % honest, and what makes a HIPAA-only tenant's view
// genuinely different from a PCI tenant's.
//
// CM-2/CM-8 (baseline configuration, asset inventory) are deliberately ABSENT:
// they are §164.308 administrative safeguards, not §164.312 technical ones, and
// a config audit cannot evidence them.
//
// NOTE: this is control EVIDENCE for the technical slice, NEVER "certified HIPAA
// compliance" (§5d defensible-claim rule); the broad §164.308/.310 realization
// is out of a config audit's reach.
func NewHIPAAProvider() *StaticFrameworkProvider {
	f := FrameworkHIPAA
	return NewStaticFrameworkProvider(f, "45 CFR 164.312", map[string][]FrameworkRequirement{
		ControlAC3:  {req(f, "164.312(a)(1)", "Access Control")},
		ControlAC17: {req(f, "164.312(a)(1)", "Access Control")},
		ControlAC2:  {req(f, "164.312(a)(2)(i)", "Unique User Identification")},
		ControlAU2:  {req(f, "164.312(b)", "Audit Controls")},
		ControlAU6:  {req(f, "164.312(b)", "Audit Controls")},
		ControlAU8:  {req(f, "164.312(b)", "Audit Controls")},
		ControlSI7:  {req(f, "164.312(c)(1)", "Integrity")},
		ControlIA2:  {req(f, "164.312(d)", "Person or Entity Authentication")},
		ControlIA5:  {req(f, "164.312(d)", "Person or Entity Authentication")},
		ControlSC8:  {req(f, "164.312(e)(1)", "Transmission Security")},
	})
}

// NewPCIProvider seeds the PCI DSS v4.0.1 crosswalk. PCI is also regulatory but its
// TECHNICAL requirements (1/2/4/6/7/8/10/11) cover more of the owned controls
// than HIPAA's technical safeguards do, so a PCI tenant's scope is broader —
// proving the two frameworks are scored on DIFFERENT, INDEPENDENT scopes from
// the same shared findings.
func NewPCIProvider() *StaticFrameworkProvider {
	f := FrameworkPCIDSS
	return NewStaticFrameworkProvider(f, "4.0.1", map[string][]FrameworkRequirement{
		ControlAC4:  {req(f, "Req 1", "Install and maintain network security controls")},
		ControlSC7:  {req(f, "Req 1", "Install and maintain network security controls")},
		ControlSC5:  {req(f, "Req 1", "Install and maintain network security controls")},
		ControlCM2:  {req(f, "Req 2", "Apply secure configurations to all system components")},
		ControlCM7:  {req(f, "Req 2", "Apply secure configurations to all system components")},
		ControlAC17: {req(f, "Req 2", "Apply secure configurations to all system components")},
		ControlSC8:  {req(f, "Req 4", "Protect cardholder data with strong cryptography during transmission")},
		ControlSI2:  {req(f, "Req 6", "Develop and maintain secure systems and software")},
		ControlAC3:  {req(f, "Req 7", "Restrict access to system components by business need to know")},
		ControlAC2:  {req(f, "Req 8", "Identify users and authenticate access to system components")},
		ControlIA2:  {req(f, "Req 8", "Identify users and authenticate access to system components")},
		ControlIA5:  {req(f, "Req 8", "Identify users and authenticate access to system components")},
		ControlIA3:  {req(f, "Req 8", "Identify users and authenticate access to system components")},
		ControlAU2:  {req(f, "Req 10", "Log and monitor all access to system components and cardholder data")},
		ControlAU6:  {req(f, "Req 10", "Log and monitor all access to system components and cardholder data")},
		ControlAU8:  {req(f, "Req 10", "Log and monitor all access to system components and cardholder data")},
		ControlSI7:  {req(f, "Req 11", "Test security of systems and networks regularly")},
		ControlCM8:  {req(f, "Req 12.5.1", "An inventory of system components in scope for PCI DSS is maintained")},
	})
}
