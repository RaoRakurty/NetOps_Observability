// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

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

// ─────────────────────────────────────────────────────────────────────────────
// The crosswalks BEYOND the default two — NIST CSF 2.0, HIPAA §164.312 and
// PCI DSS v4.0.1 — are not in this file. They are the `security_dialects`
// entitlement ("compliance frameworks beyond the default two") and live in
// src/backend/enterprise/frameworks, reaching the registry as FrameworkPack
// data (pack.go). Their IDENTITY stays here and in registry.go: an Apache-2.0
// build still names them, still validates a stored selection against them, and
// still reports — in words — that their crosswalk is not installed.
// ─────────────────────────────────────────────────────────────────────────────
