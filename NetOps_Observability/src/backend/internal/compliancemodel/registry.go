package compliancemodel

// registry.go — THE FRAMEWORK CATALOGUE AND THE SHIPPED DEFAULT SET.
//
// Owner direction, 2026-09-03: "we shouldn't be checking all compliances by
// default; compliance is analyzed per customer requirement." A framework is
// therefore an OPT-IN per tenant, and this file is the closed vocabulary that
// choice is made from: a stable id per framework, the descriptor a picker
// renders, and the small default set a tenant gets before it has chosen.
//
// WHY THESE DEFAULTS. NIST 800-53 Rev5 is the base catalogue the owned control
// layer already IS, so reporting it invents no crosswalk hop and is meaningful
// for every customer. CIS Controls v8.1 is the vendor-neutral security baseline
// a network team is expected to be able to speak to. The remaining three —
// NIST CSF 2.0, HIPAA and PCI DSS — describe a REGULATORY position a customer
// either has or does not: rendering a HIPAA scorecard for a company that
// handles no PHI is noise at best and an implied compliance claim at worst, so
// they are off until somebody says otherwise.
//
// The ID is VERSIONED because the version is part of a framework's identity
// (§5d). When CIS Controls v9 lands it is a NEW id and a NEW provider, not a
// silent renumbering of the rows a tenant already enabled.
//
// WHAT IS CORE HERE. The VOCABULARY — the ids, the descriptors, the default
// set and the closed list an API write is validated against — is Apache-2.0 and
// carries all five frameworks, because a deployment must be able to name,
// validate and keep serving a selection it has already persisted. The CROSSWALK
// EDGES for the frameworks beyond the default two are the `security_dialects`
// entitlement and arrive as FrameworkPack data from outside this package (see
// pack.go); `new: nil` below is where each of those is bound at assembly time,
// and an enabled framework with no installed crosswalk is REPORTED as such
// (MissingCrosswalks + NotLicensedCoverage), never silently dropped.

import "sort"

// Framework sources.
const (
	// SourceBase is the 800-53 hub itself — no crosswalk hop.
	SourceBase = "base"
	// SourceProjection is a framework reached by projecting an owned 800-53
	// control onto that framework's requirement.
	SourceProjection = "projection-of-800-53"
)

// Framework ids — the closed vocabulary a tenant selects from and the API
// refuses anything outside.
const (
	IDNIST80053 = "nist-800-53-r5"
	IDCISv8     = "cis-controls-v8"
	IDNISTCSF   = "nist-csf-2.0"
	IDHIPAA     = "hipaa-security-rule"
	IDPCIDSS    = "pci-dss-v4"
)

// FrameworkInfo is one framework as a picker renders it: what it is, which
// version this platform maps against, whether it is the base catalogue or a
// projection of it, and whether it is on by default.
type FrameworkInfo struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Version   string `json:"version"`
	Source    string `json:"source"`
	Scope     string `json:"scope"`      // one line: what this framework governs here
	DefaultOn bool   `json:"default_on"` // in the shipped default set
}

// frameworkCatalogue is the single declaration of the vocabulary. It is a
// function, not a package variable, so no caller can mutate the shipped list
// (§5 no globals).
func frameworkCatalogue() []struct {
	info FrameworkInfo
	new  func() *StaticFrameworkProvider
} {
	return []struct {
		info FrameworkInfo
		new  func() *StaticFrameworkProvider
	}{
		{
			info: FrameworkInfo{
				ID: IDNIST80053, Name: FrameworkNIST80053, Version: "Rev 5 (Release 5.2.0)",
				Source: SourceBase, DefaultOn: true,
				Scope: "The control catalogue this platform models directly — every hardening and posture check is tagged with an 800-53 control, so this framework reports the catalogue with no crosswalk in between.",
			},
			new: NewNIST80053Provider,
		},
		{
			info: FrameworkInfo{
				ID: IDCISv8, Name: FrameworkCIS, Version: "8.1",
				Source: SourceProjection, DefaultOn: true,
				Scope: "The vendor-neutral CIS Critical Security Controls (CIS-1 … CIS-18). Enterprise controls, not the per-platform CIS Benchmarks — a benchmark section is cited on the finding, never listed as a framework.",
			},
			new: NewCISProvider,
		},
		{
			info: FrameworkInfo{
				ID: IDNISTCSF, Name: FrameworkNISTCSF, Version: "2.0",
				Source: SourceProjection, DefaultOn: false,
				Scope: "The CSF 2.0 outcome subcategories (ID/PR/DE). Enable it when the organisation reports its programme in CSF terms.",
			},
			// Crosswalk beyond the default two: a FrameworkPack supplies it
			// (pack.go). Core carries the IDENTITY, not the edges.
			new: nil,
		},
		{
			info: FrameworkInfo{
				ID: IDHIPAA, Name: FrameworkHIPAA, Version: "45 CFR 164.312",
				Source: SourceProjection, DefaultOn: false,
				Scope: "The §164.312 technical safeguards only — the slice of the Security Rule a device configuration can evidence. Enable it for an organisation handling protected health information.",
			},
			// Crosswalk beyond the default two: a FrameworkPack supplies it
			// (pack.go). Core carries the IDENTITY, not the edges.
			new: nil,
		},
		{
			info: FrameworkInfo{
				ID: IDPCIDSS, Name: FrameworkPCIDSS, Version: "4.0.1",
				Source: SourceProjection, DefaultOn: false,
				Scope: "The PCI DSS technical requirements a network device is in scope for (1, 2, 4, 6, 7, 8, 10, 11). Enable it for a cardholder-data environment.",
			},
			// Crosswalk beyond the default two: a FrameworkPack supplies it
			// (pack.go). Core carries the IDENTITY, not the edges.
			new: nil,
		},
	}
}

// Frameworks returns the framework catalogue in the order a picker shows it:
// the base first, then the projections, each in a stable id order within its
// source. Fresh slice per call.
func Frameworks() []FrameworkInfo {
	cat := frameworkCatalogue()
	out := make([]FrameworkInfo, 0, len(cat))
	for _, e := range cat {
		out = append(out, e.info)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if (out[i].Source == SourceBase) != (out[j].Source == SourceBase) {
			return out[i].Source == SourceBase
		}
		if out[i].DefaultOn != out[j].DefaultOn {
			return out[i].DefaultOn
		}
		return out[i].ID < out[j].ID
	})
	return out
}

// KnownFrameworkIDs is the closed vocabulary an API write is validated against.
// An id outside it is REFUSED rather than stored: a row for a framework nothing
// can score is a row nothing ever reads.
func KnownFrameworkIDs() map[string]bool {
	ids := map[string]bool{}
	for _, e := range frameworkCatalogue() {
		ids[e.info.ID] = true
	}
	return ids
}

// DefaultEnabled returns the shipped default selection — the set a tenant that
// has never chosen is scored against. Deliberately SMALL (see the file header):
// the base catalogue plus CIS Controls, and nothing regulatory.
func DefaultEnabled() []string {
	out := []string{}
	for _, info := range Frameworks() {
		if info.DefaultOn {
			out = append(out, info.ID)
		}
	}
	return out
}

// InfoFor returns the catalogue descriptor for a framework id. It answers for
// every id in the vocabulary, whether or not its crosswalk is installed — the
// descriptor is what lets a deployment name a framework it cannot yet score.
func InfoFor(id string) (FrameworkInfo, bool) {
	for _, e := range frameworkCatalogue() {
		if e.info.ID == id {
			return e.info, true
		}
	}
	return FrameworkInfo{}, false
}

// ProviderFor returns the crosswalk provider for a framework id, resolving it
// from core first and then from the supplied packs (pack.go).
//
// CORE WINS: a pack can never override a framework core ships a crosswalk for,
// so the two default frameworks are exactly what the Apache-2.0 tree says they
// are. An id whose crosswalk is neither in core nor in the packs does not
// resolve — the caller reports that honestly (MissingCrosswalks) instead of
// scoring an empty scope.
func ProviderFor(id string, packs ...FrameworkPack) (FrameworkProvider, bool) {
	for _, e := range frameworkCatalogue() {
		if e.info.ID != id {
			continue
		}
		if e.new != nil {
			return e.new(), true
		}
		if p, ok := packFor(id, packs); ok {
			return p.New(), true
		}
		return nil, false
	}
	return nil, false
}

// ProvidersFor resolves a selection of framework ids to providers, in the
// catalogue's display order (not the caller's, so two tenants with the same
// selection get the same scorecard order). An unknown id is SKIPPED — a
// selection persisted before a framework was retired must not fail the read.
func ProvidersFor(ids []string, packs ...FrameworkPack) []FrameworkProvider {
	want := make(map[string]bool, len(ids))
	for _, id := range ids {
		want[id] = true
	}
	out := []FrameworkProvider{}
	for _, info := range Frameworks() {
		if !want[info.ID] {
			continue
		}
		if p, ok := ProviderFor(info.ID, packs...); ok {
			out = append(out, p)
		}
	}
	return out
}

// MissingCrosswalks returns the descriptors of the SELECTED frameworks whose
// crosswalk is not installed in this deployment, in catalogue order.
//
// It exists so the absence is REPORTED rather than silently skipped: a tenant
// that enabled PCI DSS and then finds no PCI card on the page has been told
// nothing, which is exactly the silent-failure shape §10 forbids. An id outside
// the vocabulary is not "missing" — it is unknown, and stays skipped.
func MissingCrosswalks(ids []string, packs ...FrameworkPack) []FrameworkInfo {
	want := make(map[string]bool, len(ids))
	for _, id := range ids {
		want[id] = true
	}
	out := []FrameworkInfo{}
	for _, info := range Frameworks() {
		if !want[info.ID] {
			continue
		}
		if _, ok := ProviderFor(info.ID, packs...); !ok {
			out = append(out, info)
		}
	}
	return out
}
