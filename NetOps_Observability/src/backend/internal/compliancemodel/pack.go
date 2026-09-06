package compliancemodel

// pack.go — THE FRAMEWORK CROSSWALK SEAM.
//
// A framework here is two separate things, and the licence line runs between
// them:
//
//   - its IDENTITY — a stable, versioned id, the descriptor a picker renders,
//     whether it is on by default, and the fact that an API write may name it.
//     That is the closed vocabulary a tenant's stored selection is validated
//     against, and it is Apache-2.0 CORE: a deployment must be able to read,
//     validate and keep serving a selection it has already persisted.
//   - its CROSSWALK — the control → framework-requirement edges that make a
//     scorecard possible. For the frameworks beyond the shipped default two
//     that content is the `security_dialects` entitlement ("device-hardening
//     dialects beyond the default set, AND compliance frameworks beyond the
//     default two"), and its implementation lives outside this package under
//     src/backend/enterprise/frameworks.
//
// This file is what makes that split possible without core ever naming the
// commercial package. It is the deliberate mirror of hardening.DialectPack: a
// FrameworkPack is a plain DATA contribution — framework id → crosswalk
// provider — that the registry merges in.
//
// DIRECTION. Core defines this seam; the commercial package satisfies it; the
// assembly layer (package main) is the only place that names both and passes
// the packs in. A missing pack is not an error and never a false score: an
// enabled framework whose crosswalk is not installed gets NotLicensedCoverage —
// a null score and a sentence saying why — which is the same honesty rule the
// engine follows for an unlicensed dialect (hardening.RuleDialectNotLicensed),
// never an empty list that would read as "this framework has nothing to say".

// FrameworkPack is one framework's crosswalk contribution: the provider
// constructor for a single catalogue id.
//
// It is DATA, not code injection. A pack cannot add a framework to the
// vocabulary (an ID the catalogue does not carry is IGNORED — a pack authored
// against a newer catalogue must not break an older registry), cannot rename or
// re-version one, cannot change the default set, and cannot OVERRIDE a
// framework core already provides: the two default frameworks are Apache-2.0
// and stay exactly as core ships them. It can only answer "what are THIS
// framework's requirements for THAT canonical control".
type FrameworkPack struct {
	// ID is the catalogue framework id these crosswalk edges realize.
	ID string
	// New builds the crosswalk provider. A pack with a nil New contributes
	// nothing (it cannot make a framework resolve to an empty scorecard).
	New func() *StaticFrameworkProvider
}

// packFor returns the pack registered for id, if any.
func packFor(id string, packs []FrameworkPack) (FrameworkPack, bool) {
	for _, p := range packs {
		if p.ID == id && p.New != nil {
			return p, true
		}
	}
	return FrameworkPack{}, false
}

// Requirement builds one crosswalk edge (control → framework requirement).
//
// It is exported for the same reason hardening exports its detection builders:
// an out-of-package crosswalk should express an edge declaratively through the
// package that owns the type, instead of hand-assembling the struct and drifting
// from it when a field is added.
func Requirement(framework, requirementID, title string) FrameworkRequirement {
	return req(framework, requirementID, title)
}

// LicensedFrameworkIDs returns the catalogue ids whose crosswalk is NOT shipped
// in core and therefore needs a FrameworkPack. Fresh map per call.
//
// A pack's own tests assert that every id it binds appears here, so a pack that
// names an id core already provides — or an id the catalogue does not carry at
// all — is caught where the data lives rather than as a silently missing
// scorecard in production.
func LicensedFrameworkIDs() map[string]bool {
	ids := map[string]bool{}
	for _, e := range frameworkCatalogue() {
		if e.new == nil {
			ids[e.info.ID] = true
		}
	}
	return ids
}
