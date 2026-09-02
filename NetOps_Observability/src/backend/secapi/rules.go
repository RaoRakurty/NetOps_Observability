package secapi

// rules.go — the DETECTION CATALOG the Security page lists and a tenant
// enables/disables. It is assembled from the shipped rule registries
// (internal/hardening, internal/threatlane, internal/advisory) rather than
// duplicated, so a rule that ships is a rule that is listed: a hand-maintained
// second list is how a detection silently disappears from the UI while still
// firing (or, worse, appears in the UI while not existing).
//
// `enabled` is per-TENANT state (migration 0037, tenant_iso FORCE-RLS) and
// defaults to TRUE when no row exists: the catalog ships on. That default is
// deliberate and is the §5g honesty rule again — "no row" must not mean "not
// assessed", because an operator reading a clean page would have no way to tell
// the difference between "nothing is wrong" and "nothing ran".

import (
	"sort"
	"strings"

	"netops/backend/internal/advisory"
	"netops/backend/internal/hardening"
	"netops/backend/internal/secfindings"
	"netops/backend/internal/threatlane"
)

// Rule families — the lane a catalog entry belongs to.
const (
	FamilyHardening = "hardening" // config-posture rules (internal/hardening)
	FamilyExposure  = "exposure"  // seam-aware management-service exposure probes
	FamilyThreat    = "threat"    // MITRE-tagged detections (internal/threatlane)
	FamilyAdvisory  = "advisory"  // vendor advisory / PSIRT providers
)

// Fidelity levels. This is a PROPERTY OF THE DETECTION, not a tunable: a
// deterministic match on a config line or a vendor mnemonic is high fidelity; a
// statistical/behavioral verdict over flow history is medium and says so, so an
// operator triaging a page knows which findings carry a base rate.
const (
	FidelityHigh   = "high"
	FidelityMedium = "medium"
)

// Rule is one catalog entry as the API serves it.
type Rule struct {
	RuleID    string   `json:"rule_id"`
	Family    string   `json:"family"`
	Enabled   bool     `json:"enabled"`
	Fidelity  string   `json:"fidelity"`
	MITRE     []string `json:"mitre,omitempty"`
	SeamAware bool     `json:"seam_aware"`
}

// mitreTechniques normalizes a threatlane rule's MITRE tag into the LIST the
// wire contract carries. The registry stores ONE technique id today, but the
// field is plural on the wire because a detection can legitimately map to more
// than one ATT&CK technique — and because a scalar that later grows into a list
// is a BREAKING contract change for every consumer (the Detection Rules page
// renders `mitre` as an array and white-screens on a string). Emitting the
// array from day one makes the shape stable in the direction it can only grow.
//
// The source is split on commas and whitespace so a future "T1071, T1571" entry
// degrades into two chips rather than one nonsense token; sub-technique ids
// (T1562.001) are preserved intact because the dot is part of the id. Empty
// segments are dropped — an entry that carries no technique carries no field at
// all (omitempty), never an array of "".
func mitreTechniques(technique string) []string {
	fields := strings.FieldsFunc(technique, func(r rune) bool {
		return r == ',' || r == ';' || r == ' ' || r == '\t' || r == '\n' || r == '\r'
	})
	out := make([]string, 0, len(fields))
	seen := make(map[string]bool, len(fields))
	for _, f := range fields {
		t := strings.TrimSpace(f)
		if t == "" || seen[t] {
			continue
		}
		seen[t] = true
		out = append(out, t)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// fidelityForVerdict derives fidelity from the verdict a threatlane rule emits.
// The catalog encodes the distinction there already: the deterministic
// device-log matches emit StatusFail, the behavioral (beaconing / exfil /
// scan-fanout) rules emit StatusWarning precisely because they are statistical.
// Reading it off the existing field keeps ONE source of truth instead of a
// parallel hand-maintained fidelity table that can drift.
func fidelityForVerdict(v secfindings.StatusID) string {
	if v == secfindings.StatusWarning {
		return FidelityMedium
	}
	return FidelityHigh
}

// Catalog builds the full, deterministically ordered rule catalog with every
// entry ENABLED — the shipped default. Apply(states) then overlays a tenant's
// stored overrides. It is pure and allocates fresh (no package-level mutable
// state, §5).
func Catalog() []Rule {
	out := make([]Rule, 0, 64)

	hc := hardening.DefaultCatalog()
	for _, r := range hc.Rules() {
		out = append(out, Rule{
			RuleID:   r.ID,
			Family:   FamilyHardening,
			Enabled:  true,
			Fidelity: FidelityHigh, // a config line either matches or it does not
			// Hardening rules reason about the config alone; the seam-aware
			// half of the catalog is the exposure probes below.
			SeamAware: false,
		})
	}
	for _, p := range hc.Probes() {
		out = append(out, Rule{
			RuleID:   p.ID,
			Family:   FamilyExposure,
			Enabled:  true,
			Fidelity: FidelityHigh,
			// The §5e differentiator: the same enabled service is critical on
			// an untrusted seam and informational behind an ACL, so the verdict
			// is a function of the SEAM MODEL, not the config.
			SeamAware: true,
		})
	}

	tc := threatlane.DefaultCatalog()
	for _, r := range tc.LogRules() {
		out = append(out, Rule{
			RuleID: r.ID, Family: FamilyThreat, Enabled: true,
			Fidelity: fidelityForVerdict(r.Verdict), MITRE: mitreTechniques(r.Technique),
		})
	}
	for _, r := range tc.PairRules() {
		out = append(out, Rule{
			RuleID: r.ID, Family: FamilyThreat, Enabled: true,
			Fidelity: fidelityForVerdict(r.Verdict), MITRE: mitreTechniques(r.Technique),
		})
	}
	for _, r := range tc.SourceRules() {
		out = append(out, Rule{
			RuleID: r.ID, Family: FamilyThreat, Enabled: true,
			Fidelity: fidelityForVerdict(r.Verdict), MITRE: mitreTechniques(r.Technique),
		})
	}

	// The advisory lane has no hand-authored rule list: its "rules" are the
	// swappable VendorAdvisoryProvider identities (§5h), and enabling/disabling
	// one is enabling/disabling that provider's findings for the tenant. They
	// are listed under their provider ids so the toggle addresses something
	// real rather than a synthetic label.
	for _, src := range []string{advisory.SourceOfflineFeed, advisory.SourceCiscoOpenVuln} {
		out = append(out, Rule{
			RuleID: src, Family: FamilyAdvisory, Enabled: true,
			// A CVE either applies to the running version or it does not — the
			// version constraint is an exact, replayable match.
			Fidelity: FidelityHigh,
		})
	}

	sort.Slice(out, func(i, j int) bool {
		if out[i].Family != out[j].Family {
			return out[i].Family < out[j].Family
		}
		return out[i].RuleID < out[j].RuleID
	})
	return out
}

// CatalogIDs is the set of rule ids the catalog knows, used to REFUSE a write
// naming a rule that does not exist. Storing state for an unknown id would
// create a row nothing ever reads and let a caller grow the table without
// bound — both of which a closed vocabulary prevents.
func CatalogIDs() map[string]bool {
	ids := map[string]bool{}
	for _, r := range Catalog() {
		ids[r.RuleID] = true
	}
	return ids
}

// Apply overlays a tenant's stored enable/disable overrides onto the shipped
// catalog. An id in `states` that is not in the catalog is IGNORED (a rule
// retired since the row was written must not resurrect as a phantom entry).
func Apply(catalog []Rule, states map[string]bool) []Rule {
	out := make([]Rule, len(catalog))
	copy(out, catalog)
	for i := range out {
		if enabled, ok := states[out[i].RuleID]; ok {
			out[i].Enabled = enabled
		}
	}
	return out
}

// SecuritySignalKinds is the engine-facing signal-kind vocabulary the security
// lane emits — the discriminator an Exposure Story query filters correlated
// evidence on.
//
// They are string LITERALS rather than an import of internal/secbus on purpose:
// that package's own contract is that it is a LEAF producer nothing in the core
// imports, and a read API must not be the thing that breaks it.
// rules_contract_test.go pins this list equal to secbus.Kind* so the two can
// never drift apart silently (a drifted list would answer an empty Exposure
// Story page that looks exactly like "the engine found nothing").
var SecuritySignalKinds = []string{
	"security_posture",  // secbus.KindPosture
	"security_exposure", // secbus.KindExposure
	"security_signal",   // secbus.KindSignal
}
