package secapi

// rules_test.go — the catalog's contract with the registries it is assembled
// from, and with the bus vocabulary the Exposure Story query filters on.

import (
	"testing"

	"netops/backend/internal/advisory"
	"netops/backend/internal/hardening"
	"netops/backend/internal/secbus"
	"netops/backend/internal/threatlane"
)

// TestCatalogCoversEveryShippedRule is the anti-drift guard: the page lists what
// ships. A hand-maintained list would let a detection fire while being invisible
// (or be listed while not existing) — both of which make the enable toggle a
// lie about what is running.
func TestCatalogCoversEveryShippedRule(t *testing.T) {
	cat := Catalog()
	ids := CatalogIDs()

	hc := hardening.DefaultCatalog()
	tc := threatlane.DefaultCatalog()
	want := hc.Len() + tc.Len() + 2 // +2 advisory providers
	if len(cat) != want {
		t.Fatalf("catalog holds %d entries, the registries ship %d", len(cat), want)
	}
	for _, r := range hc.Rules() {
		if !ids[r.ID] {
			t.Errorf("hardening rule %q is not in the catalog", r.ID)
		}
	}
	for _, p := range hc.Probes() {
		if !ids[p.ID] {
			t.Errorf("exposure probe %q is not in the catalog", p.ID)
		}
	}
	for _, r := range tc.LogRules() {
		if !ids[r.ID] {
			t.Errorf("threatlane log rule %q is not in the catalog", r.ID)
		}
	}
	for _, r := range tc.PairRules() {
		if !ids[r.ID] {
			t.Errorf("threatlane pair rule %q is not in the catalog", r.ID)
		}
	}
	for _, r := range tc.SourceRules() {
		if !ids[r.ID] {
			t.Errorf("threatlane source rule %q is not in the catalog", r.ID)
		}
	}
	for _, src := range []string{advisory.SourceOfflineFeed, advisory.SourceCiscoOpenVuln} {
		if !ids[src] {
			t.Errorf("advisory provider %q is not in the catalog", src)
		}
	}
}

// TestCatalogFieldsAreHonest pins the three derived fields. Fidelity and
// seam-awareness are read off the registries rather than hand-assigned, so a
// new behavioral rule cannot ship claiming high fidelity.
func TestCatalogFieldsAreHonest(t *testing.T) {
	seamAware, mitred, behavioral := 0, 0, 0
	for _, r := range Catalog() {
		switch r.Family {
		case FamilyHardening, FamilyExposure, FamilyThreat, FamilyAdvisory:
		default:
			t.Errorf("rule %s has unknown family %q", r.RuleID, r.Family)
		}
		if r.Fidelity != FidelityHigh && r.Fidelity != FidelityMedium {
			t.Errorf("rule %s has unknown fidelity %q", r.RuleID, r.Fidelity)
		}
		if r.SeamAware {
			seamAware++
			if r.Family != FamilyExposure {
				t.Errorf("rule %s claims seam awareness outside the exposure family", r.RuleID)
			}
		}
		if r.MITRE != "" {
			mitred++
			if r.Family != FamilyThreat {
				t.Errorf("rule %s carries a MITRE technique outside the threat family", r.RuleID)
			}
		}
		if r.Fidelity == FidelityMedium {
			behavioral++
		}
		if !r.Enabled {
			t.Errorf("the shipped catalog must default every rule ENABLED; %s is off", r.RuleID)
		}
	}
	if seamAware == 0 {
		t.Error("no seam-aware entries — the §5e exposure probes are missing from the catalog")
	}
	if mitred == 0 {
		t.Error("no MITRE-tagged entries — the threatlane detections are missing from the catalog")
	}
	if behavioral == 0 {
		t.Error("no medium-fidelity entries — the behavioral detections are being advertised as deterministic")
	}
}

// TestSecuritySignalKindsMatchTheBus pins the string literals in rules.go equal
// to the secbus vocabulary. secbus is a leaf producer nothing in the core
// imports, so the production code cannot import it — but a TEST can, and this
// is the only thing standing between a renamed kind and an Exposure Story page
// that is silently, permanently empty.
func TestSecuritySignalKindsMatchTheBus(t *testing.T) {
	want := []string{secbus.KindPosture, secbus.KindExposure, secbus.KindSignal}
	if len(SecuritySignalKinds) != len(want) {
		t.Fatalf("SecuritySignalKinds has %d entries, secbus defines %d", len(SecuritySignalKinds), len(want))
	}
	for i, k := range want {
		if SecuritySignalKinds[i] != k {
			t.Errorf("SecuritySignalKinds[%d] = %q, secbus says %q", i, SecuritySignalKinds[i], k)
		}
	}
}

func TestApplyIgnoresUnknownRuleIDs(t *testing.T) {
	cat := Catalog()
	got := Apply(cat, map[string]bool{"a-rule-that-was-retired": false})
	if len(got) != len(cat) {
		t.Fatalf("Apply changed the catalog size: %d → %d", len(cat), len(got))
	}
	for _, r := range got {
		if !r.Enabled {
			t.Fatalf("an unknown override disabled %s", r.RuleID)
		}
	}
}
