package threatlane

import (
	"errors"
	"testing"

	"netops/backend/internal/vendorprofile"
)

// TestDeclaredLogRulesExistInTheCatalog is the DRIFT guard between the vendor
// profiles' declared device-log coverage and this package's rule catalog: a
// profile may not claim a rule id the catalog does not ship.
func TestDeclaredLogRulesExistInTheCatalog(t *testing.T) {
	reg := vendorprofile.Default()
	cat := DefaultCatalog()
	known := map[string]struct{}{}
	for _, r := range cat.LogRules() {
		known[r.ID] = struct{}{}
	}
	claimed := 0
	for _, p := range reg.Profiles() {
		for _, id := range p.Threat.LogRuleIDs {
			claimed++
			if _, ok := known[id]; !ok {
				t.Errorf("vendor profile %s declares log rule %q, which the threatlane catalog does not ship", p.ID, id)
			}
		}
	}
	if claimed == 0 {
		t.Fatal("no vendor profile declares any assessed device-log coverage — the binding is not wired")
	}
}

func TestAssessedLogRules(t *testing.T) {
	reg := vendorprofile.Default()
	cat := DefaultCatalog()
	rules, err := AssessedLogRules(reg, cat, "cisco", "ios_xe")
	if err != nil {
		t.Fatalf("AssessedLogRules(cisco/ios_xe): %v", err)
	}
	if len(rules) != len(cat.LogRules()) {
		t.Errorf("cisco/ios_xe assessed %d rules, catalog ships %d", len(rules), len(cat.LogRules()))
	}
	// Catalog order is preserved (the engine emits in catalog order).
	for i, r := range rules {
		if r.ID != cat.LogRules()[i].ID {
			t.Errorf("rule %d = %q, want catalog order %q", i, r.ID, cat.LogRules()[i].ID)
		}
	}
	if mn, err := MnemonicPrefixesFor(reg, "cisco", "ios_xe"); err != nil || len(mn) == 0 {
		t.Errorf("MnemonicPrefixesFor(cisco/ios_xe) = %v, %v", mn, err)
	}
}

// TestUnassessedCoverageIsHonest — a platform whose log grammar has not been
// assessed (Junos uses process APP-NAMEs, not Cisco mnemonics) reports
// unassessed, NOT "every rule applies" and NOT "no threats".
func TestUnassessedCoverageIsHonest(t *testing.T) {
	reg := vendorprofile.Default()
	cat := DefaultCatalog()
	for _, c := range []struct{ vendor, platform string }{
		{"juniper", "junos"}, {"nokia", "srlinux"}, {"nokia", "sros"},
		{"sonicwall", "sonicos"}, {"", ""},
	} {
		rules, err := AssessedLogRules(reg, cat, c.vendor, c.platform)
		if !errors.Is(err, ErrNoCoverage) {
			t.Errorf("AssessedLogRules(%s/%s) = %d rules, %v; want ErrNoCoverage", c.vendor, c.platform, len(rules), err)
		}
		if rules != nil {
			t.Errorf("AssessedLogRules(%s/%s) returned rules alongside an error", c.vendor, c.platform)
		}
	}
	if _, err := AssessedLogRules(nil, cat, "cisco", "ios"); !errors.Is(err, ErrNoCoverage) {
		t.Errorf("nil registry = %v, want ErrNoCoverage", err)
	}
	if _, err := AssessedLogRules(reg, nil, "cisco", "ios"); !errors.Is(err, ErrNoCoverage) {
		t.Errorf("nil catalog = %v, want ErrNoCoverage", err)
	}
}
