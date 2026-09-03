package compliancemodel

import (
	"strings"
	"testing"

	"netops/backend/internal/secfindings"
)

// TestFrameworkCatalogueIsClosedAndVersioned pins the vocabulary a tenant picks
// from: every entry has a stable id, a name, a VERSION (the version is part of
// the identity, §5d) and a source, and every id resolves to a provider whose
// own Framework()/Version() agree with the descriptor. A descriptor that
// disagrees with its provider is how a page renders "CIS Controls v8.1" over a
// v8.0 crosswalk.
func TestFrameworkCatalogueIsClosedAndVersioned(t *testing.T) {
	seen := map[string]bool{}
	for _, info := range Frameworks() {
		if info.ID == "" || info.Name == "" || info.Version == "" || info.Scope == "" {
			t.Errorf("framework descriptor is incomplete: %+v", info)
		}
		if seen[info.ID] {
			t.Errorf("duplicate framework id %q", info.ID)
		}
		seen[info.ID] = true
		if info.Source != SourceBase && info.Source != SourceProjection {
			t.Errorf("%s: unknown source %q", info.ID, info.Source)
		}
		p, ok := ProviderFor(info.ID)
		if !ok {
			t.Fatalf("%s: no provider", info.ID)
		}
		if p.Framework() != info.Name {
			t.Errorf("%s: descriptor name %q != provider %q", info.ID, info.Name, p.Framework())
		}
		if p.Version() != info.Version {
			t.Errorf("%s: descriptor version %q != provider %q", info.ID, info.Version, p.Version())
		}
		if len(p.ControlsInScope()) == 0 {
			t.Errorf("%s: provider has an empty scope", info.ID)
		}
	}
	if !seen[IDNIST80053] || !seen[IDCISv8] || !seen[IDNISTCSF] || !seen[IDHIPAA] || !seen[IDPCIDSS] {
		t.Fatalf("the catalogue must carry all five frameworks, got %v", seen)
	}
	if _, ok := ProviderFor("cis-controls-v7"); ok {
		t.Error("an id outside the vocabulary must not resolve to a provider")
	}
	if KnownFrameworkIDs()["not-a-framework"] {
		t.Error("KnownFrameworkIDs must be closed")
	}
}

// TestDefaultSetIsNotEveryFramework is the owner's 2026-09-03 rule as a test:
// the platform does not assess every framework for everybody. The regulatory
// three are OPT-IN.
func TestDefaultSetIsNotEveryFramework(t *testing.T) {
	def := DefaultEnabled()
	on := map[string]bool{}
	for _, id := range def {
		on[id] = true
	}
	if !on[IDNIST80053] || !on[IDCISv8] {
		t.Errorf("default set must be the 800-53 base + CIS Controls, got %v", def)
	}
	for _, id := range []string{IDNISTCSF, IDHIPAA, IDPCIDSS} {
		if on[id] {
			t.Errorf("%s must be OPT-IN, not on by default (a regulatory scorecard nobody asked for is an implied claim)", id)
		}
	}
	if len(def) >= len(Frameworks()) {
		t.Errorf("the default set (%d) must be smaller than the catalogue (%d)", len(def), len(Frameworks()))
	}
}

// TestProvidersForIsSelectionOnlyAndOrdered proves the selection is what drives
// the scorecards: only the chosen frameworks are built, in the catalogue's
// order regardless of the caller's, and an unknown id is skipped rather than
// failing the read.
func TestProvidersForIsSelectionOnlyAndOrdered(t *testing.T) {
	got := ProvidersFor([]string{IDPCIDSS, "retired-framework", IDNIST80053})
	if len(got) != 2 {
		t.Fatalf("got %d providers, want 2 (the unknown id is skipped)", len(got))
	}
	if got[0].Framework() != FrameworkNIST80053 || got[1].Framework() != FrameworkPCIDSS {
		t.Errorf("catalogue order not applied: %q, %q", got[0].Framework(), got[1].Framework())
	}
	if len(ProvidersFor(nil)) != 0 {
		t.Error("an empty selection must yield no providers")
	}
}

// TestHIPAAReportsThroughTheProjection is the bug the owner reported: HIPAA is a
// projection and never a standards TAG, so before this it could never appear.
// A finding tagged only with an 800-53 control must reach HIPAA's requirement.
func TestHIPAAReportsThroughTheProjection(t *testing.T) {
	cat := DefaultCatalog()
	// A hardening finding: no legacy check id, only the producer-stamped control.
	f := secfindings.Finding{RawRuleID: "telnet-vty-enabled", ControlID: ControlAC17}
	f.SetStatus(secfindings.StatusFail)

	cov := ProjectFramework([]secfindings.Finding{f}, cat, NewHIPAAProvider())
	if cov.Framework != FrameworkHIPAA {
		t.Fatalf("framework = %q", cov.Framework)
	}
	if statusOf(cov, ControlAC17) != secfindings.StatusFail {
		t.Fatalf("AC-17 should FAIL under HIPAA via the projection, got %v", statusOf(cov, ControlAC17))
	}
	var reqs []string
	for _, c := range cov.Controls {
		if c.ControlID == ControlAC17 {
			for _, r := range c.Requirements {
				reqs = append(reqs, r.RequirementID)
			}
		}
	}
	if len(reqs) == 0 || reqs[0] != "164.312(a)(1)" {
		t.Errorf("AC-17 must carry the HIPAA requirement it satisfies, got %v", reqs)
	}
	// …and the same finding is invisible to a framework that does not scope AC-17.
	if cov.ScorePercent == nil || *cov.ScorePercent != 0 {
		t.Errorf("one failing assessed control = 0%% score, got %v", cov.ScorePercent)
	}
}

// TestNothingAssessedIsANoteNeverAPercentage is the honesty rule the compliance
// page depends on: a framework with no assessed control says so in words. A 0
// there would read as "everything failed"; a 100 would read as a clean bill.
func TestNothingAssessedIsANoteNeverAPercentage(t *testing.T) {
	cov := ProjectFramework(nil, DefaultCatalog(), NewPCIProvider())
	if cov.ScorePercent != nil {
		t.Errorf("an unassessed framework must report a null score, got %v", *cov.ScorePercent)
	}
	if !strings.Contains(cov.Note, "absence of assessment") {
		t.Errorf("empty-state note missing or wrong: %q", cov.Note)
	}
	if cov.Verdict != secfindings.StatusUnknown {
		t.Errorf("verdict = %v, want Unknown", cov.Verdict)
	}
	// A NotApplicable verdict is likewise NOT a pass.
	na := secfindings.Finding{RawRuleID: "x", ControlID: ControlSC8}
	na.SetStatus(secfindings.StatusNotApplicable)
	cov = ProjectFramework([]secfindings.Finding{na}, DefaultCatalog(), NewPCIProvider())
	if cov.Passed != 0 {
		t.Errorf("NotApplicable counted as a pass (%d) — it is not assessed evidence", cov.Passed)
	}
	if cov.ScorePercent != nil {
		t.Errorf("a NotApplicable-only run must still report a null score, got %v", *cov.ScorePercent)
	}
}

// TestWithComposesForeignMappings proves the composition seam: a caller can
// teach the catalog about check ids this package must not import (the hardening
// rule ids), raising the check-covered NUMERATOR without changing any
// framework's scope — and without mutating the catalog it was built from.
func TestWithComposesForeignMappings(t *testing.T) {
	base := DefaultCatalog()
	if base.HasCheckForControl(ControlAC17) {
		t.Fatal("AC-17 must not be check-covered by the legacy 9 checks")
	}
	composed := base.With(nil, []ControlMapping{
		{Check: "telnet-vty-enabled", Controls: []ControlRef{{ControlID: ControlAC17, Relationship: RelSupports}}},
	})
	if !composed.HasCheckForControl(ControlAC17) {
		t.Error("the composed catalog must report AC-17 as check-covered")
	}
	if base.HasCheckForControl(ControlAC17) {
		t.Error("With must not mutate the receiver")
	}
	beforeScope := ProjectFramework(nil, base, NewHIPAAProvider()).ControlsInScope
	after := ProjectFramework(nil, composed, NewHIPAAProvider())
	if after.ControlsInScope != beforeScope {
		t.Errorf("composition changed the framework SCOPE (%d → %d) — scope belongs to the provider",
			beforeScope, after.ControlsInScope)
	}
	if after.ControlsWithCheck <= ProjectFramework(nil, base, NewHIPAAProvider()).ControlsWithCheck {
		t.Error("composition should raise the check-covered numerator")
	}
}
