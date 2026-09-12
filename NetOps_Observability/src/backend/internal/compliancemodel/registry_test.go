// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

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
	licensed := LicensedFrameworkIDs()
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
		switch {
		case ok:
			if p.Framework() != info.Name {
				t.Errorf("%s: descriptor name %q != provider %q", info.ID, info.Name, p.Framework())
			}
			if p.Version() != info.Version {
				t.Errorf("%s: descriptor version %q != provider %q", info.ID, info.Version, p.Version())
			}
			if len(p.ControlsInScope()) == 0 {
				t.Errorf("%s: provider has an empty scope", info.ID)
			}
		case !licensed[info.ID]:
			// Core carries the descriptor AND the crosswalk for the default
			// two. Anything else that fails to resolve is a catalogue entry
			// nothing can ever score.
			t.Fatalf("%s: no provider and no pack awaited", info.ID)
		}
	}
	// The frameworks whose crosswalk is the `security_dialects` entitlement
	// stay in the VOCABULARY — an Apache-2.0 build must still be able to name
	// them and validate a selection already stored against them — but their
	// crosswalk resolves only when a pack supplies it (pack.go).
	for _, id := range []string{IDNIST80053, IDCISv8} {
		if licensed[id] {
			t.Errorf("%s is a DEFAULT framework: its crosswalk must be Apache-2.0 core", id)
		}
	}
	for id := range licensed {
		if _, ok := ProviderFor(id); ok {
			t.Errorf("%s: core must not carry a crosswalk it declares licensed", id)
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
	got := ProvidersFor([]string{IDCISv8, "retired-framework", IDNIST80053})
	if len(got) != 2 {
		t.Fatalf("got %d providers, want 2 (the unknown id is skipped)", len(got))
	}
	if got[0].Framework() != FrameworkNIST80053 || got[1].Framework() != FrameworkCIS {
		t.Errorf("catalogue order not applied: %q, %q", got[0].Framework(), got[1].Framework())
	}
	if len(ProvidersFor(nil)) != 0 {
		t.Error("an empty selection must yield no providers")
	}
}

// TestNothingAssessedIsANoteNeverAPercentage is the honesty rule the compliance
// page depends on: a framework with no assessed control says so in words. A 0
// there would read as "everything failed"; a 100 would read as a clean bill.
func TestNothingAssessedIsANoteNeverAPercentage(t *testing.T) {
	cov := ProjectFramework(nil, DefaultCatalog(), NewCISProvider())
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
	cov = ProjectFramework([]secfindings.Finding{na}, DefaultCatalog(), NewCISProvider())
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
	beforeScope := ProjectFramework(nil, base, NewCISProvider()).ControlsInScope
	after := ProjectFramework(nil, composed, NewCISProvider())
	if after.ControlsInScope != beforeScope {
		t.Errorf("composition changed the framework SCOPE (%d → %d) — scope belongs to the provider",
			beforeScope, after.ControlsInScope)
	}
	if after.ControlsWithCheck <= ProjectFramework(nil, base, NewCISProvider()).ControlsWithCheck {
		t.Error("composition should raise the check-covered numerator")
	}
}
