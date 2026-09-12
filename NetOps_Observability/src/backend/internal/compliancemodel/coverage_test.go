// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package compliancemodel

import (
	"strings"
	"testing"

	"netops/backend/internal/compliance"
	"netops/backend/internal/secfindings"
)

// sharedFindings builds the SAME finding set every framework here is scored
// against, so the tests prove the per-framework projection — not a difference in
// inputs — is what produces different scopes. One SNMP-crypto violation (→ SC-8)
// and one golden-baseline violation (→ CM-2). Convert routes each finding to its
// owned control purely by its Check id (the T1 converter fixes verdict=Fail,
// class=posture).
func sharedFindings(cat *Catalog) []secfindings.Finding {
	fSC8 := cat.Convert(compliance.Finding{Check: "snmp-v3-strength"}, EmitOptions{TenantID: "acme"}) // → SC-8
	fCM2 := cat.Convert(compliance.Finding{Check: "os-consensus"}, EmitOptions{TenantID: "acme"})     // → CM-2
	return []secfindings.Finding{fSC8, fCM2}
}

// narrowFramework is a deliberately NARROW in-test framework: it scopes
// transmission security and access enforcement and nothing else. It exists so
// the per-framework independence contract is proved by the ENGINE and the
// interface alone, with no dependence on which crosswalks a particular build
// happens to carry — the property has to hold in an Apache-2.0-only tree.
const narrowFramework = "Narrow Test Framework"

func newNarrowProvider() *StaticFrameworkProvider {
	return NewStaticFrameworkProvider(narrowFramework, "1.0", map[string][]FrameworkRequirement{
		ControlSC8: {Requirement(narrowFramework, "N-1", "Protect data in transit")},
		ControlAC3: {Requirement(narrowFramework, "N-2", "Enforce access")},
	})
}

// TestProjectionIsIndependentPerFramework is the crux of the model: one shared
// finding set, two frameworks, two INDEPENDENT scopes and verdicts.
func TestProjectionIsIndependentPerFramework(t *testing.T) {
	cat := DefaultCatalog()
	findings := sharedFindings(cat)

	cis := ProjectFramework(findings, cat, NewCISProvider())
	narrow := ProjectFramework(findings, cat, newNarrowProvider())

	// ── independent SCOPES from the SAME findings ────────────────────────────
	if !inScope(cis, ControlCM2) {
		t.Error("CM-2 must be in CIS scope (CIS-4 secure configuration)")
	}
	if inScope(narrow, ControlCM2) {
		t.Error("CM-2 must NOT be in the narrow framework's scope")
	}
	if !inScope(narrow, ControlSC8) {
		t.Error("SC-8 must be in the narrow framework's scope")
	}

	// ── the same shared CM-2 finding is scored DIFFERENTLY per framework ─────
	if statusOf(cis, ControlCM2) != secfindings.StatusFail {
		t.Errorf("CM-2 should FAIL under CIS, got %v", statusOf(cis, ControlCM2))
	}
	if hasControl(narrow, ControlCM2) {
		t.Error("the narrow projection must not carry CM-2 at all")
	}
	// SC-8 is shared: it fails in BOTH — same finding, both frameworks see it.
	if statusOf(cis, ControlSC8) != secfindings.StatusFail {
		t.Errorf("SC-8 should FAIL under CIS, got %v", statusOf(cis, ControlSC8))
	}
	if statusOf(narrow, ControlSC8) != secfindings.StatusFail {
		t.Errorf("SC-8 should FAIL under the narrow framework, got %v", statusOf(narrow, ControlSC8))
	}

	// ── coverage is computed against each framework's OWN scope ──────────────
	if narrow.ControlsInScope != 2 {
		t.Errorf("narrow scope = %d controls, want 2 (the provider owns the scope)", narrow.ControlsInScope)
	}
	if cis.ControlsInScope != len(NewCISProvider().ControlsInScope()) {
		t.Errorf("CIS scope = %d, want the provider's own %d",
			cis.ControlsInScope, len(NewCISProvider().ControlsInScope()))
	}
	if cis.ControlsInScope <= narrow.ControlsInScope {
		t.Errorf("CIS scope (%d) must be broader than the narrow one (%d)",
			cis.ControlsInScope, narrow.ControlsInScope)
	}
	if cis.CoveragePercent <= 0 || cis.CoveragePercent >= 100 {
		t.Errorf("CIS coverage = %.2f%%, want an honest fraction between 0 and 100", cis.CoveragePercent)
	}

	// Each reaches a Fail verdict from ITS OWN in-scope findings.
	if cis.Verdict != secfindings.StatusFail || narrow.Verdict != secfindings.StatusFail {
		t.Errorf("verdicts cis=%v narrow=%v, want both Fail", cis.Verdict, narrow.Verdict)
	}
	if narrow.Failed != 1 {
		t.Errorf("narrow failed controls = %d, want 1 (SC-8)", narrow.Failed)
	}
	if cis.Failed != 2 {
		t.Errorf("CIS failed controls = %d, want 2 (SC-8, CM-2)", cis.Failed)
	}

	// Honesty caption present on every framework view (§5d).
	if cis.Caption == "" || narrow.Caption == "" {
		t.Error("standard honesty caption must be attached to every framework view")
	}
}

// TestPerTenantSelectionIsInputSet proves the selection — not the catalogue — is
// what a tenant is scored against, and that enabling a second framework does not
// disturb the first one's independent score.
func TestPerTenantSelectionIsInputSet(t *testing.T) {
	cat := DefaultCatalog()
	findings := sharedFindings(cat)

	only := ProjectFrameworks(findings, cat, []FrameworkProvider{NewCISProvider()})
	if len(only) != 1 || only[0].Framework != FrameworkCIS {
		t.Fatalf("CIS-only selection = %+v, want a single CIS scorecard", only)
	}
	both := ProjectFrameworks(findings, cat, []FrameworkProvider{NewCISProvider(), newNarrowProvider()})
	if len(both) != 2 {
		t.Fatalf("both selection returned %d scorecards, want 2", len(both))
	}
	if both[0].Framework != FrameworkCIS || both[1].Framework != narrowFramework {
		t.Errorf("order not preserved: %q, %q", both[0].Framework, both[1].Framework)
	}
	if both[0].Failed != only[0].Failed || both[0].CoveragePercent != only[0].CoveragePercent {
		t.Error("the CIS score changed when a second framework was enabled — not independent")
	}
	if ProjectFrameworks(findings, cat, nil) != nil {
		t.Error("no selected frameworks should yield nil")
	}
}

// TestUnassessedNeverFalseClear: a run with no findings leaves covered controls
// UNASSESSED, never Pass.
func TestUnassessedNeverFalseClear(t *testing.T) {
	cat := DefaultCatalog()
	cov := ProjectFramework(nil, cat, NewCISProvider())
	if cov.Verdict != secfindings.StatusUnknown {
		t.Errorf("empty run verdict = %v, want Unknown (never a false clear)", cov.Verdict)
	}
	if cov.Passed != 0 {
		t.Errorf("empty run must not mark anything Passed, got %d", cov.Passed)
	}
	if cov.Unassessed != cov.ControlsWithCheck {
		t.Errorf("all check-covered controls should be Unassessed with no findings: %d vs %d",
			cov.Unassessed, cov.ControlsWithCheck)
	}
	if cov.ControlsWithCheck == 0 {
		t.Error("CIS must be check-covered by the legacy checks, or the coverage numerator means nothing")
	}
}

// TestSelectionReportsAMissingCrosswalkInsteadOfDroppingIt is the honesty half
// of the pack seam (pack.go): an enabled framework whose crosswalk is not
// installed is REPORTED — a null score and a sentence — never silently absent
// from the page, and never a 0 % that reads as total failure.
func TestSelectionReportsAMissingCrosswalkInsteadOfDroppingIt(t *testing.T) {
	cat := DefaultCatalog()
	findings := sharedFindings(cat)

	licensed := LicensedFrameworkIDs()
	if len(licensed) == 0 {
		t.Skip("no framework awaits a crosswalk pack in this build")
	}
	var awaiting string
	for _, info := range Frameworks() { // catalogue order, so the pick is stable
		if licensed[info.ID] {
			awaiting = info.ID
			break
		}
	}

	covs := ProjectSelection(findings, cat, []string{IDCISv8, awaiting})
	if len(covs) != 2 {
		t.Fatalf("selection produced %d scorecards, want 2 (the missing one is reported, not dropped)", len(covs))
	}
	missing := covs[1]
	info, _ := InfoFor(awaiting)
	if missing.Framework != info.Name {
		t.Errorf("the reported row is %q, want the framework the tenant enabled (%q)", missing.Framework, info.Name)
	}
	if missing.ScorePercent != nil {
		t.Errorf("a framework with no installed crosswalk must report a NULL score, got %v", *missing.ScorePercent)
	}
	if missing.Verdict != secfindings.StatusUnknown || missing.Passed != 0 || missing.Failed != 0 {
		t.Errorf("a not-installed framework must be unassessed, got %+v", missing)
	}
	if !strings.Contains(missing.Note, "not included in this deployment") {
		t.Errorf("the row must SAY why it has no score, got %q", missing.Note)
	}
	if missing.Caption == "" {
		t.Error("the honesty caption belongs on every framework view, including this one")
	}

	// With a crosswalk installed for that id, the not-installed row is gone and
	// the framework is scored like any other.
	pack := FrameworkPack{ID: awaiting, New: newNarrowProvider}
	withPack := ProjectSelection(findings, cat, []string{IDCISv8, awaiting}, pack)
	if len(withPack) != 2 {
		t.Fatalf("with the pack installed the selection produced %d scorecards, want 2", len(withPack))
	}
	if withPack[1].Note == missing.Note {
		t.Error("an installed crosswalk must be projected, not reported as missing")
	}
	if withPack[1].ControlsInScope != 2 {
		t.Errorf("the installed crosswalk's own scope should drive the scorecard, got %d",
			withPack[1].ControlsInScope)
	}
}

// TestAPackCannotAddOrRenameAFramework is the DATA-not-code-injection rule from
// the core side: a pack for an id the catalogue does not carry contributes
// nothing at all, so no module can extend the vocabulary a tenant selects from.
func TestAPackCannotAddOrRenameAFramework(t *testing.T) {
	rogue := FrameworkPack{ID: "not-a-framework", New: newNarrowProvider}
	if _, ok := ProviderFor("not-a-framework", rogue); ok {
		t.Error("a pack must not be able to add an id to the closed vocabulary")
	}
	if len(Frameworks()) != len(frameworkCatalogue()) {
		t.Error("the catalogue is the catalogue: a pack cannot lengthen it")
	}
	if KnownFrameworkIDs()["not-a-framework"] {
		t.Error("a pack must not widen what an API write may name")
	}
	if got := ProjectSelection(nil, DefaultCatalog(), []string{"not-a-framework"}, rogue); len(got) != 0 {
		t.Errorf("an unknown id is skipped, not reported as missing: %+v", got)
	}
}

// ── test helpers ─────────────────────────────────────────────────────────────

func inScope(c FrameworkCoverage, control string) bool {
	for _, r := range c.Controls {
		if r.ControlID == control {
			return true
		}
	}
	return false
}

func hasControl(c FrameworkCoverage, control string) bool { return inScope(c, control) }

func statusOf(c FrameworkCoverage, control string) secfindings.StatusID {
	for _, r := range c.Controls {
		if r.ControlID == control {
			return r.StatusID
		}
	}
	return secfindings.StatusUnknown
}

// ── 3.3-05: an unassessed control must not be counted as an assessed one ─────
//
// The hardening engine emits a REAL finding for a control it could not evaluate:
// StatusUnknown, with "running-config unavailable — control not assessed
// (fail-closed)" on it. That is the honest producer behaviour and it must stay.
//
// The projection used to count by the PRESENCE of a finding, so that control
// landed in Assessed, was excluded from Unassessed, contributed to no pass/warn/
// fail, left the score null — and was then described by a note saying no control
// was assessed. The frameworks panel prints "1 of 2 in scope assessed" directly
// above "Nothing assessed for this framework yet." Both cannot be true.

// unknownOnlyFinding is one control the platform TRIED to assess and could not,
// in the shape internal/hardening produces it.
func unknownOnlyFinding(cat *Catalog) secfindings.Finding {
	f := cat.Convert(compliance.Finding{Check: "snmp-v3-strength"}, EmitOptions{TenantID: "acme"}) // → SC-8
	f.SetStatus(secfindings.StatusUnknown)
	f.Detail = "running-config unavailable — control not assessed (fail-closed)"
	return f
}

func TestUnknownOnlyControlIsNotCountedAsAssessed(t *testing.T) {
	cat := DefaultCatalog()
	cov := ProjectFramework([]secfindings.Finding{unknownOnlyFinding(cat)}, cat, newNarrowProvider())

	if statusOf(cov, ControlSC8) != secfindings.StatusUnknown {
		t.Fatalf("the fixture is wrong: SC-8 status = %v, want Unknown", statusOf(cov, ControlSC8))
	}
	if cov.Assessed != 0 {
		t.Errorf("assessed = %d, want 0: the only finding on SC-8 says the control was NOT assessed "+
			"(running-config unavailable, fail-closed), so counting it as assessed states a measurement "+
			"that never happened", cov.Assessed)
	}
	if cov.Unassessed != cov.ControlsWithCheck {
		t.Errorf("unassessed = %d, want %d: a control whose only verdict is Unknown belongs with the "+
			"controls nobody has a verdict for, not outside both counts",
			cov.Unassessed, cov.ControlsWithCheck)
	}
	if cov.ScorePercent != nil {
		t.Errorf("score_percent = %v, want null", *cov.ScorePercent)
	}
	if cov.Verdict != secfindings.StatusUnknown {
		t.Errorf("verdict = %v, want Unknown", cov.Verdict)
	}
	// Nothing is hidden: the control row still carries its finding and its
	// non-verdict, so the operator can see WHY there is no answer.
	for _, c := range cov.Controls {
		if c.ControlID == ControlSC8 && c.Findings != 1 {
			t.Errorf("SC-8 findings = %d, want 1 — the finding must still be reported", c.Findings)
		}
	}
}

// The note and the numbers must agree. This is the half an operator actually
// reads: the panel prints the note and the counts side by side.
func TestTheNoteAndTheCountsAgree(t *testing.T) {
	cat := DefaultCatalog()

	unknownOnly := ProjectFramework([]secfindings.Finding{unknownOnlyFinding(cat)}, cat, newNarrowProvider())
	if unknownOnly.Note != unassessedNote {
		t.Errorf("note = %q, want the nothing-was-assessed sentence", unknownOnly.Note)
	}
	if unknownOnly.Note != "" && unknownOnly.Assessed != 0 {
		t.Errorf("the panel would print %q above %d assessed controls",
			unknownOnly.Note, unknownOnly.Assessed)
	}

	// The other way round: a control WAS assessed and came back not applicable,
	// so there is no passing share to report — but the note must not claim
	// nothing was assessed, because something was.
	na := cat.Convert(compliance.Finding{Check: "snmp-v3-strength"}, EmitOptions{TenantID: "acme"})
	na.SetStatus(secfindings.StatusNotApplicable)
	naOnly := ProjectFramework([]secfindings.Finding{na}, cat, newNarrowProvider())
	if naOnly.Assessed != 1 {
		t.Fatalf("assessed = %d, want 1: NotApplicable is a verdict — the control WAS looked at", naOnly.Assessed)
	}
	if naOnly.ScorePercent != nil {
		t.Errorf("score_percent = %v, want null: nothing passed, warned or failed", *naOnly.ScorePercent)
	}
	if naOnly.Note == unassessedNote {
		t.Errorf("note = %q, but %d control was assessed — the sentence contradicts the number",
			naOnly.Note, naOnly.Assessed)
	}
	if naOnly.Note == "" {
		t.Error("a null score must always carry the sentence that explains it")
	}

	// And the ordinary case is untouched: a real verdict is assessed and scored.
	scored := ProjectFramework(sharedFindings(cat), cat, newNarrowProvider())
	if scored.Assessed != 1 || scored.Failed != 1 {
		t.Errorf("assessed/failed = %d/%d, want 1/1", scored.Assessed, scored.Failed)
	}
	if scored.Note != "" {
		t.Errorf("a scored framework must carry no empty-state sentence, got %q", scored.Note)
	}
}
