package compliancemodel

import (
	"testing"

	"netops/backend/internal/compliance"
	"netops/backend/internal/secfindings"
)

// sharedFindings builds the SAME finding set both frameworks are scored against,
// so the test proves the per-framework projection — not a difference in inputs —
// is what produces different scopes. One SNMP-crypto violation (→ SC-8, in BOTH
// HIPAA and PCI scope) and one golden-baseline violation (→ CM-2, in PCI scope
// only, NOT a HIPAA §164.312 technical safeguard). Convert routes each finding to
// its owned control purely by its Check id (the T1 converter fixes verdict=Fail,
// class=posture).
func sharedFindings(cat *Catalog) []secfindings.Finding {
	fSC8 := cat.Convert(compliance.Finding{Check: "snmp-v3-strength"}, EmitOptions{TenantID: "acme"}) // → SC-8
	fCM2 := cat.Convert(compliance.Finding{Check: "os-consensus"}, EmitOptions{TenantID: "acme"})     // → CM-2
	return []secfindings.Finding{fSC8, fCM2}
}

func TestHIPAAvsPCIIndependence(t *testing.T) {
	cat := DefaultCatalog()
	findings := sharedFindings(cat)

	hipaa := ProjectFramework(findings, cat, NewHIPAAProvider())
	pci := ProjectFramework(findings, cat, NewPCIProvider())

	// ── independent SCOPES from the SAME findings ────────────────────────────
	// HIPAA §164.312 technical safeguards: SC-8, IA-5 (+ AC-3/AU-2/SI-7 unverified).
	// CM-2 (golden baseline) is NOT a HIPAA technical safeguard → out of scope.
	if inScope(hipaa, ControlCM2) {
		t.Error("CM-2 must NOT be in HIPAA scope (not a §164.312 technical safeguard)")
	}
	if !inScope(hipaa, ControlSC8) {
		t.Error("SC-8 (transmission security) must be in HIPAA scope")
	}
	// PCI includes CM-2 (Req 2 secure configuration) → in scope.
	if !inScope(pci, ControlCM2) {
		t.Error("CM-2 must be in PCI scope (Req 2)")
	}

	// ── same shared CM-2 finding scored DIFFERENTLY per framework ────────────
	// It fails a control in PCI; it is invisible to HIPAA. This is the crux of
	// per-framework independence: one finding, two independent verdicts.
	if statusOf(pci, ControlCM2) != secfindings.StatusFail {
		t.Errorf("CM-2 should FAIL under PCI, got %v", statusOf(pci, ControlCM2))
	}
	if hasControl(hipaa, ControlCM2) {
		t.Error("HIPAA projection must not carry CM-2 at all")
	}

	// SC-8 is shared: it fails in BOTH — same finding, both frameworks see it.
	if statusOf(hipaa, ControlSC8) != secfindings.StatusFail {
		t.Errorf("SC-8 should FAIL under HIPAA, got %v", statusOf(hipaa, ControlSC8))
	}
	if statusOf(pci, ControlSC8) != secfindings.StatusFail {
		t.Errorf("SC-8 should FAIL under PCI, got %v", statusOf(pci, ControlSC8))
	}

	// ── independent COVERAGE % (honest, < 100% via unverified controls) ──────
	// HIPAA: 5 in scope (SC-8, IA-5, AC-3, AU-2, SI-7), 2 check-covered → 40%.
	if hipaa.ControlsInScope != 5 || hipaa.ControlsWithCheck != 2 {
		t.Errorf("HIPAA coverage counts = %d/%d, want 2/5", hipaa.ControlsWithCheck, hipaa.ControlsInScope)
	}
	if hipaa.CoveragePercent != 40 {
		t.Errorf("HIPAA coverage = %.1f%%, want 40%%", hipaa.CoveragePercent)
	}
	// PCI: 7 in scope (SC-8, IA-5, CM-8, CM-2, SI-2, AC-3, AU-2), 5 covered → ~71.4%.
	if pci.ControlsInScope != 7 || pci.ControlsWithCheck != 5 {
		t.Errorf("PCI coverage counts = %d/%d, want 5/7", pci.ControlsWithCheck, pci.ControlsInScope)
	}
	if pci.CoveragePercent < 71.0 || pci.CoveragePercent > 71.5 {
		t.Errorf("PCI coverage = %.2f%%, want ~71.43%%", pci.CoveragePercent)
	}

	// Both frameworks reach a Fail verdict (each from ITS OWN in-scope findings)
	// but on different scopes — HIPAA off SC-8 only, PCI off SC-8 + CM-2.
	if hipaa.Verdict != secfindings.StatusFail || pci.Verdict != secfindings.StatusFail {
		t.Errorf("verdicts hipaa=%v pci=%v, want both Fail", hipaa.Verdict, pci.Verdict)
	}
	if hipaa.Failed != 1 {
		t.Errorf("HIPAA failed controls = %d, want 1 (SC-8)", hipaa.Failed)
	}
	if pci.Failed != 2 {
		t.Errorf("PCI failed controls = %d, want 2 (SC-8, CM-2)", pci.Failed)
	}

	// Honesty caption present on every framework view (§5d).
	if hipaa.Caption == "" || pci.Caption == "" {
		t.Error("standard honesty caption must be attached to every framework view")
	}
}

func TestPerTenantSelectionIsInputSet(t *testing.T) {
	cat := DefaultCatalog()
	findings := sharedFindings(cat)

	// A HIPAA-only tenant passes ONLY the HIPAA provider and sees ONLY HIPAA.
	only := ProjectFrameworks(findings, cat, []FrameworkProvider{NewHIPAAProvider()})
	if len(only) != 1 || only[0].Framework != FrameworkHIPAA {
		t.Fatalf("HIPAA-only selection = %+v, want single HIPAA scorecard", only)
	}
	// A both-enabled tenant gets two independent, separately-scored scorecards
	// from the SAME findings (run once, project onto each).
	both := ProjectFrameworks(findings, cat, []FrameworkProvider{NewHIPAAProvider(), NewPCIProvider()})
	if len(both) != 2 {
		t.Fatalf("both selection returned %d scorecards, want 2", len(both))
	}
	if both[0].Framework != FrameworkHIPAA || both[1].Framework != FrameworkPCIDSS {
		t.Errorf("order not preserved: %q, %q", both[0].Framework, both[1].Framework)
	}
	// Enabling PCI alongside HIPAA does NOT change HIPAA's independent score.
	if both[0].Failed != only[0].Failed || both[0].CoveragePercent != only[0].CoveragePercent {
		t.Error("HIPAA score changed when PCI was also enabled — not independent")
	}
	if ProjectFrameworks(findings, cat, nil) != nil {
		t.Error("no selected frameworks should yield nil")
	}
}

func TestUnassessedNeverFalseClear(t *testing.T) {
	cat := DefaultCatalog()
	// A run with NO findings at all: covered controls are UNASSESSED, never Pass.
	cov := ProjectFramework(nil, cat, NewPCIProvider())
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
	// Coverage % is a static capability and stays honest regardless of findings.
	if cov.ControlsWithCheck != 5 {
		t.Errorf("PCI check-covered = %d, want 5", cov.ControlsWithCheck)
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
