// SPDX-License-Identifier: LicenseRef-Correlix-Enterprise

package frameworks

import (
	"testing"

	"netops/backend/internal/compliance"
	"netops/backend/internal/compliancemodel"
	"netops/backend/internal/secfindings"
)

// sharedFindings builds the SAME finding set both frameworks are scored against,
// so the test proves the per-framework projection — not a difference in inputs —
// is what produces different scopes. One SNMP-crypto violation (→ SC-8, in BOTH
// HIPAA and PCI scope) and one golden-baseline violation (→ CM-2, in PCI scope
// only, NOT a HIPAA §164.312 technical safeguard). Convert routes each finding to
// its owned control purely by its Check id (the T1 converter fixes verdict=Fail,
// class=posture).
func sharedFindings(cat *compliancemodel.Catalog) []secfindings.Finding {
	fSC8 := cat.Convert(compliance.Finding{Check: "snmp-v3-strength"}, compliancemodel.EmitOptions{TenantID: "acme"}) // → SC-8
	fCM2 := cat.Convert(compliance.Finding{Check: "os-consensus"}, compliancemodel.EmitOptions{TenantID: "acme"})     // → CM-2
	return []secfindings.Finding{fSC8, fCM2}
}

func TestHIPAAvsPCIIndependence(t *testing.T) {
	cat := compliancemodel.DefaultCatalog()
	findings := sharedFindings(cat)

	hipaa := compliancemodel.ProjectFramework(findings, cat, NewHIPAAProvider())
	pci := compliancemodel.ProjectFramework(findings, cat, NewPCIProvider())

	// ── independent SCOPES from the SAME findings ────────────────────────────
	// HIPAA §164.312 technical safeguards: SC-8, IA-5 (+ AC-3/AU-2/SI-7 unverified).
	// CM-2 (golden baseline) is NOT a HIPAA technical safeguard → out of scope.
	if inScope(hipaa, compliancemodel.ControlCM2) {
		t.Error("CM-2 must NOT be in HIPAA scope (not a §164.312 technical safeguard)")
	}
	if !inScope(hipaa, compliancemodel.ControlSC8) {
		t.Error("SC-8 (transmission security) must be in HIPAA scope")
	}
	// PCI includes CM-2 (Req 2 secure configuration) → in scope.
	if !inScope(pci, compliancemodel.ControlCM2) {
		t.Error("CM-2 must be in PCI scope (Req 2)")
	}

	// ── same shared CM-2 finding scored DIFFERENTLY per framework ────────────
	// It fails a control in PCI; it is invisible to HIPAA. This is the crux of
	// per-framework independence: one finding, two independent verdicts.
	if statusOf(pci, compliancemodel.ControlCM2) != secfindings.StatusFail {
		t.Errorf("CM-2 should FAIL under PCI, got %v", statusOf(pci, compliancemodel.ControlCM2))
	}
	if hasControl(hipaa, compliancemodel.ControlCM2) {
		t.Error("HIPAA projection must not carry CM-2 at all")
	}

	// SC-8 is shared: it fails in BOTH — same finding, both frameworks see it.
	if statusOf(hipaa, compliancemodel.ControlSC8) != secfindings.StatusFail {
		t.Errorf("SC-8 should FAIL under HIPAA, got %v", statusOf(hipaa, compliancemodel.ControlSC8))
	}
	if statusOf(pci, compliancemodel.ControlSC8) != secfindings.StatusFail {
		t.Errorf("SC-8 should FAIL under PCI, got %v", statusOf(pci, compliancemodel.ControlSC8))
	}

	// ── independent COVERAGE % (honest, < 100% via uncovered controls) ───────
	// The denominator is the framework's OWN scope, the numerator is the
	// controls the LEGACY 9 checks evidence (this catalog carries no hardening
	// mappings — a caller composes those in with Catalog.With, which is what
	// raises the numerator without touching the scope).
	//
	// HIPAA §164.312 technical safeguards: 10 in scope, 2 check-covered → 20%.
	if hipaa.ControlsInScope != 10 || hipaa.ControlsWithCheck != 2 {
		t.Errorf("HIPAA coverage counts = %d/%d, want 2/10", hipaa.ControlsWithCheck, hipaa.ControlsInScope)
	}
	if hipaa.CoveragePercent != 20 {
		t.Errorf("HIPAA coverage = %.1f%%, want 20%%", hipaa.CoveragePercent)
	}
	// PCI technical requirements: 18 in scope, 5 check-covered → ~27.8%. PCI's
	// scope is BROADER than HIPAA's from the same owned catalog, which is the
	// point — the two frameworks are not two labels on one number.
	if pci.ControlsInScope != 18 || pci.ControlsWithCheck != 5 {
		t.Errorf("PCI coverage counts = %d/%d, want 5/18", pci.ControlsWithCheck, pci.ControlsInScope)
	}
	if pci.ControlsInScope <= hipaa.ControlsInScope {
		t.Errorf("PCI scope (%d) must be broader than HIPAA's (%d)", pci.ControlsInScope, hipaa.ControlsInScope)
	}
	if pci.CoveragePercent < 27.5 || pci.CoveragePercent > 28.0 {
		t.Errorf("PCI coverage = %.2f%%, want ~27.78%%", pci.CoveragePercent)
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
	cat := compliancemodel.DefaultCatalog()
	findings := sharedFindings(cat)

	// A HIPAA-only tenant passes ONLY the HIPAA provider and sees ONLY HIPAA.
	only := compliancemodel.ProjectFrameworks(findings, cat, []compliancemodel.FrameworkProvider{NewHIPAAProvider()})
	if len(only) != 1 || only[0].Framework != compliancemodel.FrameworkHIPAA {
		t.Fatalf("HIPAA-only selection = %+v, want single HIPAA scorecard", only)
	}
	// A both-enabled tenant gets two independent, separately-scored scorecards
	// from the SAME findings (run once, project onto each).
	both := compliancemodel.ProjectFrameworks(findings, cat, []compliancemodel.FrameworkProvider{NewHIPAAProvider(), NewPCIProvider()})
	if len(both) != 2 {
		t.Fatalf("both selection returned %d scorecards, want 2", len(both))
	}
	if both[0].Framework != compliancemodel.FrameworkHIPAA || both[1].Framework != compliancemodel.FrameworkPCIDSS {
		t.Errorf("order not preserved: %q, %q", both[0].Framework, both[1].Framework)
	}
	// Enabling PCI alongside HIPAA does NOT change HIPAA's independent score.
	if both[0].Failed != only[0].Failed || both[0].CoveragePercent != only[0].CoveragePercent {
		t.Error("HIPAA score changed when PCI was also enabled — not independent")
	}
	if compliancemodel.ProjectFrameworks(findings, cat, nil) != nil {
		t.Error("no selected frameworks should yield nil")
	}
}

func TestUnassessedNeverFalseClear(t *testing.T) {
	cat := compliancemodel.DefaultCatalog()
	// A run with NO findings at all: covered controls are UNASSESSED, never Pass.
	cov := compliancemodel.ProjectFramework(nil, cat, NewPCIProvider())
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

func inScope(c compliancemodel.FrameworkCoverage, control string) bool {
	for _, r := range c.Controls {
		if r.ControlID == control {
			return true
		}
	}
	return false
}

func hasControl(c compliancemodel.FrameworkCoverage, control string) bool { return inScope(c, control) }

func statusOf(c compliancemodel.FrameworkCoverage, control string) secfindings.StatusID {
	for _, r := range c.Controls {
		if r.ControlID == control {
			return r.StatusID
		}
	}
	return secfindings.StatusUnknown
}
