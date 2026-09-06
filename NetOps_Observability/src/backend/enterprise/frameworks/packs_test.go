// SPDX-License-Identifier: LicenseRef-Correlix-Enterprise

package frameworks

import (
	"testing"

	"netops/backend/internal/compliancemodel"
	"netops/backend/internal/secfindings"
)

// staticConformance asserts the moved crosswalks still satisfy the abstract
// framework seam at compile time (§5h — frameworks are interchangeable
// providers behind the interface). It is the assertion the core package carried
// for these three before they moved.
var (
	_ compliancemodel.FrameworkProvider = NewNISTCSFProvider()
	_ compliancemodel.FrameworkProvider = NewHIPAAProvider()
	_ compliancemodel.FrameworkProvider = NewPCIProvider()
)

// TestPacksBindOnlyLicensedCatalogueIDs is the pack-integrity rule that keeps a
// data contribution honest: every id this module binds must be an id the CORE
// catalogue carries AND has no crosswalk for. An id core already provides would
// be an attempt to override Apache-2.0 content (the registry refuses it, and
// the override would be invisible); an id the catalogue does not carry at all is
// ignored by the registry, so it would only ever show up as a framework nobody
// can enable.
func TestPacksBindOnlyLicensedCatalogueIDs(t *testing.T) {
	licensed := compliancemodel.LicensedFrameworkIDs()
	if len(licensed) == 0 {
		t.Fatal("core reports no licensed framework ids — the seam this module plugs into is gone")
	}
	seen := map[string]bool{}
	for _, p := range Packs() {
		if p.New == nil {
			t.Errorf("pack %q has no constructor — it would contribute nothing", p.ID)
			continue
		}
		if !licensed[p.ID] {
			t.Errorf("pack %q is not a catalogue id awaiting a crosswalk (core ids: %v)", p.ID, licensed)
		}
		if seen[p.ID] {
			t.Errorf("duplicate pack for %q", p.ID)
		}
		seen[p.ID] = true
	}
	for id := range licensed {
		if !seen[id] {
			t.Errorf("catalogue id %q awaits a crosswalk and no pack supplies it — "+
				"enabling it would report 'not included' even with this module installed", id)
		}
	}
}

// TestPacksCompleteTheCatalogue is the assertion the core registry test carried
// before the split: with the packs installed, EVERY framework in the vocabulary
// resolves to a provider whose own identity agrees with its descriptor. A
// descriptor that disagrees with its provider is how a page renders
// "PCI DSS v4.0.1" over a v3.2.1 crosswalk.
func TestPacksCompleteTheCatalogue(t *testing.T) {
	packs := Packs()
	for _, info := range compliancemodel.Frameworks() {
		p, ok := compliancemodel.ProviderFor(info.ID, packs...)
		if !ok {
			t.Fatalf("%s: no provider even with the packs installed", info.ID)
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
	if len(compliancemodel.MissingCrosswalks(idsOf(compliancemodel.Frameworks()), packs...)) != 0 {
		t.Error("nothing may be reported as missing when every pack is installed")
	}
}

// TestPacksCannotOverrideCore is the DATA-not-code-injection rule: a pack that
// names a core framework must not be able to replace the Apache-2.0 crosswalk
// core ships. Core wins on every id it provides.
func TestPacksCannotOverrideCore(t *testing.T) {
	hostile := compliancemodel.FrameworkPack{
		ID:  compliancemodel.IDCISv8,
		New: NewHIPAAProvider, // a deliberately wrong crosswalk for that id
	}
	p, ok := compliancemodel.ProviderFor(compliancemodel.IDCISv8, hostile)
	if !ok {
		t.Fatal("the core framework must still resolve")
	}
	if p.Framework() != compliancemodel.FrameworkCIS {
		t.Errorf("a pack overrode a core crosswalk: got %q", p.Framework())
	}
}

// TestHIPAAReportsThroughTheProjection is the bug the owner reported, and it
// moved here with the crosswalk it exercises: HIPAA is a projection and never a
// standards TAG, so before this it could never appear. A finding tagged only
// with an 800-53 control must reach HIPAA's requirement.
func TestHIPAAReportsThroughTheProjection(t *testing.T) {
	cat := compliancemodel.DefaultCatalog()
	// A hardening finding: no legacy check id, only the producer-stamped control.
	f := secfindings.Finding{RawRuleID: "telnet-vty-enabled", ControlID: compliancemodel.ControlAC17}
	f.SetStatus(secfindings.StatusFail)

	cov := compliancemodel.ProjectFramework([]secfindings.Finding{f}, cat, NewHIPAAProvider())
	if cov.Framework != compliancemodel.FrameworkHIPAA {
		t.Fatalf("framework = %q", cov.Framework)
	}
	if statusOf(cov, compliancemodel.ControlAC17) != secfindings.StatusFail {
		t.Fatalf("AC-17 should FAIL under HIPAA via the projection, got %v",
			statusOf(cov, compliancemodel.ControlAC17))
	}
	var reqs []string
	for _, c := range cov.Controls {
		if c.ControlID == compliancemodel.ControlAC17 {
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

// idsOf is the selection helper the missing-crosswalk assertion needs.
func idsOf(infos []compliancemodel.FrameworkInfo) []string {
	out := make([]string, 0, len(infos))
	for _, i := range infos {
		out = append(out, i.ID)
	}
	return out
}
