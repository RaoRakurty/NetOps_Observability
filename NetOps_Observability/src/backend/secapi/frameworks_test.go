package secapi

// frameworks_test.go — the per-tenant framework selection, the projection that
// replaced the tag-derived framework list, and the benchmark citations.

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"netops/backend/internal/compliancemodel"
)

// testInputs stands in for the producer-derived half of the compliance view.
// The real adapter lives in the wiring layer (main.go, inside the SECURITY-LANE
// markers) because internal/hardening is a removable module and this package
// must build without it — so the fixture here is deliberately hand-written
// rather than read from that catalogue.
func testInputs() ComplianceInputs {
	return ComplianceInputs{
		Mappings: []compliancemodel.ControlMapping{
			{Check: "telnet-vty-enabled", Controls: SupportsControls([]string{"AC-17", "SC-8"})},
			{Check: "exposure-snmp", Controls: SupportsControls([]string{"AC-4", "SC-7", "IA-5"})},
		},
		Benchmarks: []BenchmarkView{
			{
				ID: "cis-cisco-ios-xe-17", Title: "CIS Cisco IOS XE 17.x Benchmark", Version: "v2.2.1",
				Platform: "Cisco IOS-XE 17.x", SectionsVerified: true,
			},
			{
				ID: "cis-arista-eos", Title: "CIS Arista EOS Benchmark", Version: "v1.0.0",
				Platform: "Arista EOS", SectionsVerified: false,
				Note: "Section taxonomy unverified, so nothing cites it.",
			},
		},
		Citations: []BenchmarkCitation{
			{
				RuleID: "telnet-vty-enabled", BenchmarkID: "cis-cisco-ios-xe-17", Section: "1.2",
				Title: "Access Rules", Controls: []string{"AC-17", "SC-8"},
				Label: "CIS Cisco IOS XE 17.x Benchmark v2.2.1 §1.2 Access Rules",
			},
		},
	}
}

// TestDefaultSelectionIsNotEveryFramework is the owner's 2026-09-03 direction as
// a wire-level test: a tenant that has never chosen is shown the small default
// set, and the response SAYS it has not chosen.
func TestDefaultSelectionIsNotEveryFramework(t *testing.T) {
	views := frameworkViews(nil, false)
	if len(views) != len(compliancemodel.Frameworks()) {
		t.Fatalf("the catalogue must always be listed in full, got %d", len(views))
	}
	on := map[string]bool{}
	for _, v := range views {
		if v.Enabled {
			on[v.ID] = true
		}
		if v.Version == "" || v.Scope == "" || v.Source == "" {
			t.Errorf("framework %q is missing a version/scope/source: %+v", v.ID, v)
		}
	}
	if !on[compliancemodel.IDNIST80053] || !on[compliancemodel.IDCISv8] {
		t.Errorf("default selection = %v, want the 800-53 base + CIS Controls", on)
	}
	for _, id := range []string{compliancemodel.IDNISTCSF, compliancemodel.IDHIPAA, compliancemodel.IDPCIDSS} {
		if on[id] {
			t.Errorf("%q must be opt-in, not enabled by default", id)
		}
	}
}

// TestAConfiguredTenantGetsExactlyWhatItChose is the trap the `configured` flag
// exists to avoid: a tenant that deliberately turned everything off must not be
// handed the defaults back on the next read.
func TestAConfiguredTenantGetsExactlyWhatItChose(t *testing.T) {
	states := map[string]bool{
		compliancemodel.IDHIPAA:     true,
		compliancemodel.IDNIST80053: false,
		compliancemodel.IDCISv8:     false,
	}
	got := map[string]bool{}
	for _, v := range frameworkViews(states, true) {
		got[v.ID] = v.Enabled
	}
	if !got[compliancemodel.IDHIPAA] {
		t.Error("the tenant's HIPAA selection was not applied")
	}
	if got[compliancemodel.IDNIST80053] || got[compliancemodel.IDCISv8] {
		t.Error("a configured tenant must NOT have the shipped defaults re-applied over its own choice")
	}
	// An all-off selection stays all-off.
	allOff := map[string]bool{}
	for _, id := range []string{compliancemodel.IDNIST80053, compliancemodel.IDCISv8,
		compliancemodel.IDNISTCSF, compliancemodel.IDHIPAA, compliancemodel.IDPCIDSS} {
		allOff[id] = false
	}
	if ids := enabledIDs(frameworkViews(allOff, true)); len(ids) != 0 {
		t.Errorf("an all-off selection came back as %v", ids)
	}
}

// TestFrameworkFileStoreIsTenantKeyed proves the isolation is IN the store
// (§3a rule 4): one tenant's selection is invisible to another, and the
// `configured` flag is per-caller-scope too.
func TestFrameworkFileStoreIsTenantKeyed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "frameworks.json")
	s := NewFrameworkFileStore(path)
	ctx := context.Background()

	if err := s.SetFrameworkStates(ctx, "acme", false, "acme", []FrameworkState{
		{FrameworkID: compliancemodel.IDHIPAA, Enabled: true},
		{FrameworkID: compliancemodel.IDCISv8, Enabled: false},
	}); err != nil {
		t.Fatalf("set: %v", err)
	}

	states, configured, err := s.FrameworkStates(ctx, "acme", false)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if !configured || !states[compliancemodel.IDHIPAA] || states[compliancemodel.IDCISv8] {
		t.Fatalf("acme's own selection did not round-trip: %v configured=%v", states, configured)
	}

	other, otherConfigured, err := s.FrameworkStates(ctx, "globex", false)
	if err != nil {
		t.Fatalf("get globex: %v", err)
	}
	if otherConfigured || len(other) != 0 {
		t.Fatalf("TENANT LEAK: globex saw acme's selection: %v configured=%v", other, otherConfigured)
	}

	// The platform (cross) view sees it; nothing else does.
	all, allConfigured, err := s.FrameworkStates(ctx, "", true)
	if err != nil {
		t.Fatalf("get cross: %v", err)
	}
	if !allConfigured || !all[compliancemodel.IDHIPAA] {
		t.Fatalf("the cross-tenant view should see acme's row: %v", all)
	}

	// It survives a reload, and the owner is persisted with it.
	reloaded := NewFrameworkFileStore(path)
	if err := reloaded.LoadErr(); err != nil {
		t.Fatalf("reload: %v", err)
	}
	if st, cfg, _ := reloaded.FrameworkStates(ctx, "globex", false); cfg || len(st) != 0 {
		t.Fatalf("TENANT LEAK after reload: %v", st)
	}
	if st, cfg, _ := reloaded.FrameworkStates(ctx, "acme", false); !cfg || !st[compliancemodel.IDHIPAA] {
		t.Fatalf("acme's selection did not survive a reload: %v", st)
	}
}

// TestFrameworkFileStoreReportsAnUnreadableFile — "the file could not be read"
// and "this tenant has not chosen" must not render identically.
func TestFrameworkFileStoreReportsAnUnreadableFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "frameworks.json")
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	s := NewFrameworkFileStore(path)
	if s.LoadErr() == nil {
		t.Fatal("a corrupt selection file must be reported, not folded into an empty store")
	}
	if st, cfg, err := s.FrameworkStates(context.Background(), "acme", false); err != nil || cfg || len(st) != 0 {
		t.Fatalf("a store that failed to load must still SERVE the defaults: %v %v %v", st, cfg, err)
	}
}

// TestComplianceCatalogComposesTheInjectedMapping proves the composition that
// makes HIPAA/PCI report at all — and that it is ADDITIVE, so the legacy check
// mapping survives it.
func TestComplianceCatalogComposesTheInjectedMapping(t *testing.T) {
	cat := ComplianceCatalog(testInputs().Mappings)
	refs := cat.ControlsForCheck("telnet-vty-enabled")
	if len(refs) != 2 || refs[0].ControlID != "AC-17" || refs[1].ControlID != "SC-8" {
		t.Fatalf("injected mapping not composed: %+v", refs)
	}
	for _, r := range refs {
		if !r.Relationship.Valid() {
			t.Errorf("%q has an invalid relationship %q", r.ControlID, r.Relationship)
		}
	}
	if len(cat.ControlsForCheck("snmp-v3-strength")) == 0 {
		t.Error("composing the injected mapping dropped the legacy check mapping")
	}
	// With NO producer wired the catalog is still the seed one — the read API
	// keeps working with internal/hardening deleted.
	bare := ComplianceCatalog(nil)
	if len(bare.ControlsForCheck("snmp-v3-strength")) == 0 {
		t.Error("the producer-free catalog lost the legacy check mapping")
	}
	if len(bare.ControlsForCheck("telnet-vty-enabled")) != 0 {
		t.Error("the producer-free catalog invented a hardening mapping")
	}
}

// TestBenchmarkCitationsAreCitationsNotFrameworks is the shape guard for the
// reported bug: benchmark sections are served in their OWN list, never as
// framework entries, and every citation names a real benchmark.
func TestBenchmarkCitationsAreCitationsNotFrameworks(t *testing.T) {
	in := testInputs()
	body := frameworksResponse{
		Frameworks: frameworkViews(nil, false),
		Benchmarks: in.Benchmarks,
		Citations:  in.Citations,
	}
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(raw), "CIS-NET-") {
		t.Fatal("the invented CIS-NET benchmark tags are back on the wire")
	}
	for _, f := range body.Frameworks {
		if strings.Contains(strings.ToLower(f.Name), "benchmark") {
			t.Errorf("framework %q is a benchmark, not a framework", f.Name)
		}
	}
	known := map[string]BenchmarkView{}
	for _, b := range body.Benchmarks {
		known[b.ID] = b
	}
	if len(body.Citations) == 0 {
		t.Fatal("no rule cites a benchmark section — the guard would pass vacuously")
	}
	for _, c := range body.Citations {
		b, ok := known[c.BenchmarkID]
		if !ok {
			t.Errorf("citation on %q names unknown benchmark %q", c.RuleID, c.BenchmarkID)
			continue
		}
		if !b.SectionsVerified {
			t.Errorf("citation on %q names %q, whose section taxonomy is unverified", c.RuleID, b.ID)
		}
		if !strings.Contains(c.Label, b.Version) || !strings.Contains(c.Label, "§"+c.Section) {
			t.Errorf("citation label %q must carry the benchmark version and the section", c.Label)
		}
	}
}
