// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package netconcepts

import (
	"encoding/json"
	"os"
	"testing"
)

// vendorprofile_parity_test.go — the T9 NO-REGRESSION gate for the dialect
// vocabulary. testdata/vendorprofile_parity.json was captured from the
// PRE-migration code (the package-level vrfSynonyms map and the VRFDisplayTerm
// switch) before both moved into internal/vendorprofile's `dialect` blocks.

type dialectGolden struct {
	IsVRFTerm      map[string]bool   `json:"is_vrf_term"`
	VRFDisplayTerm map[string]string `json:"vrf_display_term"`
	VRFEntityToken map[string]string `json:"vrf_entity_token"`
}

func loadDialectGolden(t *testing.T) dialectGolden {
	t.Helper()
	b, err := os.ReadFile("testdata/vendorprofile_parity.json")
	if err != nil {
		t.Fatalf("read golden: %v", err)
	}
	var g dialectGolden
	if err := json.Unmarshal(b, &g); err != nil {
		t.Fatalf("decode golden: %v", err)
	}
	return g
}

// TestIsVRFTermMatchesPreMigrationGolden replays the concept-token corpus —
// every supported dialect spelling plus a set of non-VRF networking terms that
// must NOT classify as the VRF concept.
func TestIsVRFTermMatchesPreMigrationGolden(t *testing.T) {
	g := loadDialectGolden(t)
	if len(g.IsVRFTerm) == 0 {
		t.Fatal("golden carries no is_vrf_term rows")
	}
	for term, want := range g.IsVRFTerm {
		if got := IsVRFTerm(term); got != want {
			t.Errorf("IsVRFTerm(%q) = %v, pre-migration golden %v", term, got, want)
		}
	}
}

// TestVRFDisplayTermMatchesPreMigrationGolden replays the vendor-token corpus,
// including the unknown-vendor rows that must still fall back to "VRF".
func TestVRFDisplayTermMatchesPreMigrationGolden(t *testing.T) {
	g := loadDialectGolden(t)
	if len(g.VRFDisplayTerm) == 0 {
		t.Fatal("golden carries no vrf_display_term rows")
	}
	for vendor, want := range g.VRFDisplayTerm {
		if got := VRFDisplayTerm(vendor); got != want {
			t.Errorf("VRFDisplayTerm(%q) = %q, pre-migration golden %q", vendor, got, want)
		}
	}
}

// TestVRFEntityTokenUnchanged — the correlation identity is dialect-FREE and was
// deliberately left in this package (it is not vendor knowledge). Pinned so the
// migration cannot have disturbed it.
func TestVRFEntityTokenUnchanged(t *testing.T) {
	g := loadDialectGolden(t)
	cases := map[string]string{
		"r1|CORP-WAN": VRFEntityToken("r1", "CORP-WAN"),
		" R1 | CORP ": VRFEntityToken(" R1 ", " CORP "),
		"|":           VRFEntityToken("", ""),
	}
	for k, got := range cases {
		if want, ok := g.VRFEntityToken[k]; !ok || got != want {
			t.Errorf("VRFEntityToken %s = %q, pre-migration golden %q (present=%v)", k, got, want, ok)
		}
	}
}
