// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package owner

import (
	"encoding/json"
	"os"
	"testing"
)

func TestOf(t *testing.T) {
	for in, want := range map[string]string{
		"": "global", "  ": "global", "global": "global", "GLOBAL": "global", " Global ": "global",
		"t_90892feb": "t_90892feb", "T_90892FEB": "t_90892feb", "acme": "acme", "t-rca-canary": "t-rca-canary",
	} {
		if got := Of(in); got != want {
			t.Errorf("Of(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestRealTenantsNeverCollapse(t *testing.T) {
	if Same("acme", "globex") || Same("acme", "") || Same("acme", "global") {
		t.Fatal("two distinct owners compared equal")
	}
	if !Same("", "global") || !IsPlatform("") || !IsPlatform("GLOBAL") || IsPlatform("t_1") {
		t.Fatal("the platform's two spellings must be one owner")
	}
}

// ScopeReads is directional: the Provider scope reads both platform
// spellings; an unbound "" scope never widens to "global"; tenants never mix.
func TestScopeReadsIsDirectional(t *testing.T) {
	for _, c := range []struct {
		scope, row string
		want       bool
	}{
		{"global", "global", true},
		{"global", "", true},
		{" GLOBAL ", "  ", true},
		{"", "", true},
		{"", "global", false}, // unbound caller never widens into the Provider
		{"acme", "acme", true},
		{"ACME", "acme", true},
		{"acme", "", false},
		{"acme", "global", false},
		{"global", "acme", false},
		{"", "acme", false},
	} {
		if got := ScopeReads(c.scope, c.row); got != c.want {
			t.Errorf("ScopeReads(%q, %q) = %v, want %v", c.scope, c.row, got, c.want)
		}
	}
}

// TestParityWithCorrelation reads the table the correlation engine's
// canon_tenant test also reads (src/correlation/test_canon_tenant.py).
func TestParityWithCorrelation(t *testing.T) {
	b, err := os.ReadFile("testdata/parity.json")
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		Cases [][2]string `json:"cases"`
	}
	if err := json.Unmarshal(b, &f); err != nil || len(f.Cases) == 0 {
		t.Fatalf("parity table unreadable: %v", err)
	}
	for _, c := range f.Cases {
		if got := Of(c[0]); got != c[1] {
			t.Errorf("Of(%q) = %q, the shared table says %q", c[0], got, c[1])
		}
	}
}
