// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package hardening

import (
	"encoding/json"
	"os"
	"testing"
)

// vendorprofile_parity_test.go — the NO-REGRESSION gate for the hardening
// dialect selection. testdata/vendorprofile_parity.json was captured from the
// PRE-migration (T9) VendorFromPlatform / DisplayVendor switches before the
// substring table moved into internal/vendorprofile's `detection.platform_*`
// and `hardening.*` fields.
//
// SIX ROWS WERE DELIBERATELY CHANGED on 2026-09-02, when the Arista EOS and
// Nokia SR Linux hardening dialects landed (dialect_fabric.go). They are listed
// here because a golden that changes silently is not a gate:
//
//	"Arista EOS 4.33" | "arista" | "eos"      ""      → "arista"
//	                  display     "unknown vendor"    → "Arista EOS"
//	"Nokia SR Linux" | "sr linux" | "srlinux"  "nokia" → "srlinux"
//	                  display     "Nokia SR OS"       → "Nokia SR Linux"
//
// Both were BUGS the parity corpus was faithfully preserving. Arista resolved to
// no dialect at all, so every EOS device reported NotApplicable for the whole
// catalog. SR Linux resolved to the SR OS dialect and was scored against a
// configuration grammar it does not write — `configure system
// management-interface telnet-server …` never appears in an SR Linux config, so
// the SR OS telnet rule answered a confident "not enabled" on every one of them.
// Every OTHER row in the corpus is unchanged and still holds the line.

type hardeningGolden struct {
	VendorFromPlatform map[string]string `json:"vendor_from_platform"`
	DisplayForPlatform map[string]string `json:"display_for_platform"`
	DisplayVendor      map[string]string `json:"display_vendor"`
}

func loadHardeningGolden(t *testing.T) hardeningGolden {
	t.Helper()
	b, err := os.ReadFile("testdata/vendorprofile_parity.json")
	if err != nil {
		t.Fatalf("read golden: %v", err)
	}
	var g hardeningGolden
	if err := json.Unmarshal(b, &g); err != nil {
		t.Fatalf("decode golden: %v", err)
	}
	return g
}

func TestVendorFromPlatformMatchesPreMigrationGolden(t *testing.T) {
	g := loadHardeningGolden(t)
	if len(g.VendorFromPlatform) == 0 {
		t.Fatal("golden carries no vendor_from_platform rows")
	}
	for platform, want := range g.VendorFromPlatform {
		if got := string(VendorFromPlatform(platform)); got != want {
			t.Errorf("VendorFromPlatform(%q) = %q, pre-migration golden %q", platform, got, want)
		}
	}
	for platform, want := range g.DisplayForPlatform {
		if got := DisplayVendor(VendorFromPlatform(platform)); got != want {
			t.Errorf("DisplayVendor(VendorFromPlatform(%q)) = %q, pre-migration golden %q", platform, got, want)
		}
	}
}

func TestDisplayVendorMatchesPreMigrationGolden(t *testing.T) {
	g := loadHardeningGolden(t)
	if len(g.DisplayVendor) == 0 {
		t.Fatal("golden carries no display_vendor rows")
	}
	for vendor, want := range g.DisplayVendor {
		if got := DisplayVendor(Vendor(vendor)); got != want {
			t.Errorf("DisplayVendor(%q) = %q, pre-migration golden %q", vendor, got, want)
		}
	}
}

// TestEveryBoundVendorHasProfileBindings — the catalog's rule bindings key on
// Vendor constants; every one of them must be reachable from a vendor profile,
// or a whole dialect's rules would silently become unreachable.
func TestEveryBoundVendorHasProfileBindings(t *testing.T) {
	bound := map[Vendor]bool{}
	for _, r := range DefaultCatalog().Rules() {
		for _, v := range []Vendor{VendorCiscoIOSXE, VendorJuniper, VendorNokia, VendorArista, VendorSRLinux} {
			if _, ok := r.Binding(v); ok {
				bound[v] = true
			}
		}
	}
	reachable := map[Vendor]bool{}
	for _, platform := range []string{"Cisco IOS-XE 17.9", "Juniper Junos 22.4", "Nokia SR OS 22", "Nokia SR Linux", "Arista EOS 4.36"} {
		reachable[VendorFromPlatform(platform)] = true
	}
	for v := range bound {
		if !reachable[v] {
			t.Errorf("hardening dialect %q has catalog bindings but no vendor profile resolves to it", v)
		}
	}
}
