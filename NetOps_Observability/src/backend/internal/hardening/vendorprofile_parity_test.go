package hardening

import (
	"encoding/json"
	"os"
	"testing"
)

// vendorprofile_parity_test.go — the T9 NO-REGRESSION gate for the hardening
// dialect selection. testdata/vendorprofile_parity.json was captured from the
// PRE-migration VendorFromPlatform / DisplayVendor switches before the
// substring table moved into internal/vendorprofile's `detection.platform_*`
// and `hardening.*` fields.
//
// The corpus deliberately includes "Arista EOS 4.33": the catalog ships NO
// Arista bindings, so it must still map to VendorUnknown (NotApplicable, never
// a false Pass) rather than borrowing the Cisco dialect.

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
		for _, v := range []Vendor{VendorCiscoIOSXE, VendorJuniper, VendorNokia} {
			if _, ok := r.Binding(v); ok {
				bound[v] = true
			}
		}
	}
	reachable := map[Vendor]bool{}
	for _, platform := range []string{"Cisco IOS-XE 17.9", "Juniper Junos 22.4", "Nokia SR OS 22", "Nokia SR Linux"} {
		reachable[VendorFromPlatform(platform)] = true
	}
	for v := range bound {
		if !reachable[v] {
			t.Errorf("hardening dialect %q has catalog bindings but no vendor profile resolves to it", v)
		}
	}
}
