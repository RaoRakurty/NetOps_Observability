package backend

import (
	"context"
	"strings"
	"testing"

	"netops/backend/internal/entitlement"
	"netops/backend/internal/hardening"
)

// licence_dialect_gate_test.go — the licence gate on the hardening DIALECT
// registry (design §4 "dialect registry"; the owner's LOCKED Enterprise set).
//
// It lives in its OWN file, apart from the other chokepoint tests in
// licence_routes_test.go, for one reason: it is the only licence test that
// imports internal/hardening, and internal/hardening is part of the REMOVABLE
// security producer. Keeping it separate means deleting the security lane is
// still `rm` of a named file list — see the removal recipe in
// security_lane_removability_test.go, which names this file, and the
// SECURITY-LANE markers around licenceDialectAllowed in main.go.

// TestLicenceDialectGate: the core dialect is always available; the rest need
// the Enterprise entitlement.
func TestLicenceDialectGate(t *testing.T) {
	k := newLicTestKey(t)

	t.Run("community gets the core dialect only", func(t *testing.T) {
		s := &server{entitlements: k.service(t, nil)}
		if !s.licenceDialectAllowed(hardening.VendorCiscoIOSXE) {
			t.Fatal("cisco-iosxe is the core dialect and is available at every tier")
		}
		if !s.licenceDialectAllowed(hardening.VendorUnknown) {
			t.Fatal("an unresolved platform must keep its own honest finding, not be swallowed by the licence gate")
		}
		for _, v := range []hardening.Vendor{
			hardening.VendorJuniper, hardening.VendorNokia, hardening.VendorArista, hardening.VendorSRLinux,
		} {
			if s.licenceDialectAllowed(v) {
				t.Fatalf("%s is beyond the core set and needs the Enterprise dialects entitlement", v)
			}
		}
	})

	t.Run("an Enterprise licence unlocks every dialect", func(t *testing.T) {
		raw := k.issue(t, entitlement.TierEnterprise, []entitlement.Feature{entitlement.FeatureSecurityDialects}, nil)
		s := &server{entitlements: k.service(t, raw)}
		for _, v := range []hardening.Vendor{
			hardening.VendorCiscoIOSXE, hardening.VendorJuniper, hardening.VendorNokia,
			hardening.VendorArista, hardening.VendorSRLinux,
		} {
			if !s.licenceDialectAllowed(v) {
				t.Fatalf("the dialects entitlement must unlock %s", v)
			}
		}
	})

	t.Run("an unlicensed dialect is reported, never skipped", func(t *testing.T) {
		// The honesty rule: no findings for a device nothing looked at would
		// read as "this device is clean". The engine must say why instead.
		eng := hardening.NewEngine(hardening.DefaultCatalog(), hardening.MemConfigSource{}, nil,
			hardening.WithDialectGate(func(v hardening.Vendor) bool { return v == hardening.VendorCiscoIOSXE }))
		fs, err := eng.Evaluate(context.Background(), hardening.Device{ID: "d1", Hostname: "mx1", Platform: "juniper junos"})
		if err != nil {
			t.Fatalf("evaluate: %v", err)
		}
		if len(fs) != 1 {
			t.Fatalf("an unlicensed dialect yields exactly one coverage finding, got %d", len(fs))
		}
		if fs[0].ID != hardening.RuleDialectNotLicensed {
			t.Fatalf("finding id = %q, want %q", fs[0].ID, hardening.RuleDialectNotLicensed)
		}
		if !strings.Contains(fs[0].Detail, "not included in this licence") {
			t.Fatalf("the finding must say WHY nothing was assessed: %q", fs[0].Detail)
		}
		if !strings.Contains(fs[0].Detail, "still discovered") {
			t.Fatalf("the finding must say the device is not hidden or deleted: %q", fs[0].Detail)
		}
	})

	t.Run("no gate means every dialect, unchanged", func(t *testing.T) {
		// Every test and every build without the licence wiring must behave
		// exactly as it did before this feature existed.
		eng := hardening.NewEngine(hardening.DefaultCatalog(), hardening.MemConfigSource{}, nil)
		fs, err := eng.Evaluate(context.Background(), hardening.Device{ID: "d1", Hostname: "mx1", Platform: "juniper junos"})
		if err != nil {
			t.Fatal(err)
		}
		for _, f := range fs {
			if f.ID == hardening.RuleDialectNotLicensed {
				t.Fatal("a nil dialect gate must allow everything")
			}
		}
	})
}
