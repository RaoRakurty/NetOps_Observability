// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package devmon_test

// devmon_test.go — the DEFINITION of a monitored device.
//
// One number in the product depends on this file being right: the Community
// tier's 25. Every case below is a sentence from the owner's C4 decision
// (2026-09-05) turned into an assertion, because the failure mode is not a
// crash — it is a customer quietly charged for devices nobody collects from, or
// quietly collecting from devices nobody paid for.

import (
	"strings"
	"testing"

	"netops/backend/internal/devmon"
	"netops/backend/models"
)

func TestDefaultIsProvenance(t *testing.T) {
	cases := []struct {
		name    string
		device  models.Device
		want    bool
		wantWhy string
	}{
		{
			name:   "a subnet-scan result is a candidate, not a monitored device",
			device: models.Device{ID: "scan-1", Address: "10.0.0.1", Source: "snmp"},
			want:   false, wantWhy: devmon.ReasonDiscovered,
		},
		{
			name:   "a manually created device is monitored — adding it is asking to collect from it",
			device: models.Device{ID: "m1", Address: "10.0.0.2", Source: "manual"},
			want:   true, wantWhy: devmon.ReasonDeclared,
		},
		{
			name:   "an operator-authored devices file declares monitored devices",
			device: models.Device{ID: "s1", Address: "10.0.0.3", Source: "static"},
			want:   true, wantWhy: devmon.ReasonDeclared,
		},
		{
			name:   "the source of truth declares monitored devices",
			device: models.Device{ID: "n1", Address: "10.0.0.4", Source: "netbox"},
			want:   true, wantWhy: devmon.ReasonDeclared,
		},
		{
			name:   "a device nothing can reach is not monitored, whatever its source",
			device: models.Device{ID: "m2", Source: "manual"},
			want:   false, wantWhy: devmon.ReasonNoAddress,
		},
		{
			name:   "an address of blanks is no address",
			device: models.Device{ID: "m3", Address: "   ", Source: "manual"},
			want:   false, wantWhy: devmon.ReasonNoAddress,
		},
		{
			name:   "the source match is case-insensitive",
			device: models.Device{ID: "scan-2", Address: "10.0.0.5", Source: "SNMP"},
			want:   false, wantWhy: devmon.ReasonDiscovered,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, why := devmon.Default(tc.device)
			if got != tc.want {
				t.Fatalf("Default = %v, want %v (%s)", got, tc.want, why)
			}
			if why != tc.wantWhy {
				t.Fatalf("reason = %q, want %q", why, tc.wantWhy)
			}
		})
	}
}

// TestEveryDecisionCarriesAReason — §10: no silent states. A device that is not
// being collected from must always say what would change that.
func TestEveryDecisionCarriesAReason(t *testing.T) {
	for _, d := range []models.Device{
		{ID: "a", Address: "10.0.0.1", Source: "snmp"},
		{ID: "b", Address: "10.0.0.2", Source: "manual"},
		{ID: "c", Source: "manual"},
	} {
		if _, why := devmon.Default(d); strings.TrimSpace(why) == "" {
			t.Fatalf("Default(%s) gave no reason", d.ID)
		}
		for _, enabled := range []bool{true, false} {
			if _, why := devmon.Explicit(d, enabled); strings.TrimSpace(why) == "" {
				t.Fatalf("Explicit(%s, %v) gave no reason", d.ID, enabled)
			}
		}
	}
}

func TestExplicitOverridesProvenance(t *testing.T) {
	scan := models.Device{ID: "scan-1", Address: "10.0.0.1", Source: "snmp"}
	if on, why := devmon.Explicit(scan, true); !on || why != devmon.ReasonEnabled {
		t.Fatalf("an operator may enable a discovered device: %v %q", on, why)
	}
	declared := models.Device{ID: "m1", Address: "10.0.0.2", Source: "manual"}
	if on, why := devmon.Explicit(declared, false); on || why != devmon.ReasonDisabled {
		t.Fatalf("an operator may turn a declared device off: %v %q", on, why)
	}
	if !strings.Contains(devmon.ReasonDisabled, "stay exactly where they are") {
		t.Fatalf("turning monitoring off must say the device is not being deleted: %q", devmon.ReasonDisabled)
	}

	// An explicit "on" cannot conjure a collectable device out of one with no
	// address: it would consume an entitlement and collect nothing.
	noAddr := models.Device{ID: "m2", Source: "manual"}
	if on, why := devmon.Explicit(noAddr, true); on || why != devmon.ReasonNoAddress {
		t.Fatalf("enabling an addressless device must not count: %v %q", on, why)
	}
}

func TestMethodsAreDisplayNotACount(t *testing.T) {
	cases := []struct {
		name   string
		device models.Device
		want   []string
	}{
		{
			name:   "no preferred protocol means SNMP — the poller's own default",
			device: models.Device{Address: "10.0.0.1"},
			want:   []string{devmon.MethodSNMP},
		},
		{
			name:   "the gnmi label adds a second method to the same device",
			device: models.Device{Address: "10.0.0.1", Labels: map[string]string{"gnmi": "true"}},
			want:   []string{devmon.MethodGNMI, devmon.MethodSNMP},
		},
		{
			name:   "a device with no address has no methods — nothing can collect from it",
			device: models.Device{},
			want:   nil,
		},
		{
			name:   "a declared preferred protocol replaces the SNMP default",
			device: models.Device{Address: "10.0.0.1", PreferredProtocol: "netconf"},
			want:   []string{"netconf"},
		},
		{
			name:   "a label of anything but true is not a subscription",
			device: models.Device{Address: "10.0.0.1", Labels: map[string]string{"gnmi": "planned"}},
			want:   []string{devmon.MethodSNMP},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := devmon.Methods(tc.device)
			if len(got) != len(tc.want) {
				t.Fatalf("Methods = %v, want %v", got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("Methods = %v, want %v (order must be stable)", got, tc.want)
				}
			}
		})
	}
}

func TestHasAddressMirrorsTheCollectorSkip(t *testing.T) {
	if devmon.HasAddress(models.Device{}) {
		t.Fatal("an empty address is not reachable")
	}
	if devmon.HasAddress(models.Device{Address: "\t "}) {
		t.Fatal("whitespace is not an address")
	}
	if !devmon.HasAddress(models.Device{Address: "leaf1.example.test"}) {
		t.Fatal("a hostname is an address")
	}
}
