// SPDX-License-Identifier: LicenseRef-Correlix-Enterprise
// Copyright 2026 Correlix
//
// COMMERCIAL ADD-ON MODULE. This package implements the `security_dialects`
// entitlement (Enterprise tier) and is NOT Apache-2.0 core. See the LICENSE
// notice file in this directory, ../../../../LICENSING.md, and
// LICENSES/Correlix-Enterprise.txt.

package dialects

import (
	"context"
	"strings"
	"testing"

	"netops/backend/internal/hardening"
)

// TestEveryBoundRuleExistsInTheCatalogue is the guard the seam's "unknown ids
// are ignored" rule is safe behind: hardening.DefaultCatalog silently drops a
// binding for a rule it does not carry (so a pack authored against a newer
// catalogue cannot break an older engine), which means a TYPO here would
// silently stop assessing a control. Catching it is this package's job, because
// this package is where the ids are written.
func TestEveryBoundRuleExistsInTheCatalogue(t *testing.T) {
	known := hardening.DialectRuleIDs()
	if len(known) == 0 {
		t.Fatal("the catalogue reported no rules — the guard is not seeing it")
	}
	for _, p := range Packs() {
		for id := range p.Bindings {
			if !known[id] {
				t.Errorf("%s binds %q, which is not a rule in the shipped catalogue — "+
					"the binding would be silently dropped and the control never assessed", p.Vendor, id)
			}
		}
	}
}

// TestEveryBindingIsComplete: §5e — a hardening finding without a fix is
// invalid, and a binding with no detection cannot assess anything.
func TestEveryBindingIsComplete(t *testing.T) {
	for _, p := range Packs() {
		if p.Vendor == hardening.VendorUnknown {
			t.Error("a pack must name the dialect it realizes")
		}
		if len(p.Bindings) == 0 {
			t.Errorf("%s contributes no bindings", p.Vendor)
		}
		for id, b := range p.Bindings {
			if b.Detect == nil {
				t.Errorf("%s/%s has no detection", p.Vendor, id)
			}
			if strings.TrimSpace(b.Remediation) == "" {
				t.Errorf("%s/%s carries no remediation — a finding without a fix is invalid (§5e)", p.Vendor, id)
			}
		}
	}
}

// TestPackedDialectsReachTheCatalogue pins the SHAPE of the move: exactly these
// dialects, with exactly these binding counts, arrive through the packs and none
// of them is bound by the Apache-2.0 core. If a binding is added or removed the
// number changes here deliberately — silence would mean a dialect quietly
// stopped being assessed.
func TestPackedDialectsReachTheCatalogue(t *testing.T) {
	want := map[hardening.Vendor]int{
		hardening.VendorJuniper: 5,
		hardening.VendorNokia:   1,
		hardening.VendorArista:  14,
		hardening.VendorSRLinux: 14,
	}
	core := hardening.DefaultCatalog()
	merged := hardening.DefaultCatalog(Packs()...)

	for vendor, n := range want {
		coreBound := 0
		for _, r := range core.Rules() {
			if _, ok := r.Binding(vendor); ok {
				coreBound++
			}
		}
		if coreBound != 0 {
			t.Errorf("%s is bound %d times by the Apache-2.0 core — a commercial dialect must arrive through a pack",
				vendor, coreBound)
		}
		got := 0
		for _, r := range merged.Rules() {
			if _, ok := r.Binding(vendor); ok {
				got++
			}
		}
		if got != n {
			t.Errorf("%s: %d bound rules in the merged catalogue, want %d", vendor, got, n)
		}
	}

	// The core dialect is untouched by the merge.
	coreCisco, mergedCisco := 0, 0
	for _, r := range core.Rules() {
		if _, ok := r.Binding(hardening.VendorCiscoIOSXE); ok {
			coreCisco++
		}
	}
	for _, r := range merged.Rules() {
		if _, ok := r.Binding(hardening.VendorCiscoIOSXE); ok {
			mergedCisco++
		}
	}
	if coreCisco == 0 || coreCisco != mergedCisco {
		t.Errorf("the core dialect changed when packs were merged: %d → %d", coreCisco, mergedCisco)
	}
}

// TestJunosTelnetDetection is the Junos leg of what used to be
// internal/hardening's TestMultiVendorBindingsDeclarative: the set-format
// detection both trips on its dialect and does not trip without it. It moved
// here with the binding it tests.
func TestJunosTelnetDetection(t *testing.T) {
	cat := hardening.DefaultCatalog(Packs()...)
	var telnet hardening.Rule
	for _, r := range cat.Rules() {
		if r.ID == "telnet-vty-enabled" {
			telnet = r
		}
	}
	b, ok := telnet.Binding(hardening.VendorJuniper)
	if !ok {
		t.Fatal("the Junos pack did not bind telnet-vty-enabled")
	}
	if !b.Detect(hardening.NewConfig(hardening.VendorJuniper, "set system services telnet\n")).Tripped {
		t.Error("Juniper telnet detection did not trip on `set system services telnet`")
	}
	if b.Detect(hardening.NewConfig(hardening.VendorJuniper, "set system services ssh\n")).Tripped {
		t.Error("Juniper telnet detection falsely tripped without telnet")
	}
}

// TestOnlyBoundRulesAreEvaluatedForPackDialects is the enterprise half of
// internal/hardening's TestOnlyBoundRulesAreEvaluated: a device evaluates ITS
// OWN control set and nothing else. Core runs the same invariant over the core
// dialect; this runs it over every dialect the packs contribute.
func TestOnlyBoundRulesAreEvaluatedForPackDialects(t *testing.T) {
	cat := hardening.DefaultCatalog(Packs()...)
	for _, tc := range []struct {
		name     string
		platform string
		vendor   hardening.Vendor
	}{
		{"srlinux", "nokia SR Linux", hardening.VendorSRLinux},
		{"arista", "Arista EOS 4.36.0.1F", hardening.VendorArista},
		{"juniper", "Juniper Junos 21.4", hardening.VendorJuniper},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := hardening.VendorFromPlatform(tc.platform); got != tc.vendor {
				t.Fatalf("VendorFromPlatform(%q) = %q, want %q", tc.platform, got, tc.vendor)
			}
			want := map[string]bool{}
			for _, r := range cat.Rules() {
				if _, ok := r.Binding(tc.vendor); ok {
					want[r.ID] = true
				}
			}
			for _, p := range cat.Probes() {
				if _, ok := p.Binding(tc.vendor); ok {
					want[p.ID] = true
				}
			}
			if len(want) == 0 {
				t.Fatalf("%s has no bindings at all — the pack is not reaching the catalogue", tc.vendor)
			}
			for _, cfg := range []hardening.ConfigSource{
				hardening.MemConfigSource{"d1": "hostname lab\n"},
				hardening.MemConfigSource{}, // fail-closed leg
			} {
				eng := hardening.NewEngine(cat, cfg,
					hardening.MemSeamResolver{"d1": {{SeamID: "s", SeamType: "mgmt"}}},
					hardening.WithClock(fixedClock()))
				fs, err := eng.Evaluate(context.Background(),
					hardening.Device{ID: "d1", Platform: tc.platform, TenantID: "acme"})
				if err != nil {
					t.Fatal(err)
				}
				got := map[string]bool{}
				for _, f := range fs {
					got[f.RawRuleID] = true
				}
				for id := range want {
					if !got[id] {
						t.Errorf("bound rule %q was NOT evaluated", id)
					}
				}
				for id := range got {
					if !want[id] {
						t.Errorf("rule %q was evaluated with NO binding for %q — a foreign dialect leaked in", id, tc.vendor)
					}
				}
			}
		})
	}
}
