// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package tac

// plan_reach_test.go — THE REACHABILITY INVARIANT (tracker 271).
//
// A dialect plan is a command set for a real device. It is worth exactly nothing
// unless a real device's platform string RESOLVES onto it: Catalog.Plan and
// Gate.Allows both start at DialectForPlatform, so an unreachable dialect can
// never build a plan and can never authorise a command, however many bindings it
// carries and however well those bindings are cited.
//
// That failure mode is silent by construction — every OTHER test in this package
// walks c.Dialects() directly and passes on a plan no device can ever reach. It
// went unnoticed for three plans and 118 authored bindings (cisco-asa 9,
// fortinet-fortios 45, paloalto-panos 64): the three profiles declared no
// `detection.platform_contains` in internal/vendorprofile/profiles/*.json, so
// ProfileForPlatformText never landed on them. `Cisco Adaptive Security Appliance
// ASA 5525-X` resolved to cisco/ios — the bare "cisco" catch-all — and got IOS
// commands; FortiGate and PA text resolved to nothing at all.
//
// This file is the ratchet that keeps it fixed. It asserts, for EVERY authored
// dialect:
//
//  1. a platform string is declared for it here, and that string resolves to it;
//  2. the resolution is the whole round trip an operator's device takes —
//     DialectForPlatform, then PlanFor, then a plan that actually has commands.
//
// The strings in reachPlatformText are the shapes the vendors document (see each
// profile document's `notes` for the citation and the DOC_CLAIMED caveat). A new
// plan with no reachable platform string fails here rather than shipping as a
// coverage claim nobody can exercise.

import (
	"sort"
	"testing"
)

// reachPlatformText is at least one platform label — the shape a real device of
// that dialect reports — per authored dialect. Where a dialect answers to its own
// plan Display string, that is stated explicitly rather than left implicit: the
// point of this table is that SOMEBODY wrote down what a device says.
var reachPlatformText = map[string][]string{
	// Cisco. `cisco-ios` owns the bare vendor token, so the three family
	// platforms and the ASA all have to out-rank it.
	"cisco-ios":   {"Cisco IOS Software, Version 15.2(7)E3", "cisco"},
	"cisco-iosxe": {"Cisco IOS-XE 17.9", "cisco iosxe", "Cisco IOS XE Software, Version 17.09.04a"},
	"cisco-iosxr": {"Cisco IOS-XR 7.5.2"},
	"cisco-nxos":  {"Cisco NX-OS 10.2", "cisco nxos"},
	// ASA: the `show version` first line and the sysDescr both carry the
	// product phrase. It must beat the bare "cisco" catch-all.
	"cisco-asa": {
		"Cisco Adaptive Security Appliance Software Version 9.16(4)",
		"Cisco Adaptive Security Appliance ASA 5525-X",
	},
	"juniper-junos": {"Juniper Junos 22.4R3", "junos"},
	"arista-eos":    {"Arista EOS 4.30.2F", "ceos"},
	"nokia-sros":    {"Nokia SR OS 22.10.R4", "timos"},
	"nokia-srlinux": {"SR Linux 23.3", "srlinux"},
	"huawei-vrp":    {"Huawei VRP V800R021"},
	// FortiOS: the model/version line `get system status` prints. NOT the bare
	// "fortinet" token — FortiSwitch and FortiAnalyzer carry that and do not
	// speak this grammar.
	"fortinet-fortios": {
		"FortiGate-60F v7.2.8,build1639,240228 (GA.M)",
		"Version: FortiGate-VM64-AZURE v8.0.0,buildXXXX,200330 (GA)",
	},
	// PAN-OS: the firewall model shape and the OS token.
	"paloalto-panos": {
		"Palo Alto Networks PA-220 series firewall",
		"Palo Alto Networks PA-3220 series firewall, PAN-OS 10.2.4-h2",
	},
}

// TestEveryAuthoredDialectIsReachableFromAPlatformString is the invariant.
func TestEveryAuthoredDialectIsReachableFromAPlatformString(t *testing.T) {
	c := mustCatalog(t)
	for _, dialect := range c.Dialects() {
		p, ok := c.PlanFor(dialect)
		if !ok {
			t.Fatalf("dialect %s is listed but carries no plan", dialect)
		}
		if len(p.Bindings) == 0 {
			t.Errorf("dialect %s carries no bindings — an empty plan is not a coverage claim", dialect)
			continue
		}
		texts := reachPlatformText[dialect]
		if len(texts) == 0 {
			t.Errorf("dialect %s has %d authored bindings and NO platform string that reaches it: "+
				"add one to reachPlatformText and give its profile a detection.platform_contains "+
				"in internal/vendorprofile/profiles/*.json, or the plan can never be built",
				dialect, len(p.Bindings))
			continue
		}
		for _, text := range texts {
			got, display, resolved := DialectForPlatform(text)
			if !resolved {
				t.Errorf("dialect %s: platform %q resolves to nothing", dialect, text)
				continue
			}
			if got != dialect {
				t.Errorf("dialect %s: platform %q resolves to %s — the plan for %s is unreachable "+
					"through this string", dialect, text, got, dialect)
				continue
			}
			if display == "" {
				t.Errorf("dialect %s: platform %q resolved with an empty display name", dialect, text)
			}
			// The whole round trip: resolution must land on a plan with commands.
			dp, ok := c.PlanFor(got)
			if !ok || len(dp.Bindings) == 0 {
				t.Errorf("dialect %s: platform %q resolved but PlanFor(%s) has no commands", dialect, text, got)
			}
		}
	}
}

// TestReachPlatformTextNamesOnlyAuthoredDialects keeps the table from rotting in
// the other direction: an entry for a dialect that no longer exists is a claim
// about coverage that nothing checks.
func TestReachPlatformTextNamesOnlyAuthoredDialects(t *testing.T) {
	c := mustCatalog(t)
	authored := map[string]bool{}
	for _, d := range c.Dialects() {
		authored[d] = true
	}
	stale := []string{}
	for d := range reachPlatformText {
		if !authored[d] {
			stale = append(stale, d)
		}
	}
	sort.Strings(stale)
	if len(stale) > 0 {
		t.Errorf("reachPlatformText names dialects that carry no plan: %v", stale)
	}
}

// TestTheThreeFirewallDialectsAreNoLongerStolenByAnotherProfile pins the exact
// regression tracker 271 was opened for, by its symptom rather than by the fix:
// before the fix an ASA reported IOS commands, and the two others reported
// nothing. A future rank change that re-breaks any of the three fails here with
// the reason attached.
func TestTheThreeFirewallDialectsAreNoLongerStolenByAnotherProfile(t *testing.T) {
	for _, tc := range []struct{ text, want string }{
		{"Cisco Adaptive Security Appliance ASA 5525-X", "cisco-asa"},
		{"FortiGate-60F v7.2.8,build1639,240228 (GA.M)", "fortinet-fortios"},
		{"Palo Alto Networks PA-220 series firewall", "paloalto-panos"},
	} {
		got, _, ok := DialectForPlatform(tc.text)
		if !ok || got != tc.want {
			t.Errorf("DialectForPlatform(%q) = (%q,%v), want %q — the plan for %s is unreachable again",
				tc.text, got, ok, tc.want, tc.want)
		}
	}
	// …and the Cisco families the ASA rule now out-ranks must be untouched.
	for _, tc := range []struct{ text, want string }{
		{"Cisco IOS Software, Version 15.2(7)E3", "cisco-ios"},
		{"Cisco IOS-XE 17.9", "cisco-iosxe"},
		{"Cisco IOS-XR 7.5.2", "cisco-iosxr"},
		{"Cisco NX-OS 10.2", "cisco-nxos"},
	} {
		got, _, ok := DialectForPlatform(tc.text)
		if !ok || got != tc.want {
			t.Errorf("DialectForPlatform(%q) = (%q,%v), want %q — the ASA rank stole a Cisco family",
				tc.text, got, ok, tc.want)
		}
	}
}

// TestPanoramaIsNotRoutedOntoTheFirewallPlan. Panorama is Palo Alto's management
// platform: different command grammar, no profile of its own. The PAN-OS
// detection string is deliberately narrow enough to miss it, because handing a
// Panorama a firewall command plan is worse than honestly not resolving it.
func TestPanoramaIsNotRoutedOntoTheFirewallPlan(t *testing.T) {
	for _, text := range []string{
		"Palo Alto Networks Panorama",
		"Palo Alto Networks Panorama M-600",
	} {
		if got, _, ok := DialectForPlatform(text); ok {
			t.Errorf("DialectForPlatform(%q) = %q — Panorama was routed onto a plan it does not speak",
				text, got)
		}
	}
}
