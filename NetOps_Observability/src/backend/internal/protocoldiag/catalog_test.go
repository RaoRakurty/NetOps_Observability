// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package protocoldiag

import "testing"

func TestCatalog_FifteenIssues(t *testing.T) {
	cat := DefaultCatalog()
	if cat.Len() != 15 {
		t.Fatalf("catalog has %d issues, want 15", cat.Len())
	}
	perProto := map[Protocol]int{}
	seen := map[string]bool{}
	for _, is := range cat.Issues() {
		if is.ID == "" || seen[is.ID] {
			t.Errorf("issue id empty or duplicate: %q", is.ID)
		}
		seen[is.ID] = true
		if is.Title == "" || is.Description == "" {
			t.Errorf("issue %s missing title/description", is.ID)
		}
		b := is.Bundle()
		// Every bundle = protocol probes + the 4-command common supporting set.
		if len(b) <= len(commonSupportingSet) {
			t.Errorf("issue %s bundle too small: %d commands", is.ID, len(b))
		}
		perProto[is.Protocol]++
	}
	for _, p := range []Protocol{ProtocolBGP, ProtocolOSPF, ProtocolISIS} {
		if perProto[p] != 5 {
			t.Errorf("protocol %s has %d issues, want 5", p, perProto[p])
		}
	}
}

func TestBundleRendersPerVendor(t *testing.T) {
	cat := DefaultCatalog()
	issue, ok := cat.Issue("ospf-neighbor-stuck")
	if !ok {
		t.Fatal("missing ospf-neighbor-stuck")
	}
	var nbr CommandSpec
	for _, s := range issue.Bundle() {
		if s.ID == "ospf-neighbor" {
			nbr = s
		}
	}
	tgt := Target{}
	cases := []struct {
		vendor Vendor
		want   string
	}{
		{VendorCiscoIOSXE, "show ip ospf neighbor"},
		{VendorJuniper, "show ospf neighbor"},
		{VendorNokia, "show router ospf neighbor"},
		{VendorUnknown, "show ip ospf neighbor"}, // unknown falls back to primary
	}
	for _, tc := range cases {
		if got := nbr.Render(tc.vendor, tgt); got != tc.want {
			t.Errorf("ospf-neighbor render(%s) = %q, want %q", tc.vendor, got, tc.want)
		}
	}
}

func TestVRFScopedRendering(t *testing.T) {
	cat := DefaultCatalog()
	issue, _ := cat.Issue("bgp-session-down")
	var route CommandSpec
	for _, s := range issue.Bundle() {
		if s.ID == "ip-route" {
			route = s
		}
	}
	tgt := Target{Prefix: "10.9.9.9", VRF: "CORP"}
	cases := []struct {
		vendor Vendor
		want   string
	}{
		{VendorCiscoIOSXE, "show ip route vrf CORP 10.9.9.9"},
		{VendorJuniper, "show route instance CORP 10.9.9.9"},
		{VendorNokia, "show router CORP route-table 10.9.9.9"},
	}
	for _, tc := range cases {
		if got := route.Render(tc.vendor, tgt); got != tc.want {
			t.Errorf("ip-route render(%s) = %q, want %q", tc.vendor, got, tc.want)
		}
	}
	// No VRF collapses cleanly to the global form.
	if got := route.Render(VendorCiscoIOSXE, Target{Prefix: "10.9.9.9"}); got != "show ip route 10.9.9.9" {
		t.Errorf("global route render = %q", got)
	}
}

func TestVendorFromPlatform(t *testing.T) {
	cases := map[string]Vendor{
		"Cisco IOS-XE 17.9": VendorCiscoIOSXE,
		"cisco-iosxr":       VendorCiscoIOSXE,
		"Arista EOS":        VendorCiscoIOSXE,
		"Juniper Junos 22":  VendorJuniper,
		"Nokia SR OS 23":    VendorNokia,
		// SR Linux is NOT SR OS. It has no authored CLI dialect (nokia.json's
		// srlinux platform carries an empty `cli` block), so it resolves to
		// VendorUnknown and the renderer falls back to the primary dialect —
		// recording that fallback in RenderedVendor rather than claiming the
		// device speaks SR OS. Issuing `show router …` at an SR Linux prompt is
		// a parse error, which is exactly what the live run of 2026-09-03 saw
		// (7 of 7 commands rejected). A real srlinux dialect is a feature, not a
		// mapping entry.
		"srlinux":           VendorUnknown,
		"Nokia SR Linux":    VendorUnknown,
		"":                  VendorUnknown,
		"MikroTik RouterOS": VendorUnknown,
	}
	for in, want := range cases {
		if got := VendorFromPlatform(in); got != want {
			t.Errorf("VendorFromPlatform(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestSignaturesCoverEveryIssue asserts every issue has at least one signature,
// every signature points at a real issue, and every signature is complete
// (verdict/cause/remediation + a valid confidence). This is the self-consistency
// guard that a new issue cannot ship without an analyze story.
func TestSignaturesCoverEveryIssue(t *testing.T) {
	cat := DefaultCatalog()
	an := DefaultAnalyzer()

	issuesWithSig := map[string]bool{}
	seen := map[string]bool{}
	for _, s := range an.Signatures() {
		if s.ID == "" || seen[s.ID] {
			t.Errorf("signature id empty or duplicate: %q", s.ID)
		}
		seen[s.ID] = true
		if _, ok := cat.Issue(s.IssueID); !ok {
			t.Errorf("signature %s references unknown issue %q", s.ID, s.IssueID)
		}
		if s.Verdict == "" || s.Cause == "" || s.Remediation == "" {
			t.Errorf("signature %s incomplete (verdict/cause/remediation)", s.ID)
		}
		switch s.Confidence {
		case ConfidenceHigh, ConfidenceMedium, ConfidenceLow:
		default:
			t.Errorf("signature %s has invalid confidence %q", s.ID, s.Confidence)
		}
		issuesWithSig[s.IssueID] = true
	}
	for _, is := range cat.Issues() {
		if !issuesWithSig[is.ID] {
			t.Errorf("issue %s has no signature", is.ID)
		}
	}
}

// TestCatalog_SymptomsAndVendorCoverage pins the two fields the Troubleshooting
// UI renders beside every issue: the operator-facing symptom list (how an
// operator picks the right issue) and the honest dialect coverage (which vendors
// the WHOLE bundle is authored for). Every one of the 15 issues must carry both
// — a symptom-less issue is unpickable and a coverage-less issue is unclaimable.
func TestCatalog_SymptomsAndVendorCoverage(t *testing.T) {
	cat := DefaultCatalog()
	for _, is := range cat.Issues() {
		if len(is.Symptoms) < 2 {
			t.Errorf("issue %s has %d symptoms, want at least 2", is.ID, len(is.Symptoms))
		}
		seen := map[string]bool{}
		for _, sym := range is.Symptoms {
			if len(sym) < 10 {
				t.Errorf("issue %s symptom %q is too terse to be useful", is.ID, sym)
			}
			if seen[sym] {
				t.Errorf("issue %s repeats symptom %q", is.ID, sym)
			}
			seen[sym] = true
		}
		vendors := is.Vendors()
		if len(vendors) == 0 {
			t.Errorf("issue %s claims no vendor coverage", is.ID)
			continue
		}
		if vendors[0] != VendorCiscoIOSXE {
			t.Errorf("issue %s coverage = %v; the primary dialect must always be first and present", is.ID, vendors)
		}
		// Coverage must be REAL: every claimed vendor must have an authored
		// template for every command in the bundle, never a silent fallback.
		for _, v := range vendors {
			for _, s := range is.Bundle() {
				if _, ok := s.templates[v]; !ok {
					t.Errorf("issue %s claims %s coverage but spec %s has no %s template", is.ID, v, s.ID, v)
				}
			}
		}
	}
}

// TestIssueVendors_ExcludesFallbackOnlyDialects proves coverage is an
// INTERSECTION: one unbound command in a bundle drops that vendor from the
// claim, even though the command still renders (via the primary fallback).
func TestIssueVendors_ExcludesFallbackOnlyDialects(t *testing.T) {
	partial := Issue{
		ID: "partial", Protocol: ProtocolOSPF, Title: "partial", Description: "partial",
		probes: []CommandSpec{
			spec("bound", "fully bound", "show ip ospf neighbor", "show ospf neighbor", "show router ospf neighbor"),
			spec("cisco-only", "primary dialect only", "show ip ospf database", "", ""),
		},
	}
	got := partial.Vendors()
	if len(got) != 1 || got[0] != VendorCiscoIOSXE {
		t.Fatalf("Vendors() = %v, want only [%s]", got, VendorCiscoIOSXE)
	}
	// The unbound command still RENDERS — coverage is a claim about authorship,
	// not about whether a command can be produced.
	if cmd := partial.probes[1].Render(VendorJuniper, Target{}); cmd != "show ip ospf database" {
		t.Errorf("unbound Juniper render = %q, want the primary fallback", cmd)
	}
}
