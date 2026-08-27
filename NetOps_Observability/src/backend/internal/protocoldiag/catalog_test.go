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
		"srlinux":           VendorNokia,
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
