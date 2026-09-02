package protocoldiag

import "testing"

// TestCommandTable_AcceptsEveryRenderedCatalogCommand is the completeness half
// of the closed-table contract: if the table refused a command the catalog can
// actually render, the live runner would break a shipped bundle. Every issue ×
// every vendor × the empty AND populated target forms must be accepted.
func TestCommandTable_AcceptsEveryRenderedCatalogCommand(t *testing.T) {
	cat := DefaultCatalog()
	tbl := newCommandTable(cat)
	targets := []Target{
		{},
		stdTarget,
		{Interface: "GigabitEthernet0/0.100", Peer: "2001:db8::1", Prefix: "192.0.2.0/24", VRF: "CUST-A"},
		{VRF: "mgmt"},
		{Prefix: "10.0.0.0/8"},
	}
	vendors := []Vendor{VendorCiscoIOSXE, VendorJuniper, VendorNokia, VendorUnknown}
	for _, is := range cat.Issues() {
		for _, s := range is.Bundle() {
			for _, v := range vendors {
				for _, tgt := range targets {
					cmd := s.Render(v, tgt)
					if !tbl.Allows(v, cmd) {
						t.Errorf("table refused a catalog command: issue=%s spec=%s vendor=%s tgt=%+v cmd=%q",
							is.ID, s.ID, v, tgt, cmd)
					}
				}
			}
		}
	}
}

// TestCommandTable_RefusesEverythingElse is the soundness half: read-only
// commands that the catalog never authored must NOT be admitted.
func TestCommandTable_RefusesEverythingElse(t *testing.T) {
	tbl := newCommandTable(DefaultCatalog())
	refused := []string{
		"show running-config",
		"show running-config | section router bgp",
		"show startup-config",
		"show version",
		"show tech-support",
		"show users",
		"show ip ospf neighbor extra",
		"show ip ospfx", // a near-miss of the real `show ip ospf` summary spec
		"",
		"   ",
	}
	// `show ip ospf` really IS a catalog command (the ospf-summary spec) — the
	// near-miss above only counts as a refusal because this one is admitted.
	if !tbl.Allows(VendorCiscoIOSXE, "show ip ospf") {
		t.Error("show ip ospf should be in the table (ospf-summary)")
	}
	for _, c := range refused {
		if tbl.Allows(VendorCiscoIOSXE, c) {
			t.Errorf("table admitted %q, want refusal", c)
		}
	}
}

// TestCommandTable_DialectIsolation proves the table is per-dialect: a Juniper
// form is not admitted for a Cisco device and vice versa, so a mis-derived
// vendor cannot smuggle a command onto the wrong platform.
func TestCommandTable_DialectIsolation(t *testing.T) {
	tbl := newCommandTable(DefaultCatalog())
	if tbl.Allows(VendorCiscoIOSXE, "show router bgp summary") {
		t.Error("Nokia form admitted for a Cisco device")
	}
	if tbl.Allows(VendorNokia, "show ip bgp summary") {
		t.Error("Cisco form admitted for a Nokia device")
	}
	if !tbl.Allows(VendorNokia, "show router bgp summary") {
		t.Error("Nokia form refused for a Nokia device")
	}
	// An unknown vendor renders the primary dialect, so it must accept it.
	if !tbl.Allows(VendorUnknown, "show ip bgp summary") {
		t.Error("unknown vendor did not fall back to the primary dialect")
	}
}

// TestCommandTable_VRFScope pins the {vrf-scope} placeholder's three shapes
// against what vrfScopeToken actually emits, so the two cannot drift.
func TestCommandTable_VRFScope(t *testing.T) {
	tbl := newCommandTable(DefaultCatalog())
	cases := []struct {
		vendor Vendor
		cmd    string
		want   bool
	}{
		{VendorCiscoIOSXE, "show ip route", true},                  // both placeholders empty
		{VendorCiscoIOSXE, "show ip route vrf CUST-A", true},       // qualifier + name
		{VendorCiscoIOSXE, "show ip route 192.0.2.0/24", true},     // prefix only
		{VendorCiscoIOSXE, "show ip route vrf A 10.0.0.0/8", true}, // both
		{VendorJuniper, "show route instance CUST-A", true},
		{VendorNokia, "show router CUST-A route-table", true},
		{VendorCiscoIOSXE, "show ip route vrf A B C", false}, // one token too many
	}
	for _, tc := range cases {
		if got := tbl.Allows(tc.vendor, tc.cmd); got != tc.want {
			t.Errorf("Allows(%s, %q) = %v, want %v", tc.vendor, tc.cmd, got, tc.want)
		}
	}
}

// TestCommandTable_ArgumentShape proves a substituted argument must look like an
// interface/address/prefix/instance name. A junk argument is refused even in an
// otherwise valid template — defence in depth behind ValidateReadOnly.
func TestCommandTable_ArgumentShape(t *testing.T) {
	tbl := newCommandTable(DefaultCatalog())
	for _, bad := range []string{
		"show ip bgp neighbors 10.0.0.2 x", // non-breaking space inside the token
		"show ip bgp neighbors ab*cd",
		"show ip bgp neighbors \"quoted\"",
		"show ip bgp neighbors " + longToken(maxArgToken+1),
	} {
		if tbl.Allows(VendorCiscoIOSXE, bad) {
			t.Errorf("table admitted a malformed argument: %q", bad)
		}
	}
	if !tbl.Allows(VendorCiscoIOSXE, "show ip bgp neighbors 10.0.0.2") {
		t.Error("a well-formed peer argument was refused")
	}
}

func longToken(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = 'a'
	}
	return string(b)
}
