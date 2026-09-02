package protocoldiag

// statebattery_test.go — the battery's safety and honesty proofs.
//
// The battery is a set of strings this package will put on a wire at a
// production router, so its tests are shaped like the catalog table's: prove
// COMPLETENESS (every authored command is admitted by its own closed table),
// prove SOUNDNESS (nothing else is), and prove HONESTY (a dialect we have no
// command for gets no command, not somebody else's).

import (
	"sort"
	"strings"
	"testing"

	"netops/backend/internal/showparse"
	"netops/backend/internal/vendorprofile"
)

// batteryTargets are the argument shapes every battery proof is run against.
func batteryTargets() []Target {
	return []Target{
		{},
		{Interface: "GigabitEthernet0/0"},
		{Interface: "ge-0/0/0.100", Peer: "2001:db8::1", Prefix: "192.0.2.0/24",
			Address: "000c.29ab.cdef", VRF: "CUST-A"},
		{Prefix: "10.0.0.0/8", VRF: "mgmt"},
		{Address: "10.0.0.2"},
		{VRF: "VPN-1"},
	}
}

// TestStateBattery_EveryCommandIsReadOnly is the safety floor: every command the
// battery can render, for every dialect and every argument shape, must pass the
// read-only guard AND be admitted by the battery's own closed table.
func TestStateBattery_EveryCommandIsReadOnly(t *testing.T) {
	b := DefaultStateBattery()
	n := 0
	for _, area := range Areas() {
		for _, d := range showparse.Dialects() {
			for _, tgt := range batteryTargets() {
				for _, rc := range b.Battery(area, d, tgt) {
					n++
					if err := ValidateReadOnly(rc.Command); err != nil {
						t.Errorf("%s/%s renders a non-read-only command %q: %v", rc.SpecID, d, rc.Command, err)
					}
					if !b.Allows(d, rc.Command) {
						t.Errorf("%s/%s renders %q, which the battery's own table refuses", rc.SpecID, d, rc.Command)
					}
					if rc.Area != area || rc.Dialect != d {
						t.Errorf("rendered command carries the wrong provenance: %+v", rc)
					}
					if rc.Purpose == "" {
						t.Errorf("%s/%s has no purpose", rc.SpecID, d)
					}
				}
			}
		}
	}
	if n == 0 {
		t.Fatal("the battery rendered nothing at all")
	}
	t.Logf("validated %d rendered battery commands", n)
}

// TestStateBattery_RefusesEverythingElse is the soundness half. `show
// running-config` is the case that matters: it is a perfectly read-only command
// and it must never be admitted, on any dialect.
func TestStateBattery_RefusesEverythingElse(t *testing.T) {
	b := DefaultStateBattery()
	refused := []string{
		"show running-config",
		"show running-config | section router bgp",
		"show startup-config",
		"show configuration",
		"display current-configuration",
		"show tech-support",
		"show users",
		"show interfaces Gi0/0 extra-token",
		"show ip bgp neighbors 10.0.0.2",
		"show archive config differences",
		"",
		"   ",
	}
	for _, d := range showparse.Dialects() {
		for _, c := range refused {
			if b.Allows(d, c) {
				t.Errorf("battery table admitted %q for dialect %s", c, d)
			}
		}
	}
	// Sanity: a real battery command IS admitted, so the refusals above mean
	// something.
	if !b.Allows(showparse.DialectCiscoIOSXE, "show ip bgp summary") {
		t.Error("a real battery command was refused")
	}
}

// TestStateBattery_NoConfigTemplates proves at the SOURCE level that no template
// reads a configuration. It is belt-and-braces against the closed table: a
// future author cannot add one without this failing.
func TestStateBattery_NoConfigTemplates(t *testing.T) {
	banned := []string{"running-config", "startup-config", "current-configuration",
		"show configuration", "tech-support", "archive"}
	for _, s := range DefaultStateBattery().Specs() {
		for _, d := range s.Dialects() {
			cmd, ok := s.Render(d, Target{Interface: "Gi0/0", Prefix: "10.0.0.0/8",
				Address: "10.0.0.2", VRF: "A", Peer: "10.0.0.2"})
			if !ok {
				continue
			}
			for _, bad := range banned {
				if strings.Contains(strings.ToLower(cmd), bad) {
					t.Errorf("battery spec %s/%s renders a configuration read: %q", s.ID, d, cmd)
				}
			}
		}
	}
}

// TestStateBattery_NeverFallsBack is the honesty proof: an unbound dialect
// contributes NOTHING, and an unknown dialect gets an empty battery — the
// catalog's fall-back-to-Cisco behaviour is deliberately absent here.
func TestStateBattery_NeverFallsBack(t *testing.T) {
	b := DefaultStateBattery()
	tgt := Target{Interface: "GigabitEthernet0/0", Address: "10.0.0.2", Prefix: "10.0.0.0/8"}

	if got := b.Battery(AreaInterfaces, "nokia/srlinux", tgt); len(got) != 0 {
		t.Errorf("an unknown dialect got %d commands, want 0", len(got))
	}
	if got := b.Battery(AreaInterfaces, "", tgt); len(got) != 0 {
		t.Errorf("an empty dialect got %d commands, want 0", len(got))
	}
	// The authored gaps: optics on IOS-XR / EOS / SR OS, MAC on IOS-XR / SR OS.
	gaps := []struct {
		spec    string
		dialect showparse.Dialect
	}{
		{showparse.CmdInterfaceOptics, showparse.DialectCiscoIOSXR},
		{showparse.CmdInterfaceOptics, showparse.DialectAristaEOS},
		{showparse.CmdInterfaceOptics, showparse.DialectNokiaSROS},
		{showparse.CmdMAC, showparse.DialectCiscoIOSXR},
		{showparse.CmdMAC, showparse.DialectNokiaSROS},
		{showparse.CmdMAC, showparse.DialectJunos},
		{showparse.CmdPlatformMemory, showparse.DialectCiscoNXOS},
		{showparse.CmdPlatformMemory, showparse.DialectJunos},
		{showparse.CmdPlatformMemory, showparse.DialectAristaEOS},
	}
	for _, g := range gaps {
		for _, s := range b.Specs() {
			if s.ID != g.spec {
				continue
			}
			if _, ok := s.Render(g.dialect, tgt); ok {
				t.Errorf("spec %s renders for %s, but that gap is deliberate", g.spec, g.dialect)
			}
		}
	}
}

// TestStateBattery_RequiredArguments proves a command whose required argument is
// missing is OMITTED, not rendered into a dangling keyword. `show mac
// address-table address` with no address is not a valid command and must never
// leave this package.
func TestStateBattery_RequiredArguments(t *testing.T) {
	b := DefaultStateBattery()
	withoutAddr := b.Battery(AreaL2, showparse.DialectCiscoIOSXE, Target{})
	for _, rc := range withoutAddr {
		if rc.SpecID == showparse.CmdMAC {
			t.Fatalf("the MAC lookup rendered with no address: %q", rc.Command)
		}
		if strings.HasSuffix(rc.Command, "address") || strings.HasSuffix(rc.Command, "address-table") {
			t.Fatalf("a dangling keyword was rendered: %q", rc.Command)
		}
	}
	withAddr := b.Battery(AreaL2, showparse.DialectCiscoIOSXE, Target{Address: "000c.29ab.cdef"})
	found := false
	for _, rc := range withAddr {
		if rc.SpecID == showparse.CmdMAC {
			found = true
			if rc.Command != "show mac address-table address 000c.29ab.cdef" {
				t.Errorf("MAC command = %q", rc.Command)
			}
		}
	}
	if !found {
		t.Error("the MAC lookup did not render even with an address")
	}
	// Optics needs an interface on VRP (the template would otherwise dangle).
	if got := b.Battery(AreaInterfaces, showparse.DialectHuaweiVRP, Target{}); len(got) != 2 {
		t.Errorf("VRP interfaces with no {if} = %d commands, want 2 (optics requires one)", len(got))
	}
}

// TestStateBattery_VRFScope pins each dialect's VRF qualifier against what the
// battery's own table will accept, so the two cannot drift.
func TestStateBattery_VRFScope(t *testing.T) {
	b := DefaultStateBattery()
	cases := []struct {
		dialect showparse.Dialect
		want    string
	}{
		{showparse.DialectCiscoIOSXE, "show ip route vrf CUST-A 192.0.2.0/24"},
		{showparse.DialectCiscoIOSXR, "show route vrf CUST-A 192.0.2.0/24"},
		{showparse.DialectCiscoNXOS, "show ip route 192.0.2.0/24 vrf CUST-A"},
		{showparse.DialectAristaEOS, "show ip route vrf CUST-A 192.0.2.0/24"},
		{showparse.DialectJunos, "show route instance CUST-A 192.0.2.0/24"},
		{showparse.DialectNokiaSROS, "show router CUST-A route-table 192.0.2.0/24"},
		{showparse.DialectHuaweiVRP, "display ip routing-table vpn-instance CUST-A 192.0.2.0/24"},
	}
	tgt := Target{Prefix: "192.0.2.0/24", VRF: "CUST-A"}
	for _, tc := range cases {
		got := b.Battery(AreaRoutes, tc.dialect, tgt)
		if len(got) != 1 {
			t.Fatalf("%s: got %d route commands, want 1", tc.dialect, len(got))
		}
		if got[0].Command != tc.want {
			t.Errorf("%s: command = %q, want %q", tc.dialect, got[0].Command, tc.want)
		}
		if !b.Allows(tc.dialect, got[0].Command) {
			t.Errorf("%s: the table refuses its own VRF rendering %q", tc.dialect, got[0].Command)
		}
	}
	// Unscoped collapses cleanly.
	got := b.Battery(AreaRoutes, showparse.DialectCiscoIOSXE, Target{})
	if len(got) != 1 || got[0].Command != "show ip route" {
		t.Errorf("unscoped route command = %+v, want `show ip route`", got)
	}
}

// TestStateBattery_DialectIsolation proves the battery is per-dialect: a Junos
// form is not admitted for a Cisco device and the reverse.
func TestStateBattery_DialectIsolation(t *testing.T) {
	b := DefaultStateBattery()
	if b.Allows(showparse.DialectCiscoIOSXE, "show router bgp summary") {
		t.Error("the Nokia form was admitted for a Cisco IOS-XE device")
	}
	if b.Allows(showparse.DialectNokiaSROS, "show ip bgp summary") {
		t.Error("the Cisco form was admitted for a Nokia device")
	}
	if b.Allows(showparse.DialectJunos, "display interface Gi0/0") {
		t.Error("the Huawei form was admitted for a Junos device")
	}
	if !b.Allows(showparse.DialectHuaweiVRP, "display interface GigabitEthernet0/0/1") {
		t.Error("the Huawei form was refused for a Huawei device")
	}
}

// TestStateBattery_CatalogTableUnaffected proves the two closed tables are
// SEPARATE: adding {addr} and the vpn-instance qualifier to the battery's
// grammar must not widen the 15-issue catalog's table by a single token.
func TestStateBattery_CatalogTableUnaffected(t *testing.T) {
	tbl := newCommandTable(DefaultCatalog())
	for _, c := range []string{
		"show mac address-table address 000c.29ab.cdef",
		"show ip route vpn-instance CUST-A 192.0.2.0/24",
		"display interface GigabitEthernet0/0/1",
		"show logging last 200",
	} {
		for _, v := range []Vendor{VendorCiscoIOSXE, VendorJuniper, VendorNokia} {
			if tbl.Allows(v, c) {
				t.Errorf("the CATALOG table admitted a battery-only command %q for %s", c, v)
			}
		}
	}
	// And the reverse: a catalog-only command is not in the battery table.
	b := DefaultStateBattery()
	for _, d := range showparse.Dialects() {
		if b.Allows(d, "show ip bgp neighbors 10.0.0.2 advertised-routes") {
			t.Errorf("the BATTERY table admitted a catalog-only command for %s", d)
		}
	}
}

// TestStateBattery_ParserCoverage reports which (spec, dialect) pairs have a
// showparse parser and which do not. A battery command with no parser is not a
// failure — its output is honest raw evidence — but the ratio is a fact the
// design's acceptance is counted from, so it is asserted and logged.
func TestStateBattery_ParserCoverage(t *testing.T) {
	b := DefaultStateBattery()
	lib := showparse.NewLibrary()
	var have, missing []string
	for _, s := range b.Specs() {
		for _, d := range s.Dialects() {
			pair := s.ID + " @ " + string(d)
			if lib.Supports(s.ID, d) {
				have = append(have, pair)
			} else {
				missing = append(missing, pair)
			}
		}
	}
	sort.Strings(have)
	sort.Strings(missing)
	if len(have) < 20 {
		t.Errorf("only %d battery commands have a parser, design floor is 20", len(have))
	}
	t.Logf("battery commands with a parser: %d; without: %d", len(have), len(missing))
	for _, m := range missing {
		t.Logf("  no parser (raw evidence only): %s", m)
	}
}

// TestStateBattery_SpecIDsAreShowparseCommands proves the battery and the parser
// library share ONE command vocabulary — a spec id that is not a showparse
// command id could never be parsed and would be a silent dead end.
func TestStateBattery_SpecIDsAreShowparseCommands(t *testing.T) {
	known := map[string]bool{}
	for _, c := range showparse.Commands() {
		known[c] = true
	}
	for _, id := range DefaultStateBattery().SpecIDs() {
		if !known[id] {
			t.Errorf("battery spec id %q is not a showparse command id", id)
		}
	}
}

// TestStateBattery_DialectsAreVendorProfileIDs is the §13 "one vendor
// vocabulary" proof at the battery's own boundary.
func TestStateBattery_DialectsAreVendorProfileIDs(t *testing.T) {
	reg := vendorprofile.Default()
	cov := DefaultStateBattery().Coverage()
	if len(cov) == 0 {
		t.Fatal("the battery covers no dialect at all")
	}
	for d, n := range cov {
		if _, ok := reg.Lookup(string(d)); !ok {
			t.Errorf("battery dialect %q is not a vendorprofile profile id", d)
		}
		if n == 0 {
			t.Errorf("dialect %q is listed with zero specs", d)
		}
		t.Logf("  %-16s %d specs", d, n)
	}
	for _, d := range showparse.Dialects() {
		if cov[d] == 0 {
			t.Errorf("dialect %q has no battery command at all", d)
		}
	}
}

// TestStateBattery_AreasAreComplete proves every declared area actually carries
// commands, so an area is never an empty promise in the API.
func TestStateBattery_AreasAreComplete(t *testing.T) {
	b := DefaultStateBattery()
	tgt := Target{Interface: "GigabitEthernet0/0", Prefix: "10.0.0.0/8", Address: "10.0.0.2"}
	for _, a := range Areas() {
		if !ValidArea(a) {
			t.Errorf("Areas() lists %q but ValidArea rejects it", a)
		}
		if len(b.SpecsFor(a)) == 0 {
			t.Errorf("area %q has no specs", a)
		}
		if len(b.Battery(a, showparse.DialectCiscoIOSXE, tgt)) == 0 {
			t.Errorf("area %q renders nothing for the primary dialect", a)
		}
	}
	if ValidArea("not-an-area") {
		t.Error("ValidArea accepted an unknown area")
	}
}

// TestNewStateBattery_RejectsUnsafeAuthoring proves the build-time validation is
// real: a battery whose template is not read-only, or whose area is unknown,
// never becomes an object.
func TestNewStateBattery_RejectsUnsafeAuthoring(t *testing.T) {
	bad := []struct {
		name string
		spec BatterySpec
	}{
		{"not read-only", bs("x", AreaLogs, "p", map[showparse.Dialect]string{
			showparse.DialectCiscoIOSXE: "configure terminal"})},
		{"unknown area", bs("x", Area("nope"), "p", map[showparse.Dialect]string{
			showparse.DialectCiscoIOSXE: "show version"})},
		{"empty template", bs("x", AreaLogs, "p", map[showparse.Dialect]string{
			showparse.DialectCiscoIOSXE: "   "})},
		{"metacharacter", bs("x", AreaLogs, "p", map[showparse.Dialect]string{
			showparse.DialectCiscoIOSXE: "show logging > flash:out.txt"})},
	}
	for _, tc := range bad {
		if _, err := NewStateBattery([]BatterySpec{tc.spec}); err == nil {
			t.Errorf("%s: NewStateBattery accepted an unsafe spec", tc.name)
		}
	}
	if _, err := NewStateBattery(defaultBatterySpecs()); err != nil {
		t.Fatalf("the shipped battery must build: %v", err)
	}
}

// TestBattery_InputCapMatchesOutputCap pins the two packages' bounds together:
// the parser refuses exactly the blob the collector refuses, so there is no
// window where a capture is accepted by one and rejected by the other.
func TestBattery_InputCapMatchesOutputCap(t *testing.T) {
	if showparse.MaxInputBytes != MaxOutputBytes {
		t.Fatalf("showparse.MaxInputBytes (%d) != protocoldiag.MaxOutputBytes (%d)",
			showparse.MaxInputBytes, MaxOutputBytes)
	}
}
