package tac

import (
	"strings"
	"testing"

	"netops/backend/internal/protocoldiag"
)

func iosxeDevice() Device {
	return Device{ID: "d1", Hostname: "core1", Platform: "Cisco IOS-XE 17.9", TenantID: "t1"}
}

// TestPlanBaselinePlusDeepDive pins the plan's shape: baseline first, then the
// class's own intents, with optional captures held back.
func TestPlanBaselinePlusDeepDive(t *testing.T) {
	c := mustCatalog(t)
	p, err := c.Plan("ospf-adjacency", iosxeDevice(), PlanOptions{})
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	if !p.HasPlan {
		t.Fatal("IOS-XE must have an authored plan")
	}
	if p.Dialect != "cisco-iosxe" {
		t.Fatalf("dialect = %q", p.Dialect)
	}
	var sawBaseline, sawDeep bool
	for _, s := range p.Steps {
		if s.Section == SectionBaseline {
			sawBaseline = true
		}
		if s.Section == SectionDeepDive {
			sawDeep = true
		}
		if !s.Bound || s.Command == "" {
			t.Fatalf("step %q is in Steps but carries no command", s.Intent)
		}
	}
	if !sawBaseline || !sawDeep {
		t.Fatal("a plan must carry both the baseline and the class deep-dive")
	}
	// The design's worked example: these must be in an IOS-XE ospf-adjacency plan.
	want := []string{"show ip ospf interface", "show ip ospf neighbor detail", "show ip ospf database"}
	got := map[string]bool{}
	for _, s := range p.Steps {
		got[s.Command] = true
	}
	for _, w := range want {
		if !got[w] {
			t.Errorf("plan is missing the documented command %q", w)
		}
	}
	if p.EstimatedBytes <= 0 || p.EstimatedSeconds <= 0 {
		t.Fatal("the preview must carry a size and time ceiling")
	}
	if !strings.Contains(p.RedactionNote, "[REDACTED]") {
		t.Fatal("the preview must state what will be redacted")
	}
}

// TestPlanOptionalIsOffByDefault proves show tech-support is opt-in and is shown
// honestly rather than hidden.
func TestPlanOptionalIsOffByDefault(t *testing.T) {
	c := mustCatalog(t)
	off, _ := c.Plan("ospf-adjacency", iosxeDevice(), PlanOptions{})
	for _, s := range off.Steps {
		if s.Intent == "tech.support" {
			t.Fatal("show tech-support ran without being asked for")
		}
	}
	var listed bool
	for _, s := range off.Unbound {
		if s.Intent == "tech.support" && strings.Contains(s.Note, "OFF by default") {
			listed = true
		}
	}
	if !listed {
		t.Fatal("an optional capture must be SHOWN as available-but-off, not hidden")
	}
	on, _ := c.Plan("ospf-adjacency", iosxeDevice(), PlanOptions{IncludeOptional: true})
	var included bool
	for _, s := range on.Steps {
		if s.Intent == "tech.support" {
			included = true
		}
	}
	if !included {
		t.Fatal("IncludeOptional did not include the optional capture")
	}
}

// TestPlanHonestyUnboundIntents is the honesty gate: an intent the dialect does
// not bind is NAMED, never dropped and never rendered in another dialect.
func TestPlanHonestyUnboundIntents(t *testing.T) {
	c := mustCatalog(t)
	// Junos binds no hardware.fans and no tech.support: the hardware class must
	// say so rather than borrow the Cisco command.
	p, err := c.Plan("hardware-fault", Device{ID: "d2", Hostname: "edge1", Platform: "Juniper Junos 22.4R3", TenantID: "t1"}, PlanOptions{})
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	if !p.HasPlan {
		t.Fatal("Junos must have an authored plan")
	}
	var fans bool
	for _, s := range p.Unbound {
		if s.Intent == "hardware.fans" {
			fans = true
			if !strings.Contains(s.Note, "no binding on") {
				t.Fatalf("unbound note is not honest: %q", s.Note)
			}
		}
	}
	if !fans {
		t.Fatal("hardware.fans is unbound on Junos and must be listed as such")
	}
	for _, s := range p.Steps {
		if strings.Contains(s.Command, "show environment fan") {
			t.Fatal("a Cisco command was rendered at a Junos device")
		}
	}
	if !strings.Contains(p.Note, "unbound") && !strings.Contains(p.Note, "bound on") {
		t.Fatalf("the plan note must state the coverage, got %q", p.Note)
	}
}

// TestPlanNoAuthoredPlanIsHonest is the no-plan path: a platform Correlix
// RECOGNISES but has authored no command set for runs nothing, lists every
// intent the class wanted, and says so.
//
// MikroTik RouterOS is that platform: internal/vendorprofile carries it, and
// its CLI (`/system resource print`) shares no grammar with the read-only show
// table, so no plan was authored. It replaced Nokia SR Linux here on 2026-09-05
// when the vendor research supplied 40 cited SR Linux issues and SR Linux gained
// a real plan — the honest path is still exercised, against a platform that
// genuinely has no commands rather than one we had simply not got to.
func TestPlanNoAuthoredPlanIsHonest(t *testing.T) {
	c := mustCatalog(t)
	p, err := c.Plan("ospf-adjacency", Device{ID: "edge9", Hostname: "edge9", Platform: "MikroTik RouterOS 7.14", TenantID: "t1"}, PlanOptions{})
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	if p.HasPlan {
		t.Fatal("MikroTik RouterOS has no authored plan; HasPlan must be false")
	}
	if len(p.Steps) != 0 {
		t.Fatalf("a platform with no plan must run NOTHING, got %d steps", len(p.Steps))
	}
	if len(p.Unbound) == 0 {
		t.Fatal("the intents Correlix would have collected must still be listed")
	}
	if !strings.Contains(p.Note, "No authored command plan") || !strings.Contains(p.Note, "paste") {
		t.Fatalf("the note must say there is no plan and offer the paste path, got %q", p.Note)
	}
}

// TestPlanUnknownPlatformNeverBorrowsADialect pins the D-2 lesson.
func TestPlanUnknownPlatformNeverBorrowsADialect(t *testing.T) {
	c := mustCatalog(t)
	p, _ := c.Plan("bgp-session", Device{ID: "x", Hostname: "x", Platform: "Acme RouterThing 1.0", TenantID: "t1"}, PlanOptions{})
	if p.HasPlan || len(p.Steps) > 0 {
		t.Fatal("an unrecognised platform must produce no commands at all")
	}
	if !strings.Contains(p.Note, "No authored command plan") {
		t.Fatalf("note = %q", p.Note)
	}
}

// TestPlanRendersTargetArguments proves substitution and the refusal of a
// malformed argument.
func TestPlanRendersTargetArguments(t *testing.T) {
	c := mustCatalog(t)
	p, _ := c.Plan("bgp-route-missing", iosxeDevice(), PlanOptions{
		Target: Target{Peer: "192.0.2.1", Prefix: "198.51.100.0/24"},
	})
	var sawPeer, sawPrefix bool
	for _, s := range p.Steps {
		if s.Command == "show ip bgp neighbors 192.0.2.1" {
			sawPeer = true
		}
		if s.Command == "show ip bgp 198.51.100.0/24" {
			sawPrefix = true
		}
	}
	if !sawPeer || !sawPrefix {
		t.Fatalf("target arguments were not substituted (peer=%v prefix=%v)", sawPeer, sawPrefix)
	}

	bad, _ := c.Plan("bgp-route-missing", iosxeDevice(), PlanOptions{
		Target: Target{Peer: "1.2.3.4; reload"},
	})
	for _, s := range bad.Steps {
		if strings.Contains(s.Command, "reload") || strings.Contains(s.Command, ";") {
			t.Fatalf("a malformed argument reached a command line: %q", s.Command)
		}
	}
}

// TestPlanIDIsDeterministic proves a collection can be tied back to the exact
// plan the operator approved.
func TestPlanIDIsDeterministic(t *testing.T) {
	c := mustCatalog(t)
	a, _ := c.Plan("ospf-adjacency", iosxeDevice(), PlanOptions{Target: Target{Interface: "Gi0/1"}})
	b, _ := c.Plan("ospf-adjacency", iosxeDevice(), PlanOptions{Target: Target{Interface: "Gi0/1"}})
	if a.ID == "" || a.ID != b.ID {
		t.Fatalf("plan ids differ for identical inputs: %q vs %q", a.ID, b.ID)
	}
	d, _ := c.Plan("ospf-adjacency", iosxeDevice(), PlanOptions{Target: Target{Interface: "Gi0/2"}})
	if d.ID == a.ID {
		t.Fatal("a different target produced the same plan id")
	}
}

// TestPlanUnknownClassIsAnError separates "we do not know this platform"
// (an answer) from "you sent an id we do not have" (an error).
func TestPlanUnknownClassIsAnError(t *testing.T) {
	c := mustCatalog(t)
	if _, err := c.Plan("not-a-class", iosxeDevice(), PlanOptions{}); err == nil {
		t.Fatal("expected ErrUnknownClass")
	}
}

// TestGateAllowsOnlyPlannedCommands is the run-time closed table.
func TestGateAllowsOnlyPlannedCommands(t *testing.T) {
	c := mustCatalog(t)
	g := NewGate(c)
	for _, tc := range []struct {
		dialect, cmd string
		want         bool
	}{
		{"cisco-iosxe", "show ip ospf neighbor detail", true},
		{"cisco-iosxe", "show interfaces GigabitEthernet0/1", true},
		{"cisco-iosxe", "show ip route 198.51.100.0/24", true},
		{"cisco-iosxe", "show ip bgp neighbors 192.0.2.1 received-routes", true},
		// read-only, and NOT in the plan → refused
		{"cisco-iosxe", "show crypto key mypubkey rsa", false},
		{"cisco-iosxe", "show running-config | include password", false},
		// a Junos-only command at a Cisco device. (`show interfaces terse` is NOT
		// the example to use: it matches the IOS-XE `show interfaces {if}`
		// template with "terse" as the argument, which is a read-only show of a
		// non-existent interface — harmless, and the honest consequence of a
		// placeholder table. The table's job is to keep the SHAPE closed.)
		{"cisco-iosxe", "show ethernet-switching table", false},
		{"juniper-junos", "show ethernet-switching table", true},
		{"cisco-iosxe", "show configuration | display set", false},
		// a dialect with no plan allows nothing
		{"mikrotik-routeros", "show version", false},
		{"", "show version", false},
	} {
		if got := g.AllowsDialect(tc.dialect, tc.cmd); got != tc.want {
			t.Errorf("AllowsDialect(%q, %q) = %v, want %v", tc.dialect, tc.cmd, got, tc.want)
		}
	}
}

// TestGateRefusesAnUnknownPlatform proves there is no fallback dialect here.
func TestGateRefusesAnUnknownPlatform(t *testing.T) {
	c := mustCatalog(t)
	g := NewGate(c)
	if g.Allows(protoDevice("Acme RouterThing"), "show version") {
		t.Fatal("the gate borrowed a dialect for an unknown platform")
	}
	if !g.Allows(protoDevice("Cisco IOS-XE 17.9"), "show version") {
		t.Fatal("the gate refused a planned command on a known platform")
	}
}

func protoDevice(platform string) protocoldiag.Device { return protocoldiag.Device{Platform: platform} }
