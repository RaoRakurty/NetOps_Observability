package showparse

// showparse_test.go — the library's contract proofs.
//
// The tests are organized around the ONE invariant: a parser never fabricates a
// field. That is asserted three ways —
//
//	1. positive: a realistic capture yields the EXACT typed values, and the
//	   fields the capture does not carry are nil (TestParse_Positive);
//	2. negative: garbage, truncated, cross-dialect and adversarial input yields
//	   Skipped with zero rows (TestParse_Garbage, TestParse_CrossDialect,
//	   TestParse_Adversarial, TestParse_Truncated);
//	3. exhaustive: EVERY registered (command, dialect) is fed garbage and must
//	   skip (TestEveryBinding_SkipsGarbage).

import (
	"errors"
	"strings"
	"testing"
	"time"

	"netops/backend/internal/vendorprofile"
)

// ── registry / vocabulary ───────────────────────────────────────────────────

// TestDialects_ResolveThroughVendorProfile is the "one vendor vocabulary" proof
// (CLAUDE.md §13): every Dialect constant must be a REAL vendorprofile profile
// id, so this package cannot drift into a second vendor table.
func TestDialects_ResolveThroughVendorProfile(t *testing.T) {
	reg := vendorprofile.Default()
	for _, d := range Dialects() {
		if _, ok := reg.Lookup(string(d)); !ok {
			t.Errorf("dialect %q is not a vendorprofile profile id", d)
		}
	}
	// Every supported dialect must be REACHABLE from platform text through the
	// registry alone. This is what replaced the Arista/Huawei fallback token map
	// (T9 residual, tracker 216): a dialect the registry cannot resolve is a
	// missing platform_contains in internal/vendorprofile/profiles/*.json, and
	// this assertion is what makes that a build failure rather than a silent
	// "unassessed" at runtime.
	for _, d := range Dialects() {
		prof, ok := reg.Lookup(string(d))
		if !ok {
			continue // already reported above
		}
		if len(prof.Detection.PlatformContains) == 0 {
			t.Errorf("dialect %q declares no detection.platform_contains — no platform text can resolve to it", d)
			continue
		}
		for _, sub := range prof.Detection.PlatformContains {
			got, ok := DialectFromPlatform(sub)
			if !ok || got != d {
				t.Errorf("DialectFromPlatform(%q) = (%q,%v), want (%q,true) — %s's own detection string must resolve to it",
					sub, got, ok, d, d)
			}
		}
	}
}

// TestDialectFromPlatform_EveryProfileDetectionString is the CROSS-PROFILE
// no-regression gate for the fallback deletion: EVERY profile in the registry
// that declares detection strings must still resolve to ITSELF through
// DialectFromPlatform's registry path (or to "unsupported dialect" when this
// library ships no parsers for it). Adding the Arista and Huawei
// platform_contains rows must not have stolen any other profile's text.
func TestDialectFromPlatform_EveryProfileDetectionString(t *testing.T) {
	reg := vendorprofile.Default()
	supported := map[string]bool{}
	for _, d := range Dialects() {
		supported[string(d)] = true
	}
	for _, prof := range reg.Profiles() {
		for _, sub := range prof.Detection.PlatformContains {
			resolved, ok := reg.ProfileForPlatformText(sub)
			if !ok {
				t.Errorf("profile %s: its own detection string %q resolves to nothing", prof.ID, sub)
				continue
			}
			if resolved.ID != prof.ID {
				t.Errorf("profile %s: its own detection string %q now resolves to %s — a higher-ranked rule stole it",
					prof.ID, sub, resolved.ID)
				continue
			}
			got, gotOK := DialectFromPlatform(sub)
			wantOK := supported[prof.ID]
			if gotOK != wantOK || (wantOK && string(got) != prof.ID) {
				t.Errorf("DialectFromPlatform(%q) = (%q,%v), want (%q,%v)", sub, got, gotOK, prof.ID, wantOK)
			}
		}
	}
}

func TestDialectFromPlatform(t *testing.T) {
	cases := []struct {
		platform string
		want     Dialect
		ok       bool
	}{
		{"Cisco IOS-XE 17.9", DialectCiscoIOSXE, true},
		{"cisco iosxe", DialectCiscoIOSXE, true},
		{"Cisco IOS-XR 7.5.2", DialectCiscoIOSXR, true},
		{"Cisco NX-OS 10.2", DialectCiscoNXOS, true},
		{"Cisco IOS 15.2", DialectCiscoIOS, true},
		{"Juniper Junos 22.4R3", DialectJunos, true},
		{"Nokia SR OS 22.10.R4", DialectNokiaSROS, true},
		{"Arista EOS 4.30.2F", DialectAristaEOS, true},
		{"Huawei VRP V800R021", DialectHuaweiVRP, true},
		{"SR Linux 23.3", "", false}, // a real vendorprofile profile, but no parser dialect here
		{"MikroTik RouterOS 7", "", false},
		{"", "", false},
		{"   ", "", false},
	}
	for _, tc := range cases {
		got, ok := DialectFromPlatform(tc.platform)
		if ok != tc.ok || got != tc.want {
			t.Errorf("DialectFromPlatform(%q) = (%q,%v), want (%q,%v)", tc.platform, got, ok, tc.want, tc.ok)
		}
	}
}

// TestBindings_CoverageFloor pins the design's acceptance floor: at least 20
// (command, dialect) parsers, spanning every supported dialect.
func TestBindings_CoverageFloor(t *testing.T) {
	l := NewLibrary()
	b := l.Bindings()
	if len(b) < 20 {
		t.Fatalf("only %d (command,dialect) parsers registered, design floor is 20", len(b))
	}
	perDialect := map[string]int{}
	for _, pair := range b {
		perDialect[pair[1]]++
	}
	for _, d := range Dialects() {
		if perDialect[string(d)] == 0 {
			t.Errorf("dialect %q has no parser at all", d)
		}
	}
	t.Logf("registered parsers: %d across %d dialects", len(b), len(perDialect))
	for _, d := range Dialects() {
		t.Logf("  %-16s %d", d, perDialect[string(d)])
	}
}

// TestLibrary_Deterministic proves two independently-built libraries agree, so
// there is no construction-order or map-iteration dependence.
func TestLibrary_Deterministic(t *testing.T) {
	a, b := NewLibrary().Bindings(), NewLibrary().Bindings()
	if len(a) != len(b) {
		t.Fatalf("binding counts differ: %d vs %d", len(a), len(b))
	}
	for i := range a {
		if a[i] != b[i] {
			t.Fatalf("binding %d differs: %v vs %v", i, a[i], b[i])
		}
	}
}

// ── Parse contract ──────────────────────────────────────────────────────────

func TestParse_ContractErrors(t *testing.T) {
	if _, err := Parse("", DialectCiscoIOSXE, "x"); !errors.Is(err, ErrNoCommand) {
		t.Errorf("empty command id: got %v, want ErrNoCommand", err)
	}
	big := strings.Repeat("a", MaxInputBytes+1)
	if _, err := Parse(CmdLogs, DialectCiscoIOSXE, big); !errors.Is(err, ErrInputTooLarge) {
		t.Errorf("over-cap input: got %v, want ErrInputTooLarge", err)
	}
	// Exactly at the cap is accepted (and skips, because it is not log output).
	atCap := strings.Repeat("a\n", MaxInputBytes/2)
	res, err := Parse(CmdLogs, DialectCiscoIOSXE, atCap)
	if err != nil {
		t.Fatalf("at-cap input errored: %v", err)
	}
	if !res.Skipped {
		t.Error("at-cap junk should skip")
	}
}

func TestParse_UnknownCommandAndDialect(t *testing.T) {
	res, err := Parse("no-such-command", DialectCiscoIOSXE, ciscoShowInterfaces)
	if err != nil {
		t.Fatalf("unknown command should not error: %v", err)
	}
	if !res.Skipped || res.Reason == "" || res.Rows() != 0 {
		t.Errorf("unknown command: got %+v, want skipped+reason+0 rows", res)
	}
	res, err = Parse(CmdInterfaceOptics, DialectCiscoIOSXR, ciscoTransceiverCombined)
	if err != nil {
		t.Fatalf("unsupported dialect should not error: %v", err)
	}
	if !res.Skipped || res.Rows() != 0 {
		t.Error("IOS-XR optics is deliberately unbound and must skip")
	}
}

func TestParse_EmptyInput(t *testing.T) {
	res, err := Parse(CmdBGPSummary, DialectCiscoIOSXE, "")
	if err != nil {
		t.Fatalf("empty input errored: %v", err)
	}
	if !res.Skipped || res.Rows() != 0 {
		t.Errorf("empty input must skip: %+v", res)
	}
}

// ── positive parses ─────────────────────────────────────────────────────────

func TestParse_CiscoInterfaces(t *testing.T) {
	res := mustParse(t, CmdInterfaceDetail, DialectCiscoIOSXE, ciscoShowInterfaces)
	if len(res.Interfaces) != 2 {
		t.Fatalf("got %d interfaces, want 2", len(res.Interfaces))
	}
	i0 := res.Interfaces[0]
	wantStr(t, "Name", &i0.Name, "GigabitEthernet0/0")
	wantStrP(t, "Admin", i0.Admin, "up")
	wantStrP(t, "Oper", i0.Oper, "up")
	wantStrP(t, "Description", i0.Description, "uplink to core-02")
	wantStrP(t, "IPv4", i0.IPv4, "10.0.0.1/30")
	wantIntP(t, "MTU", i0.MTU, 1500)
	wantI64P(t, "SpeedMbps", i0.SpeedMbps, 1000)
	wantStrP(t, "Duplex", i0.Duplex, "Full")
	wantI64P(t, "InErrors", i0.InErrors, 12)
	wantI64P(t, "CRC", i0.CRC, 7)
	wantI64P(t, "OutErrors", i0.OutErrors, 0)
	wantI64P(t, "OutDrops", i0.OutDrops, 4)
	// IOS `show interfaces` does NOT report a last-flap time. Absent means absent.
	if i0.LastFlap != nil {
		t.Errorf("LastFlap must be nil on IOS (got %q) — it is not in the output", *i0.LastFlap)
	}
	if i0.RxPowerDbm != nil || i0.TempC != nil {
		t.Error("optics fields must be nil: this command carries no DDM readings")
	}
	i1 := res.Interfaces[1]
	wantStrP(t, "Admin", i1.Admin, "administratively down")
	wantStrP(t, "Oper", i1.Oper, "down")
	if i1.Description != nil {
		t.Errorf("Description must be nil for an interface with none (got %q)", *i1.Description)
	}
}

func TestParse_JunosInterfaces(t *testing.T) {
	res := mustParse(t, CmdInterfaceDetail, DialectJunos, junosShowInterfacesExtensive)
	if len(res.Interfaces) != 1 {
		t.Fatalf("got %d interfaces, want 1", len(res.Interfaces))
	}
	i := res.Interfaces[0]
	wantStr(t, "Name", &i.Name, "ge-0/0/0")
	wantStrP(t, "Admin", i.Admin, "Enabled")
	wantStrP(t, "Oper", i.Oper, "Up")
	wantIntP(t, "MTU", i.MTU, 1514)
	wantI64P(t, "SpeedMbps", i.SpeedMbps, 1000)
	wantI64P(t, "InErrors", i.InErrors, 12)
	wantI64P(t, "CRC", i.CRC, 7) // Junos framing errors == the FCS counter
	wantI64P(t, "InDrops", i.InDrops, 3)
	wantI64P(t, "OutErrors", i.OutErrors, 0)
	wantI64P(t, "OutDrops", i.OutDrops, 4)
	wantI64P(t, "CarrierTransitions", i.CarrierTransitions, 5)
	wantStrP(t, "LastFlap", i.LastFlap, "2026-08-30 12:11:03 UTC (2d 03:12:44 ago)")
}

func TestParse_VRPInterfaces(t *testing.T) {
	res := mustParse(t, CmdInterfaceDetail, DialectHuaweiVRP, vrpDisplayInterface)
	if len(res.Interfaces) != 1 {
		t.Fatalf("got %d interfaces, want 1", len(res.Interfaces))
	}
	i := res.Interfaces[0]
	wantStr(t, "Name", &i.Name, "GigabitEthernet0/0/1")
	wantStrP(t, "Admin", i.Admin, "UP")
	wantStrP(t, "Oper", i.Oper, "UP")
	wantIntP(t, "MTU", i.MTU, 1500)
	wantI64P(t, "SpeedMbps", i.SpeedMbps, 1000)
	wantStrP(t, "Duplex", i.Duplex, "FULL")
	wantI64P(t, "CRC", i.CRC, 7)
	wantI64P(t, "InErrors", i.InErrors, 12)
	wantI64P(t, "InDrops", i.InDrops, 3)
	wantI64P(t, "OutErrors", i.OutErrors, 0)
	wantI64P(t, "OutDrops", i.OutDrops, 4)
}

func TestParse_SROSPortDetail(t *testing.T) {
	res := mustParse(t, CmdInterfaceDetail, DialectNokiaSROS, srosShowPortDetail)
	if len(res.Interfaces) != 1 {
		t.Fatalf("got %d interfaces, want 1", len(res.Interfaces))
	}
	i := res.Interfaces[0]
	wantStr(t, "Name", &i.Name, "1/1/1")
	wantStrP(t, "Admin", i.Admin, "up")
	wantStrP(t, "Oper", i.Oper, "up")
	wantIntP(t, "MTU", i.MTU, 1514)
	wantI64P(t, "SpeedMbps", i.SpeedMbps, 1000)
	wantF64P(t, "RxPowerDbm", i.RxPowerDbm, -5.23)
	wantF64P(t, "TxPowerDbm", i.TxPowerDbm, -2.10)
	wantF64P(t, "TempC", i.TempC, 34.5)
}

func TestParse_BriefTables(t *testing.T) {
	t.Run("cisco", func(t *testing.T) {
		res := mustParse(t, CmdInterfaceBrief, DialectCiscoIOSXE, ciscoIPIntBrief)
		if len(res.Interfaces) != 3 {
			t.Fatalf("got %d rows, want 3", len(res.Interfaces))
		}
		wantStrP(t, "IPv4", res.Interfaces[0].IPv4, "10.0.0.1")
		wantStrP(t, "Admin", res.Interfaces[1].Admin, "administratively down")
		if res.Interfaces[1].IPv4 != nil {
			t.Error("an unassigned interface must have a nil IPv4, not the literal 'unassigned'")
		}
	})
	t.Run("nxos", func(t *testing.T) {
		res := mustParse(t, CmdInterfaceBrief, DialectCiscoNXOS, nxosIPIntBrief)
		if len(res.Interfaces) != 2 {
			t.Fatalf("got %d rows, want 2", len(res.Interfaces))
		}
		wantStrP(t, "Oper", res.Interfaces[1].Oper, "down")
		wantStrP(t, "Admin", res.Interfaces[1].Admin, "up")
	})
	t.Run("eos", func(t *testing.T) {
		res := mustParse(t, CmdInterfaceBrief, DialectAristaEOS, eosIPIntBrief)
		if len(res.Interfaces) != 2 {
			t.Fatalf("got %d rows, want 2", len(res.Interfaces))
		}
		wantStrP(t, "IPv4", res.Interfaces[0].IPv4, "10.0.0.1/30")
		wantIntP(t, "MTU", res.Interfaces[0].MTU, 1500)
		if res.Interfaces[1].IPv4 != nil {
			t.Error("unassigned must stay nil")
		}
	})
	t.Run("junos", func(t *testing.T) {
		res := mustParse(t, CmdInterfaceBrief, DialectJunos, junosInterfacesTerse)
		if len(res.Interfaces) != 4 {
			t.Fatalf("got %d rows, want 4", len(res.Interfaces))
		}
		wantStrP(t, "IPv4", res.Interfaces[1].IPv4, "10.0.0.1/30")
		if res.Interfaces[0].IPv4 != nil {
			t.Error("a physical interface row carries no address")
		}
	})
}

func TestParse_Optics(t *testing.T) {
	t.Run("cisco-combined", func(t *testing.T) {
		res := mustParse(t, CmdInterfaceOptics, DialectCiscoIOSXE, ciscoTransceiverCombined)
		if len(res.Interfaces) != 2 {
			t.Fatalf("got %d rows, want 2", len(res.Interfaces))
		}
		i := res.Interfaces[0]
		wantF64P(t, "TempC", i.TempC, 34.2)
		wantF64P(t, "VoltageV", i.VoltageV, 3.29)
		wantF64P(t, "TxPowerDbm", i.TxPowerDbm, -2.1)
		wantF64P(t, "RxPowerDbm", i.RxPowerDbm, -5.6)
		wantF64P(t, "BiasCurrentMa", i.BiasCurrentMa, 6.3)
		wantF64P(t, "RxPowerDbm(2)", res.Interfaces[1].RxPowerDbm, -19.8)
	})
	t.Run("nxos", func(t *testing.T) {
		res := mustParse(t, CmdInterfaceOptics, DialectCiscoNXOS, nxosTransceiverDetails)
		if len(res.Interfaces) != 1 {
			t.Fatalf("got %d rows, want 1", len(res.Interfaces))
		}
		i := res.Interfaces[0]
		wantStr(t, "Name", &i.Name, "Ethernet1/1")
		wantF64P(t, "TxPowerDbm", i.TxPowerDbm, -2.1)
		wantF64P(t, "RxPowerDbm", i.RxPowerDbm, -5.6)
		wantF64P(t, "TempC", i.TempC, 34.2)
	})
	t.Run("junos", func(t *testing.T) {
		res := mustParse(t, CmdInterfaceOptics, DialectJunos, junosOpticsDiagnostics)
		i := res.Interfaces[0]
		wantF64P(t, "TxPowerDbm", i.TxPowerDbm, -2.1)
		wantF64P(t, "RxPowerDbm", i.RxPowerDbm, -5.6)
		wantF64P(t, "TempC", i.TempC, 34)
		wantF64P(t, "BiasCurrentMa", i.BiasCurrentMa, 6.3)
	})
	t.Run("vrp", func(t *testing.T) {
		res := mustParse(t, CmdInterfaceOptics, DialectHuaweiVRP, vrpTransceiverVerbose)
		i := res.Interfaces[0]
		wantStr(t, "Name", &i.Name, "GigabitEthernet0/0/1")
		wantF64P(t, "TxPowerDbm", i.TxPowerDbm, -2.1)
		wantF64P(t, "RxPowerDbm", i.RxPowerDbm, -5.6)
	})
}

func TestParse_OSPFNeighbors(t *testing.T) {
	t.Run("cisco", func(t *testing.T) {
		res := mustParse(t, CmdOSPFNeighbor, DialectCiscoIOSXE, ciscoOSPFNeighbor)
		if len(res.IGPNeighbors) != 2 {
			t.Fatalf("got %d rows, want 2", len(res.IGPNeighbors))
		}
		n := res.IGPNeighbors[1]
		wantStr(t, "State", &n.State, "EXSTART/DROTHER")
		wantStr(t, "Iface", &n.Iface, "GigabitEthernet0/1")
		wantStrP(t, "DeadTime", n.DeadTime, "00:00:33")
		if n.Uptime != nil {
			t.Error("the IOS OSPF table shows DEAD TIME, never uptime — Uptime must be nil")
		}
	})
	t.Run("nxos-uptime-not-deadtime", func(t *testing.T) {
		res := mustParse(t, CmdOSPFNeighbor, DialectCiscoNXOS, nxosOSPFNeighbor)
		if len(res.IGPNeighbors) != 2 {
			t.Fatalf("got %d rows, want 2", len(res.IGPNeighbors))
		}
		n := res.IGPNeighbors[0]
		wantStrP(t, "Uptime", n.Uptime, "02:31:11")
		if n.DeadTime != nil {
			t.Error("the NX-OS OSPF table shows UP TIME — DeadTime must be nil")
		}
	})
	t.Run("eos-vrf-column", func(t *testing.T) {
		res := mustParse(t, CmdOSPFNeighbor, DialectAristaEOS, eosOSPFNeighbor)
		if len(res.IGPNeighbors) != 2 {
			t.Fatalf("got %d rows, want 2", len(res.IGPNeighbors))
		}
		wantStr(t, "Iface", &res.IGPNeighbors[0].Iface, "Ethernet1")
		wantStr(t, "State", &res.IGPNeighbors[1].State, "2WAY/DROTHER")
	})
	t.Run("junos", func(t *testing.T) {
		res := mustParse(t, CmdOSPFNeighbor, DialectJunos, junosOSPFNeighbor)
		if len(res.IGPNeighbors) != 2 {
			t.Fatalf("got %d rows, want 2", len(res.IGPNeighbors))
		}
		wantStr(t, "ID", &res.IGPNeighbors[0].ID, "10.0.0.2")
		wantStr(t, "State", &res.IGPNeighbors[1].State, "ExStart")
	})
	t.Run("sros", func(t *testing.T) {
		res := mustParse(t, CmdOSPFNeighbor, DialectNokiaSROS, srosOSPFNeighbor)
		if len(res.IGPNeighbors) != 2 {
			t.Fatalf("got %d rows, want 2", len(res.IGPNeighbors))
		}
		wantStr(t, "Iface", &res.IGPNeighbors[0].Iface, "to-core-02")
	})
	t.Run("vrp", func(t *testing.T) {
		res := mustParse(t, CmdOSPFNeighbor, DialectHuaweiVRP, vrpOSPFPeerBrief)
		if len(res.IGPNeighbors) != 2 {
			t.Fatalf("got %d rows, want 2", len(res.IGPNeighbors))
		}
		wantStrP(t, "Area", res.IGPNeighbors[0].Area, "0.0.0.0")
		wantStr(t, "State", &res.IGPNeighbors[1].State, "Init")
	})
}

func TestParse_ISISNeighbors(t *testing.T) {
	t.Run("cisco", func(t *testing.T) {
		res := mustParse(t, CmdISISNeighbor, DialectCiscoIOSXE, ciscoISISNeighbors)
		if len(res.IGPNeighbors) != 2 {
			t.Fatalf("got %d rows, want 2", len(res.IGPNeighbors))
		}
		wantStrP(t, "Level", res.IGPNeighbors[0].Level, "L2")
		wantStr(t, "State", &res.IGPNeighbors[1].State, "INIT")
	})
	t.Run("iosxr-level-from-banner", func(t *testing.T) {
		res := mustParse(t, CmdISISNeighbor, DialectCiscoIOSXR, iosxrISISAdjacency)
		if len(res.IGPNeighbors) != 2 {
			t.Fatalf("got %d rows, want 2", len(res.IGPNeighbors))
		}
		wantStrP(t, "Level", res.IGPNeighbors[0].Level, "L2")
		wantStrP(t, "Uptime", res.IGPNeighbors[0].Uptime, "00:12:34")
	})
	t.Run("junos", func(t *testing.T) {
		res := mustParse(t, CmdISISNeighbor, DialectJunos, junosISISAdjacency)
		if len(res.IGPNeighbors) != 2 {
			t.Fatalf("got %d rows, want 2", len(res.IGPNeighbors))
		}
		wantStrP(t, "Level", res.IGPNeighbors[0].Level, "L2")
		wantStrP(t, "Level", res.IGPNeighbors[1].Level, "L1")
	})
	t.Run("sros", func(t *testing.T) {
		res := mustParse(t, CmdISISNeighbor, DialectNokiaSROS, srosISISAdjacency)
		if len(res.IGPNeighbors) != 2 {
			t.Fatalf("got %d rows, want 2", len(res.IGPNeighbors))
		}
		wantStr(t, "Iface", &res.IGPNeighbors[0].Iface, "to-core-02")
	})
}

func TestParse_BGPSummary(t *testing.T) {
	t.Run("cisco", func(t *testing.T) {
		res := mustParse(t, CmdBGPSummary, DialectCiscoIOSXE, ciscoBGPSummary)
		if len(res.BGPPeers) != 4 {
			t.Fatalf("got %d peers, want 4", len(res.BGPPeers))
		}
		p0 := res.BGPPeers[0]
		wantStr(t, "State", &p0.State, "Established")
		if !p0.Established {
			t.Error("a numeric State/PfxRcd column means Established")
		}
		wantI64P(t, "PrefixesRx", p0.PrefixesRx, 12)
		wantI64P(t, "AS", p0.AS, 65002)
		wantStrP(t, "UpDown", p0.UpDown, "02:31:11")
		wantStr(t, "State", &res.BGPPeers[1].State, "Idle")
		if res.BGPPeers[1].PrefixesRx != nil {
			t.Error("a non-established peer has NO prefix count — it must be nil, not 0")
		}
		wantStr(t, "State", &res.BGPPeers[2].State, "Active")
		wantStr(t, "State", &res.BGPPeers[3].State, "Idle (Admin)")
	})
	t.Run("eos-split-state-column", func(t *testing.T) {
		res := mustParse(t, CmdBGPSummary, DialectAristaEOS, eosBGPSummary)
		if len(res.BGPPeers) != 2 {
			t.Fatalf("got %d peers, want 2", len(res.BGPPeers))
		}
		wantStr(t, "State", &res.BGPPeers[0].State, "Established")
		wantI64P(t, "PrefixesRx", res.BGPPeers[0].PrefixesRx, 12)
		// The row that would trap a naive "last field is a number ⇒ established"
		// reader: Idle with a 0 prefix count.
		p := res.BGPPeers[1]
		wantStr(t, "State", &p.State, "Idle")
		if p.Established {
			t.Fatal("Arista Idle-with-0-prefixes was read as Established — fabrication")
		}
	})
	t.Run("junos", func(t *testing.T) {
		res := mustParse(t, CmdBGPSummary, DialectJunos, junosBGPSummary)
		if len(res.BGPPeers) != 2 {
			t.Fatalf("got %d peers, want 2", len(res.BGPPeers))
		}
		wantStr(t, "State", &res.BGPPeers[0].State, "Established")
		wantI64P(t, "PrefixesRx", res.BGPPeers[0].PrefixesRx, 120)
		wantStr(t, "State", &res.BGPPeers[1].State, "Active")
	})
	t.Run("sros", func(t *testing.T) {
		res := mustParse(t, CmdBGPSummary, DialectNokiaSROS, srosBGPSummary)
		if len(res.BGPPeers) != 2 {
			t.Fatalf("got %d peers, want 2", len(res.BGPPeers))
		}
		wantStr(t, "Peer", &res.BGPPeers[0].Peer, "10.0.0.2")
		wantI64P(t, "PrefixesRx", res.BGPPeers[0].PrefixesRx, 100)
		wantStr(t, "State", &res.BGPPeers[1].State, "Active")
	})
	t.Run("vrp", func(t *testing.T) {
		res := mustParse(t, CmdBGPSummary, DialectHuaweiVRP, vrpBGPPeer)
		if len(res.BGPPeers) != 2 {
			t.Fatalf("got %d peers, want 2", len(res.BGPPeers))
		}
		wantStr(t, "State", &res.BGPPeers[0].State, "Established")
		wantI64P(t, "PrefixesRx", res.BGPPeers[0].PrefixesRx, 12)
		wantStr(t, "State", &res.BGPPeers[1].State, "Idle")
	})
}

func TestParse_Routes(t *testing.T) {
	t.Run("cisco-detail", func(t *testing.T) {
		res := mustParse(t, CmdRoutePrefix, DialectCiscoIOSXE, ciscoRouteDetail)
		if len(res.Routes) != 1 {
			t.Fatalf("got %d routes, want 1", len(res.Routes))
		}
		r := res.Routes[0]
		wantStr(t, "Prefix", &r.Prefix, "192.0.2.0/24")
		wantStrP(t, "Protocol", r.Protocol, "ospf 1")
		wantI64P(t, "Preference", r.Preference, 110)
		wantI64P(t, "Metric", r.Metric, 20)
		wantStrP(t, "NextHop", r.NextHop, "10.0.0.2")
		wantStrP(t, "Iface", r.Iface, "GigabitEthernet0/0")
	})
	t.Run("cisco-table", func(t *testing.T) {
		res := mustParse(t, CmdRoutePrefix, DialectCiscoIOSXE, ciscoRouteTable)
		if len(res.Routes) != 2 {
			t.Fatalf("got %d routes, want 2", len(res.Routes))
		}
		wantStrP(t, "NextHop", res.Routes[0].NextHop, "10.0.0.2")
		wantStrP(t, "Iface", res.Routes[1].Iface, "GigabitEthernet0/1")
	})
	t.Run("device-says-none-is-not-skipped", func(t *testing.T) {
		res, err := Parse(CmdRoutePrefix, DialectCiscoIOSXE, ciscoRouteNotInTable)
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		if res.Skipped {
			t.Fatal(`"% Network not in table" is the DEVICE's negative answer, not an unreadable capture`)
		}
		if len(res.Routes) != 0 || res.Reason == "" {
			t.Errorf("want 0 routes with a reason, got %+v", res)
		}
	})
	t.Run("junos", func(t *testing.T) {
		res := mustParse(t, CmdRoutePrefix, DialectJunos, junosRouteDetail)
		if len(res.Routes) != 2 {
			t.Fatalf("got %d routes, want 2", len(res.Routes))
		}
		r := res.Routes[0]
		wantStrP(t, "Protocol", r.Protocol, "OSPF")
		wantI64P(t, "Preference", r.Preference, 10)
		wantI64P(t, "Metric", r.Metric, 20)
		wantStrP(t, "NextHop", r.NextHop, "10.0.0.2")
		wantStrP(t, "Iface", r.Iface, "ge-0/0/0.0")
		if r.Active == nil || !*r.Active {
			t.Error("the Junos '*' marker means active")
		}
	})
}

func TestParse_L2(t *testing.T) {
	t.Run("cisco-arp", func(t *testing.T) {
		res := mustParse(t, CmdARP, DialectCiscoIOSXE, ciscoARP)
		if len(res.ARP) != 2 {
			t.Fatalf("got %d entries, want 2", len(res.ARP))
		}
		wantStrP(t, "MAC", res.ARP[1].MAC, "000c.29ab.cdf1")
		wantStrP(t, "Age", res.ARP[1].Age, "12")
		wantStrP(t, "Iface", res.ARP[1].Iface, "GigabitEthernet0/0")
	})
	t.Run("nxos-arp", func(t *testing.T) {
		res := mustParse(t, CmdARP, DialectCiscoNXOS, nxosARP)
		if len(res.ARP) != 2 {
			t.Fatalf("got %d entries, want 2", len(res.ARP))
		}
		wantStrP(t, "Age", res.ARP[0].Age, "00:12:34")
	})
	t.Run("sros-arp", func(t *testing.T) {
		res := mustParse(t, CmdARP, DialectNokiaSROS, srosARP)
		if len(res.ARP) != 1 {
			t.Fatalf("got %d entries, want 1", len(res.ARP))
		}
		wantStrP(t, "MAC", res.ARP[0].MAC, "00:0c:29:ab:cd:f1")
	})
	t.Run("cisco-mac", func(t *testing.T) {
		res := mustParse(t, CmdMAC, DialectCiscoIOSXE, ciscoMACTable)
		if len(res.MAC) != 2 {
			t.Fatalf("got %d entries, want 2", len(res.MAC))
		}
		wantIntP(t, "VLAN", res.MAC[0].VLAN, 10)
		wantStrP(t, "Iface", res.MAC[0].Iface, "Gi0/1")
	})
	t.Run("nxos-mac", func(t *testing.T) {
		res := mustParse(t, CmdMAC, DialectCiscoNXOS, nxosMACTable)
		if len(res.MAC) != 1 {
			t.Fatalf("got %d entries, want 1", len(res.MAC))
		}
		wantStrP(t, "Iface", res.MAC[0].Iface, "Eth1/1")
	})
	t.Run("vrp-mac", func(t *testing.T) {
		res := mustParse(t, CmdMAC, DialectHuaweiVRP, vrpMACTable)
		if len(res.MAC) != 1 {
			t.Fatalf("got %d entries, want 1", len(res.MAC))
		}
		wantIntP(t, "VLAN", res.MAC[0].VLAN, 10)
		wantStrP(t, "Iface", res.MAC[0].Iface, "GE0/0/1")
	})
}

func TestParse_Platform(t *testing.T) {
	t.Run("cisco-cpu", func(t *testing.T) {
		res := mustParse(t, CmdPlatformCPU, DialectCiscoIOSXE, ciscoProcessesCPU)
		p := res.Platform
		if p == nil {
			t.Fatal("no platform health")
		}
		wantF64P(t, "CPU5Sec", p.CPU5Sec, 12)
		wantF64P(t, "CPU1Min", p.CPU1Min, 10)
		wantF64P(t, "CPU5Min", p.CPU5Min, 9)
		if p.MemUsedPercent != nil {
			t.Error("`show processes cpu` reports no memory — MemUsedPercent must be nil")
		}
	})
	t.Run("nxos-resources", func(t *testing.T) {
		res := mustParse(t, CmdPlatformCPU, DialectCiscoNXOS, nxosSystemResources)
		p := res.Platform
		wantF64P(t, "CPUPercent", p.CPUPercent, 8)
		wantI64P(t, "MemTotalKB", p.MemTotalKB, 8127096)
		wantI64P(t, "MemUsedKB", p.MemUsedKB, 3225104)
		if p.MemUsedPercent == nil || *p.MemUsedPercent < 39 || *p.MemUsedPercent > 40 {
			t.Errorf("MemUsedPercent = %v, want ~39.7", p.MemUsedPercent)
		}
	})
	t.Run("junos-re", func(t *testing.T) {
		res := mustParse(t, CmdPlatformCPU, DialectJunos, junosRoutingEngine)
		p := res.Platform
		wantF64P(t, "CPUPercent", p.CPUPercent, 9)
		wantF64P(t, "MemUsedPercent", p.MemUsedPercent, 22)
		if len(p.Temps) != 2 {
			t.Fatalf("got %d temps, want 2", len(p.Temps))
		}
		wantF64P(t, "Temps[0]", p.Temps[0].ValueC, 34)
		wantStrP(t, "Uptime", p.Uptime, "10 days, 2 hours, 31 minutes, 11 seconds")
		wantStrP(t, "LastReload", p.LastReload, "0x200:normal shutdown")
	})
	t.Run("vrp-cpu-mem", func(t *testing.T) {
		res := mustParse(t, CmdPlatformCPU, DialectHuaweiVRP, vrpCPUUsage)
		wantF64P(t, "CPUPercent", res.Platform.CPUPercent, 12)
		res = mustParse(t, CmdPlatformMemory, DialectHuaweiVRP, vrpMemoryUsage)
		wantF64P(t, "MemUsedPercent", res.Platform.MemUsedPercent, 42)
	})
	t.Run("cisco-version", func(t *testing.T) {
		res := mustParse(t, CmdPlatformUptime, DialectCiscoIOSXE, ciscoShowVersion)
		p := res.Platform
		wantStrP(t, "Uptime", p.Uptime, "10 weeks, 2 days, 3 hours, 12 minutes")
		wantStrP(t, "LastReload", p.LastReload, "reload")
		wantStrP(t, "Version", p.Version, "17.09.04a")
	})
	t.Run("junos-uptime", func(t *testing.T) {
		res := mustParse(t, CmdPlatformUptime, DialectJunos, junosSystemUptime)
		wantStrP(t, "Uptime", res.Platform.Uptime, "10 days, 2:31")
	})
}

func TestParse_Logs(t *testing.T) {
	t.Run("cisco", func(t *testing.T) {
		res := mustParse(t, CmdLogs, DialectCiscoIOSXE, ciscoLogging)
		if len(res.Logs) != 3 {
			t.Fatalf("got %d lines, want 3", len(res.Logs))
		}
		l := res.Logs[0]
		wantStrP(t, "Facility", l.Facility, "OSPF")
		wantIntP(t, "Severity", l.Severity, 5)
		wantStrP(t, "Mnemonic", l.Mnemonic, "ADJCHG")
		wantStrP(t, "Timestamp", l.Timestamp, "Sep  2 09:58:12.345")
		wantStrP(t, "Facility", res.Logs[1].Facility, "LINK")
		wantIntP(t, "Severity", res.Logs[1].Severity, 3)
	})
	t.Run("junos", func(t *testing.T) {
		res := mustParse(t, CmdLogs, DialectJunos, junosLogMessages)
		if len(res.Logs) != 2 {
			t.Fatalf("got %d lines, want 2", len(res.Logs))
		}
		wantStrP(t, "Facility", res.Logs[0].Facility, "rpd")
		wantStrP(t, "Mnemonic", res.Logs[0].Mnemonic, "RPD_OSPF_NBRUP")
		if res.Logs[0].Severity != nil {
			t.Error("the Junos message buffer carries no numeric severity — it must be nil")
		}
	})
	t.Run("vrp", func(t *testing.T) {
		res := mustParse(t, CmdLogs, DialectHuaweiVRP, vrpLogbuffer)
		if len(res.Logs) != 2 {
			t.Fatalf("got %d lines, want 2", len(res.Logs))
		}
		wantStrP(t, "Facility", res.Logs[0].Facility, "OSPF")
		wantIntP(t, "Severity", res.Logs[0].Severity, 5)
		wantStrP(t, "Mnemonic", res.Logs[1].Mnemonic, "LINK_STATE")
	})
	t.Run("sros", func(t *testing.T) {
		res := mustParse(t, CmdLogs, DialectNokiaSROS, srosEventLog)
		if len(res.Logs) != 2 {
			t.Fatalf("got %d lines, want 2", len(res.Logs))
		}
		wantStrP(t, "Facility", res.Logs[0].Facility, "OSPF")
		if res.Logs[0].Severity != nil {
			t.Error("SR OS severities are WORDS — the numeric Severity must stay nil")
		}
	})
}

// ── negative / conservative behaviour ───────────────────────────────────────

// TestConservative_SkipRatherThanGuess is the design's explicit requirement for
// formats we could not pin down: the parser must skip, not guess.
func TestConservative_SkipRatherThanGuess(t *testing.T) {
	cases := []struct {
		name    string
		cmd     string
		dialect Dialect
		raw     string
		why     string
	}{
		{
			name: "cisco per-metric transceiver detail", cmd: CmdInterfaceOptics,
			dialect: DialectCiscoIOSXE, raw: ciscoTransceiverDetailSkipFixture,
			why: "the header names one metric but the row carries four threshold columns",
		},
		{
			name: "iosxr optics is unbound", cmd: CmdInterfaceOptics,
			dialect: DialectCiscoIOSXR, raw: ciscoTransceiverCombined,
			why: "no IOS-XR optics command is authored in the battery",
		},
		{
			name: "sros mac is unbound", cmd: CmdMAC,
			dialect: DialectNokiaSROS, raw: ciscoMACTable,
			why: "the SR OS service FDB shape is not established",
		},
		{
			name: "iosxr arp is unbound", cmd: CmdARP,
			dialect: DialectCiscoIOSXR, raw: ciscoARP,
			why: "the IOS-XR ARP table shape is not established",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res, err := Parse(tc.cmd, tc.dialect, tc.raw)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			if !res.Skipped || res.Rows() != 0 {
				t.Fatalf("must skip (%s), got %d rows skipped=%v", tc.why, res.Rows(), res.Skipped)
			}
		})
	}
}

// TestEveryBinding_SkipsGarbage feeds prose to EVERY registered parser. None may
// produce a row: a parser that invents structure out of English is exactly the
// failure this package is built to prevent.
func TestEveryBinding_SkipsGarbage(t *testing.T) {
	l := NewLibrary()
	for _, pair := range l.Bindings() {
		cmd, d := pair[0], Dialect(pair[1])
		res, err := l.Parse(cmd, d, garbageOutput)
		if err != nil {
			t.Fatalf("%s/%s: %v", cmd, d, err)
		}
		if !res.Skipped || res.Rows() != 0 {
			t.Errorf("%s/%s produced %d rows from prose (skipped=%v)", cmd, d, res.Rows(), res.Skipped)
		}
	}
}

// TestParse_CrossDialect proves a capture from the WRONG platform skips rather
// than being force-fit onto the typed struct.
func TestParse_CrossDialect(t *testing.T) {
	cases := []struct {
		cmd     string
		dialect Dialect
		raw     string
	}{
		{CmdInterfaceDetail, DialectJunos, ciscoShowInterfaces},
		{CmdInterfaceDetail, DialectCiscoIOSXE, junosShowInterfacesExtensive},
		{CmdInterfaceDetail, DialectHuaweiVRP, ciscoShowInterfaces},
		{CmdOSPFNeighbor, DialectJunos, ciscoOSPFNeighbor},
		{CmdOSPFNeighbor, DialectHuaweiVRP, junosOSPFNeighbor},
		{CmdBGPSummary, DialectHuaweiVRP, ciscoBGPSummary},
		{CmdBGPSummary, DialectNokiaSROS, junosBGPSummary},
		{CmdLogs, DialectJunos, ciscoLogging},
		{CmdLogs, DialectHuaweiVRP, junosLogMessages},
		{CmdMAC, DialectHuaweiVRP, ciscoMACTable},
		{CmdRoutePrefix, DialectJunos, ciscoRouteDetail},
	}
	for _, tc := range cases {
		res, err := Parse(tc.cmd, tc.dialect, tc.raw)
		if err != nil {
			t.Fatalf("%s/%s: %v", tc.cmd, tc.dialect, err)
		}
		if !res.Skipped || res.Rows() != 0 {
			t.Errorf("%s parsed with the %s parser: %d rows", tc.cmd, tc.dialect, res.Rows())
		}
	}
}

// TestParse_Truncated proves a capture cut off mid-line still yields only what
// was actually read, and never a defaulted field.
func TestParse_Truncated(t *testing.T) {
	res := mustParse(t, CmdInterfaceDetail, DialectCiscoIOSXE, truncatedCiscoInterfaces)
	if len(res.Interfaces) != 1 {
		t.Fatalf("got %d interfaces, want 1", len(res.Interfaces))
	}
	i := res.Interfaces[0]
	wantStrP(t, "Admin", i.Admin, "up")
	wantStrP(t, "Oper", i.Oper, "up")
	if i.MTU != nil {
		t.Errorf("the MTU line was never reached — MTU must be nil, got %d", *i.MTU)
	}
	if i.InErrors != nil || i.CRC != nil || i.OutDrops != nil || i.SpeedMbps != nil || i.Duplex != nil {
		t.Error("counters were never reached in a truncated capture — all must be nil")
	}
	// Half a BGP row: four columns of a ten-column table.
	res, err := Parse(CmdBGPSummary, DialectCiscoIOSXE,
		"Neighbor        V           AS MsgRcvd MsgSent   TblVer  InQ OutQ Up/Down  State/PfxRcd\n10.0.0.2        4        65002    1234")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if res.Rows() != 0 || !res.Skipped {
		t.Errorf("a truncated BGP row must not become a peer: %+v", res)
	}
}

// TestParse_Partial proves a capture that carries SOME rows in a recognizable
// shape and some in an unrecognizable one keeps only the recognizable ones.
func TestParse_Partial(t *testing.T) {
	mixed := ciscoOSPFNeighbor + "10.0.0.9 <<corrupted row>> ???\n10.0.0.10  1  BOGUS/STATE  00:00:30  10.0.0.10  Gi0/2\n"
	res := mustParse(t, CmdOSPFNeighbor, DialectCiscoIOSXE, mixed)
	if len(res.IGPNeighbors) != 2 {
		t.Fatalf("got %d rows, want only the 2 well-formed ones", len(res.IGPNeighbors))
	}
	for _, n := range res.IGPNeighbors {
		if strings.Contains(n.State, "BOGUS") {
			t.Error("an unknown FSM state word was accepted")
		}
	}
}

// TestParse_Adversarial feeds pathological input: a single enormous line, deeply
// repeated separators and colons, and a table of near-miss rows. It asserts both
// the honest outcome AND that the whole batch completes well inside a second —
// the no-catastrophic-backtracking property, observed rather than asserted by
// inspection.
func TestParse_Adversarial(t *testing.T) {
	long := strings.Repeat("A", maxLineBytes*4)
	inputs := map[string]string{
		"one enormous line":     long,
		"enormous header":       long + " is up, line protocol is up\n  MTU 1500 bytes\n",
		"colon storm":           strings.Repeat(":", 40000),
		"space storm":           strings.Repeat(" ", 60000) + "x",
		"dot storm":             strings.Repeat(".", 50000),
		"slash storm":           strings.Repeat("1/", 30000),
		"dash storm":            strings.Repeat("-", 70000),
		"percent storm":         strings.Repeat("%", 40000),
		"nested parens":         strings.Repeat("(", 20000) + strings.Repeat(")", 20000),
		"many tiny lines":       strings.Repeat("a b c d e f g h\n", 5000),
		"prefix-shaped repeats": strings.Repeat("10.0.0.1/24 ", 20000),
		"mac-shaped repeats":    strings.Repeat("000c.29ab.cdef ", 20000),
	}
	l := NewLibrary()
	start := time.Now()
	for name, raw := range inputs {
		for _, pair := range l.Bindings() {
			res, err := l.Parse(pair[0], Dialect(pair[1]), raw)
			if err != nil {
				t.Fatalf("%s on %s/%s: %v", name, pair[0], pair[1], err)
			}
			if res.Rows() > 0 {
				t.Errorf("%s produced %d rows on %s/%s", name, res.Rows(), pair[0], pair[1])
			}
		}
	}
	if d := time.Since(start); d > 20*time.Second {
		t.Fatalf("adversarial batch took %v — suspect superlinear scanning", d)
	}
	t.Logf("adversarial batch over %d bindings in %v", len(l.Bindings()), time.Since(start))
}

// TestSplitLines_Bounds proves the line and count caps.
func TestSplitLines_Bounds(t *testing.T) {
	tooMany := strings.Repeat("x\n", maxLines+500)
	if got := len(splitLines(tooMany)); got != maxLines {
		t.Errorf("line count = %d, want the %d cap", got, maxLines)
	}
	long := strings.Repeat("y", maxLineBytes+1)
	got := splitLines(long + "\nshort")
	if got[0] != "" {
		t.Error("an over-long line must be dropped, not scanned")
	}
	if got[1] != "short" {
		t.Error("the following line must survive")
	}
	if got := splitLines("a\r\nb\r\n"); len(got) != 2 || got[0] != "a" || got[1] != "b" {
		t.Errorf("CRLF normalization failed: %q", got)
	}
}

// TestHelpers_ShapePredicates pins the shape predicates every parser gates on.
func TestHelpers_ShapePredicates(t *testing.T) {
	for _, s := range []string{"10.0.0.1", "255.255.255.255", "0.0.0.0"} {
		if !looksIPv4(s) {
			t.Errorf("looksIPv4(%q) = false", s)
		}
	}
	for _, s := range []string{"10.0.0.256", "10.0.0", "10.0.0.1.2", "inet.0", "a.b.c.d", "010.0.0.1x", ""} {
		if looksIPv4(s) {
			t.Errorf("looksIPv4(%q) = true", s)
		}
	}
	for _, s := range []string{"000c.29ab.cdef", "00:0c:29:ab:cd:ef", "00-0c-29-ab-cd-ef", "000c-29ab-cdef"} {
		if !looksMAC(s) {
			t.Errorf("looksMAC(%q) = false", s)
		}
	}
	for _, s := range []string{"000c.29ab", "zzzz.29ab.cdef", "10.0.0.1", ""} {
		if looksMAC(s) {
			t.Errorf("looksMAC(%q) = true", s)
		}
	}
	for _, s := range []string{"00:12:34", "2d3:12:44", "02h31m11s", "never", "1w2d"} {
		if !looksDuration(s) {
			t.Errorf("looksDuration(%q) = false", s)
		}
	}
	for _, s := range []string{"Idle", "12", "", "Gi0/0", "10.0.0.1/24"} {
		if looksDuration(s) {
			t.Errorf("looksDuration(%q) = true", s)
		}
	}
	if _, ok := atoiOK("12abc"); ok {
		t.Error("atoiOK accepted 12abc")
	}
	if n, ok := atoiOK("12,"); !ok || n != 12 {
		t.Error("atoiOK should tolerate a trailing comma")
	}
}

// ── assertions ──────────────────────────────────────────────────────────────

func mustParse(t *testing.T, cmd string, d Dialect, raw string) Result {
	t.Helper()
	res, err := Parse(cmd, d, raw)
	if err != nil {
		t.Fatalf("Parse(%s,%s): %v", cmd, d, err)
	}
	if res.Skipped {
		t.Fatalf("Parse(%s,%s) skipped: %s", cmd, d, res.Reason)
	}
	return res
}

func wantStr(t *testing.T, field string, got *string, want string) {
	t.Helper()
	if got == nil || *got != want {
		t.Errorf("%s = %v, want %q", field, deref(got), want)
	}
}

func wantStrP(t *testing.T, field string, got *string, want string) {
	t.Helper()
	if got == nil {
		t.Errorf("%s is nil, want %q", field, want)
		return
	}
	if *got != want {
		t.Errorf("%s = %q, want %q", field, *got, want)
	}
}

func wantIntP(t *testing.T, field string, got *int, want int) {
	t.Helper()
	if got == nil {
		t.Errorf("%s is nil, want %d", field, want)
		return
	}
	if *got != want {
		t.Errorf("%s = %d, want %d", field, *got, want)
	}
}

func wantI64P(t *testing.T, field string, got *int64, want int64) {
	t.Helper()
	if got == nil {
		t.Errorf("%s is nil, want %d", field, want)
		return
	}
	if *got != want {
		t.Errorf("%s = %d, want %d", field, *got, want)
	}
}

func wantF64P(t *testing.T, field string, got *float64, want float64) {
	t.Helper()
	if got == nil {
		t.Errorf("%s is nil, want %v", field, want)
		return
	}
	if diff := *got - want; diff > 0.001 || diff < -0.001 {
		t.Errorf("%s = %v, want %v", field, *got, want)
	}
}

func deref(s *string) string {
	if s == nil {
		return "<nil>"
	}
	return *s
}
