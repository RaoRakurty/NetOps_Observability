package main

// verify_modules_test.go — troubleshooting-module checks (verify_modules.go):
// closed-table invariants, seam/fault trigger gates, and the deterministic
// parsers against canned per-vendor command outputs (Cisco IOS-XE/XR-style,
// Arista EOS, Juniper Junos, Huawei VRP, Nokia SR OS).

import (
	"context"
	"strings"
	"testing"
	"time"
)

// Fixed clock: incident window opened 30 minutes before "now", so the recent
// window is 1h30m (incident age + 1h slack).
var (
	modNow = time.Date(2026, 7, 18, 12, 0, 0, 0, time.UTC)
	modCC  = verifyCaseContext{
		Owner:         "isp",
		TopHypothesis: "sig.ent.wan-edge.routing-instability",
		VerdictTier:   "suspected",
		WindowStart:   modNow.Add(-30 * time.Minute),
	}
)

// ---- closed tables ----------------------------------------------------------

func TestModuleCommandTableCoversAllVendorsAndChecks(t *testing.T) {
	vendors := []string{"cisco", "arista", "juniper", "huawei", "nokia"}
	for _, v := range vendors {
		for _, spec := range verifyModuleSpecs() {
			cmd, ok := verifyModuleCommandFor(v, spec.ID)
			if !ok || cmd == "" {
				t.Fatalf("%s/%s: no module command", v, spec.ID)
			}
			if !verifyCommandAllowed(cmd) {
				t.Fatalf("%s/%s: module command %q must pass the allowlist gate", v, spec.ID, cmd)
			}
		}
	}
	if _, ok := verifyModuleCommandFor("mikrotik", "ssh_iface_deep"); ok {
		t.Fatal("unknown vendor must not resolve a module command")
	}
	if _, ok := verifyModuleCommandFor("cisco", "ssh_reboot"); ok {
		t.Fatal("unknown check must not resolve a module command")
	}
	if verifyModuleCommandAllowed("configure terminal") || verifyModuleCommandAllowed("") {
		t.Fatal("non-table commands must be refused")
	}
}

func TestVerifyCommandForFallsThroughToModuleTable(t *testing.T) {
	if cmd, ok := verifyCommandFor("cisco", "ssh_config_change"); !ok || cmd != "show running-config" {
		t.Fatalf("module check must resolve through verifyCommandFor, got %q %v", cmd, ok)
	}
	if cmd, ok := verifyCommandFor("cisco", "ssh_interfaces"); !ok || cmd != "show ip interface brief" {
		t.Fatalf("core table must stay authoritative for core checks, got %q %v", cmd, ok)
	}
}

// ---- trigger gates ----------------------------------------------------------

func TestVerifyModulesForTriggerGates(t *testing.T) {
	has := func(mods []string, m string) bool {
		for _, x := range mods {
			if x == m {
				return true
			}
		}
		return false
	}
	cases := []struct {
		name       string
		cc         verifyCaseContext
		wantBGP    bool
		wantChange bool
	}{
		{"isp owner fires bgp_edge", verifyCaseContext{Owner: "isp", VerdictTier: "confirmed"}, true, false},
		{"carrier owner fires bgp_edge", verifyCaseContext{Owner: "carrier"}, true, false},
		{"netops owner alone does not", verifyCaseContext{Owner: "netops", TopHypothesis: "sig.ent.campus.stp-loop"}, false, false},
		{"wan-edge hypothesis fires bgp_edge", verifyCaseContext{Owner: "netops", TopHypothesis: "sig.ent.wan-edge.routing-instability"}, true, false},
		{"middle-mile hypothesis fires bgp_edge", verifyCaseContext{TopHypothesis: "sig.ent.middle-mile.physical-degradation"}, true, false},
		{"bgp hypothesis fires bgp_edge", verifyCaseContext{TopHypothesis: "sig.ent.dc.bgp-session-flap"}, true, false},
		{"suspected tier fires recent_change", verifyCaseContext{VerdictTier: "suspected"}, false, true},
		{"confirmed tier does not fire recent_change", verifyCaseContext{VerdictTier: "confirmed"}, false, false},
		{"empty context fires only iface_deep", verifyCaseContext{}, false, false},
	}
	for _, c := range cases {
		mods := verifyModulesFor(c.cc)
		if !has(mods, verifyModuleIfaceDeep) {
			t.Errorf("%s: iface_deep must always fire for a localized case", c.name)
		}
		if has(mods, verifyModuleBGPEdge) != c.wantBGP {
			t.Errorf("%s: bgp_edge fired=%v want %v", c.name, !c.wantBGP, c.wantBGP)
		}
		if has(mods, verifyModuleRecentChange) != c.wantChange {
			t.Errorf("%s: recent_change fired=%v want %v", c.name, !c.wantChange, c.wantChange)
		}
	}
}

func TestVerifyActiveBatteryComposition(t *testing.T) {
	core := len(verifyBattery())
	all := verifyActiveBattery(modCC) // isp + suspected ⇒ all three modules
	if len(all) != core+3 {
		t.Fatalf("want core+3 checks, got %d (core %d)", len(all), core)
	}
	none := verifyActiveBattery(verifyCaseContext{VerdictTier: "confirmed", Owner: "netops"})
	if len(none) != core+1 { // iface_deep only
		t.Fatalf("want core+1 checks, got %d", len(none))
	}
	if got := verifyModuleNames(); len(got) != 3 {
		t.Fatalf("module registry: %v", got)
	}
}

// ---- duration / timestamp helpers ------------------------------------------

func TestParseNetDuration(t *testing.T) {
	cases := []struct {
		in   string
		want time.Duration
		ok   bool
	}{
		{"00:02:11", 2*time.Minute + 11*time.Second, true},
		{"2:33", 2*time.Hour + 33*time.Minute, true},
		{"2d10h", 58 * time.Hour, true},
		{"1w2d", 9 * 24 * time.Hour, true},
		{"00h07m34s", 7*time.Minute + 34*time.Second, true},
		{"33 minutes, 20 seconds", 33*time.Minute + 20*time.Second, true},
		{"never", 0, false},
		{"", 0, false},
		{"garbage", 0, false},
	}
	for _, c := range cases {
		got, ok := parseNetDuration(c.in)
		if ok != c.ok || (ok && got != c.want) {
			t.Errorf("parseNetDuration(%q) = %v %v, want %v %v", c.in, got, ok, c.want, c.ok)
		}
	}
}

// ---- module 1: interface deep-dive ------------------------------------------

const ciscoIfFaulty = `GigabitEthernet0/0 is up, line protocol is up
  Hardware is iGbE, address is 0cbf.0d11.2233
  MTU 1500 bytes, BW 1000000 Kbit/sec, DLY 10 usec,
  Half-duplex, 100Mb/s, media type is RJ45
  5 minute input rate 2000 bits/sec, 3 packets/sec
     1543 packets input, 187642 bytes, 0 no buffer
     34 input errors, 34 CRC, 0 frame, 0 overrun, 0 ignored
     0 output errors, 0 collisions, 3 interface resets
GigabitEthernet0/1 is administratively down, line protocol is down
     99 input errors, 99 CRC, 0 frame, 0 overrun, 0 ignored
`

const ciscoIfClean = `GigabitEthernet0/0 is up, line protocol is up
  Hardware is iGbE, address is 0cbf.0d11.2233
  Full-duplex, 1000Mb/s, media type is RJ45
     1543 packets input, 187642 bytes, 0 no buffer
     0 input errors, 0 CRC, 0 frame, 0 overrun, 0 ignored
     0 output errors, 0 collisions, 0 interface resets
`

const aristaIfFlap = `Ethernet1 is up, line protocol is up (connected)
  Hardware is Ethernet, address is 001c.7301.5b2b
  Full-duplex, 10Gb/s, auto negotiation: off
  Up 12 minutes, 40 seconds
  4 link status changes since last clear
     0 input errors, 0 CRC, 0 alignment, 0 symbol, 0 input discards
     0 output errors, 0 collisions
`

const junosIfErrors = `Physical interface: ge-0/0/0, Enabled, Physical link is Up
  Link-level type: Ethernet, MTU: 1514, Link-mode: Full-duplex, Speed: 1000mbps
  Carrier transitions: 7
  Input errors:
    Errors: 12, Drops: 3, Framing errors: 0, Runts: 0
  MAC statistics:                      Receive         Transmit
    CRC/Align errors                        34                0
`

const vrpIfCRC = `GigabitEthernet0/0/1 current state : UP
Line protocol current state : UP
Last physical up time   : 2026-07-18 11:45:10
    Input:  1234567 packets, 123456789 bytes
      CRC:                5, Giants:               0
    Output:  234567 packets, 23456789 bytes
`

const nokiaPortFault = `===============================================================================
Ethernet Interface
===============================================================================
Description        : uplink to core
Interface          : 1/1/1                  Oper Speed       : 10 Gbps
Admin State        : up                     Oper Duplex      : half
Oper State         : up                     Config Duplex    : full
Errors                                  Input                 Output
CRC/Align Errors                            5                     0
`

func TestParseIfaceDeep(t *testing.T) {
	cases := []struct {
		name, in, wantStatus, wantSub string
	}{
		{"cisco CRC+duplex faults; admin-down ignored has own faults suppressed", ciscoIfFaulty, verifyStatusFail, "CRC"},
		{"cisco clean passes", ciscoIfClean, verifyStatusPass, "clean"},
		{"arista recent flap + link changes", aristaIfFlap, verifyStatusFail, "link status changes"},
		{"junos errors + carrier transitions", junosIfErrors, verifyStatusFail, "carrier transitions"},
		{"vrp CRC + recent physical up", vrpIfCRC, verifyStatusFail, "CRC"},
		{"nokia CRC + half duplex", nokiaPortFault, verifyStatusFail, "half-duplex"},
		{"gibberish skipped", "% Invalid input detected", verifyStatusSkipped, "unrecognized"},
	}
	for _, c := range cases {
		got, obs := parseIfaceDeep(strings.TrimSpace(c.in), modNow, modCC)
		if got != c.wantStatus || !strings.Contains(obs, c.wantSub) {
			t.Errorf("%s: got %s %q", c.name, got, obs)
		}
	}
	// The admin-down interface's counters must NOT be the only reason a check
	// fails: strip the up interface from the cisco fixture and keep only the
	// administratively down one — expect PASS (its faults are intended state).
	adminOnly := "GigabitEthernet0/1 is administratively down, line protocol is down\n     99 input errors, 99 CRC, 0 frame, 0 overrun, 0 ignored\n"
	if st, obs := parseIfaceDeep(adminOnly, modNow, modCC); st != verifyStatusPass {
		t.Errorf("admin-down-only counters must pass, got %s %q", st, obs)
	}
	// Arista up-duration far older than the incident window must not fail.
	old := strings.Replace(aristaIfFlap, "Up 12 minutes, 40 seconds", "Up 5 days, 3 hours", 1)
	old = strings.Replace(old, "4 link status changes", "1 link status changes", 1)
	if st, obs := parseIfaceDeep(old, modNow, modCC); st != verifyStatusPass {
		t.Errorf("old up-time must pass, got %s %q", st, obs)
	}
}

// ---- module 2: BGP/edge seam ------------------------------------------------

const ciscoBGPRecentReset = `BGP router identifier 10.0.0.1, local AS number 65000
Neighbor        V           AS MsgRcvd MsgSent   TblVer  InQ OutQ Up/Down  State/PfxRcd
10.0.0.2        4        65001     152     148        5    0    0 00:04:11       42
10.0.0.6        4        65002    9021    9033        5    0    0 5d02h         120
`

const ciscoBGPDown = `Neighbor        V           AS MsgRcvd MsgSent   TblVer  InQ OutQ Up/Down  State/PfxRcd
10.0.0.2        4        65001       0       0        1    0    0 never    Idle
`

const aristaBGPCollapse = `BGP summary information for VRF default
Neighbor        V AS      MsgRcvd MsgSent InQ OutQ  Up/Down State  PfxRcd PfxAcc
10.0.0.2        4 65001       152     148   0    0  4d05h   Estab  5      5
10.0.0.9        4 65003       152     148   0    0    2d3h        0
`

const junosBGPMixed = `Groups: 1 Peers: 2 Down peers: 1
Peer                     AS      InPkt     OutPkt    OutQ   Flaps Last Up/Dwn State|#Active/Received/Accepted/Damped...
10.0.0.2              65001        152        148       0       3     2:33:12 5/5/5/0              0/0/0/0
10.0.0.6              65001          4          2       0       1        1:22 Active
`

const vrpBGPIdle = ` BGP local router ID : 10.0.0.1
 Peer            V    AS  MsgRcvd  MsgSent  OutQ  Up/Down       State  PrefRcv
 10.0.0.2        4 65001      152      148     0  00:00:00       Idle        0
`

const vrpBGPHealthy = ` Peer            V    AS  MsgRcvd  MsgSent  OutQ  Up/Down       State  PrefRcv
 10.0.0.2        4 65001      152      148     0  02:11:09 Established       9
`

const nokiaBGPSummary = `BGP Summary
Neighbor
Description
                   AS PktRcvd InQ  Up/Down   State|Rcv/Act/Sent (Addr Family)
10.0.0.2
                65001    1234   0 00h07m34s 10/8/50 (IPv4)
10.0.0.6
                65001      12   0 02d15h22m Active
`

func TestParseBGPEdge(t *testing.T) {
	cases := []struct {
		name, in, wantStatus, wantSub string
	}{
		{"cisco recent session reset", ciscoBGPRecentReset, verifyStatusFail, "reset inside the incident window"},
		{"cisco idle neighbor", ciscoBGPDown, verifyStatusFail, "not established"},
		{"arista prefix collapse", aristaBGPCollapse, verifyStatusFail, "prefix-count collapse"},
		{"junos down peer + active", junosBGPMixed, verifyStatusFail, "down peer"},
		{"vrp idle row", vrpBGPIdle, verifyStatusFail, "not established"},
		{"vrp healthy", vrpBGPHealthy, verifyStatusPass, "established"},
		{"nokia recent uptime + active peer", nokiaBGPSummary, verifyStatusFail, "reset inside the incident window"},
		{"bgp not running", "% BGP not active\n", verifyStatusSkipped, "not running"},
		{"gibberish", "hello world", verifyStatusSkipped, "unrecognized"},
	}
	for _, c := range cases {
		got, obs := parseBGPEdge(strings.TrimSpace(c.in), modNow, modCC)
		if got != c.wantStatus || !strings.Contains(obs, c.wantSub) {
			t.Errorf("%s: got %s %q", c.name, got, obs)
		}
	}
	// A summary whose only session is long-established with prefixes passes.
	healthy := `Neighbor        V           AS MsgRcvd MsgSent   TblVer  InQ OutQ Up/Down  State/PfxRcd
10.0.0.6        4        65002    9021    9033        5    0    0 5d02h         120
`
	if st, obs := parseBGPEdge(healthy, modNow, modCC); st != verifyStatusPass {
		t.Errorf("healthy summary must pass, got %s %q", st, obs)
	}
}

// ---- module 3: recent-change detector ---------------------------------------

func TestParseConfigChange(t *testing.T) {
	inWindow := "11:40:10 UTC Fri Jul 18 2026" // 20 min before now, inside window+slack
	old := "09:00:00 UTC Tue Jun 30 2026"      // weeks earlier
	cases := []struct {
		name, vendor, in, wantStatus, wantSub string
	}{
		{"ios-xe change inside window", "cisco",
			"Building configuration...\n! Last configuration change at " + inWindow + " by admin\n! NVRAM config last updated at 09:00:00 UTC Tue Jun 30 2026\nhostname edge-1\n",
			verifyStatusFail, "inside or shortly before"},
		{"ios-xe old change", "cisco",
			"! Last configuration change at " + old + " by admin\nhostname edge-1\n",
			verifyStatusPass, "predates"},
		{"ios-xr format inside window", "cisco",
			"!! IOS XR Configuration 7.5.2\n!! Last configuration change at Fri Jul 18 11:41:00 2026 by admin\n",
			verifyStatusFail, "inside or shortly before"},
		{"junos commit inside window", "juniper",
			"0   2026-07-18 11:42:33 UTC by admin via cli\n1   2026-07-01 08:00:00 UTC by admin via cli\n",
			verifyStatusFail, "inside or shortly before"},
		{"junos old commits", "juniper",
			"0   2026-06-20 08:00:00 UTC by admin via cli\n1   2026-06-01 08:00:00 UTC by admin via cli\n",
			verifyStatusPass, "predates"},
		{"vrp commit list inside window", "huawei",
			"Slot  CommitId      Label  User   TimeStamp\n1     1000000042    -      admin  2026-07-18 11:39:00\n",
			verifyStatusFail, "inside or shortly before"},
		{"nokia rollback inside window", "nokia",
			"Rollback Files\nIdx Suffix   Comment      Date\nlatest-rb    pre-change   2026/07/18 11:38:00\n",
			verifyStatusFail, "inside or shortly before"},
		{"arista unsaved diff", "arista",
			"--- flash:startup-config\n+++ system:running-config\n@@ -10,2 +10,3 @@\n+ntp server 10.9.9.9\n",
			verifyStatusFail, "unsaved"},
		{"arista no diff (empty output)", "arista", "", verifyStatusPass, "matches startup-config"},
		{"cisco nothing recognizable", "cisco", "hostname edge-1\ninterface Gi0/0\n", verifyStatusSkipped, "no configuration-change timestamp"},
	}
	for _, c := range cases {
		got, obs := parseVerifyModuleOutput("ssh_config_change", c.vendor, c.in, modNow, modCC)
		if got != c.wantStatus || !strings.Contains(obs, c.wantSub) {
			t.Errorf("%s: got %s %q", c.name, got, obs)
		}
	}
	// Unknown incident window falls back to a 24h lookback.
	noWin := verifyCaseContext{}
	if st, _ := parseConfigChange("! Last configuration change at 13:00:00 UTC Fri Jul 17 2026 by x", "cisco", modNow, noWin); st != verifyStatusFail {
		t.Errorf("change 23h ago with unknown window must fail, got %s", st)
	}
	if st, _ := parseConfigChange("! Last configuration change at 09:00:00 UTC Tue Jun 30 2026 by x", "cisco", modNow, noWin); st != verifyStatusPass {
		t.Errorf("old change with unknown window must pass, got %s", st)
	}
}

// ---- engine integration: module checks run only when fired ------------------

func TestEngineRunsFiredModulesWithEvidenceStamping(t *testing.T) {
	e := newVerifyEngineForCase(fakeDialers(map[string]verifySSHOut{
		"ssh_interfaces":    {Output: "Interface Status Protocol\nGi0/0 10.0.0.1 YES NVRAM up up\n"},
		"ssh_routing":       {Output: "Neighbor V AS Up/Down State/PfxRcd\n10.0.0.2 4 65001 00:10:11 42\n"},
		"ssh_iface_deep":    {Output: ciscoIfFaulty},
		"ssh_bgp_edge":      {Output: ciscoBGPDown},
		"ssh_config_change": {Output: "! Last configuration change at 11:40:10 UTC Fri Jul 18 2026 by admin\n"},
	}), modCC)
	e.now = func() time.Time { return modNow }
	m := resultsByCheck(e.run(context.Background(), []verifyTarget{testTarget()}))

	deep := m["ssh_iface_deep"]
	if deep.Status != verifyStatusFail || len(deep.CorroboratesKinds) != 3 {
		t.Fatalf("ssh_iface_deep: %+v", deep)
	}
	if deep.Command != "show interfaces" {
		t.Fatalf("executed module command must be recorded, got %q", deep.Command)
	}
	bgp := m["ssh_bgp_edge"]
	if bgp.Status != verifyStatusFail || len(bgp.CorroboratesKinds) != 3 {
		t.Fatalf("ssh_bgp_edge: %+v", bgp)
	}
	chg := m["ssh_config_change"]
	if chg.Status != verifyStatusFail || len(chg.CorroboratesKinds) != 1 || chg.CorroboratesKinds[0] != "config_change" {
		t.Fatalf("ssh_config_change: %+v", chg)
	}
}

func TestEngineSkipsUnfiredModules(t *testing.T) {
	// confirmed + netops + campus hypothesis ⇒ only iface_deep fires.
	cc := verifyCaseContext{Owner: "netops", TopHypothesis: "sig.ent.campus.stp-loop", VerdictTier: "confirmed"}
	e := newVerifyEngineForCase(fakeDialers(map[string]verifySSHOut{
		"ssh_iface_deep": {Output: ciscoIfClean},
	}), cc)
	m := resultsByCheck(e.run(context.Background(), []verifyTarget{testTarget()}))
	if _, present := m["ssh_bgp_edge"]; present {
		t.Fatal("bgp_edge must not run for a non-edge case")
	}
	if _, present := m["ssh_config_change"]; present {
		t.Fatal("recent_change must not run for a confirmed case")
	}
	if m["ssh_iface_deep"].Status != verifyStatusPass {
		t.Fatalf("ssh_iface_deep: %+v", m["ssh_iface_deep"])
	}
	// Healthy module checks refute their declared vocabulary.
	if got := m["ssh_iface_deep"].RefutesKinds; len(got) != 2 {
		t.Fatalf("refutes stamping: %+v", got)
	}
}
