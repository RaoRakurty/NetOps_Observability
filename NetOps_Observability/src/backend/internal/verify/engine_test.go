package verify

// verify_engine_test.go — Active Verification engine (RCA spec item 8):
// allowlist enforcement (a non-allowlisted command must be IMPOSSIBLE),
// timeout/budget behavior against fake slow targets, result normalization,
// conservative output parsing, and an end-to-end run against an in-process
// fake SSH server (golang.org/x/crypto/ssh server side).

import (
	"context"
	"sort"
	"strings"
	"testing"
	"time"

	"netops/backend/collectors"
	"netops/backend/models"
)

// ---- allowlist: the closed table ------------------------------------------

// TestVerifyCommandTableReadOnly asserts the read-only invariant over the table
// the vendor-profile REGISTRY serves (T9: the command knowledge moved into
// internal/vendorprofile's `verify.commands` blocks; the invariant did not).
// The registry enforces the same shape at load — this test is the independent
// second assertion, and it is what fails first if the enforcement is ever
// loosened there.
func TestVerifyCommandTableReadOnly(t *testing.T) {
	// "configure" (the config-MODE verb) is forbidden; reading configuration
	// state ("show running-config", "display configuration commit list") is
	// exactly what the recent-change module exists to do and stays legal.
	forbidden := []string{";", "|", "&", "`", "$", "\n", "reload", "configure", "write ", "copy ", "delete", "clear ", "request ", "rollback "}
	table := CommandTable()
	if len(table) == 0 {
		t.Fatal("the registry served an EMPTY command table — the battery would silently skip every ssh check")
	}
	for _, table := range []map[string]map[string]string{table} {
		for vendor, fam := range table {
			for check, cmd := range fam {
				if !strings.HasPrefix(cmd, "show ") && !strings.HasPrefix(cmd, "display ") {
					t.Fatalf("%s/%s: command %q is not a read-only show/display command", vendor, check, cmd)
				}
				for _, tok := range forbidden {
					if strings.Contains(cmd, tok) {
						t.Fatalf("%s/%s: command %q contains forbidden token %q", vendor, check, cmd, tok)
					}
				}
			}
		}
	}
}

// TestVerifyCommandTableMatchesTheShippedRows pins the EXACT table the registry
// serves. It is the T9 no-regression gate: the rows below are the ones the
// in-code verifyCommandTable / verifyModuleCommandTable literals held before
// they moved into the profile documents, byte for byte.
func TestVerifyCommandTableMatchesTheShippedRows(t *testing.T) {
	want := map[string]map[string]string{
		"cisco": {
			"ssh_interfaces":    "show ip interface brief",
			"ssh_routing":       "show ip bgp summary",
			"ssh_iface_deep":    "show interfaces",
			"ssh_bgp_edge":      "show bgp all summary",
			"ssh_config_change": "show running-config",
		},
		"arista": {
			"ssh_interfaces":    "show interfaces status",
			"ssh_routing":       "show ip bgp summary",
			"ssh_iface_deep":    "show interfaces",
			"ssh_bgp_edge":      "show ip bgp summary vrf all",
			"ssh_config_change": "show running-config diffs",
		},
		"juniper": {
			"ssh_interfaces":    "show interfaces terse",
			"ssh_routing":       "show bgp summary",
			"ssh_iface_deep":    "show interfaces extensive",
			"ssh_bgp_edge":      "show bgp summary",
			"ssh_config_change": "show system commit",
		},
		"huawei": {
			"ssh_interfaces":    "display interface brief",
			"ssh_routing":       "display bgp peer",
			"ssh_iface_deep":    "display interface",
			"ssh_bgp_edge":      "display bgp peer",
			"ssh_config_change": "display configuration commit list",
		},
		"nokia": {
			"ssh_interfaces":    "show port",
			"ssh_routing":       "show router bgp summary",
			"ssh_iface_deep":    "show port detail",
			"ssh_bgp_edge":      "show router bgp summary",
			"ssh_config_change": "show system rollback",
		},
	}
	got := CommandTable()
	if len(got) != len(want) {
		t.Fatalf("vendor families: got %d (%v), want %d", len(got), keysOf(got), len(want))
	}
	for vendor, wantFam := range want {
		gotFam, ok := got[vendor]
		if !ok {
			t.Fatalf("vendor %q missing from the registry table", vendor)
		}
		if len(gotFam) != len(wantFam) {
			t.Fatalf("vendor %q: got %d rows, want %d", vendor, len(gotFam), len(wantFam))
		}
		for check, wantCmd := range wantFam {
			if gotCmd := gotFam[check]; gotCmd != wantCmd {
				t.Errorf("%s/%s = %q, want %q", vendor, check, gotCmd, wantCmd)
			}
		}
	}
}

// TestVerifyCommandTableIsACopy proves the accessor hands out a COPY: a caller
// that mutates what it got must not be able to widen what the runner will run.
func TestVerifyCommandTableIsACopy(t *testing.T) {
	tbl := CommandTable()
	tbl["cisco"]["ssh_interfaces"] = "reload"
	tbl["acme"] = map[string]string{"ssh_interfaces": "reload"}
	if CommandAllowed("reload") {
		t.Fatal("mutating the returned table widened the allowlist")
	}
	if cmd, _ := CommandFor("cisco", "ssh_interfaces"); cmd != "show ip interface brief" {
		t.Fatalf("mutating the returned table changed a resolution: %q", cmd)
	}
	if _, ok := CommandFor("acme", "ssh_interfaces"); ok {
		t.Fatal("mutating the returned table added a vendor family")
	}
}

func keysOf(m map[string]map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func TestVerifyCommandForClosedTable(t *testing.T) {
	if _, ok := CommandFor("cisco", "ssh_interfaces"); !ok {
		t.Fatal("cisco ssh_interfaces must resolve")
	}
	if _, ok := CommandFor("mikrotik", "ssh_interfaces"); ok {
		t.Fatal("unknown vendor must not resolve a command")
	}
	if _, ok := CommandFor("cisco", "ssh_reboot"); ok {
		t.Fatal("unknown check must not resolve a command")
	}
}

func TestVerifyCommandAllowedRejectsEverythingElse(t *testing.T) {
	if !CommandAllowed("show ip interface brief") {
		t.Fatal("table command must be allowed")
	}
	for _, cmd := range []string{
		"reload",
		"configure terminal",
		"show ip interface brief; reload",
		"show ip interface brief\nreload",
		"write memory",
		"",
		"SHOW IP INTERFACE BRIEF", // verbatim match only — no normalization surface
	} {
		if CommandAllowed(cmd) {
			t.Fatalf("command %q must NOT be allowed", cmd)
		}
	}
}

// ---- engine: normalization, skips, bounds ---------------------------------

func fakeDialers(sshOut map[string]SSHOut) Dialers {
	return Dialers{
		TCPReach:   func(ctx context.Context, addr string) error { return nil },
		SNMPReach:  func(ctx context.Context, tgt collectors.Target) error { return nil },
		SNMPUptime: func(ctx context.Context, tgt collectors.Target) (int64, error) { return 50, nil },
		SSHRun: func(ctx context.Context, dev models.Device, cred SSHCred, cmds map[string]string) map[string]SSHOut {
			out := map[string]SSHOut{}
			for id := range cmds {
				if r, ok := sshOut[id]; ok {
					out[id] = r
				}
			}
			return out
		},
	}
}

func testTarget() Target {
	return Target{
		Device: models.Device{ID: "dev-1", Name: "edge-1", Address: "10.0.0.1", Vendor: "cisco"},
		SNMP:   &collectors.Target{ID: "dev-1", Address: "10.0.0.1", Community: "public"},
		SSH:    &SSHCred{User: "verify", Password: "x"},
	}
}

func resultsByCheck(rs []CheckResult) map[string]CheckResult {
	m := map[string]CheckResult{}
	for _, r := range rs {
		m[r.Check] = r
	}
	return m
}

func TestEngineNormalizationAndEvidenceStamping(t *testing.T) {
	e := NewEngine(fakeDialers(map[string]SSHOut{
		"ssh_interfaces": {Output: "Interface IP-Address OK? Method Status Protocol\nGi0/0 10.0.0.1 YES NVRAM up up\nGi0/1 unassigned YES NVRAM up down\n"},
		"ssh_routing":    {Output: "Neighbor V AS MsgRcvd MsgSent TblVer InQ OutQ Up/Down State/PfxRcd\n10.0.0.2 4 65001 10 10 5 0 0 00:10:11 42\n"},
	}))
	rs := e.Run(context.Background(), []Target{testTarget()})
	if len(rs) != len(verifyBattery()) {
		t.Fatalf("want %d results, got %d: %+v", len(verifyBattery()), len(rs), rs)
	}
	m := resultsByCheck(rs)

	if m["reach_tcp"].Status != StatusPass {
		t.Fatalf("reach_tcp: %+v", m["reach_tcp"])
	}
	if m["reach_tcp"].RefutesKinds != nil {
		t.Fatal("reach probes must claim no refuting vocabulary")
	}
	// uptime 50s < 900s ⇒ recent restart ⇒ FAIL corroborating device_restart
	up := m["snmp_uptime"]
	if up.Status != StatusFail || len(up.CorroboratesKinds) != 1 || up.CorroboratesKinds[0] != "device_restart" {
		t.Fatalf("snmp_uptime: %+v", up)
	}
	// one admin-up/oper-down interface ⇒ FAIL corroborating link_state_change
	ifs := m["ssh_interfaces"]
	if ifs.Status != StatusFail || len(ifs.CorroboratesKinds) != 1 || ifs.CorroboratesKinds[0] != "link_state_change" {
		t.Fatalf("ssh_interfaces: %+v", ifs)
	}
	if ifs.Command != "show ip interface brief" {
		t.Fatalf("executed command must be recorded, got %q", ifs.Command)
	}
	// all neighbors established ⇒ PASS refuting the bgp kinds
	bgp := m["ssh_routing"]
	if bgp.Status != StatusPass || len(bgp.RefutesKinds) != 2 {
		t.Fatalf("ssh_routing: %+v", bgp)
	}
	for _, r := range rs {
		if r.DeviceID != "dev-1" || r.Ts.IsZero() || r.Method == "" {
			t.Fatalf("normalization incomplete: %+v", r)
		}
	}
}

func TestEngineSkipsChecksWithoutChannels(t *testing.T) {
	e := NewEngine(fakeDialers(nil))
	tgt := testTarget()
	tgt.SNMP = nil
	tgt.SSH = nil
	m := resultsByCheck(e.Run(context.Background(), []Target{tgt}))
	for _, check := range []string{"reach_snmp", "snmp_uptime", "ssh_interfaces", "ssh_routing"} {
		r := m[check]
		if r.Status != StatusSkipped || r.Observed == "" {
			t.Fatalf("%s must be skipped with a reason, got %+v", check, r)
		}
		if r.RefutesKinds != nil || r.CorroboratesKinds != nil {
			t.Fatalf("a skipped check must claim nothing: %+v", r)
		}
	}
	if m["reach_tcp"].Status != StatusPass {
		t.Fatalf("tcp reach needs no credential: %+v", m["reach_tcp"])
	}
}

func TestEnginePerCheckTimeout(t *testing.T) {
	d := fakeDialers(nil)
	d.TCPReach = func(ctx context.Context, addr string) error {
		<-ctx.Done() // a black-holed target: blocks until the per-check deadline
		return ctx.Err()
	}
	e := NewEngine(d)
	e.checkTimeout = 50 * time.Millisecond
	start := time.Now()
	m := resultsByCheck(e.Run(context.Background(), []Target{{
		Device: models.Device{ID: "dev-1", Address: "10.0.0.9"},
	}}))
	if m["reach_tcp"].Status != verifyStatusUnreachable {
		t.Fatalf("blocked dial must normalize to unreachable: %+v", m["reach_tcp"])
	}
	if took := time.Since(start); took > 5*time.Second {
		t.Fatalf("per-check timeout did not bound the run: %v", took)
	}
}

func TestEngineRunBudgetSkipsRemainder(t *testing.T) {
	d := fakeDialers(nil)
	d.SNMPReach = func(ctx context.Context, tgt collectors.Target) error {
		select { // slow target — each snmp group eats the whole budget
		case <-ctx.Done():
		case <-time.After(2 * time.Second):
		}
		return ctx.Err()
	}
	d.SNMPUptime = func(ctx context.Context, tgt collectors.Target) (int64, error) {
		<-ctx.Done()
		return 0, ctx.Err()
	}
	e := NewEngine(d)
	e.runBudget = 150 * time.Millisecond
	e.checkTimeout = 100 * time.Millisecond
	e.maxConc = 1 // serialize so later groups find the budget exhausted

	targets := []Target{testTarget(), func() Target {
		tgt := testTarget()
		tgt.Device.ID = "dev-2"
		return tgt
	}()}
	start := time.Now()
	rs := e.Run(context.Background(), targets)
	if took := time.Since(start); took > 3*time.Second {
		t.Fatalf("run budget did not bound the run: %v", took)
	}
	skipped := 0
	for _, r := range rs {
		if r.Status == StatusSkipped && strings.Contains(r.Observed, "budget") {
			skipped++
		}
	}
	if skipped == 0 {
		t.Fatalf("expected budget-skipped checks, got %+v", rs)
	}
	// every planned check is accounted for — never silently dropped
	if len(rs) != 2*len(verifyBattery()) {
		t.Fatalf("want %d results, got %d", 2*len(verifyBattery()), len(rs))
	}
}

// ---- output parsing --------------------------------------------------------

func TestParseVerifyOutputConservative(t *testing.T) {
	cases := []struct {
		check, output, wantStatus string
	}{
		{"ssh_interfaces", "Interface Status Protocol\nGi0/0 up up\nGi0/1 up up\n", StatusPass},
		{"ssh_interfaces", "Interface Status Protocol\nGi0/1 unassigned YES NVRAM up down\n", StatusFail},
		{"ssh_interfaces", "Interface Status Protocol\nGi0/2 unassigned YES NVRAM administratively down down\n", StatusPass},
		{"ssh_interfaces", "Port Name Status Vlan\nEt1  uplink errdisabled 1\nEt2  x connected 1\n", StatusFail},
		{"ssh_interfaces", "ge-0/0/0 up down\nge-0/0/1 up up\n", StatusFail},
		{"ssh_interfaces", "", StatusSkipped},
		{"ssh_interfaces", "% Invalid input detected", StatusSkipped},
		{"ssh_routing", "Neighbor V AS State\n10.0.0.2 4 65001 0 0 1 0 0 never Idle\n", StatusFail},
		{"ssh_routing", "Neighbor V AS Up/Down State/PfxRcd\n10.0.0.2 4 65001 00:11:22 42\n", StatusPass},
		{"ssh_routing", "Peer AS InPkt State\n10.0.0.2 65001 100 Establ\n", StatusPass},
		{"ssh_routing", "% BGP not active\n", StatusSkipped},
		{"ssh_routing", "gibberish", StatusSkipped},
	}
	for _, c := range cases {
		got, observed := parseVerifyOutput(c.check, c.output)
		if got != c.wantStatus {
			t.Errorf("%s %q: want %s got %s (%s)", c.check, c.output, c.wantStatus, got, observed)
		}
	}
}

func TestSanitizeObservedStripsControlAndBounds(t *testing.T) {
	in := "a\x1b[31mb\x00c" + strings.Repeat("x", 1000)
	out := sanitizeObserved(in)
	if strings.ContainsAny(out, "\x1b\x00") {
		t.Fatal("control characters must be stripped")
	}
	if len(out) > 500 {
		t.Fatalf("observed must be capped, got %d", len(out))
	}
}

// ---- e2e: fake SSH server --------------------------------------------------

// The routing parser's conservative fail: a BGP neighbor that has never come
// up ("never Idle") must fail verification. (Kept here when the fake-SSH
// transport tests moved to the integrator: the parser is package territory.)
func TestParseVerifyOutputIdleNeighborFails(t *testing.T) {
	st, obs := parseVerifyOutput("ssh_routing", "Neighbor V AS State\n10.0.0.2 4 65001 never Idle\n")
	if st != StatusFail {
		t.Fatalf("fake Idle neighbor must fail verification: %s %s", st, obs)
	}
}
