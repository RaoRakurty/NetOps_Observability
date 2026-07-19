package main

// verify_engine_test.go — Active Verification engine (RCA spec item 8):
// allowlist enforcement (a non-allowlisted command must be IMPOSSIBLE),
// timeout/budget behavior against fake slow targets, result normalization,
// conservative output parsing, and an end-to-end run against an in-process
// fake SSH server (golang.org/x/crypto/ssh server side).

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"netops/backend/collectors"
	"netops/backend/models"

	"golang.org/x/crypto/ssh"
)

// ---- allowlist: the closed table ------------------------------------------

func TestVerifyCommandTableReadOnly(t *testing.T) {
	// "configure" (the config-MODE verb) is forbidden; reading configuration
	// state ("show running-config", "display configuration commit list") is
	// exactly what the recent-change module exists to do and stays legal.
	forbidden := []string{";", "|", "&", "`", "$", "\n", "reload", "configure", "write ", "copy ", "delete", "clear ", "request ", "rollback "}
	for _, table := range []map[string]map[string]string{verifyCommandTable, verifyModuleCommandTable} {
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

func TestVerifyCommandForClosedTable(t *testing.T) {
	if _, ok := verifyCommandFor("cisco", "ssh_interfaces"); !ok {
		t.Fatal("cisco ssh_interfaces must resolve")
	}
	if _, ok := verifyCommandFor("mikrotik", "ssh_interfaces"); ok {
		t.Fatal("unknown vendor must not resolve a command")
	}
	if _, ok := verifyCommandFor("cisco", "ssh_reboot"); ok {
		t.Fatal("unknown check must not resolve a command")
	}
}

func TestVerifyCommandAllowedRejectsEverythingElse(t *testing.T) {
	if !verifyCommandAllowed("show ip interface brief") {
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
		if verifyCommandAllowed(cmd) {
			t.Fatalf("command %q must NOT be allowed", cmd)
		}
	}
}

func TestVerifySSHRunRefusesNonAllowlistedCommand(t *testing.T) {
	s := &server{sshHosts: newSSHHostStore(filepath.Join(t.TempDir(), "hosts.json"))}
	// Even when a caller hands the runner an arbitrary command, it must be
	// refused before any network IO for that command.
	out := s.verifySSHRun(context.Background(), models.Device{ID: "d1", Address: "127.0.0.1"},
		verifySSHCred{User: "u", Password: "p", Port: 1}, // port 1: nothing listens
		map[string]string{"evil": "reload"})
	res, ok := out["evil"]
	if !ok || res.Err == nil || !strings.Contains(res.Err.Error(), "allowlist") {
		t.Fatalf("non-allowlisted command must be refused, got %+v", res)
	}
}

// ---- engine: normalization, skips, bounds ---------------------------------

func fakeDialers(sshOut map[string]verifySSHOut) verifyDialers {
	return verifyDialers{
		TCPReach:   func(ctx context.Context, addr string) error { return nil },
		SNMPReach:  func(ctx context.Context, tgt collectors.Target) error { return nil },
		SNMPUptime: func(ctx context.Context, tgt collectors.Target) (int64, error) { return 50, nil },
		SSHRun: func(ctx context.Context, dev models.Device, cred verifySSHCred, cmds map[string]string) map[string]verifySSHOut {
			out := map[string]verifySSHOut{}
			for id := range cmds {
				if r, ok := sshOut[id]; ok {
					out[id] = r
				}
			}
			return out
		},
	}
}

func testTarget() verifyTarget {
	return verifyTarget{
		Device: models.Device{ID: "dev-1", Name: "edge-1", Address: "10.0.0.1", Vendor: "cisco"},
		SNMP:   &collectors.Target{ID: "dev-1", Address: "10.0.0.1", Community: "public"},
		SSH:    &verifySSHCred{User: "verify", Password: "x"},
	}
}

func resultsByCheck(rs []verifyCheckResult) map[string]verifyCheckResult {
	m := map[string]verifyCheckResult{}
	for _, r := range rs {
		m[r.Check] = r
	}
	return m
}

func TestEngineNormalizationAndEvidenceStamping(t *testing.T) {
	e := newVerifyEngine(fakeDialers(map[string]verifySSHOut{
		"ssh_interfaces": {Output: "Interface IP-Address OK? Method Status Protocol\nGi0/0 10.0.0.1 YES NVRAM up up\nGi0/1 unassigned YES NVRAM up down\n"},
		"ssh_routing":    {Output: "Neighbor V AS MsgRcvd MsgSent TblVer InQ OutQ Up/Down State/PfxRcd\n10.0.0.2 4 65001 10 10 5 0 0 00:10:11 42\n"},
	}))
	rs := e.run(context.Background(), []verifyTarget{testTarget()})
	if len(rs) != len(verifyBattery()) {
		t.Fatalf("want %d results, got %d: %+v", len(verifyBattery()), len(rs), rs)
	}
	m := resultsByCheck(rs)

	if m["reach_tcp"].Status != verifyStatusPass {
		t.Fatalf("reach_tcp: %+v", m["reach_tcp"])
	}
	if m["reach_tcp"].RefutesKinds != nil {
		t.Fatal("reach probes must claim no refuting vocabulary")
	}
	// uptime 50s < 900s ⇒ recent restart ⇒ FAIL corroborating device_restart
	up := m["snmp_uptime"]
	if up.Status != verifyStatusFail || len(up.CorroboratesKinds) != 1 || up.CorroboratesKinds[0] != "device_restart" {
		t.Fatalf("snmp_uptime: %+v", up)
	}
	// one admin-up/oper-down interface ⇒ FAIL corroborating link_state_change
	ifs := m["ssh_interfaces"]
	if ifs.Status != verifyStatusFail || len(ifs.CorroboratesKinds) != 1 || ifs.CorroboratesKinds[0] != "link_state_change" {
		t.Fatalf("ssh_interfaces: %+v", ifs)
	}
	if ifs.Command != "show ip interface brief" {
		t.Fatalf("executed command must be recorded, got %q", ifs.Command)
	}
	// all neighbors established ⇒ PASS refuting the bgp kinds
	bgp := m["ssh_routing"]
	if bgp.Status != verifyStatusPass || len(bgp.RefutesKinds) != 2 {
		t.Fatalf("ssh_routing: %+v", bgp)
	}
	for _, r := range rs {
		if r.DeviceID != "dev-1" || r.Ts.IsZero() || r.Method == "" {
			t.Fatalf("normalization incomplete: %+v", r)
		}
	}
}

func TestEngineSkipsChecksWithoutChannels(t *testing.T) {
	e := newVerifyEngine(fakeDialers(nil))
	tgt := testTarget()
	tgt.SNMP = nil
	tgt.SSH = nil
	m := resultsByCheck(e.run(context.Background(), []verifyTarget{tgt}))
	for _, check := range []string{"reach_snmp", "snmp_uptime", "ssh_interfaces", "ssh_routing"} {
		r := m[check]
		if r.Status != verifyStatusSkipped || r.Observed == "" {
			t.Fatalf("%s must be skipped with a reason, got %+v", check, r)
		}
		if r.RefutesKinds != nil || r.CorroboratesKinds != nil {
			t.Fatalf("a skipped check must claim nothing: %+v", r)
		}
	}
	if m["reach_tcp"].Status != verifyStatusPass {
		t.Fatalf("tcp reach needs no credential: %+v", m["reach_tcp"])
	}
}

func TestEnginePerCheckTimeout(t *testing.T) {
	d := fakeDialers(nil)
	d.TCPReach = func(ctx context.Context, addr string) error {
		<-ctx.Done() // a black-holed target: blocks until the per-check deadline
		return ctx.Err()
	}
	e := newVerifyEngine(d)
	e.checkTimeout = 50 * time.Millisecond
	start := time.Now()
	m := resultsByCheck(e.run(context.Background(), []verifyTarget{{
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
	e := newVerifyEngine(d)
	e.runBudget = 150 * time.Millisecond
	e.checkTimeout = 100 * time.Millisecond
	e.maxConc = 1 // serialize so later groups find the budget exhausted

	targets := []verifyTarget{testTarget(), func() verifyTarget {
		tgt := testTarget()
		tgt.Device.ID = "dev-2"
		return tgt
	}()}
	start := time.Now()
	rs := e.run(context.Background(), targets)
	if took := time.Since(start); took > 3*time.Second {
		t.Fatalf("run budget did not bound the run: %v", took)
	}
	skipped := 0
	for _, r := range rs {
		if r.Status == verifyStatusSkipped && strings.Contains(r.Observed, "budget") {
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
		{"ssh_interfaces", "Interface Status Protocol\nGi0/0 up up\nGi0/1 up up\n", verifyStatusPass},
		{"ssh_interfaces", "Interface Status Protocol\nGi0/1 unassigned YES NVRAM up down\n", verifyStatusFail},
		{"ssh_interfaces", "Interface Status Protocol\nGi0/2 unassigned YES NVRAM administratively down down\n", verifyStatusPass},
		{"ssh_interfaces", "Port Name Status Vlan\nEt1  uplink errdisabled 1\nEt2  x connected 1\n", verifyStatusFail},
		{"ssh_interfaces", "ge-0/0/0 up down\nge-0/0/1 up up\n", verifyStatusFail},
		{"ssh_interfaces", "", verifyStatusSkipped},
		{"ssh_interfaces", "% Invalid input detected", verifyStatusSkipped},
		{"ssh_routing", "Neighbor V AS State\n10.0.0.2 4 65001 0 0 1 0 0 never Idle\n", verifyStatusFail},
		{"ssh_routing", "Neighbor V AS Up/Down State/PfxRcd\n10.0.0.2 4 65001 00:11:22 42\n", verifyStatusPass},
		{"ssh_routing", "Peer AS InPkt State\n10.0.0.2 65001 100 Establ\n", verifyStatusPass},
		{"ssh_routing", "% BGP not active\n", verifyStatusSkipped},
		{"ssh_routing", "gibberish", verifyStatusSkipped},
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

func newTestHostSigner(t *testing.T) ssh.Signer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return signer
}

// startFakeSSHServer serves password-auth SSH sessions answering exec requests
// from the canned outputs map. Returns the listen port.
func startFakeSSHServer(t *testing.T, signer ssh.Signer, outputs map[string]string) int {
	t.Helper()
	cfg := &ssh.ServerConfig{
		PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			if c.User() == "verify" && string(pass) == "pw" {
				return nil, nil
			}
			return nil, errors.New("bad credentials")
		},
	}
	cfg.AddHostKey(signer)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, aerr := ln.Accept()
			if aerr != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				sconn, chans, reqs, herr := ssh.NewServerConn(c, cfg)
				if herr != nil {
					return
				}
				defer sconn.Close()
				go ssh.DiscardRequests(reqs)
				for newChan := range chans {
					if newChan.ChannelType() != "session" {
						_ = newChan.Reject(ssh.UnknownChannelType, "unsupported")
						continue
					}
					ch, chReqs, cerr := newChan.Accept()
					if cerr != nil {
						continue
					}
					go func(ch ssh.Channel, chReqs <-chan *ssh.Request) {
						defer ch.Close()
						for req := range chReqs {
							if req.Type != "exec" {
								_ = req.Reply(false, nil)
								continue
							}
							var payload struct{ Command string }
							if ssh.Unmarshal(req.Payload, &payload) != nil {
								_ = req.Reply(false, nil)
								continue
							}
							_ = req.Reply(true, nil)
							if out, ok := outputs[payload.Command]; ok {
								_, _ = ch.Write([]byte(out))
							}
							_, _ = ch.SendRequest("exit-status", false, []byte{0, 0, 0, 0})
							return // one exec per session, like real network OSes
						}
					}(ch, chReqs)
				}
			}(conn)
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port
}

func TestVerifySSHRunAgainstFakeServer(t *testing.T) {
	signer := newTestHostSigner(t)
	port := startFakeSSHServer(t, signer, map[string]string{
		"show ip interface brief": "Interface Status Protocol\nGi0/0 up up\nGi0/1 up down\n",
		"show ip bgp summary":     "Neighbor V AS State\n10.0.0.2 4 65001 never Idle\n",
	})
	s := &server{sshHosts: newSSHHostStore(filepath.Join(t.TempDir(), "hosts.json"))}
	dev := models.Device{ID: "dev-1", Name: "edge-1", Address: "127.0.0.1", Vendor: "cisco"}
	cred := verifySSHCred{User: "verify", Password: "pw", Port: port}

	out := s.verifySSHRun(context.Background(), dev, cred, map[string]string{
		"ssh_interfaces": "show ip interface brief",
		"ssh_routing":    "show ip bgp summary",
	})
	if len(out) != 2 {
		t.Fatalf("want 2 outputs, got %+v", out)
	}
	if out["ssh_interfaces"].Err != nil || !strings.Contains(out["ssh_interfaces"].Output, "Gi0/1") {
		t.Fatalf("ssh_interfaces: %+v", out["ssh_interfaces"])
	}
	st, obs := parseVerifyOutput("ssh_routing", out["ssh_routing"].Output)
	if st != verifyStatusFail {
		t.Fatalf("fake Idle neighbor must fail verification: %s %s", st, obs)
	}

	// TOFU: a NEW host key on the same address must be refused (possible MITM).
	otherSigner := newTestHostSigner(t)
	port2 := startFakeSSHServer(t, otherSigner, nil)
	cred.Port = port2
	out2 := s.verifySSHRun(context.Background(), dev, cred, map[string]string{
		"ssh_routing": "show ip bgp summary",
	})
	if out2["ssh_routing"].Err == nil || !strings.Contains(out2["ssh_routing"].Err.Error(), "host key mismatch") {
		t.Fatalf("changed host key must be refused, got %+v", out2["ssh_routing"])
	}
}

func TestVerifyEngineEndToEndWithFakeSSH(t *testing.T) {
	signer := newTestHostSigner(t)
	port := startFakeSSHServer(t, signer, map[string]string{
		"show ip interface brief": "Interface Status Protocol\nGi0/0 up up\n",
		"show ip bgp summary":     "Neighbor V AS Up/Down State/PfxRcd\n10.0.0.2 4 65001 01:02:03 12\n",
	})
	s := &server{sshHosts: newSSHHostStore(filepath.Join(t.TempDir(), "hosts.json"))}
	d := s.newVerifyDialers()
	// no SNMP daemon in tests: keep snmp faked, exercise tcp + ssh for real
	d.SNMPReach = func(ctx context.Context, tgt collectors.Target) error { return nil }
	d.SNMPUptime = func(ctx context.Context, tgt collectors.Target) (int64, error) { return 4000, nil }
	e := newVerifyEngine(d)
	tgt := verifyTarget{
		Device: models.Device{ID: "dev-1", Name: "edge-1", Address: "127.0.0.1", Vendor: "cisco"},
		SNMP:   &collectors.Target{ID: "dev-1", Address: "127.0.0.1"},
		SSH:    &verifySSHCred{User: "verify", Password: "pw", Port: port},
	}
	m := resultsByCheck(e.run(context.Background(), []verifyTarget{tgt}))
	if m["reach_tcp"].Status != verifyStatusPass {
		t.Fatalf("reach_tcp against live listener: %+v", m["reach_tcp"])
	}
	if m["snmp_uptime"].Status != verifyStatusPass || len(m["snmp_uptime"].RefutesKinds) != 1 {
		t.Fatalf("snmp_uptime: %+v", m["snmp_uptime"])
	}
	if m["ssh_interfaces"].Status != verifyStatusPass {
		t.Fatalf("ssh_interfaces: %+v", m["ssh_interfaces"])
	}
	if m["ssh_routing"].Status != verifyStatusPass || len(m["ssh_routing"].RefutesKinds) != 2 {
		t.Fatalf("ssh_routing: %+v", m["ssh_routing"])
	}
}
