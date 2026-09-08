// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package osprobe

// identity_test.go — the HARDWARE IDENTITY half of the ladder: the SSH rung
// reading a chassis serial and model on the visit it was already making, and
// the overwrite/plan rules that decide whether the row can accept it.
//
// Like sources_test.go these run against the SHIPPED profile data: the thing
// most likely to break is the authored commands and patterns, not this Go code.

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"netops/backend/internal/deviceident"
	"netops/backend/internal/vendorprofile"
)

// ── fixtures (see internal/deviceident/fixtures_test.go for provenance) ──────

const identSRLinuxShowVersion = `--------------------------------------------------------------------------------
Hostname             : spine1
Chassis Type         : 7220 IXR-D3L
Part Number          : Sim Part No.
Serial Number        : Sim Serial No.
System HW MAC Address: 1A:9E:02:FF:00:00
OS                   : SR Linux
Software Version     : v26.3.2
Build Number         : 426-g2b38957bbca
--------------------------------------------------------------------------------`

const identIOSXEShowVersion = `Cisco IOS XE Software, Version 17.09.04a
Cisco IOS Software [Cupertino], Catalyst L3 Switch Software (CAT9K_IOSXE), Version 17.9.4a, RELEASE SOFTWARE (fc1)

switch uptime is 41 weeks, 2 days, 6 hours, 11 minutes

cisco C9300-48P (X86) processor with 1343803K/6147K bytes of memory.
`

const identIOSXEShowInventory = `NAME: "Switch1 Chassis", DESCR: "Cisco Catalyst 9300 Series Switch"
PID: C9300-48P         , VID: V03  , SN: FOC2130Z0RD
`

const identIOSXRShowInventory = `NAME: "Rack 0", DESCR: "Cisco ASR9006 4 Line Card Slot Chassis with V2 AC PEM"
PID: ASR-9006-AC-V2, VID: V01, SN: FOX1441GPWM
`

// scriptRunner answers per command and records the exact command sequence, so a
// test can prove not just WHAT was read but how many times the device was asked.
type scriptRunner struct {
	answers  map[string]string
	fail     map[string]error
	commands []string
}

func (r *scriptRunner) Run(_ context.Context, _ Target, command string) (string, error) {
	r.commands = append(r.commands, command)
	if err, ok := r.fail[command]; ok {
		return "", err
	}
	out, ok := r.answers[command]
	if !ok {
		return "", errors.New("no script for " + command)
	}
	return out, nil
}

func srlinuxTarget() Target {
	return Target{DeviceID: "spine1", Address: "172.40.40.11", Vendor: "nokia", OSText: "SR Linux", TenantID: "acme"}
}

func iosxeTarget() Target {
	return Target{DeviceID: "cat-1", Address: "10.0.0.9", Vendor: "cisco", OSText: "Cisco IOS-XE 17.9", TenantID: "acme"}
}

// ── the rung ────────────────────────────────────────────────────────────────

// TestSSHRungReadsIdentityFromTheShowVersionItAlreadyRan is the property that
// makes this an extension of the OS-version rung rather than a second probe: on
// a platform whose identity is in its own show-version output, the device is
// asked ONCE and answers both questions.
func TestSSHRungReadsIdentityFromTheShowVersionItAlreadyRan(t *testing.T) {
	run := &scriptRunner{answers: map[string]string{"show version": identSRLinuxShowVersion}}
	src := NewSSHSource(run, vendorprofile.Default())

	version, id, err := src.ProbeWithIdentity(context.Background(), srlinuxTarget())
	if err != nil {
		t.Fatalf("probe: %v", err)
	}
	if version != "SRLinux-v26.3.2" {
		t.Errorf("version = %q, want SRLinux-v26.3.2", version)
	}
	if id.Serial != "Sim Serial No." || id.Model != "7220 IXR-D3L" {
		t.Errorf("identity = %+v, want the chassis serial and type the device printed", id)
	}
	if len(run.commands) != 1 {
		t.Errorf("ran %v — one command must answer both questions on this platform", run.commands)
	}
}

// TestSSHRungRunsTheSecondCommandOnlyWhenTheFirstDidNotAnswer — IOS-XE's serial
// is not in the show-version banner this fixture carries, so the profile's
// second authored command is run; the model, which WAS in the banner, is kept
// from the first.
func TestSSHRungRunsTheSecondCommandOnlyWhenTheFirstDidNotAnswer(t *testing.T) {
	run := &scriptRunner{answers: map[string]string{
		"show version":   identIOSXEShowVersion,
		"show inventory": identIOSXEShowInventory,
	}}
	src := NewSSHSource(run, vendorprofile.Default())

	version, id, err := src.ProbeWithIdentity(context.Background(), iosxeTarget())
	if err != nil {
		t.Fatalf("probe: %v", err)
	}
	if version != "Version 17.09.04a" {
		t.Errorf("version = %q", version)
	}
	if id.Serial != "FOC2130Z0RD" {
		t.Errorf("serial = %q, want the inventory's chassis serial", id.Serial)
	}
	if id.SerialCommand != "show inventory" {
		t.Errorf("serial_command = %q, want show inventory", id.SerialCommand)
	}
	if id.Model != "C9300-48P" || id.ModelCommand != "show version" {
		t.Errorf("model = %q via %q, want C9300-48P from the banner already in hand", id.Model, id.ModelCommand)
	}
	if want := []string{"show version", "show inventory"}; !equalStrings(run.commands, want) {
		t.Errorf("ran %v, want %v", run.commands, want)
	}
}

// TestSSHRungStopsWhenBothFieldsAreKnown — a platform whose first command
// answered everything never pays for the second.
func TestSSHRungStopsWhenBothFieldsAreKnown(t *testing.T) {
	full := identIOSXEShowVersion + "\nSystem Serial Number               : FOC2130Z0RD\n"
	run := &scriptRunner{answers: map[string]string{
		"show version":   full,
		"show inventory": identIOSXEShowInventory,
	}}
	src := NewSSHSource(run, vendorprofile.Default())

	_, id, err := src.ProbeWithIdentity(context.Background(), iosxeTarget())
	if err != nil {
		t.Fatalf("probe: %v", err)
	}
	if id.Serial != "FOC2130Z0RD" || id.Model != "C9300-48P" {
		t.Fatalf("identity = %+v", id)
	}
	if want := []string{"show version"}; !equalStrings(run.commands, want) {
		t.Errorf("ran %v, want only %v — the second command had nothing left to answer", run.commands, want)
	}
}

// TestSSHRungReadsIdentityForAPlatformWithNoVersionProbe — cisco/ios_xr declares
// an identity source and NO cli version pattern. The rung must still run for it:
// the two blocks are independent, which is the whole reason they are two blocks.
func TestSSHRungReadsIdentityForAPlatformWithNoVersionProbe(t *testing.T) {
	run := &scriptRunner{answers: map[string]string{"show inventory": identIOSXRShowInventory}}
	src := NewSSHSource(run, vendorprofile.Default())
	target := Target{DeviceID: "xr-1", Address: "10.0.0.7", Vendor: "cisco", OSText: "Cisco IOS-XR 7.5"}

	version, id, err := src.ProbeWithIdentity(context.Background(), target)
	if err != nil {
		t.Fatalf("probe: %v", err)
	}
	if version != "" {
		t.Errorf("version = %q, want none — this platform declares no cli version pattern", version)
	}
	if id.Serial != "FOX1441GPWM" || id.Model != "ASR-9006-AC-V2" {
		t.Errorf("identity = %+v, want the inventory's chassis row", id)
	}
}

// TestSSHRungKeepsTheVersionWhenAnIdentityCommandFails — a second command that
// times out must not cost the version the first command already produced.
func TestSSHRungKeepsTheVersionWhenAnIdentityCommandFails(t *testing.T) {
	run := &scriptRunner{
		answers: map[string]string{"show version": identIOSXEShowVersion},
		fail:    map[string]error{"show inventory": errors.New("session timed out")},
	}
	var logged []string
	src := NewSSHSource(run, vendorprofile.Default())
	src.Logf = func(msg string, _ map[string]any) { logged = append(logged, msg) }

	version, id, err := src.ProbeWithIdentity(context.Background(), iosxeTarget())
	if err != nil {
		t.Fatalf("probe returned an error for a NON-fatal identity failure: %v", err)
	}
	if version != "Version 17.09.04a" {
		t.Errorf("version = %q, want the reading the first command produced", version)
	}
	if id.Serial != "" {
		t.Errorf("serial = %q, want none — the command that carries it failed", id.Serial)
	}
	if id.Model != "C9300-48P" {
		t.Errorf("model = %q, want the one already read", id.Model)
	}
	if len(logged) == 0 {
		t.Error("the identity command failure was not reported — §10 forbids a silent failure")
	}
}

// TestSSHRungProbeStillVersionOnly — the plain Source contract is unchanged: a
// caller that did not ask for an identity runs only the version command.
func TestSSHRungProbeStillVersionOnly(t *testing.T) {
	run := &scriptRunner{answers: map[string]string{
		"show version":   identIOSXEShowVersion,
		"show inventory": identIOSXEShowInventory,
	}}
	src := NewSSHSource(run, vendorprofile.Default())

	version, err := src.Probe(context.Background(), iosxeTarget())
	if err != nil {
		t.Fatalf("probe: %v", err)
	}
	if version != "Version 17.09.04a" {
		t.Errorf("version = %q", version)
	}
	if want := []string{"show version"}; !equalStrings(run.commands, want) {
		t.Errorf("ran %v, want %v", run.commands, want)
	}
}

// TestSSHRungLeavesUnparseableOutputUnset — the invariant, at the rung.
func TestSSHRungLeavesUnparseableOutputUnset(t *testing.T) {
	run := &scriptRunner{answers: map[string]string{
		"show version":   "% Invalid input detected at '^' marker.",
		"show inventory": "% Invalid input detected at '^' marker.",
	}}
	src := NewSSHSource(run, vendorprofile.Default())

	version, id, err := src.ProbeWithIdentity(context.Background(), iosxeTarget())
	if err != nil {
		t.Fatalf("probe: %v", err)
	}
	if version != "" || !id.Empty() {
		t.Fatalf("invented version %q / identity %+v out of a rejected command", version, id)
	}
}

// TestSSHRungRefusesAnUnrunnableIdentityCommand — the closed-command-source
// property, at the byte level. A profile whose identity command carries a
// chaining metacharacter is refused rather than run.
func TestSSHRungRefusesAnUnrunnableIdentityCommand(t *testing.T) {
	profiles := fakeProfiles{
		profile:    vendorprofile.Profile{ID: "acme/os"},
		identityOK: true,
		identity: vendorprofile.IdentityProbe{Commands: []vendorprofile.IdentityCommand{
			{Command: "show version; reload", SerialPatterns: []string{`(?m)^SN: (\S+)$`}},
		}},
	}
	run := &scriptRunner{answers: map[string]string{}}
	src := NewSSHSource(run, profiles)
	var logged []string
	src.Logf = func(msg string, _ map[string]any) { logged = append(logged, msg) }

	_, id, err := src.ProbeWithIdentity(context.Background(), iosxeTarget())
	if err != nil {
		t.Fatalf("probe: %v", err)
	}
	if !id.Empty() {
		t.Fatalf("read %+v from a command that must never have run", id)
	}
	if len(run.commands) != 0 {
		t.Fatalf("put %v on the wire", run.commands)
	}
	if len(logged) == 0 {
		t.Error("the refusal was not reported")
	}
}

// TestSSHRungUnavailableWhenNeitherBlockIsDeclared — a platform that declares
// neither a CLI version pattern nor an identity probe reports the rung
// UNAVAILABLE, which is different from a probe FAILURE.
func TestSSHRungUnavailableWhenNeitherBlockIsDeclared(t *testing.T) {
	src := NewSSHSource(&scriptRunner{}, fakeProfiles{})
	if _, _, err := src.ProbeWithIdentity(context.Background(), iosxeTarget()); !errors.Is(err, ErrNotConfigured) {
		t.Fatalf("err = %v, want ErrNotConfigured", err)
	}
}

// ── the overwrite rule ──────────────────────────────────────────────────────

// TestAcceptIdentityRules pins the three rules, on the serial.
func TestAcceptIdentityRules(t *testing.T) {
	read := func(serial string, m Method) Reading {
		return Reading{Identity: deviceident.Identity{Serial: serial}, IdentityMethod: m}
	}
	cases := []struct {
		name string
		cur  Current
		r    Reading
		want bool
	}{
		{"empty reading never writes", Current{}, read("", MethodSSH), false},
		{"blank reading never writes", Current{Serial: "SN1", SerialSource: MethodSSH}, read("   ", MethodSSH), false},
		{"empty row accepts any rung", Current{}, read("SN1", MethodSSH), true},
		{"same rung refreshes", Current{Serial: "SN1", SerialSource: MethodSSH}, read("SN2", MethodSSH), true},
		{"another rung does not fight for the row", Current{Serial: "SN1", SerialSource: MethodSSH}, read("SN2", MethodSNMP), false},
		{"an operator's serial is never displaced", Current{Serial: "SN1", SerialSource: MethodManual}, read("SN2", MethodSSH), false},
		{"unknown provenance is treated as manual", Current{Serial: "SN1"}, read("SN2", MethodSSH), false},
		{"a manual reading may not write through a rung", Current{}, read("SN1", MethodManual), false},
	}
	for _, tc := range cases {
		if got := AcceptIdentity(tc.cur, tc.r); got != tc.want {
			t.Errorf("%s: AcceptIdentity = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// TestPlanIdentityIsDerivedFromAcceptIdentity — the ladder must never run a
// transport at a live device only to throw the answer away.
func TestPlanIdentityIsDerivedFromAcceptIdentity(t *testing.T) {
	currents := []Current{
		{},
		{Serial: "SN1", SerialSource: MethodSSH},
		{Serial: "SN1", SerialSource: MethodSNMP},
		{Serial: "SN1", SerialSource: MethodManual},
		{Serial: "SN1"},
	}
	for _, cur := range currents {
		planned := map[Method]bool{}
		for _, m := range PlanIdentity(cur) {
			planned[m] = true
		}
		for _, m := range LadderOrder {
			r := Reading{Identity: deviceident.Identity{Serial: "SN9"}, IdentityMethod: m}
			if AcceptIdentity(cur, r) != planned[m] {
				t.Errorf("cur=%+v method=%s: planned=%v but AcceptIdentity=%v",
					cur, m, planned[m], AcceptIdentity(cur, r))
			}
		}
	}
}

// ── the ladder walk ─────────────────────────────────────────────────────────

// identityRung is a rung that can answer both questions.
type identityRung struct {
	method   Method
	version  string
	identity deviceident.Identity
	calls    int
}

func (r *identityRung) Method() Method { return r.method }
func (r *identityRung) Probe(context.Context, Target) (string, error) {
	r.calls++
	return r.version, nil
}
func (r *identityRung) ProbeWithIdentity(context.Context, Target) (string, deviceident.Identity, error) {
	r.calls++
	return r.version, r.identity, nil
}

// versionRung answers the version question only.
type versionRung struct {
	method  Method
	version string
	calls   int
}

func (r *versionRung) Method() Method { return r.method }
func (r *versionRung) Probe(context.Context, Target) (string, error) {
	r.calls++
	return r.version, nil
}

// TestLadderKeepsWalkingForTheSerialAfterTheVersionIsAnswered — the case the
// whole two-question walk exists for: SNMP answers the version, and the serial
// is still one rung down.
func TestLadderKeepsWalkingForTheSerialAfterTheVersionIsAnswered(t *testing.T) {
	snmp := &versionRung{method: MethodSNMP, version: "SRLinux-v26.3.2 7220 IXR-D3L"}
	ssh := &identityRung{method: MethodSSH, version: "SRLinux-v26.3.2",
		identity: deviceident.Identity{Serial: "SN-A", Model: "7220 IXR-D3L", SerialCommand: "show version"}}
	l, err := NewLadder(nil, snmp, ssh)
	if err != nil {
		t.Fatalf("NewLadder: %v", err)
	}
	r, ok := l.Probe(context.Background(), srlinuxTarget(), Current{})
	if !ok {
		t.Fatal("the ladder learned nothing")
	}
	if r.Version != "SRLinux-v26.3.2 7220 IXR-D3L" || r.Method != MethodSNMP {
		t.Errorf("version = %q via %q, want the SNMP rung's", r.Version, r.Method)
	}
	if r.Identity.Serial != "SN-A" || r.IdentityMethod != MethodSSH {
		t.Errorf("identity = %+v via %q, want the SSH rung's", r.Identity, r.IdentityMethod)
	}
	if ssh.calls != 1 {
		t.Errorf("the SSH rung ran %d times, want exactly 1", ssh.calls)
	}
}

// TestLadderDoesNotDialARungThatCannotAnswerEitherOpenQuestion — a row that
// already holds an operator's version and an operator's serial is not dialled at
// all, and a version-only rung is never dialled for a serial.
func TestLadderDoesNotDialARungThatCannotAnswerEitherOpenQuestion(t *testing.T) {
	snmp := &versionRung{method: MethodSNMP, version: "whatever"}
	ssh := &identityRung{method: MethodSSH, version: "v1", identity: deviceident.Identity{Serial: "SN-A"}}
	l, err := NewLadder(nil, snmp, ssh)
	if err != nil {
		t.Fatalf("NewLadder: %v", err)
	}

	// Both halves operator-owned: nothing is dialled.
	if _, ok := l.Probe(context.Background(), srlinuxTarget(), Current{
		Version: "v0", Source: MethodManual, Serial: "SN0", SerialSource: MethodManual,
	}); ok {
		t.Error("the ladder claimed a reading for a fully operator-owned row")
	}
	if snmp.calls != 0 || ssh.calls != 0 {
		t.Errorf("dialled snmp=%d ssh=%d for a row nothing could be written to", snmp.calls, ssh.calls)
	}

	// Version operator-owned, serial unknown: only the rung that can read a
	// serial is dialled.
	if _, ok := l.Probe(context.Background(), srlinuxTarget(), Current{
		Version: "v0", Source: MethodManual,
	}); !ok {
		t.Error("the serial was not learned")
	}
	if snmp.calls != 0 {
		t.Errorf("the SNMP rung was dialled %d times for a question it cannot answer", snmp.calls)
	}
	if ssh.calls != 1 {
		t.Errorf("the SSH rung ran %d times, want 1", ssh.calls)
	}
}

// TestLadderCountsTheIdentityOutcome — §10: an operator has to be able to see
// which of the two questions the fleet is getting answers to.
func TestLadderCountsTheIdentityOutcome(t *testing.T) {
	ssh := &identityRung{method: MethodSSH, identity: deviceident.Identity{Serial: "SN-A"}}
	l, err := NewLadder(nil, ssh)
	if err != nil {
		t.Fatalf("NewLadder: %v", err)
	}
	if _, ok := l.Probe(context.Background(), srlinuxTarget(), Current{}); !ok {
		t.Fatal("the ladder learned nothing")
	}
	var sb strings.Builder
	l.WriteMetrics(&sb)
	if !strings.Contains(sb.String(), `method="ssh",outcome="identity"`) {
		t.Fatalf("metrics do not count the identity outcome:\n%s", sb.String())
	}
}

// TestLadderStampsIdentityTime — a serial with no timestamp is a reading nobody
// can tell is stale.
func TestLadderStampsIdentityTime(t *testing.T) {
	ssh := &identityRung{method: MethodSSH, identity: deviceident.Identity{Serial: "SN-A"}}
	l, err := NewLadder(nil, ssh)
	if err != nil {
		t.Fatalf("NewLadder: %v", err)
	}
	before := time.Now().UTC()
	r, ok := l.Probe(context.Background(), srlinuxTarget(), Current{})
	if !ok {
		t.Fatal("the ladder learned nothing")
	}
	if r.IdentityAt.Before(before) || r.IdentityAt.IsZero() {
		t.Fatalf("identity_at = %v, want a stamp taken during the probe", r.IdentityAt)
	}
}

func equalStrings(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}
