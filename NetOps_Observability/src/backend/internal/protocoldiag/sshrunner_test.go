// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package protocoldiag

// sshrunner_test.go — the live-runner policy proofs, all against a FAKE gateway.
// No test in this file opens a socket or touches a device: the Gateway seam is
// what keeps CI offline (CLAUDE.md §11 "mock telemetry streams required").

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeGateway is the in-memory stand-in for the SSH transport. It records every
// command it was asked to run, can be made to block (so the one-in-flight rule
// can be observed), and can enforce the byte cap the way a real device response
// would trip it.
type fakeGateway struct {
	mu       sync.Mutex
	ran      []string
	maxSeen  int64
	out      string
	err      error
	deadline bool          // record whether the ctx carried a deadline
	block    chan struct{} // when non-nil, Run waits on it before returning
	entered  chan struct{} // closed-ish signal: one send per entry
}

func (f *fakeGateway) Run(ctx context.Context, _ Device, command string, maxBytes int64) (string, error) {
	f.mu.Lock()
	f.ran = append(f.ran, command)
	f.maxSeen = maxBytes
	_, hasDeadline := ctx.Deadline()
	f.deadline = hasDeadline
	block, entered := f.block, f.entered
	out, err := f.out, f.err
	f.mu.Unlock()

	if entered != nil {
		entered <- struct{}{}
	}
	if block != nil {
		select {
		case <-block:
		case <-ctx.Done():
			return "", ctx.Err()
		}
	}
	if err != nil {
		return "", err
	}
	// Mirror the real gateway's cap refusal so the runner's plumbing of maxBytes
	// is observable end to end.
	if int64(len(out)) > maxBytes {
		return "", ErrTooLarge
	}
	return out, nil
}

func (f *fakeGateway) commands() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]string, len(f.ran))
	copy(out, f.ran)
	return out
}

// liveDev is a device with a dialable address (the stub devices deliberately
// have none, which the runner refuses).
var liveDev = Device{
	ID:       "dev-1",
	Hostname: "core-01",
	Platform: "Cisco IOS-XE 17.9",
	Address:  "192.0.2.10",
	TenantID: "acme",
}

func newRunner(t *testing.T, gw Gateway, opts ...SSHRunnerOption) *SSHCommandRunner {
	t.Helper()
	r, err := NewSSHCommandRunner(DefaultCatalog(), gw, opts...)
	if err != nil {
		t.Fatalf("NewSSHCommandRunner: %v", err)
	}
	return r
}

func TestSSHRunner_RejectsNilDeps(t *testing.T) {
	if _, err := NewSSHCommandRunner(nil, &fakeGateway{}); err == nil {
		t.Error("nil catalog accepted, want error")
	}
	if _, err := NewSSHCommandRunner(DefaultCatalog(), nil); err == nil {
		t.Error("nil gateway accepted, want error")
	}
}

// TestSSHRunner_OnlyClosedTableCommands is the core least-privilege proof: a
// command the CATALOG can render runs; a perfectly read-only command that is not
// in the table is refused, and the gateway never sees it.
func TestSSHRunner_OnlyClosedTableCommands(t *testing.T) {
	gw := &fakeGateway{out: "ok"}
	r := newRunner(t, gw)

	// In the table: the OSPF neighbor probe, rendered for Cisco.
	if got, err := r.Run(context.Background(), liveDev, "show ip ospf neighbor"); err != nil || got != "ok" {
		t.Fatalf("catalog command: got %q, %v; want %q, nil", got, err, "ok")
	}

	// NOT in the table, though read-only and harmless-looking. This is the
	// command an operator (or a compromised caller) would reach for to exfiltrate
	// a device's whole configuration.
	refused := []string{
		"show running-config",
		"show running-config | section router bgp",
		"show version",
		"show tech-support",
		"show ip ospf neighbor detail extra-token",
	}
	for _, c := range refused {
		if _, err := r.Run(context.Background(), liveDev, c); !errors.Is(err, ErrCommandNotInTable) {
			t.Errorf("Run(%q) error = %v, want ErrCommandNotInTable", c, err)
		}
	}
	if got := gw.commands(); len(got) != 1 || got[0] != "show ip ospf neighbor" {
		t.Fatalf("gateway saw %v, want only the one catalog command", got)
	}
}

// TestSSHRunner_RefusesNonReadOnly proves the read-only guard runs on this path
// too — the runner does not lean on the Collector having checked.
func TestSSHRunner_RefusesNonReadOnly(t *testing.T) {
	gw := &fakeGateway{}
	r := newRunner(t, gw)
	for _, c := range []string{"configure terminal", "show ip ospf neighbor ; reload", "reload"} {
		if _, err := r.Run(context.Background(), liveDev, c); err == nil {
			t.Errorf("Run(%q) = nil error, want a refusal", c)
		}
	}
	if got := gw.commands(); len(got) != 0 {
		t.Fatalf("gateway ran %v, want nothing", got)
	}
}

// TestSSHRunner_IssueOutsideTheTableIsRefused drives the refusal the way the
// Collector would: an issue whose bundle is NOT part of the shipped catalog
// renders commands the runner's table does not contain, so every one is refused
// and nothing reaches the device.
func TestSSHRunner_IssueOutsideTheTableIsRefused(t *testing.T) {
	gw := &fakeGateway{out: "should never be produced"}
	// The runner's table comes from the SHIPPED catalog.
	r := newRunner(t, gw)

	// The collector, however, is handed a rogue catalog with an extra issue whose
	// commands are read-only but were never authored into the shipped matrix.
	rogue := NewCatalog([]Issue{{
		ID: "rogue-exfil", Protocol: ProtocolBGP, Title: "rogue", Description: "rogue",
		probes: []CommandSpec{
			spec("dump", "exfiltrate the configuration", "show running-config", "", ""),
		},
	}})
	col, err := NewCollector(rogue, r, WithClock(fixedClock()))
	if err != nil {
		t.Fatalf("NewCollector: %v", err)
	}
	got, err := col.Collect(context.Background(), liveDev, "rogue-exfil", Target{})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	// The rogue PROBE is refused by the table; the common supporting set the
	// rogue issue inherits is genuinely part of the shipped catalog and still
	// runs, which is exactly the point: the table gates COMMANDS, so a rogue
	// issue cannot smuggle a new one in behind a legitimate bundle.
	var sawRogue bool
	for _, cc := range got.Commands {
		if cc.SpecID != "dump" {
			continue
		}
		sawRogue = true
		if !strings.Contains(cc.Err, "closed per-vendor command table") {
			t.Errorf("rogue command %q error = %q; want a closed-table refusal", cc.Command, cc.Err)
		}
		if cc.Output != "" {
			t.Errorf("rogue command %q produced output %q; want none", cc.Command, cc.Output)
		}
	}
	if !sawRogue {
		t.Fatal("the rogue probe never appeared in the collection")
	}
	for _, c := range gw.commands() {
		if c == "show running-config" {
			t.Fatal("the rogue command reached the gateway")
		}
	}
}

func TestSSHRunner_RequiresAddress(t *testing.T) {
	gw := &fakeGateway{out: "ok"}
	r := newRunner(t, gw)
	noAddr := liveDev
	noAddr.Address = ""
	if _, err := r.Run(context.Background(), noAddr, "show ip ospf neighbor"); !errors.Is(err, ErrNoAddress) {
		t.Fatalf("error = %v, want ErrNoAddress", err)
	}
	if n := len(gw.commands()); n != 0 {
		t.Fatalf("gateway ran %d commands, want 0", n)
	}
}

// TestSSHRunner_OutputCap proves the cap is (a) plumbed to the gateway and
// (b) clamped to the package ceiling rather than widened by a caller.
func TestSSHRunner_OutputCap(t *testing.T) {
	gw := &fakeGateway{out: strings.Repeat("A", 128)}
	r := newRunner(t, gw, WithMaxOutputBytes(64))
	if _, err := r.Run(context.Background(), liveDev, "show ip ospf neighbor"); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("error = %v, want ErrTooLarge", err)
	}
	gw.mu.Lock()
	seen := gw.maxSeen
	gw.mu.Unlock()
	if seen != 64 {
		t.Errorf("gateway saw maxBytes = %d, want 64", seen)
	}

	// A caller cannot widen the ceiling: an over-ceiling (or non-positive)
	// option is ignored and the package default stands.
	wide := newRunner(t, &fakeGateway{out: "ok"}, WithMaxOutputBytes(MaxOutputBytes*8))
	if wide.max != MaxOutputBytes {
		t.Errorf("max = %d after an over-ceiling option, want %d", wide.max, int64(MaxOutputBytes))
	}
	zero := newRunner(t, &fakeGateway{out: "ok"}, WithMaxOutputBytes(0))
	if zero.max != MaxOutputBytes {
		t.Errorf("max = %d after a zero option, want %d", zero.max, int64(MaxOutputBytes))
	}
}

// TestSSHRunner_CommandDeadline proves every command reaches the gateway with a
// deadline attached (§9: all IO is bounded), and that a non-positive override
// cannot remove it.
func TestSSHRunner_CommandDeadline(t *testing.T) {
	gw := &fakeGateway{out: "ok"}
	r := newRunner(t, gw, WithCommandTimeout(0)) // ignored: there is no "no timeout"
	if r.timeout != DefaultCommandTimeout {
		t.Fatalf("timeout = %v, want the %v default", r.timeout, DefaultCommandTimeout)
	}
	if _, err := r.Run(context.Background(), liveDev, "show ip ospf neighbor"); err != nil {
		t.Fatalf("Run: %v", err)
	}
	gw.mu.Lock()
	hadDeadline := gw.deadline
	gw.mu.Unlock()
	if !hadDeadline {
		t.Error("gateway context carried no deadline")
	}

	// A short timeout must actually cut a stuck device off.
	stuck := &fakeGateway{block: make(chan struct{})}
	rs := newRunner(t, stuck, WithCommandTimeout(20*time.Millisecond))
	if _, err := rs.Run(context.Background(), liveDev, "show ip ospf neighbor"); err == nil {
		t.Error("stuck command returned nil error, want a deadline failure")
	}
	close(stuck.block)
}

// TestSSHRunner_OneInFlightPerDevice proves a second concurrent command on the
// SAME device is refused (not queued), while a different device proceeds.
func TestSSHRunner_OneInFlightPerDevice(t *testing.T) {
	gw := &fakeGateway{out: "ok", block: make(chan struct{}), entered: make(chan struct{}, 4)}
	r := newRunner(t, gw)

	done := make(chan error, 1)
	go func() {
		_, err := r.Run(context.Background(), liveDev, "show ip ospf neighbor")
		done <- err
	}()
	<-gw.entered // the first command is inside the gateway and holds the claim

	if _, err := r.Run(context.Background(), liveDev, "show ip bgp summary"); !errors.Is(err, ErrDeviceBusy) {
		t.Fatalf("second command on the same device: %v, want ErrDeviceBusy", err)
	}
	// A DIFFERENT device is unaffected — the claim is per device, not global.
	other := liveDev
	other.ID = "dev-2"
	other.Address = "192.0.2.11"
	go func() {
		_, _ = r.Run(context.Background(), other, "show ip bgp summary")
	}()
	<-gw.entered

	close(gw.block)
	if err := <-done; err != nil {
		t.Fatalf("first command: %v", err)
	}
	// Once released, the device accepts a command again.
	gw2 := &fakeGateway{out: "ok"}
	r2 := newRunner(t, gw2)
	if _, err := r2.Run(context.Background(), liveDev, "show ip ospf neighbor"); err != nil {
		t.Fatalf("first: %v", err)
	}
	if _, err := r2.Run(context.Background(), liveDev, "show ip ospf neighbor"); err != nil {
		t.Fatalf("sequential second: %v, want the claim to have been released", err)
	}
}

// TestSSHRunner_CollectEndToEndOnFakeGateway drives a whole real bundle through
// the runner: every rendered command is accepted by the closed table and the
// capture comes back complete.
func TestSSHRunner_CollectEndToEndOnFakeGateway(t *testing.T) {
	gw := &fakeGateway{out: "10.0.0.2 1 EXSTART/DR 00:00:35 10.0.0.2 Gi0/0"}
	r := newRunner(t, gw)
	cat := DefaultCatalog()
	col, err := NewCollector(cat, r, WithClock(fixedClock()))
	if err != nil {
		t.Fatalf("NewCollector: %v", err)
	}
	for _, id := range cat.SortedIssueIDs() {
		got, err := col.Collect(context.Background(), liveDev, id, stdTarget)
		if err != nil {
			t.Fatalf("Collect(%s): %v", id, err)
		}
		for _, cc := range got.Commands {
			if cc.Err != "" {
				t.Errorf("issue %s command %q refused: %s", id, cc.Command, cc.Err)
			}
		}
	}
}
