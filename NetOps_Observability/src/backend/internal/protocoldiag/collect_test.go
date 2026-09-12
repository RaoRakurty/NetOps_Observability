// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package protocoldiag

import (
	"context"
	"errors"
	"testing"
)

func TestValidateReadOnly(t *testing.T) {
	ok := []string{
		"show ip ospf neighbor",
		"show ip bgp summary",
		"show logging | include OSPF",
		"show log messages | match rpd",
		"display ospf peer",
		"show router bgp summary | count",
		"info from state /network-instance", // SR Linux-style
	}
	for _, c := range ok {
		if err := ValidateReadOnly(c); err != nil {
			t.Errorf("ValidateReadOnly(%q) = %v, want nil", c, err)
		}
	}
	bad := []string{
		"configure terminal",
		"conf t",
		"no router ospf 1",
		"clear ip bgp *",
		"reload",
		"copy running-config startup-config",
		"show run ; reload",
		"show ip route && configure terminal",
		"show run | redirect flash:cfg.txt",
		"show run > flash:cfg.txt",
		"show logging | append flash:x",
		"",
	}
	for _, c := range bad {
		if err := ValidateReadOnly(c); err == nil {
			t.Errorf("ValidateReadOnly(%q) = nil, want rejection", c)
		}
	}
}

// TestCollect_RejectsNonReadOnlyBundle proves the collector aborts (and runs
// NOTHING) if a bundle ever renders a non-read-only command. We inject a catalog
// whose issue carries a config command to simulate a future/dynamic misuse.
func TestCollect_RejectsNonReadOnlyBundle(t *testing.T) {
	badIssue := Issue{
		ID: "evil", Protocol: ProtocolOSPF, Title: "evil", Description: "evil",
		probes: []CommandSpec{
			spec("cfg", "should never run", "configure terminal", "", ""),
		},
	}
	cat := NewCatalog([]Issue{badIssue})
	var ran int
	runner := runnerFunc(func(context.Context, Device, string) (string, error) {
		ran++
		return "", nil
	})
	col, err := NewCollector(cat, runner)
	if err != nil {
		t.Fatal(err)
	}
	_, err = col.Collect(context.Background(), ciscoDev, "evil", Target{})
	if !errors.Is(err, ErrNotReadOnly) {
		t.Fatalf("Collect err = %v, want ErrNotReadOnly", err)
	}
	if ran != 0 {
		t.Fatalf("runner ran %d commands; a rejected bundle must run nothing", ran)
	}
}

// TestCollect_StampsTenantFromDevice proves §3a: the owning tenant is stamped
// from the subject device, and there is no request-body path that could override
// it (Collect takes only Device + Target — Target carries no tenant).
func TestCollect_StampsTenantFromDevice(t *testing.T) {
	cat := DefaultCatalog()
	col := collectFor(t, cat, ciscoDev, stdTarget, "ospf-neighbor-stuck", nil)
	if col.TenantID != "acme" {
		t.Errorf("TenantID = %q, want acme", col.TenantID)
	}
	other := ciscoDev
	other.TenantID = "globex"
	col2 := collectFor(t, cat, other, stdTarget, "ospf-neighbor-stuck", nil)
	if col2.TenantID != "globex" {
		t.Errorf("TenantID = %q, want globex", col2.TenantID)
	}
}

// TestCollect_TimestampsAndOrder asserts every command is timestamped, order is
// the stable bundle order, and the rendered dialect is recorded.
func TestCollect_TimestampsAndOrder(t *testing.T) {
	cat := DefaultCatalog()
	issue, _ := cat.Issue("bgp-session-down")
	col := collectFor(t, cat, ciscoDev, stdTarget, "bgp-session-down", nil)

	if len(col.Commands) != len(issue.Bundle()) {
		t.Fatalf("collected %d commands, want %d", len(col.Commands), len(issue.Bundle()))
	}
	if col.RenderedVendor != VendorCiscoIOSXE {
		t.Errorf("RenderedVendor = %q", col.RenderedVendor)
	}
	var last int64
	for i, cc := range col.Commands {
		if cc.Timestamp.IsZero() {
			t.Errorf("command %d has zero timestamp", i)
		}
		if cc.SpecID != issue.Bundle()[i].ID {
			t.Errorf("command %d spec = %q, want %q (order not stable)", i, cc.SpecID, issue.Bundle()[i].ID)
		}
		if ts := cc.Timestamp.UnixNano(); ts < last {
			t.Errorf("timestamps not monotonic at %d", i)
		} else {
			last = ts
		}
	}
}

// TestCollect_PerCommandErrorRecorded proves a single command failure is recorded
// honestly on that command (not swallowed, not fatal), so a partial capture is
// still produced.
func TestCollect_PerCommandErrorRecorded(t *testing.T) {
	cat := DefaultCatalog()
	issue, _ := cat.Issue("ospf-neighbor-stuck")
	failCmd := issue.Bundle()[0].Render(ciscoDev.Vendor(), stdTarget)
	runner := runnerFunc(func(_ context.Context, _ Device, cmd string) (string, error) {
		if cmd == failCmd {
			return "", errors.New("transport reset")
		}
		return "ok", nil
	})
	c, err := NewCollector(cat, runner, WithClock(fixedClock()))
	if err != nil {
		t.Fatal(err)
	}
	col, err := c.Collect(context.Background(), ciscoDev, "ospf-neighbor-stuck", stdTarget)
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if col.Commands[0].Err == "" {
		t.Error("first command error was not recorded")
	}
	if len(col.Commands) != len(issue.Bundle()) {
		t.Error("collection did not continue past the failed command")
	}
}

// TestCollect_Determinism proves two identical collects produce identical
// captures (same commands, same order).
func TestCollect_Determinism(t *testing.T) {
	cat := DefaultCatalog()
	a := collectFor(t, cat, ciscoDev, stdTarget, "isis-flapping", nil)
	b := collectFor(t, cat, ciscoDev, stdTarget, "isis-flapping", nil)
	if len(a.Commands) != len(b.Commands) {
		t.Fatal("command count differs")
	}
	for i := range a.Commands {
		if a.Commands[i].Command != b.Commands[i].Command || a.Commands[i].SpecID != b.Commands[i].SpecID {
			t.Errorf("command %d differs between runs", i)
		}
	}
}

func TestNewCollector_RejectsNilDeps(t *testing.T) {
	if _, err := NewCollector(nil, MemCommandRunner{}); err == nil {
		t.Error("nil catalog accepted")
	}
	if _, err := NewCollector(DefaultCatalog(), nil); err == nil {
		t.Error("nil runner accepted")
	}
}

// runnerFunc adapts a function to CommandRunner for tests.
type runnerFunc func(context.Context, Device, string) (string, error)

func (f runnerFunc) Run(ctx context.Context, d Device, cmd string) (string, error) {
	return f(ctx, d, cmd)
}
