// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package nms

import (
	"os"
	"path/filepath"
	"testing"
)

// severity_contract_test.go — the controller-event severity contract is
// info|warn|high|crit (model.go). Until 2026-10-24 vManage passed its own words
// (critical|major|minor) through; the engine read "major" as WARN, below its
// open floor, so a polled vManage outage could never open an incident alone.

var canonicalSev = map[string]bool{"info": true, "warn": true, "high": true, "crit": true}

func TestVManageSeverityLevelsAreCanonical(t *testing.T) {
	want := map[string]string{
		"critical": "crit", "major": "high", "minor": "warn", "medium": "warn",
		"low": "info", "": "info", "Major ": "high",
	}
	for in, w := range want {
		if got := vmEventSeverity(in); got != w {
			t.Errorf("vmEventSeverity(%q) = %q, want %q", in, got, w)
		}
	}
	if got := vmEventSeverity("something-new"); !canonicalSev[got] {
		t.Errorf("unknown vManage level mapped outside the contract: %q", got)
	}
}

func TestSDWANStateChangeSeveritiesAreCanonical(t *testing.T) {
	for _, kind := range []string{"bfd", "control_conn", "omp", "reachability", "bgp", "device_health", "hardware_health"} {
		for _, to := range []string{"down", "unreachable", "red", "error", "yellow", "warning", "up", "green"} {
			evs := SDWANStateChangeEvents(Specs()["vmanage"], "t-a", "i-1", []StateChange{{
				Record: StateRecord{EntityKey: "e1", StateKind: kind, DeviceID: "10.255.255.1"}, From: "x", To: to,
			}})
			for _, e := range evs {
				if !canonicalSev[e.Severity] {
					t.Errorf("%s change to %q emitted severity %q", kind, to, e.Severity)
				}
				if sdwanBad(to) && e.Severity != "high" {
					t.Errorf("%s change INTO fault %q is %q — must reach the engine's open floor (high)", kind, to, e.Severity)
				}
			}
		}
	}
}

func TestCanonicalSeveritiesFixesStrayWords(t *testing.T) {
	evs := []ControllerEvent{{Severity: "major"}, {Severity: "high"}, {Severity: "critical"}, {Severity: "minor"}}
	if n := canonicalSeverities(evs); n != 3 {
		t.Fatalf("fixed %d, want 3", n)
	}
	for i, w := range []string{"high", "high", "crit", "warn"} {
		if evs[i].Severity != w {
			t.Errorf("event %d severity %q, want %q", i, evs[i].Severity, w)
		}
	}
}

// Every connector's fixtures must transform into canonical severities only.
func TestEveryConnectorFixtureEmitsCanonicalSeverity(t *testing.T) {
	dirToVendor := map[string]string{"catalyst": "catalyst_center", "catalyst9800": "catalyst_9800"}
	reg := NewRegistry()
	dirs, err := os.ReadDir("fixtures")
	if err != nil {
		t.Fatal(err)
	}
	seen := 0
	for _, d := range dirs {
		if !d.IsDir() {
			continue
		}
		vendor := d.Name()
		if v, ok := dirToVendor[vendor]; ok {
			vendor = v
		}
		c, ok := reg.Get(vendor)
		if !ok || c.Transformer() == nil {
			t.Errorf("fixture dir %q has no registered transformer", d.Name())
			continue
		}
		files, _ := filepath.Glob(filepath.Join("fixtures", d.Name(), "*.json"))
		for _, f := range files {
			raw, err := os.ReadFile(f)
			if err != nil {
				t.Fatal(err)
			}
			b, err := c.Transformer().Transform("t-a", "i-1", raw)
			if err != nil {
				continue // a fixture for a stream the plain Transform does not take
			}
			for _, e := range b.Events {
				seen++
				if !canonicalSev[e.Severity] {
					t.Errorf("%s: event %q severity %q is outside info|warn|high|crit", f, e.NormalizedEventType, e.Severity)
				}
			}
		}
	}
	if seen == 0 {
		t.Fatal("no fixture produced an event — the contract check is vacuous")
	}
}
