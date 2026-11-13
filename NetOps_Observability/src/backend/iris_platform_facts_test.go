// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// iris_platform_facts_test.go — NetClaw ingestion Batch 1: the server derives
// `state:reload`, `state:clock`, `state:if_faults` and `state:if_drops` from
// TYPED fields only, and an unread field never becomes a calm fact.
//
// The platform fixtures are real Cisco IOS XE 17.3.2 output (lab SD-WAN edge,
// 2026-11-13) run through the REAL showparse library, so the facts asserted are
// the ones a live read of that device produces. The hostname and the NTP
// reference are replaced (edge-1, an RFC 5737 address); nothing else is edited.

import (
	"strings"
	"testing"

	"netops/backend/ai"
	"netops/backend/internal/protocoldiag"
	"netops/backend/internal/showparse"
)

const (
	capturedVersionHead = `Cisco IOS XE Software, Version 17.03.02
Cisco IOS Software [Amsterdam], Virtual XE Software (X86_64_LINUX_IOSD-UNIVERSALK9-M), Version 17.3.2, RELEASE SOFTWARE (fc3)
ROM: IOS-XE ROMMON
edge-1 uptime is 3 days, 25 minutes
Uptime for this control processor is 3 days, 32 minutes
System returned to ROM by reload
System restarted at 09:38:55 CDT Tue Nov 10 2026
System image file is "bootflash:packages.conf"
Last reload reason: reload`
	capturedMemoryHead = `Processor Pool Total: 2121596732 Used:  258195496 Free: 1863401236
reserve P Pool Total:     102404 Used:         88 Free:     102316
 lsmpi_io Pool Total:    3149400 Used:    3148568 Free:        832`
	capturedNTPStatus = `Clock is synchronized, stratum 6, reference is 192.0.2.10
nominal freq is 250.0000 Hz, actual freq is 249.9979 Hz, precision is 2**10
clock offset is 15.8760 msec, root delay is 47.72 msec`
)

// platformStateFrom runs captured IOS-XE outputs through the real parser
// library and returns the battery DeviceState the projection consumes.
func platformStateFrom(t *testing.T, outputs map[string]string) protocoldiag.DeviceState {
	t.Helper()
	lib := showparse.NewLibrary()
	st := protocoldiag.DeviceState{Status: protocoldiag.DeviceStatusOK}
	for _, id := range []string{showparse.CmdPlatformMemory, showparse.CmdPlatformUptime, showparse.CmdPlatformClock} {
		raw, ok := outputs[id]
		if !ok {
			continue
		}
		st.Commands = append(st.Commands, protocoldiag.CollectedCommand{SpecID: id, Command: id, Output: raw})
		res, err := lib.Parse(id, showparse.DialectCiscoIOSXE, raw)
		if err != nil {
			t.Fatalf("parse %s: %v", id, err)
		}
		res.CmdID = id
		st.Parsed = append(st.Parsed, res)
	}
	return st
}

func stateSignals(rep ai.DeviceStateReport) map[string]bool {
	out := map[string]bool{}
	for _, r := range rep.Rows {
		for _, s := range r.Signals {
			out[s] = true
		}
	}
	return out
}

// TestCapturedIOSXEPlatformReadYieldsCalmFacts: the live lab edge — up three
// days, memory at 12 %, clock synchronized 15.9 ms off — projects exactly the
// calm facts, with the device's own figures in the rendered rows.
func TestCapturedIOSXEPlatformReadYieldsCalmFacts(t *testing.T) {
	st := platformStateFrom(t, map[string]string{
		showparse.CmdPlatformUptime: capturedVersionHead,
		showparse.CmdPlatformMemory: capturedMemoryHead,
		showparse.CmdPlatformClock:  capturedNTPStatus,
	})
	var rep ai.DeviceStateReport
	aiProjectDeviceState(&rep, st, "")
	sig := stateSignals(rep)
	for _, want := range []string{"state:reload=earlier", "state:clock=synced", "state:platform=ok"} {
		if !sig[want] {
			t.Errorf("missing %s; signals = %v", want, sig)
		}
	}
	text := ""
	for _, r := range rep.Rows {
		text += r.Text + "\n"
	}
	for _, want := range []string{"uptime 3 days, 25 minutes", "memory 12.2% used", "clock synchronized", "stratum 6", "clock offset 15.9 ms"} {
		if !strings.Contains(text, want) {
			t.Errorf("rendered rows lack %q:\n%s", want, text)
		}
	}
}

// TestPlatformFactsFromTypedFields covers each derivation's boundaries.
func TestPlatformFactsFromTypedFields(t *testing.T) {
	b := func(v bool) *bool { return &v }
	f := func(v float64) *float64 { return &v }
	s := func(v string) *string { return &v }

	clock := []struct {
		name string
		h    showparse.PlatformHealth
		want string
	}{
		{"synchronized, small offset", showparse.PlatformHealth{ClockSynced: b(true), ClockOffsetMs: f(15.876)}, "synced"},
		{"synchronized, offset past 100 ms", showparse.PlatformHealth{ClockSynced: b(true), ClockOffsetMs: f(-250)}, "offset_high"},
		{"synchronized, no offset printed", showparse.PlatformHealth{ClockSynced: b(true)}, "synced"},
		{"not synchronized", showparse.PlatformHealth{ClockSynced: b(false), ClockOffsetMs: f(0)}, "unsynced"},
		{"no clock read at all", showparse.PlatformHealth{ClockOffsetMs: f(5)}, ""},
	}
	for _, tc := range clock {
		if got, _ := aiPlatformClock(tc.h); got != tc.want {
			t.Errorf("clock %s: got %q, want %q", tc.name, got, tc.want)
		}
	}

	reload := []struct {
		uptime string
		want   string
	}{
		{"3 days, 25 minutes", "earlier"},
		{"1 year, 2 weeks, 3 days, 4 hours, 5 minutes", "earlier"},
		{"1 day, 0 hours", "earlier"},
		{"23 hours, 59 minutes", "recent"},
		{"12 minutes", "recent"},
		{"0 days, 3 hours", "recent"},
		{"10 days, 2:31", "earlier"}, // the Junos clause shape
		{"2:31", ""},                 // no unit at all: no fact
		{"", ""},
		{"unknown", ""},
	}
	for _, tc := range reload {
		h := showparse.PlatformHealth{}
		if tc.uptime != "" {
			h.Uptime = s(tc.uptime)
		}
		if got, _ := aiPlatformReload(h); got != tc.want {
			t.Errorf("reload %q: got %q, want %q", tc.uptime, got, tc.want)
		}
	}

	i := func(v int64) *int64 { return &v }
	counters := []struct {
		name string
		in   []*int64
		want string
	}{
		{"one counter above zero", []*int64{i(0), i(7), nil}, "present"},
		{"all reported zero", []*int64{i(0), nil, i(0)}, "none"},
		{"nothing reported", []*int64{nil, nil}, ""},
	}
	for _, tc := range counters {
		if got, _ := aiCounterFact(tc.in...); got != tc.want {
			t.Errorf("counters %s: got %q, want %q", tc.name, got, tc.want)
		}
	}
}

// TestDropsWithCleanErrorsAreTwoFacts: the congestion method's distinction —
// drops present, errors clean — survives projection as two separate facts.
func TestDropsWithCleanErrorsAreTwoFacts(t *testing.T) {
	i := func(v int64) *int64 { return &v }
	up := "up"
	st := protocoldiag.DeviceState{
		Status:   protocoldiag.DeviceStatusOK,
		Commands: []protocoldiag.CollectedCommand{{SpecID: showparse.CmdInterfaceDetail, Command: "show interfaces GigabitEthernet1"}},
		Parsed: []showparse.Result{{
			CmdID: showparse.CmdInterfaceDetail, Dialect: showparse.DialectCiscoIOSXE,
			Interfaces: []showparse.InterfaceState{{
				Name: "GigabitEthernet1", Admin: &up, Oper: &up,
				InErrors: i(0), CRC: i(0), OutErrors: i(0), InDrops: i(0), OutDrops: i(4120),
			}},
		}},
	}
	var rep ai.DeviceStateReport
	aiProjectDeviceState(&rep, st, "")
	sig := stateSignals(rep)
	for _, want := range []string{"state:if_drops=present", "state:if_faults=none"} {
		if !sig[want] {
			t.Errorf("missing %s; signals = %v", want, sig)
		}
	}
	// The older combined facet still reads drops as "errors present" — kept
	// unchanged for the skills written against it.
	if !sig["state:if_errors=present"] {
		t.Errorf("if_errors changed meaning; signals = %v", sig)
	}
}
