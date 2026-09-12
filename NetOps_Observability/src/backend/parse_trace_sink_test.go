// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// parse_trace_sink_test.go — what a record off the wire may write into the
// debugger's memory (review 3.3-13).
//
// A record carrying `cx_debug=<ulid>` is traced with no arm, on purpose: making
// the parser stage depend on a second call would produce an empty parser.log
// that reads as "the parser never saw it". The records reaching the parse hook
// are NOT all authenticated, though — an SNMP trap whose community does not
// match loses device attribution and is still parsed — so the marker on a
// record is attacker-supplied, and a stranger could mint their own to push an
// operator's in-flight trace out of a bounded ring during an incident.

import (
	"testing"
	"time"

	"netops/backend/internal/applog"
	"netops/backend/internal/pipedebug"
)

// logged captures what the sink writes to the application log. The ring refuses
// a foreign marker on its own, so asserting only on the ring would pass with the
// sink's guard deleted — the log line is the half only this guard controls.
func logged(t *testing.T) *[]string {
	t.Helper()
	prevLevel := applog.Level()
	applog.SetLevel("debug") // Debug() is a no-op otherwise, and silence would prove nothing
	var lines []string
	restore := applog.SetObserver(func(_, component, msg string, _ map[string]any) {
		lines = append(lines, component+" "+msg)
	})
	t.Cleanup(func() {
		restore()
		applog.SetLevel(prevLevel)
	})
	return &lines
}

func TestParseTraceSinkKeepsOnlyMarkersThisProcessMinted(t *testing.T) {
	s := &server{debugRing: pipedebug.NewRing()}
	lines := logged(t)

	// A marker off the wire: well-formed, and nobody here minted it.
	theirs := pipedebug.NewMarker(time.Unix(1757000000, 0))
	s.parseTraceSink(theirs, "parse:snmptrap", "trap decoded", map[string]any{"rule": "linkDown"})
	if got := len(s.debugRing.Lines(theirs)); got != 0 {
		t.Fatalf("a marker off the wire wrote %d lines into the debug ring", got)
	}
	if len(*lines) != 0 {
		t.Fatalf("a marker off the wire wrote %d application log lines: %v — whoever can reach a "+
			"collector port can fill the log during an incident", len(*lines), *lines)
	}

	// The operator's own trace, minted here.
	mine := pipedebug.NewMarker(time.Unix(1757000001, 0))
	s.debugRing.Admit(mine)
	s.parseTraceSink(mine, "parse:snmptrap", "trap decoded", map[string]any{"rule": "linkDown"})
	if got := len(s.debugRing.Lines(mine)); got != 1 {
		t.Fatalf("the operator's own trace kept %d lines, want 1 — the guard has broken the feature "+
			"it protects", got)
	}
	if len(*lines) != 1 {
		t.Fatalf("the operator's own trace wrote %d log lines, want 1: %v", len(*lines), *lines)
	}
}

// An ARMED filter matches on the operator's own needle, which is not
// marker-shaped. That arm is an authenticated act, and its decision lines must
// keep flowing — the guard is about markers off the wire, not about tracing.
func TestParseTraceSinkStillServesAnArmedNeedle(t *testing.T) {
	s := &server{debugRing: pipedebug.NewRing()}
	// Nothing is admitted, and the needle is not a marker: the line is not
	// refused. It does not land in the ring either (the ring is marker-keyed by
	// construction), which is exactly today's behaviour for an armed trace —
	// what matters is that the call is not short-circuited before the log.
	if pipedebug.ValidMarker("%ETHPORT-5-IF_DOWN") {
		t.Fatal("the fixture needle is marker-shaped; it cannot stand in for an armed needle")
	}
	lines := logged(t)
	s.parseTraceSink("%ETHPORT-5-IF_DOWN", "parse:syslog", "matched profile", nil)
	if len(*lines) != 1 {
		t.Fatalf("an armed needle's decision line was dropped (%v) — arming is an authenticated act "+
			"and the guard is about markers off the wire, not about tracing", *lines)
	}
}
