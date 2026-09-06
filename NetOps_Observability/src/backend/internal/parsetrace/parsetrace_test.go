// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package parsetrace

import (
	"strings"
	"sync"
	"testing"
	"time"
)

const testMarker = "01m1kyybjwne1fpjzktftka0wd"

type capture struct {
	mu    sync.Mutex
	lines []line
}

type line struct {
	marker, component, msg string
	fields                 map[string]any
}

func (c *capture) sink(marker, component, msg string, fields map[string]any) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.lines = append(c.lines, line{marker, component, msg, fields})
}

func (c *capture) len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.lines)
}

// A disarmed filter is the SHIPPED state, and it must trace nothing at all for
// an ordinary record. This is the whole cost argument: if a disarmed filter
// matched anything, every syslog line in the fleet would build a map.
func TestDisarmedFilterTracesNothing(t *testing.T) {
	c := &capture{}
	f := New(c.sink)
	if _, ok := f.Match("Sep  4 11:05:07 spine1 bgpd: neighbor 10.0.0.1 Down"); ok {
		t.Fatal("a disarmed filter matched an ordinary record")
	}
	if f.Trace("ordinary line", "parse:x", "msg", nil) {
		t.Fatal("Trace fired on a disarmed filter")
	}
	if c.len() != 0 {
		t.Fatalf("a disarmed filter emitted %d lines", c.len())
	}
}

// A record carrying its OWN marker is traced without any arming. This is the
// invariant that keeps a trace's parser stage from silently depending on a
// second call the operator has to remember to make.
func TestMarkedRecordTracesWithoutArming(t *testing.T) {
	c := &capture{}
	f := New(c.sink)
	text := "cx_synthetic=true cx_debug=" + testMarker + " correlix pipeline debug probe"
	m, ok := f.Match(text)
	if !ok || m != testMarker {
		t.Fatalf("marked record: got (%q,%v), want (%q,true)", m, ok, testMarker)
	}
	if !f.Trace(text, "parse:snmptrap", "trap decoded", func() map[string]any {
		return map[string]any{"matched_trap_name": "linkDown"}
	}) {
		t.Fatal("Trace did not fire for a marked record")
	}
	if c.len() != 1 {
		t.Fatalf("emitted %d lines, want 1", c.len())
	}
	if c.lines[0].fields["matched_trap_name"] != "linkDown" {
		t.Fatalf("fields not passed through: %v", c.lines[0].fields)
	}
}

// An armed needle traces a REAL, unmarked record — the DEBUG_PARSE_MARKER case.
func TestArmedNeedleTracesRealRecord(t *testing.T) {
	c := &capture{}
	f := New(c.sink)
	if _, err := f.Arm("spine1", time.Minute); err != nil {
		t.Fatalf("Arm: %v", err)
	}
	if m, ok := f.Match("Sep  4 11:05:07 spine1 bgpd: neighbor down"); !ok || m != "spine1" {
		t.Fatalf("armed match: got (%q,%v)", m, ok)
	}
	if _, ok := f.Match("Sep  4 11:05:07 leaf9 bgpd: neighbor down"); ok {
		t.Fatal("armed filter matched a record that does not contain the needle")
	}
}

// The window is CLAMPED and the disarm is armed inside this process. A filter
// that could be armed forever is a log-volume incident waiting to happen.
func TestArmClampsAndAutoDisarms(t *testing.T) {
	c := &capture{}
	f := New(c.sink)
	var fired func()
	f.afterFunc = func(d time.Duration, fn func()) stopper {
		if d != MaxWindow {
			t.Fatalf("window not clamped: got %s, want %s", d, MaxWindow)
		}
		fired = fn
		return noopStopper{}
	}
	if _, err := f.Arm("needle", 24*time.Hour); err != nil {
		t.Fatalf("Arm: %v", err)
	}
	if _, _, on := f.Active(); !on {
		t.Fatal("filter is not armed after Arm")
	}
	fired()
	if _, _, on := f.Active(); on {
		t.Fatal("the auto-disarm timer did not disarm the filter")
	}
}

// Even if the timer goroutine never runs, an elapsed window reads as OFF. The
// deadline is checked on READ as well as fired by a timer, so a stalled timer
// cannot keep a filter alive past its window.
func TestElapsedWindowReadsAsOff(t *testing.T) {
	f := New(nil)
	now := time.Now().UTC()
	f.now = func() time.Time { return now }
	f.afterFunc = func(time.Duration, func()) stopper { return noopStopper{} }
	if _, err := f.Arm("needle", time.Minute); err != nil {
		t.Fatalf("Arm: %v", err)
	}
	now = now.Add(2 * time.Minute)
	if _, _, on := f.Active(); on {
		t.Fatal("an elapsed window still reads as armed")
	}
	if _, ok := f.Match("a line containing needle"); ok {
		t.Fatal("an elapsed filter still matches")
	}
}

// Re-arming must REPLACE, not stack: two timers racing to disarm would let the
// first operator's window end the second operator's trace.
func TestRearmCancelsThePreviousTimer(t *testing.T) {
	f := New(nil)
	stopped := 0
	f.afterFunc = func(time.Duration, func()) stopper {
		return stopCounter{&stopped}
	}
	if _, err := f.Arm("a", time.Minute); err != nil {
		t.Fatal(err)
	}
	if _, err := f.Arm("b", time.Minute); err != nil {
		t.Fatal(err)
	}
	if stopped != 1 {
		t.Fatalf("re-arm stopped %d timers, want 1", stopped)
	}
	if n, _, _ := f.Active(); n != "b" {
		t.Fatalf("re-arm did not replace the needle: %q", n)
	}
	f.Disarm()
	if stopped != 2 {
		t.Fatalf("Disarm stopped %d timers cumulatively, want 2", stopped)
	}
}

func TestArmRejectsEmptyAndOverlongNeedles(t *testing.T) {
	f := New(nil)
	if _, err := f.Arm("   ", time.Minute); err == nil {
		t.Fatal("an empty needle was accepted")
	}
	if _, err := f.Arm(strings.Repeat("x", maxFilter+1), time.Minute); err == nil {
		t.Fatal("an over-long needle was accepted")
	}
}

// MarkerIn is a second implementation of the marker grammar (the collectors
// must not import the debugger's HTTP surface to parse a token). This is the
// test that keeps the two in step.
func TestMarkerInGrammar(t *testing.T) {
	cases := []struct {
		name, in, want string
	}{
		{"exact", "cx_debug=" + testMarker, testMarker},
		{"embedded", "prefix cx_debug=" + testMarker + " suffix", testMarker},
		{"absent", "no marker here", ""},
		{"truncated", "cx_debug=01m1kyy", ""},
		{"bad alphabet", "cx_debug=01m1kyybjwne1fpjzktftka0wU", ""},
		{"illegal crockford letter i", "cx_debug=01m1kyybjwne1fpjzktftkaiwd", ""},
	}
	for _, c := range cases {
		if got := MarkerIn(c.in); got != c.want {
			t.Errorf("%s: MarkerIn(%q) = %q, want %q", c.name, c.in, got, c.want)
		}
	}
	if markerLen != 26 {
		t.Fatalf("marker length drifted from the ULID shape pipedebug mints: %d", markerLen)
	}
	for _, r := range "ilou" {
		if strings.ContainsRune(markerAlphabet, r) {
			t.Fatalf("the alphabet contains %q, which Crockford base32 excludes", r)
		}
	}
}

// A nil sink must not panic: a process may have a filter before it has anywhere
// to put the lines, and a boot-time panic in a debug facility is unacceptable.
func TestNilSinkIsSafe(t *testing.T) {
	f := New(nil)
	if _, err := f.Arm("x", time.Minute); err != nil {
		t.Fatal(err)
	}
	f.Emit("marker", "parse:x", "msg", func() map[string]any { return nil })
	var nilFilter *Filter
	if _, ok := nilFilter.Match("anything"); ok {
		t.Fatal("a nil filter matched")
	}
	nilFilter.Emit("m", "c", "m", nil)
}

// Default() is the ONE piece of package-level state, and it must be stable.
func TestDefaultIsStable(t *testing.T) {
	first, second := Default(), Default()
	if first != second {
		t.Fatal("Default() returned two different filters — the collectors and the api would arm different switches")
	}
	if first == nil {
		t.Fatal("Default() returned nil")
	}
}

type noopStopper struct{}

func (noopStopper) Stop() bool { return true }

type stopCounter struct{ n *int }

func (s stopCounter) Stop() bool { *s.n++; return true }
