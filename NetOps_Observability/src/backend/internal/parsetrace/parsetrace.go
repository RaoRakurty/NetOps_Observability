// Package parsetrace is the runtime PARSER DECISION TRACE
// (docs/design/PIPELINE_DEBUGGER_2026-09-04.md §2, stage 2).
//
// THE PROBLEM IT SOLVES. `correlix-debug trace` collects the parser stage from
// a Vector tap and, for the Go collectors, from nothing at all. A tap shows the
// EVENT — the record as it left the transform. It does not show the DECISION:
// which profile matched, which rule fired, which fields were extracted, and,
// above all, WHY a record was dropped. "The record is not in the store" and
// "the parser decided to drop it, here is the rule" are different findings, and
// only the second one ends an incident.
//
// TWO WAYS A RECORD BECOMES TRACED, and the difference matters:
//
//  1. IT CARRIES ITS OWN MARKER. Every record the debugger injects carries
//     `cx_debug=<ulid>` in its text. Such a record is traced unconditionally —
//     requiring an operator to arm a filter first would make a trace's parser
//     stage depend on a second call that is easy to forget, and the resulting
//     empty parser.log would read as "the parser never saw it".
//  2. THE FILTER IS ARMED. For a REAL record — a device's own syslog line, a
//     trap from a router in the field — there is no marker to carry. An
//     operator arms the filter with a substring (`PUT /api/debug/parsemarker`),
//     and matching records get the same decision trace. This is the
//     DEBUG_PARSE_MARKER switch the design names.
//
// DEFAULT-OFF AND SELF-DISARMING (§5, the same invariant as the log level). The
// filter starts empty, every arm is bounded by a window clamped by the caller,
// and the disarm timer is armed HERE, inside the process being traced — so the
// filter comes back off even if whoever armed it is killed. A parse trace left
// armed on a busy lane is a log-volume incident of its own.
//
// COST WHEN OFF. One atomic load plus one strings.Contains for the marker
// token. Nothing is formatted, allocated or logged unless a record matches: the
// Emit* entry points take the fields as a closure precisely so an unmatched
// record pays no map allocation.
//
// NO AMBIENT AUTHORITY. A *Filter is an ordinary value with an injected clock,
// timer and sink, so every test drives its own. The package-level Default()
// exists for exactly one reason — the collectors are called from deep inside
// poll loops that cannot plumb a value down, the same constraint internal/applog
// solves the same way — and it is the ONLY package-level state here.
package parsetrace

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
)

const (
	// MarkerPrefix is the key half of the tag an injected record carries — the
	// full token is this prefix followed by a 26-character ULID. Named
	// "prefix" rather than "token" both because that is what it is and because
	// a constant whose identifier contains "Token" trips gosec's G101
	// hardcoded-credential heuristic; a #nosec on a field name would be the
	// wrong fix for a wrong name. A record containing it is traced whether or
	// not the filter is armed (reason 1 in the package doc).
	MarkerPrefix = "cx_debug="

	// MaxWindow is the hard cap on how long the filter may stay armed. It
	// deliberately matches the debug log level's cap: both are "a module is
	// doing extra work because a human asked", and both must expire.
	MaxWindow = 30 * time.Minute

	// DefaultWindow is the window an arm gets when none is requested.
	DefaultWindow = 5 * time.Minute

	// maxFilter bounds the armed substring. It is used only as a needle for
	// strings.Contains — never as a regex, a path or a query — so length is the
	// only bound it needs, but it needs that one.
	maxFilter = 200
)

// Sink receives one decision line. The marker is the record's trace id (the
// ULID when the record carried one, otherwise the armed filter string), which
// is what files the line under the right trace.
type Sink func(marker, component, msg string, fields map[string]any)

// stopper is the small part of *time.Timer this type needs, so the auto-disarm
// is testable without sleeping.
type stopper interface{ Stop() bool }

// Filter is one process's parser decision trace.
type Filter struct {
	mu      sync.RWMutex
	needle  string
	until   time.Time
	pending stopper
	sink    Sink

	now       func() time.Time
	afterFunc func(time.Duration, func()) stopper
}

// New builds a disarmed filter over a sink. A nil sink is legal and means the
// process has nowhere to put decision lines — Match still reports honestly, and
// Emit is a no-op, rather than the constructor panicking at boot.
func New(sink Sink) *Filter {
	return &Filter{
		sink: sink,
		now:  func() time.Time { return time.Now().UTC() },
		afterFunc: func(d time.Duration, f func()) stopper {
			return time.AfterFunc(d, f)
		},
	}
}

// ClampWindow bounds a requested window into (0, MaxWindow].
func ClampWindow(d time.Duration) time.Duration {
	if d <= 0 {
		return DefaultWindow
	}
	if d > MaxWindow {
		return MaxWindow
	}
	return d
}

// Arm turns the filter on for a bounded window and returns the disarm time.
//
// Re-arming REPLACES the needle and EXTENDS to the new deadline rather than
// stacking timers: two overlapping arms must not leave a timer that disarms the
// second operator's trace out from under them, nor two timers racing to disarm.
func (f *Filter) Arm(needle string, window time.Duration) (time.Time, error) {
	needle = strings.TrimSpace(needle)
	if needle == "" {
		return time.Time{}, errors.New("a parse-marker filter needs a non-empty needle")
	}
	if len(needle) > maxFilter {
		return time.Time{}, fmt.Errorf("parse-marker filter must be at most %d characters", maxFilter)
	}
	w := ClampWindow(window)
	f.mu.Lock()
	defer f.mu.Unlock()
	f.cancelPendingLocked()
	f.needle = needle
	f.until = f.now().Add(w)
	f.pending = f.afterFunc(w, f.Disarm)
	return f.until, nil
}

// Disarm turns the filter off immediately and cancels any pending timer.
func (f *Filter) Disarm() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.cancelPendingLocked()
	f.needle = ""
	f.until = time.Time{}
}

func (f *Filter) cancelPendingLocked() {
	if f.pending != nil {
		f.pending.Stop()
		f.pending = nil
	}
}

// Active reports the armed needle and its disarm time. `on` is false when the
// filter is off OR when its window has already elapsed — the deadline is
// checked on read as well as fired by the timer, so a stalled timer goroutine
// can never keep the filter alive past its window.
func (f *Filter) Active() (needle string, until time.Time, on bool) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	if f.needle == "" {
		return "", time.Time{}, false
	}
	if !f.until.IsZero() && f.now().After(f.until) {
		return "", f.until, false
	}
	return f.needle, f.until, true
}

// Match reports whether a record should be traced, and under which trace id.
//
// It is on the hot path of every parser it is called from, so the order is
// deliberate: the cheap unconditional check for an injected record's own marker
// first, then the armed needle behind a read lock.
func (f *Filter) Match(text string) (marker string, ok bool) {
	if f == nil {
		return "", false
	}
	if m := MarkerIn(text); m != "" {
		return m, true
	}
	needle, _, on := f.Active()
	if !on || !strings.Contains(text, needle) {
		return "", false
	}
	return needle, true
}

// Emit records one decision line for a matched record.
//
// `fields` is a closure so an unmatched record allocates nothing: callers write
//
//	if m, ok := f.Match(line); ok {
//	    f.Emit(m, "parse:snmptrap", "varbind decoded", func() map[string]any { … })
//	}
//
// and the map is built only when the line is actually being traced.
func (f *Filter) Emit(marker, component, msg string, fields func() map[string]any) {
	if f == nil || f.sink == nil || marker == "" {
		return
	}
	var kv map[string]any
	if fields != nil {
		kv = fields()
	}
	f.sink(marker, component, msg, kv)
}

// Trace is the whole hook in one call: match, and emit if matched. It returns
// whether the record was traced, so a caller can skip building further detail.
func (f *Filter) Trace(text, component, msg string, fields func() map[string]any) bool {
	m, ok := f.Match(text)
	if !ok {
		return false
	}
	f.Emit(m, component, msg, fields)
	return true
}

// SetSink installs the sink after construction. The collectors build their
// filter at package init, before the API's debug ring exists; this is how the
// two are joined without either importing the other.
func (f *Filter) SetSink(s Sink) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sink = s
}

// MarkerIn extracts a `cx_debug=<26 chars>` token from a string, or "".
//
// The length and alphabet are checked here rather than delegated to
// internal/pipedebug: this package is imported by the collectors, and making
// the collectors depend on the debugger's HTTP surface to parse a token would
// be exactly the hidden coupling §2 forbids. The two definitions are held in
// step by parsetrace_test.go, which asserts the alphabet and length against the
// values pipedebug mints.
func MarkerIn(s string) string {
	i := strings.Index(s, MarkerPrefix)
	if i < 0 {
		return ""
	}
	rest := s[i+len(MarkerPrefix):]
	if len(rest) < markerLen {
		return ""
	}
	tok := rest[:markerLen]
	for j := 0; j < len(tok); j++ {
		if !strings.ContainsRune(markerAlphabet, rune(tok[j])) {
			return ""
		}
	}
	return tok
}

const (
	markerLen      = 26
	markerAlphabet = "0123456789abcdefghjkmnpqrstvwxyz"
)

// ── the process-wide default (see the package doc) ──────────────────────────

var (
	defaultOnce sync.Once
	defaultFlt  *Filter
)

// Default returns the process-wide filter the collectors use. It is created
// disarmed and sink-less; package backend installs the sink at boot.
func Default() *Filter {
	defaultOnce.Do(func() { defaultFlt = New(nil) })
	return defaultFlt
}
