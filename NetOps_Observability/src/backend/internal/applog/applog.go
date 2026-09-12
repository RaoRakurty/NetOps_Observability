// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// Package applog is the process-wide structured logger — one JSON line per
// event to stdout. Vector's docker_logs source picks them up, parses the
// JSON, ships to the Kafka bus (topic netops.applogs), and vector-router then
// writes them into the `netops-applogs-YYYY.MM.DD` OpenSearch index.
package applog

import (
	"encoding/json"
	"io"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Logger serializes structured events onto one writer. The zero value is not
// usable; construct with New.
type Logger struct {
	mu sync.Mutex
	w  io.Writer
}

// debugEnabled gates Debug() only. It is deliberately NOT a full level ladder:
// a ladder invites LOWERING a module below its operational level, which hides
// an incident rather than debugging one. Info/Warn/Error are unconditional and
// always have been — turning this on ADDS lines and never removes any.
//
// Atomic rather than mutex-guarded because every Debug call reads it and the
// overwhelming majority of calls are made with it off.
var debugEnabled atomic.Bool

// SetDebug turns debug-level emission on or off and returns the PREVIOUS state,
// so a caller can restore exactly what it found. The pipeline debugger drives
// this through internal/pipedebug.LevelSwitch, which arms the auto-revert.
func SetDebug(on bool) (previous bool) { return debugEnabled.Swap(on) }

// DebugEnabled reports whether debug emission is on.
func DebugEnabled() bool { return debugEnabled.Load() }

// Level renders the current level as the two-value vocabulary the debug route
// speaks ("debug" | "info").
func Level() string {
	if debugEnabled.Load() {
		return "debug"
	}
	return "info"
}

// SetLevel accepts that same vocabulary. Anything other than "debug" turns
// debug emission OFF — the fail-safe direction for an unrecognised value.
func SetLevel(level string) (previous string) {
	prev := Level()
	debugEnabled.Store(strings.EqualFold(strings.TrimSpace(level), "debug"))
	return prev
}

// Observer is notified of every emitted event, after it is written. It exists
// for ONE consumer: the pipeline debugger's bounded in-memory ring, which must
// be able to serve the API's own log lines for a trace marker WITHOUT reading
// them back through the applogs → Kafka → OpenSearch pipeline that is itself
// the thing under test.
//
// It is a single slot, not a list: one optional in-process observer is a seam,
// a registry of them is an event bus nobody asked for. It must not block and
// must not panic — it runs on the emitting goroutine, inside the log path.
type Observer func(level, component, msg string, fields map[string]any)

var (
	obsMu    sync.RWMutex
	observer Observer
)

// SetObserver installs (or, with nil, removes) the process observer and returns
// a func restoring the previous one.
func SetObserver(o Observer) (restore func()) {
	obsMu.Lock()
	prev := observer
	observer = o
	obsMu.Unlock()
	return func() {
		obsMu.Lock()
		observer = prev
		obsMu.Unlock()
	}
}

func notify(level, component, msg string, fields map[string]any) {
	obsMu.RLock()
	o := observer
	obsMu.RUnlock()
	if o != nil {
		o(level, component, msg, fields)
	}
}

// New returns a Logger emitting JSON lines to w.
func New(w io.Writer) *Logger { return &Logger{w: w} }

// Log emits one event. Caller-supplied fields win over the base keys, which
// is the historical behavior some emitters rely on (e.g. stamping their own
// "component" detail).
func (l *Logger) Log(level, component, msg string, fields map[string]any) {
	event := map[string]any{
		"ts":        time.Now().UTC().Format(time.RFC3339Nano),
		"level":     level,
		"component": component,
		"msg":       msg,
	}
	for k, v := range fields {
		event[k] = v
	}
	l.mu.Lock()
	_ = json.NewEncoder(l.w).Encode(event) // best-effort: the logger has nowhere to report its own failure
	l.mu.Unlock()
	// Outside the writer lock: an observer must never be able to serialise the
	// process's whole log stream behind its own work.
	notify(level, component, msg, fields)
}

// std is the process logger. Package-level on purpose: it mirrors the
// stdlib's log.Default and the pre-extraction appLog global — every caller in
// the process shares one serialized stdout stream.
var std = New(os.Stdout)

// Info logs at level info on the process logger.
func Info(component, msg string, fields map[string]any) { std.Log("info", component, msg, fields) }

// Warn logs at level warn on the process logger.
func Warn(component, msg string, fields map[string]any) { std.Log("warn", component, msg, fields) }

// Error logs at level error on the process logger.
func Error(component, msg string, fields map[string]any) { std.Log("error", component, msg, fields) }

// Debug logs at level debug on the process logger — but ONLY while debug
// emission is on (SetDebug/SetLevel). Off by default, so the shipped stack's
// log volume is byte-for-byte unchanged by the existence of this function.
func Debug(component, msg string, fields map[string]any) {
	if !debugEnabled.Load() {
		return
	}
	std.Log("debug", component, msg, fields)
}

// Log logs at a caller-chosen level on the process logger — for adapters that
// forward another component's already-leveled events (e.g. the notifier).
func Log(level, component, msg string, fields map[string]any) { std.Log(level, component, msg, fields) }

// SwapWriterForTest points the process logger at w and returns a restore
// func. Tests that assert on emitted lines use this instead of poking the
// logger's fields.
func SwapWriterForTest(w io.Writer) func() {
	std.mu.Lock()
	prev := std.w
	std.w = w
	std.mu.Unlock()
	return func() {
		std.mu.Lock()
		std.w = prev
		std.mu.Unlock()
	}
}
