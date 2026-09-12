// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package safego

import (
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

// writeToNilMap panics the way a real bug does — an uninitialized map write.
// Written through a variable so the compiler/linters can't fold it away.
func writeToNilMap() {
	var m map[string]int
	set := func(k string, v int) { m[k] = v }
	set("k", 1)
}

// recorder is a Logger that captures what was reported.
type recorder struct {
	mu    sync.Mutex
	calls []string
	stack []byte
}

func (r *recorder) log(name string, recovered any, stack []byte) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, name)
	r.stack = stack
}

func (r *recorder) names() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.calls...)
}

func TestRunRecoversAndReports(t *testing.T) {
	tests := []struct {
		name      string
		fn        func()
		completed bool
		reported  bool
	}{
		{name: "clean", fn: func() {}, completed: true, reported: false},
		{name: "panic-string", fn: func() { panic("boom") }, completed: false, reported: true},
		{name: "panic-error", fn: func() { panic(errors.New("boom")) }, completed: false, reported: true},
		{name: "panic-nil-map", fn: writeToNilMap, completed: false, reported: true},
		{name: "panic-bounds", fn: func() { b := []byte{1}; _ = b[5:] }, completed: false, reported: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rec := &recorder{}
			got := Run(rec.log, tc.name, tc.fn)
			if got != tc.completed {
				t.Fatalf("completed = %v, want %v", got, tc.completed)
			}
			if reported := len(rec.names()) == 1; reported != tc.reported {
				t.Fatalf("reported = %v, want %v", reported, tc.reported)
			}
			if tc.reported && !strings.Contains(string(rec.stack), "safego") {
				t.Fatalf("stack not captured: %q", rec.stack)
			}
		})
	}
}

func TestGoWithRecoversOnItsOwnGoroutine(t *testing.T) {
	rec := &recorder{}
	done := make(chan struct{})
	GoWith(rec.log, "worker", func() {
		defer close(done)
		panic("worker exploded")
	})
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("goroutine never ran")
	}
	// The report happens after the deferred close, so poll briefly.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if len(rec.names()) == 1 {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("panic was never reported")
}

// A Logger that itself panics must not defeat the guard — otherwise the
// reporting path re-panics inside the deferred recover and kills the process.
func TestPanickingLoggerDoesNotEscape(t *testing.T) {
	bad := func(string, any, []byte) { panic("logger exploded") }
	if Run(bad, "bad-logger", func() { panic("boom") }) {
		t.Fatal("expected completed=false")
	}
}

func TestNilLoggerFallsBack(t *testing.T) {
	if Run(nil, "nil-logger", func() { panic("boom") }) {
		t.Fatal("expected completed=false")
	}
}

func TestRecoverDeferredForm(t *testing.T) {
	rec := &recorder{}
	func() {
		defer Recover(rec.log, "deferred")
		panic("boom")
	}()
	if names := rec.names(); len(names) != 1 || names[0] != "deferred" {
		t.Fatalf("reports = %v", names)
	}
}
