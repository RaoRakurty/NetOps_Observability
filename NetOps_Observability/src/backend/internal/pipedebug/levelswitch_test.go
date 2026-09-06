// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package pipedebug

import (
	"errors"
	"sync"
	"testing"
	"time"
)

// fakeTimer is the afterFunc seam, so the auto-revert is proven without sleeping.
type fakeTimer struct {
	mu      sync.Mutex
	fn      func()
	d       time.Duration
	stopped bool
}

func (f *fakeTimer) Stop() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.stopped = true
	return true
}

func (f *fakeTimer) fire() {
	f.mu.Lock()
	fn := f.fn
	f.mu.Unlock()
	if fn != nil {
		fn()
	}
}

func newTestSwitch(apply func(Level) error) (*LevelSwitch, *[]*fakeTimer) {
	s := NewLevelSwitch(ModuleAPI, apply)
	timers := &[]*fakeTimer{}
	s.afterFunc = func(d time.Duration, fn func()) stopper {
		ft := &fakeTimer{fn: fn, d: d}
		*timers = append(*timers, ft)
		return ft
	}
	return s, timers
}

// THE invariant: a module raised to debug ALWAYS comes back down, from a timer
// armed in its OWN process — a killed CLI must not be able to leave it raised.
func TestRaisingArmsAnAutoRevertThatActuallyReverts(t *testing.T) {
	var applied []Level
	s, timers := newTestSwitch(func(l Level) error { applied = append(applied, l); return nil })

	change := s.Set(LevelDebug, 5*time.Minute)
	if !change.Applied || change.Level != LevelDebug || change.Previous != LevelInfo {
		t.Fatalf("raise not applied: %+v", change)
	}
	if change.RevertAt.IsZero() {
		t.Fatal("no revert time stamped — the caller cannot tell when it comes down")
	}
	if len(*timers) != 1 || (*timers)[0].d != 5*time.Minute {
		t.Fatalf("auto-revert not armed for the window: %v", *timers)
	}
	(*timers)[0].fire()
	if s.Current() != LevelInfo {
		t.Error("the module did not come back down when its window expired")
	}
	if len(applied) != 2 || applied[1] != LevelInfo {
		t.Errorf("apply sequence = %v, want [debug info]", applied)
	}
}

func TestWindowIsClampedToTheHardCap(t *testing.T) {
	s, timers := newTestSwitch(func(Level) error { return nil })
	s.Set(LevelDebug, 99*time.Hour)
	if (*timers)[0].d != MaxWindow {
		t.Errorf("window %v was not clamped to %v", (*timers)[0].d, MaxWindow)
	}
}

// §9 idempotence: a second raise replaces the pending timer rather than
// stacking a second one that would fire early and revert an active window.
func TestSecondRaiseReplacesRatherThanStacksTheTimer(t *testing.T) {
	s, timers := newTestSwitch(func(Level) error { return nil })
	s.Set(LevelDebug, time.Minute)
	first := (*timers)[0]
	s.Set(LevelDebug, 10*time.Minute)
	if !first.stopped {
		t.Error("the first auto-revert timer was left running — it would revert an extended window early")
	}
	if len(*timers) != 2 || (*timers)[1].d != 10*time.Minute {
		t.Errorf("the replacement timer is wrong: %v", *timers)
	}
}

func TestExplicitRevertCancelsThePendingTimer(t *testing.T) {
	s, timers := newTestSwitch(func(Level) error { return nil })
	s.Set(LevelDebug, time.Minute)
	s.Set(LevelInfo, 0)
	if !(*timers)[0].stopped {
		t.Error("an explicit revert did not cancel the pending auto-revert")
	}
	if !s.RevertAt().IsZero() || s.Current() != LevelInfo {
		t.Error("state after an explicit revert is wrong")
	}
}

// A failed apply must never be reported as a success — that is the exact
// inversion the whole feature exists to prevent.
func TestAFailedApplyIsReportedNotSwallowed(t *testing.T) {
	s, _ := newTestSwitch(func(Level) error { return errors.New("logger is gone") })
	change := s.Set(LevelDebug, time.Minute)
	if change.Applied {
		t.Fatal("a failed level change was reported as applied")
	}
	if change.Reason == "" {
		t.Error("a failed level change carries no reason")
	}
	if s.Current() != LevelInfo {
		t.Error("the switch recorded a level it did not manage to apply")
	}
}

// A revert that FAILS must leave the switch reporting debug (so the operator
// knows) and must re-arm — never silently claim the module came down.
func TestAFailedRevertRetriesAndKeepsReportingDebug(t *testing.T) {
	fail := false
	s, timers := newTestSwitch(func(l Level) error {
		if l == LevelInfo && fail {
			return errors.New("cannot revert")
		}
		return nil
	})
	s.Set(LevelDebug, time.Minute)
	fail = true
	(*timers)[0].fire()
	if s.Current() != LevelDebug {
		t.Error("a failed revert was recorded as if the module had come down")
	}
	if len(*timers) != 2 {
		t.Error("a failed revert did not re-arm a retry")
	}
	fail = false
	(*timers)[1].fire()
	if s.Current() != LevelInfo {
		t.Error("the retry did not bring the module down")
	}
}
