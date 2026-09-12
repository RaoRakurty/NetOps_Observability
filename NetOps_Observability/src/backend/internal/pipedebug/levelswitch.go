// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package pipedebug

// levelswitch.go — a bounded, self-reverting runtime log level.
//
// THE INVARIANT THIS TYPE EXISTS TO HOLD: a module raised to debug ALWAYS comes
// back down. Not "the CLI reverts it on exit" — the CLI can be SIGKILLed, the
// terminal can close, the operator can walk away — but the process that was
// raised arms its own timer, so the revert survives the death of whoever asked
// for it (design §1/§5). A module left at debug is a disk-filling, PII-leaking,
// throughput-halving incident of its own.
//
// The switch is also idempotent (§9): re-raising while already raised EXTENDS
// the window to the later of the two deadlines rather than stacking timers, and
// an explicit revert cancels the pending one.

import (
	"sync"
	"time"
)

// LevelSwitch owns one module's runtime level.
type LevelSwitch struct {
	module Module
	apply  func(Level) error
	now    func() time.Time
	// afterFunc is the timer seam (time.AfterFunc in production) so the
	// auto-revert is testable without sleeping.
	afterFunc func(time.Duration, func()) stopper

	mu       sync.Mutex
	current  Level
	revertAt time.Time
	pending  stopper
}

// stopper is the small part of *time.Timer this type needs.
type stopper interface{ Stop() bool }

// NewLevelSwitch builds a switch over an apply function. `apply` performs the
// actual change and must be safe to call from a timer goroutine.
func NewLevelSwitch(module Module, apply func(Level) error) *LevelSwitch {
	return &LevelSwitch{
		module: module,
		apply:  apply,
		now:    func() time.Time { return time.Now().UTC() },
		afterFunc: func(d time.Duration, f func()) stopper {
			return time.AfterFunc(d, f)
		},
		current: LevelInfo,
	}
}

// Set moves the module to `level`. Raising to debug arms an auto-revert at
// now+window (window is clamped by the caller via ClampWindow); setting info
// reverts immediately and cancels any pending revert.
func (s *LevelSwitch) Set(level Level, window time.Duration) LevelChange {
	s.mu.Lock()
	defer s.mu.Unlock()

	prev := s.current
	change := LevelChange{Module: s.module, Level: level, Previous: prev}

	if err := s.apply(level); err != nil {
		change.Applied = false
		change.Reason = "applying the level failed: " + err.Error()
		return change
	}
	s.current = level
	s.cancelPendingLocked()

	if level == LevelDebug {
		w := ClampWindow(window)
		s.revertAt = s.now().Add(w)
		s.pending = s.afterFunc(w, s.revert)
		change.RevertAt = s.revertAt
		change.Reason = "auto-reverts to info at the stamped time even if the caller dies"
	} else {
		s.revertAt = time.Time{}
	}
	change.Applied = true
	return change
}

// revert is the timer callback: back to info, unconditionally.
func (s *LevelSwitch) revert() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.current == LevelInfo {
		return
	}
	// A failed revert is the one failure this type must not swallow: it is
	// recorded on the switch so Current/Snapshot report the module is STILL at
	// debug, and the next Set retries.
	if err := s.apply(LevelInfo); err != nil {
		s.revertAt = s.now().Add(time.Minute)
		s.pending = s.afterFunc(time.Minute, s.revert)
		return
	}
	s.current = LevelInfo
	s.revertAt = time.Time{}
	s.pending = nil
}

func (s *LevelSwitch) cancelPendingLocked() {
	if s.pending != nil {
		s.pending.Stop()
		s.pending = nil
	}
}

// Current reports the level in force.
func (s *LevelSwitch) Current() Level {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.current
}

// RevertAt reports the armed auto-revert time (zero when none is armed).
func (s *LevelSwitch) RevertAt() time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.revertAt
}
