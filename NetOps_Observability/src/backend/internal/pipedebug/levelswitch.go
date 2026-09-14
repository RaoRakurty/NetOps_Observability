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
	// gen identifies the CURRENT raise. Stop() reports false for a timer that
	// has already fired, and that callback is then waiting on mu for whoever is
	// replacing it: without a generation to check, it reverted the raise that
	// replaced it while the API had already answered "raised until T+window"
	// (review 3.5-16, the same defect as internal/parsetrace's). Every Set bumps
	// it, so a callback from an older generation is a no-op rather than a silent
	// revert. A failed revert's RETRY keeps its own generation, because it is
	// still that raise's revert.
	gen uint64
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
	s.gen++
	gen := s.gen

	if level == LevelDebug {
		w := ClampWindow(window)
		s.revertAt = s.now().Add(w)
		s.pending = s.afterFunc(w, func() { s.revert(gen) })
		change.RevertAt = s.revertAt
		change.Reason = "auto-reverts to info at the stamped time even if the caller dies"
	} else {
		s.revertAt = time.Time{}
	}
	change.Applied = true
	return change
}

// revert is the timer callback: back to info — for the raise that armed it and
// no other. A timer that had already fired when Set called Stop() arrives here
// holding an older generation and must leave the live raise alone, or it reverts
// a window the API has already reported as armed (review 3.5-16).
func (s *LevelSwitch) revert(gen uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.gen != gen {
		return
	}
	if s.current == LevelInfo {
		return
	}
	// A failed revert is the one failure this type must not swallow: it is
	// recorded on the switch so Current/Snapshot report the module is STILL at
	// debug, and the next Set retries.
	if err := s.apply(LevelInfo); err != nil {
		s.revertAt = s.now().Add(time.Minute)
		s.pending = s.afterFunc(time.Minute, func() { s.revert(gen) })
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
