// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package pipedebug

// levelswitch_stale_timer_test.go — A TIMER THAT HAS ALREADY FIRED MUST NOT
// REVERT THE RAISE THAT REPLACED IT (review 3.5-16, the same defect in the
// sibling switch).
//
// 3.5-16 was filed against internal/parsetrace, where cancelPendingLocked
// discarded Stop()'s answer so a timer already past firing sat on the mutex and
// then disarmed the window that replaced it. LevelSwitch is the other half of
// the same design — parsetrace's own doc says its cap "deliberately matches the
// debug log level's cap" — and it had the identical hole: Set() cancels the
// pending revert, ignores Stop() reporting "too late", and revert() then reverts
// whatever it finds. The sequence is
//
//	Set(debug, 1m)          → timer T1
//	T1 fires at +1m         → blocked on s.mu
//	Set(debug, 10m)         → Stop() says false (ignored), T2 armed,
//	                          LevelChange.RevertAt = +10m is returned to the
//	                          operator and stamped in the audit row
//	T1's callback runs      → applies info
//
// so the module is back at info while the operator has been told, in the API
// response, that it is raised for another ten minutes. The debug lines they
// raised it to collect are never written, and nothing anywhere reports an error
// (§10). A generation counter makes the stale callback a no-op.

import (
	"errors"
	"testing"
	"time"
)

// lateTimer is a fired timer, deterministically: Stop() reports "too late" and
// the test releases the callback afterwards the way the scheduler would.
type lateTimer struct{ fn func() }

func (lateTimer) Stop() bool { return false }

func newLateSwitch(apply func(Level) error) (*LevelSwitch, *[]*lateTimer) {
	s := NewLevelSwitch(ModuleAPI, apply)
	timers := &[]*lateTimer{}
	s.afterFunc = func(_ time.Duration, fn func()) stopper {
		lt := &lateTimer{fn: fn}
		*timers = append(*timers, lt)
		return lt
	}
	return s, timers
}

func TestAnAlreadyFiredRevertDoesNotUndoTheRaiseThatReplacedIt(t *testing.T) {
	var applied []Level
	s, timers := newLateSwitch(func(l Level) error { applied = append(applied, l); return nil })

	s.Set(LevelDebug, time.Minute)
	change := s.Set(LevelDebug, 10*time.Minute)
	if !change.Applied || change.RevertAt.IsZero() {
		t.Fatalf("the extending raise was not applied: %+v", change)
	}
	if len(*timers) != 2 {
		t.Fatalf("expected one timer per raise, got %d", len(*timers))
	}

	(*timers)[0].fn() // the first window's expiry, landing after the second raise

	if s.Current() != LevelDebug {
		t.Fatalf("the first window's timer reverted the raise that replaced it (level=%s) — "+
			"the API answered %q and the operator's debug lines are never written; applied=%v",
			s.Current(), change.RevertAt.Format(time.RFC3339), applied)
	}
	if s.RevertAt() != change.RevertAt {
		t.Fatalf("RevertAt() = %v, want the extended deadline %v the caller was given",
			s.RevertAt(), change.RevertAt)
	}

	// The CURRENT window's timer still reverts, or the module would never come
	// back down — which is the invariant this type exists for.
	(*timers)[1].fn()
	if s.Current() != LevelInfo {
		t.Fatal("the live window's timer no longer reverts the module")
	}
}

// An explicit revert followed by a fresh raise must also survive a callback
// that was already past Stop() when the revert ran.
func TestAnAlreadyFiredRevertCannotUndoARevertAndRaise(t *testing.T) {
	s, timers := newLateSwitch(func(Level) error { return nil })

	s.Set(LevelDebug, time.Minute)
	s.Set(LevelInfo, 0)
	change := s.Set(LevelDebug, 10*time.Minute)

	(*timers)[0].fn() // two state changes late

	if s.Current() != LevelDebug || s.RevertAt() != change.RevertAt {
		t.Fatalf("a stale revert brought down a raise made after an explicit revert "+
			"(level=%s revert_at=%v, want debug/%v)", s.Current(), s.RevertAt(), change.RevertAt)
	}
}

// The RETRY a failed revert arms belongs to the same generation as the revert
// that failed: it must still fire, or a module that could not come down would
// stay up with nothing left to bring it back.
func TestAFailedRevertsRetryStillReverts(t *testing.T) {
	fail := true
	s, timers := newLateSwitch(func(l Level) error {
		if l == LevelInfo && fail {
			return errFailedRevert
		}
		return nil
	})
	s.Set(LevelDebug, time.Minute)
	(*timers)[0].fn() // revert fails, a retry is armed
	if s.Current() != LevelDebug {
		t.Fatal("a failed revert was recorded as if the module had come down")
	}
	if len(*timers) != 2 {
		t.Fatalf("a failed revert armed %d retries, want 1", len(*timers)-1)
	}
	fail = false
	(*timers)[1].fn()
	if s.Current() != LevelInfo {
		t.Fatal("the retry armed by a failed revert did not bring the module down")
	}
}

// errFailedRevert stands for "the logger could not be reconfigured".
var errFailedRevert = errors.New("cannot revert")
