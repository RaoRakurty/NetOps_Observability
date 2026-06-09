package main

import (
	"strings"
	"sync"
	"time"
)

// loginThrottle is an in-memory, process-local failed-login counter that locks an
// account after too many consecutive failures, per the scope's Security Settings
// (login_attempts_allowed / unlock_time_seconds). Best-effort by design: it
// throttles online brute force without adding a persistent store, and resets on
// restart. A successful login clears the account's failure state.
//
// All methods are nil-safe so test servers that don't wire a throttle simply
// have lockout disabled.
type loginThrottle struct {
	mu      sync.Mutex
	entries map[string]*throttleEntry
}

type throttleEntry struct {
	fails       int
	lockedUntil time.Time
}

const throttleMaxAccounts = 50000 // memory backstop against username spraying

func newLoginThrottle() *loginThrottle {
	return &loginThrottle{entries: map[string]*throttleEntry{}}
}

func throttleKey(user string) string { return strings.ToLower(strings.TrimSpace(user)) }

// locked reports whether the account is currently locked and the remaining time.
// An expired lock is cleared lazily.
func (t *loginThrottle) locked(user string) (bool, time.Duration) {
	if t == nil {
		return false, 0
	}
	k := throttleKey(user)
	t.mu.Lock()
	defer t.mu.Unlock()
	e := t.entries[k]
	if e == nil || e.lockedUntil.IsZero() {
		return false, 0
	}
	if d := time.Until(e.lockedUntil); d > 0 {
		return true, d
	}
	delete(t.entries, k) // lock window elapsed
	return false, 0
}

// fail records one failed attempt and locks the account once it reaches `allowed`.
// allowed<=0 disables lockout (no-op).
func (t *loginThrottle) fail(user string, allowed, unlockSeconds int) {
	if t == nil || allowed <= 0 {
		return
	}
	k := throttleKey(user)
	t.mu.Lock()
	defer t.mu.Unlock()
	e := t.entries[k]
	if e == nil {
		if len(t.entries) >= throttleMaxAccounts {
			return // backstop: stop tracking new accounts under a spray
		}
		e = &throttleEntry{}
		t.entries[k] = e
	}
	e.fails++
	if e.fails >= allowed {
		secs := unlockSeconds
		if secs <= 0 {
			secs = 300
		}
		e.lockedUntil = time.Now().Add(time.Duration(secs) * time.Second)
	}
}

// success clears any failure/lock state for the account.
func (t *loginThrottle) success(user string) {
	if t == nil {
		return
	}
	k := throttleKey(user)
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.entries, k)
}
