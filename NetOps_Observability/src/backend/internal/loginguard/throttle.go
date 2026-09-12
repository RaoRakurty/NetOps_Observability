// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package loginguard

import (
	"context"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Throttle is an in-memory, process-local failed-login counter that locks an
// account after too many consecutive failures, per the scope's Security Settings
// (login_attempts_allowed / unlock_time_seconds). Best-effort by design: it
// throttles online brute force without adding a persistent store, and resets on
// restart. A successful login clears the account's failure state.
//
// All methods are nil-safe so test servers that don't wire a throttle simply
// have lockout disabled.
//
// ── F-25: this map used to FAIL OPEN, silently ───────────────────────────────
// The old code returned from fail() the moment the map hit 50,000 entries. An
// entry with fails<allowed and a zero lockedUntil was never swept, so the map
// only ever grew. /api/auth/login is unauthenticated (publicPaths), so anyone
// could spray ~50k junk usernames, fill the map, and from then on NO new
// account was tracked — brute-force lockout was off platform-wide, with no log
// and no metric. Operators would still see "lockout: enabled" in Security
// Settings. A throttle that disables itself under load is worse than no
// throttle, because it is believed.
//
// The replacement keeps the memory bound and never stops counting:
//
//  1. SWEEP. Unlocked entries older than trackWindow, and locks that have
//     expired, are dropped. Junk from a spray evaporates on its own.
//  2. LRU EVICTION of UNLOCKED entries when the cap is reached. A locked entry
//     is never evictable — otherwise the spray becomes an UNLOCK primitive:
//     50k junk logins would clear the lock on the account being attacked.
//     Attacker entries (touched once) are the LRU; an account actively being
//     brute-forced is touched every guess and stays hot, so reaching the
//     lockout threshold survives eviction.
//  3. FAIL CLOSED at true saturation. If every one of the 50k slots is a live
//     lock there is no room and no eviction candidate. The old code shrugged;
//     this one reports untracked=false to the caller, which refuses the sign-in
//     the way a lock does, and counts + logs it. That is a login brown-out
//     caused by an attacker — deliberate: refusing sign-ins loudly is the
//     lesser failure against silently disabling brute-force protection for
//     every account. It self-heals as locks expire (default 300s), and it takes
//     allowed×50k failures inside one unlock window to reach.
type Throttle struct {
	warn    func(msg string, fields map[string]any)
	mu      sync.Mutex
	entries map[string]*throttleEntry
	max     int
	window  time.Duration
	now     func() time.Time

	// Observability (§10): every one of these was a silent event before.
	evictions  atomic.Uint64
	sweeps     atomic.Uint64
	saturation atomic.Uint64
}

type throttleEntry struct {
	fails       int
	lockedUntil time.Time
	// lastSeen drives both sweeping and LRU eviction. Its absence is why the
	// old map could only grow.
	lastSeen time.Time
}

const (
	throttleMaxAccounts = 50000           // memory backstop against username spraying
	throttleTrackWindow = 1 * time.Hour   // unlocked failure state older than this is stale
	throttleSweepEvery  = 5 * time.Minute // janitor cadence
)

// Evictions reports how many tracked accounts were evicted by the cap.
func (t *Throttle) Evictions() uint64 { return t.evictions.Load() }

// Sweeps reports how many janitor sweeps have run.
func (t *Throttle) Sweeps() uint64 { return t.sweeps.Load() }

// Saturations reports how many sign-ins were refused because the tracker was
// full of locked accounts (the F-25 fail-closed signal).
func (t *Throttle) Saturations() uint64 { return t.saturation.Load() }

// NewThrottleWithLimits is NewThrottle with an explicit tracker cap and clock —
// test support for saturation/expiry scenarios without waiting real time.
func NewThrottleWithLimits(max int, now func() time.Time, warn func(msg string, fields map[string]any)) *Throttle {
	t := NewThrottle(warn)
	if max > 0 {
		t.max = max
	}
	if now != nil {
		t.now = now
	}
	return t
}

// NewThrottle builds the in-memory lockout throttle. warn is the structured
// warning sink for the F-25 saturation signal (nil → silent, but the refusal
// behavior is unchanged).
func NewThrottle(warn func(msg string, fields map[string]any)) *Throttle {
	if warn == nil {
		warn = func(string, map[string]any) {}
	}
	return &Throttle{
		warn:    warn,
		entries: map[string]*throttleEntry{},
		max:     throttleMaxAccounts,
		window:  throttleTrackWindow,
		now:     time.Now,
	}
}

func throttleKey(user string) string { return strings.ToLower(strings.TrimSpace(user)) }

func (t *Throttle) clock() time.Time {
	if t.now != nil {
		return t.now()
	}
	return time.Now()
}

// locked reports whether the account is currently locked and the remaining time.
// An expired lock is cleared lazily.
func (t *Throttle) Locked(user string) (bool, time.Duration) {
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
	if d := e.lockedUntil.Sub(t.clock()); d > 0 {
		return true, d
	}
	delete(t.entries, k) // lock window elapsed
	return false, 0
}

// fail records one failed attempt and locks the account once it reaches
// `allowed`. allowed<=0 disables lockout (no-op, tracked=true).
//
// tracked reports whether the failure was actually COUNTED. false means the
// throttle is saturated (F-25) and the caller MUST refuse the attempt — an
// uncounted failure is an unlimited guess.
func (t *Throttle) Fail(user string, allowed, unlockSeconds int) (tracked bool) {
	if t == nil || allowed <= 0 {
		return true
	}
	k := throttleKey(user)
	now := t.clock()

	t.mu.Lock()
	defer t.mu.Unlock()
	e := t.entries[k]
	if e == nil {
		if len(t.entries) >= t.max {
			t.sweepLocked(now)
		}
		if len(t.entries) >= t.max && !t.evictLRULocked(now) {
			// Every slot is a live lock: no room, nothing evictable.
			t.saturation.Add(1)
			t.warn("login throttle saturated — sign-ins refused while every tracked account is locked",
				map[string]any{"tracked_accounts": len(t.entries), "max": t.max})
			return false
		}
		e = &throttleEntry{}
		t.entries[k] = e
	}
	e.fails++
	e.lastSeen = now
	if e.fails >= allowed {
		secs := unlockSeconds
		if secs <= 0 {
			secs = 300
		}
		e.lockedUntil = now.Add(time.Duration(secs) * time.Second)
	}
	return true
}

// success clears any failure/lock state for the account.
func (t *Throttle) Success(user string) {
	if t == nil {
		return
	}
	k := throttleKey(user)
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.entries, k)
}

// sweep drops stale state. Called by the janitor; also inline at the cap.
func (t *Throttle) sweep() {
	if t == nil {
		return
	}
	now := t.clock()
	t.mu.Lock()
	defer t.mu.Unlock()
	t.sweepLocked(now)
}

// sweepLocked removes expired locks and unlocked entries idle past the tracking
// window. This is the deletion path the original had NO equivalent of: entries
// were only ever removed on a successful login or a lock expiry check, so a
// spray of usernames that never log in successfully accumulated forever.
func (t *Throttle) sweepLocked(now time.Time) {
	removed := 0
	for k, e := range t.entries {
		switch {
		case !e.lockedUntil.IsZero():
			if !e.lockedUntil.After(now) {
				delete(t.entries, k)
				removed++
			}
		case now.Sub(e.lastSeen) >= t.window:
			delete(t.entries, k)
			removed++
		}
	}
	if removed > 0 {
		t.sweeps.Add(uint64(removed))
	}
}

// evictLRULocked frees one slot by dropping the least-recently-touched UNLOCKED
// entry, and reports whether it found one. Locked entries are deliberately not
// candidates: evicting a lock would let a spray unlock the account under attack.
func (t *Throttle) evictLRULocked(now time.Time) bool {
	oldestKey := ""
	var oldest time.Time
	for k, e := range t.entries {
		if !e.lockedUntil.IsZero() && e.lockedUntil.After(now) {
			continue // live lock — never evictable
		}
		if oldestKey == "" || e.lastSeen.Before(oldest) {
			oldestKey, oldest = k, e.lastSeen
		}
	}
	if oldestKey == "" {
		return false
	}
	delete(t.entries, oldestKey)
	t.evictions.Add(1)
	return true
}

// size reports the tracked-account count (metrics + tests).
func (t *Throttle) Size() int {
	if t == nil {
		return 0
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.entries)
}

// runJanitor sweeps stale state until ctx is cancelled, so an idle process
// releases the memory a spray parked in the map instead of holding it until
// restart.
func (t *Throttle) RunJanitor(ctx context.Context) {
	if t == nil {
		return
	}
	tk := time.NewTicker(throttleSweepEvery)
	defer tk.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tk.C:
			t.sweep()
		}
	}
}
