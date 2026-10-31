// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package nms

import (
	"sync"
	"time"
)

// breaker.go — the per-integration circuit breaker (NMS-first T1).
//
// A controller that is down, refusing us, or failing every request must stop
// being called on every cycle: each cycle costs a poll worker up to the
// deadline, and an auth failure retried every interval locks the service
// account out on controllers that count failed logins (vManage, Catalyst
// Center, NDFC all do). The breaker turns "N cycles in a row ended dead" into
// "stop calling it; probe it now and then with one login".
//
//	closed    → every cycle polls. breakerTripAfter consecutive TRIPPING cycles
//	            (unreachable · timeout · 5xx · auth_failed) open it.
//	open      → no network call at all; the run is recorded circuit_open.
//	            After the cooldown it goes half-open.
//	half-open → the next cycle makes ONE call: a login. Success closes the
//	            breaker (and the cycle then polls with that session); failure
//	            re-opens it with a doubled cooldown.
//
// Cooldown = FULL jitter over an exponential window (AWS "full jitter"):
// uniform in [0, min(cap, base·2^(opens-1))), base = the integration's poll
// interval, cap = 30 min. Full jitter spreads a fleet of integrations that all
// tripped in the same outage across the window instead of re-synchronising
// their probes. The scheduler only runs an integration when its interval is
// due, so the effective probe spacing is never below one interval.

const (
	breakerTripAfter   = 3
	breakerCooldownCap = 30 * time.Minute
)

// BreakerState is the breaker's position.
type BreakerState int

// Breaker states.
const (
	BreakerClosed BreakerState = iota
	BreakerOpen
	BreakerHalfOpen
)

func (s BreakerState) String() string {
	switch s {
	case BreakerOpen:
		return "open"
	case BreakerHalfOpen:
		return "half_open"
	default:
		return "closed"
	}
}

// Breaker is one integration's circuit breaker. Safe for concurrent use; the
// clock and the jitter source are injected (tests drive both).
type Breaker struct {
	mu        sync.Mutex
	state     BreakerState
	trips     int // consecutive tripping cycles while closed
	opens     int // consecutive opens without a successful close (cooldown exponent)
	openUntil time.Time
	base      time.Duration
	cap       time.Duration
	now       func() time.Time
	jitter    func() float64 // [0,1)
}

// NewBreaker builds a closed breaker. base is the cooldown base (the poll
// interval); nil now/jitter take the real clock and randJitter.
func NewBreaker(base time.Duration, now func() time.Time, jitter func() float64) *Breaker {
	if base <= 0 {
		base = defaultPollInterval
	}
	if now == nil {
		now = time.Now
	}
	if jitter == nil {
		jitter = randJitter
	}
	return &Breaker{base: base, cap: breakerCooldownCap, now: now, jitter: jitter}
}

// SetBase updates the cooldown base (the integration's interval changed).
func (b *Breaker) SetBase(base time.Duration) {
	if base <= 0 {
		return
	}
	b.mu.Lock()
	b.base = base
	b.mu.Unlock()
}

// Admit decides what this cycle may do: poll normally (closed), make one
// login probe (half-open; probe=true), or nothing (open; allowed=false). An
// open breaker whose cooldown has elapsed moves to half-open here.
func (b *Breaker) Admit() (allowed, probe bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	switch b.state {
	case BreakerOpen:
		if b.now().Before(b.openUntil) {
			return false, false
		}
		b.state = BreakerHalfOpen
		return true, true
	case BreakerHalfOpen:
		// A probe admitted earlier never reported (its cycle was cut short):
		// probe again rather than wedge half-open forever.
		return true, true
	default:
		return true, false
	}
}

// ForceProbe moves an open breaker to half-open now (the operator's "Poll
// now": one login probe instead of waiting out the cooldown). A closed or
// half-open breaker is unchanged.
func (b *Breaker) ForceProbe() {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.state == BreakerOpen {
		b.state = BreakerHalfOpen
	}
}

// Record folds one cycle's outcome. tripping = the cycle ended in a class
// that says the controller is down or refusing us. A probe's outcome is
// recorded the same way: success closes, a tripping failure re-opens.
func (b *Breaker) Record(tripping bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	switch b.state {
	case BreakerHalfOpen:
		if tripping {
			b.openLocked()
			return
		}
		b.state, b.trips, b.opens = BreakerClosed, 0, 0
	case BreakerOpen:
		// No cycle runs while open; nothing to fold.
	default:
		if !tripping {
			b.trips = 0
			return
		}
		b.trips++
		if b.trips >= breakerTripAfter {
			b.openLocked()
		}
	}
}

func (b *Breaker) openLocked() {
	b.opens++
	window := b.base
	for i := 1; i < b.opens && window < b.cap; i++ {
		window *= 2
	}
	if window > b.cap {
		window = b.cap
	}
	b.state = BreakerOpen
	b.trips = 0
	b.openUntil = b.now().Add(time.Duration(float64(window) * b.jitter()))
}

// State reports the breaker's position (open past its cooldown still reads
// open until a cycle is admitted).
func (b *Breaker) State() BreakerState {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.state
}
