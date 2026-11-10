// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// Package aiprovider guards model-provider calls: a circuit breaker per
// (tenant, provider) and the call metrics (Iris latency batch, 2026-11-10).
//
// Why a breaker: on 2026-11-10 the lab's provider failed every call, and every
// question still paid the full wait for it (20 s on the model-compile path, 60 s
// on narration). After N consecutive failures the breaker opens and calls are
// SKIPPED for a cool-down — the answer ships at once with an honest note — then
// one probe call is let through (half-open); success closes it, failure
// re-opens it.
//
// Keys are (tenant, provider) so one tenant's bad BYO key never pauses another
// tenant's AI (CLAUDE.md §3a: tenant isolation holds for availability state
// too). The key set is BOUNDED (MaxKeys): past it, the least recently used
// closed breaker is evicted — an open one is kept, since forgetting it would
// re-admit the very calls it exists to stop.
//
// Stdlib only; no globals; the clock is injectable.
package aiprovider

import (
	"sort"
	"sync"
	"time"
)

// State is a breaker's state.
type State int

// Breaker states.
const (
	Closed State = iota
	Open
	HalfOpen
)

// String is the metric label for a state.
func (s State) String() string {
	switch s {
	case Open:
		return "open"
	case HalfOpen:
		return "half_open"
	}
	return "closed"
}

// States is every state, in label order.
var States = []State{Closed, Open, HalfOpen}

// Defaults.
const (
	DefaultThreshold = 3
	DefaultCooldown  = 60 * time.Second
	DefaultMaxKeys   = 4096
)

// Config tunes a Breaker. Zero fields take the defaults.
type Config struct {
	Threshold int              // consecutive failures that open the breaker
	Cooldown  time.Duration    // how long an open breaker skips calls before a probe
	MaxKeys   int              // bound on remembered (tenant, provider) pairs
	Now       func() time.Time // clock (tests)
}

type entry struct {
	state     State
	failures  int       // consecutive failures while closed
	openedAt  time.Time // when it last opened
	probing   bool      // a half-open probe is in flight
	lastTouch time.Time
}

type key struct{ tenant, provider string }

// Breaker is the per-(tenant, provider) circuit breaker. Safe for concurrent
// use; a nil *Breaker admits every call and records nothing.
type Breaker struct {
	mu          sync.Mutex
	cfg         Config
	m           map[key]*entry
	transitions map[string]map[State]int64 // provider → to-state → count
}

// NewBreaker builds a breaker.
func NewBreaker(cfg Config) *Breaker {
	if cfg.Threshold <= 0 {
		cfg.Threshold = DefaultThreshold
	}
	if cfg.Cooldown <= 0 {
		cfg.Cooldown = DefaultCooldown
	}
	if cfg.MaxKeys <= 0 {
		cfg.MaxKeys = DefaultMaxKeys
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &Breaker{cfg: cfg, m: map[key]*entry{}, transitions: map[string]map[State]int64{}}
}

// Allow reports whether a call to provider for tenant may proceed. An open
// breaker past its cool-down becomes half-open and admits exactly ONE probe;
// concurrent callers are refused until the probe reports.
func (b *Breaker) Allow(tenant, provider string) bool {
	if b == nil {
		return true
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	e := b.m[key{tenant, provider}]
	if e == nil {
		return true
	}
	now := b.cfg.Now()
	e.lastTouch = now
	switch e.state {
	case Closed:
		return true
	case Open:
		if now.Sub(e.openedAt) < b.cfg.Cooldown {
			return false
		}
		b.setState(provider, e, HalfOpen)
		e.probing = true
		return true
	default: // HalfOpen
		if e.probing {
			return false
		}
		e.probing = true
		return true
	}
}

// Peek reports whether Allow WOULD admit a call, without claiming the probe.
// It is for "is there any usable provider" checks that decide whether to try
// at all (the model-compile path skips itself entirely when nothing is usable).
func (b *Breaker) Peek(tenant, provider string) bool {
	if b == nil {
		return true
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	e := b.m[key{tenant, provider}]
	if e == nil {
		return true
	}
	switch e.state {
	case Closed:
		return true
	case Open:
		return b.cfg.Now().Sub(e.openedAt) >= b.cfg.Cooldown
	default:
		return !e.probing
	}
}

// Record reports a call's result. failure=false is a success (closes the
// breaker, clears the count). A call that should not count either way (the
// caller left, budget spent) must simply not be recorded — use Release.
func (b *Breaker) Record(tenant, provider string, failure bool) {
	if b == nil {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	k := key{tenant, provider}
	e := b.m[k]
	now := b.cfg.Now()
	if e == nil {
		if !failure {
			return // nothing to remember about a healthy pair
		}
		b.evictLocked()
		e = &entry{}
		b.m[k] = e
	}
	e.lastTouch = now
	e.probing = false
	if !failure {
		e.failures = 0
		if e.state != Closed {
			b.setState(provider, e, Closed)
		}
		return
	}
	switch e.state {
	case HalfOpen:
		e.openedAt = now
		b.setState(provider, e, Open)
	case Closed:
		e.failures++
		if e.failures >= b.cfg.Threshold {
			e.openedAt = now
			b.setState(provider, e, Open)
		}
	case Open:
		e.openedAt = now
	}
}

// Release gives back a half-open probe slot claimed by Allow whose call ended
// without a verdict (the caller left). The breaker stays half-open.
func (b *Breaker) Release(tenant, provider string) {
	if b == nil {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if e := b.m[key{tenant, provider}]; e != nil {
		e.probing = false
	}
}

// State returns the current state of a pair (Closed when unknown).
func (b *Breaker) State(tenant, provider string) State {
	if b == nil {
		return Closed
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if e := b.m[key{tenant, provider}]; e != nil {
		return e.state
	}
	return Closed
}

// Len is the number of remembered pairs (bounded by MaxKeys).
func (b *Breaker) Len() int {
	if b == nil {
		return 0
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.m)
}

func (b *Breaker) setState(provider string, e *entry, to State) {
	e.state = to
	t := b.transitions[provider]
	if t == nil {
		t = map[State]int64{}
		b.transitions[provider] = t
	}
	t[to]++
}

// evictLocked makes room for one new pair: the least recently touched CLOSED
// pair goes first; only when every pair is open or half-open does the oldest
// of those go (the bound is a hard bound).
func (b *Breaker) evictLocked() {
	if len(b.m) < b.cfg.MaxKeys {
		return
	}
	if k, ok := b.oldestLocked(true); ok {
		delete(b.m, k)
		return
	}
	if k, ok := b.oldestLocked(false); ok {
		delete(b.m, k)
	}
}

// oldestLocked finds the least recently touched pair (closed ones only when
// closedOnly).
func (b *Breaker) oldestLocked(closedOnly bool) (key, bool) {
	var victim key
	var oldest time.Time
	found := false
	for k, e := range b.m {
		if closedOnly && e.state != Closed {
			continue
		}
		if !found || e.lastTouch.Before(oldest) {
			victim, oldest, found = k, e.lastTouch, true
		}
	}
	return victim, found
}

// Snapshot is the breaker's state for the metrics endpoint: per provider, how
// many tenant pairs are in each state, and transition counts.
type Snapshot struct {
	Providers   []string
	States      map[string]map[State]int
	Transitions map[string]map[State]int64
}

// Snapshot copies the current counts.
func (b *Breaker) Snapshot() Snapshot {
	out := Snapshot{States: map[string]map[State]int{}, Transitions: map[string]map[State]int64{}}
	if b == nil {
		return out
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	seen := map[string]bool{}
	for k, e := range b.m {
		if out.States[k.provider] == nil {
			out.States[k.provider] = map[State]int{}
		}
		out.States[k.provider][e.state]++
		seen[k.provider] = true
	}
	for p, t := range b.transitions {
		c := make(map[State]int64, len(t))
		for s, n := range t {
			c[s] = n
		}
		out.Transitions[p] = c
		seen[p] = true
	}
	for p := range seen {
		out.Providers = append(out.Providers, p)
	}
	sort.Strings(out.Providers)
	return out
}
