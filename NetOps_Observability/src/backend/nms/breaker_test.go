// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package nms

import (
	"sync"
	"testing"
	"time"
)

// fakeClock is a hand-advanced clock shared by the breaker and runtime tests.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func newFakeClock() *fakeClock { return &fakeClock{t: time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC)} }

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

func TestBreakerTransitions(t *testing.T) {
	clk := newFakeClock()
	b := NewBreaker(time.Minute, clk.Now, func() float64 { return 0.5 })

	// Two tripping cycles and a clean one: the count resets, still closed.
	b.Record(true)
	b.Record(true)
	b.Record(false)
	b.Record(true)
	b.Record(true)
	if b.State() != BreakerClosed {
		t.Fatalf("state %v after 2 consecutive trips; want closed", b.State())
	}
	if ok, probe := b.Admit(); !ok || probe {
		t.Fatalf("closed breaker must admit a normal cycle: ok=%v probe=%v", ok, probe)
	}
	b.Record(true) // third consecutive → open
	if b.State() != BreakerOpen {
		t.Fatalf("state %v after 3 consecutive trips; want open", b.State())
	}
	// First cooldown: full jitter over base·2^0 = 1m → 0.5 × 1m = 30s.
	clk.Advance(29 * time.Second)
	if ok, _ := b.Admit(); ok {
		t.Fatal("open breaker admitted a cycle before its cooldown")
	}
	clk.Advance(2 * time.Second)
	ok, probe := b.Admit()
	if !ok || !probe || b.State() != BreakerHalfOpen {
		t.Fatalf("after the cooldown: ok=%v probe=%v state=%v; want a half-open probe", ok, probe, b.State())
	}
	// A failed probe re-opens with a doubled window: 0.5 × 2m = 60s.
	b.Record(true)
	if b.State() != BreakerOpen {
		t.Fatalf("failed probe left state %v; want open", b.State())
	}
	clk.Advance(59 * time.Second)
	if ok, _ := b.Admit(); ok {
		t.Fatal("second cooldown not doubled")
	}
	clk.Advance(2 * time.Second)
	if ok, probe := b.Admit(); !ok || !probe {
		t.Fatal("second cooldown elapsed but no probe admitted")
	}
	// A good probe closes it and resets the exponent.
	b.Record(false)
	if b.State() != BreakerClosed {
		t.Fatalf("good probe left state %v; want closed", b.State())
	}
	for i := 0; i < 3; i++ {
		b.Record(true)
	}
	clk.Advance(31 * time.Second) // back to the FIRST window, not the third
	if ok, probe := b.Admit(); !ok || !probe {
		t.Fatal("exponent was not reset by the successful close")
	}
}

func TestBreakerCooldownCapAndFullJitter(t *testing.T) {
	clk := newFakeClock()
	jit := 0.999
	b := NewBreaker(10*time.Minute, clk.Now, func() float64 { return jit })
	for i := 0; i < 3; i++ {
		b.Record(true)
	}
	// Drive many opens; the window must never exceed the 30-minute cap.
	for i := 0; i < 8; i++ {
		clk.Advance(breakerCooldownCap)
		if ok, probe := b.Admit(); !ok || !probe {
			t.Fatalf("open %d: no probe after a full cap of waiting", i)
		}
		b.Record(true)
	}
	// Full jitter: a zero draw means an immediate probe (the scheduler's
	// interval gate is what spaces it).
	jit = 0
	clk.Advance(breakerCooldownCap)
	b.Admit()
	b.Record(true)
	if ok, _ := b.Admit(); !ok {
		t.Fatal("full jitter with a zero draw must allow the next due cycle")
	}
}

func TestBreakerForceProbe(t *testing.T) {
	clk := newFakeClock()
	b := NewBreaker(time.Minute, clk.Now, func() float64 { return 0.9 })
	b.ForceProbe() // closed: no effect
	if b.State() != BreakerClosed {
		t.Fatal("ForceProbe changed a closed breaker")
	}
	for i := 0; i < 3; i++ {
		b.Record(true)
	}
	b.ForceProbe()
	if ok, probe := b.Admit(); !ok || !probe {
		t.Fatal("ForceProbe on an open breaker must admit one probe now")
	}
}
