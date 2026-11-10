// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package aiprovider

import (
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

func newTestBreaker(threshold int, cooldown time.Duration, maxKeys int) (*Breaker, *clock) {
	c := &clock{t: time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC)}
	return NewBreaker(Config{Threshold: threshold, Cooldown: cooldown, MaxKeys: maxKeys, Now: c.now}), c
}

func TestBreakerOpensAfterConsecutiveFailures(t *testing.T) {
	b, _ := newTestBreaker(3, time.Minute, 0)
	for i := 0; i < 2; i++ {
		if !b.Allow("t-a", "gemini") {
			t.Fatalf("call %d must be admitted while closed", i)
		}
		b.Record("t-a", "gemini", true)
	}
	if b.State("t-a", "gemini") != Closed {
		t.Fatal("2 failures < threshold 3: still closed")
	}
	b.Record("t-a", "gemini", true)
	if b.State("t-a", "gemini") != Open {
		t.Fatal("3 consecutive failures must open the breaker")
	}
	if b.Allow("t-a", "gemini") || b.Peek("t-a", "gemini") {
		t.Fatal("an open breaker inside its cool-down must refuse")
	}
}

func TestBreakerSuccessResetsTheCount(t *testing.T) {
	b, _ := newTestBreaker(3, time.Minute, 0)
	b.Record("t-a", "gemini", true)
	b.Record("t-a", "gemini", true)
	b.Record("t-a", "gemini", false) // success between failures
	b.Record("t-a", "gemini", true)
	b.Record("t-a", "gemini", true)
	if b.State("t-a", "gemini") != Closed {
		t.Fatal("failures must be CONSECUTIVE to open the breaker")
	}
}

func TestBreakerHalfOpenAdmitsOneProbe(t *testing.T) {
	b, c := newTestBreaker(1, time.Minute, 0)
	b.Record("t-a", "gemini", true)
	c.add(59 * time.Second)
	if b.Allow("t-a", "gemini") {
		t.Fatal("still cooling down")
	}
	c.add(2 * time.Second)
	if !b.Peek("t-a", "gemini") {
		t.Fatal("Peek must report a probe is possible after the cool-down")
	}
	if !b.Allow("t-a", "gemini") {
		t.Fatal("after the cool-down exactly one probe goes through")
	}
	if b.State("t-a", "gemini") != HalfOpen {
		t.Fatal("probing = half-open")
	}
	if b.Allow("t-a", "gemini") || b.Peek("t-a", "gemini") {
		t.Fatal("a second caller must not get a probe while one is in flight")
	}
	// Probe fails → open again for a full cool-down.
	b.Record("t-a", "gemini", true)
	if b.State("t-a", "gemini") != Open || b.Allow("t-a", "gemini") {
		t.Fatal("a failed probe re-opens")
	}
	c.add(61 * time.Second)
	if !b.Allow("t-a", "gemini") {
		t.Fatal("next probe after the new cool-down")
	}
	b.Record("t-a", "gemini", false)
	if b.State("t-a", "gemini") != Closed || !b.Allow("t-a", "gemini") {
		t.Fatal("a successful probe closes the breaker")
	}
}

func TestBreakerReleaseReturnsTheProbe(t *testing.T) {
	b, c := newTestBreaker(1, time.Second, 0)
	b.Record("t-a", "gemini", true)
	c.add(2 * time.Second)
	if !b.Allow("t-a", "gemini") {
		t.Fatal("probe")
	}
	b.Release("t-a", "gemini") // the caller left; no verdict
	if !b.Allow("t-a", "gemini") {
		t.Fatal("a released probe slot must be claimable again")
	}
}

// §3a: one workspace's failing provider never pauses another workspace.
func TestBreakerIsPerTenantAndProvider(t *testing.T) {
	b, _ := newTestBreaker(2, time.Hour, 0)
	b.Record("t-a", "gemini", true)
	b.Record("t-a", "gemini", true)
	if b.Allow("t-a", "gemini") {
		t.Fatal("t-a gemini is open")
	}
	if !b.Allow("t-b", "gemini") {
		t.Fatal("ISOLATION: t-a's failures paused t-b")
	}
	if !b.Allow("t-a", "openai") {
		t.Fatal("a different provider of the same tenant stays closed")
	}
}

func TestBreakerIsBoundedAndKeepsOpenEntries(t *testing.T) {
	b, c := newTestBreaker(1, time.Hour, 4)
	b.Record("open-tenant", "gemini", true) // open, oldest
	for i := 0; i < 20; i++ {
		c.add(time.Second)
		b.Record(fmt.Sprintf("t-%d", i), "gemini", true)
		b.Record(fmt.Sprintf("t-%d", i), "gemini", false) // closed again
	}
	if b.Len() > 4 {
		t.Fatalf("breaker remembers %d pairs, bound is 4", b.Len())
	}
	if b.State("open-tenant", "gemini") != Open {
		t.Fatal("an OPEN breaker must survive eviction of closed ones")
	}
	// A healthy pair is never stored at all.
	b2, _ := newTestBreaker(3, time.Hour, 0)
	b2.Record("t-x", "gemini", false)
	if b2.Len() != 0 {
		t.Fatal("success on an unknown pair must not allocate")
	}
}

func TestNilBreakerAdmitsEverything(t *testing.T) {
	var b *Breaker
	if !b.Allow("t", "p") || !b.Peek("t", "p") || b.State("t", "p") != Closed || b.Len() != 0 {
		t.Fatal("nil breaker")
	}
	b.Record("t", "p", true)
	b.Release("t", "p")
	_ = b.Snapshot()
}

func TestBreakerConcurrentUse(t *testing.T) {
	b, _ := newTestBreaker(3, time.Minute, 64)
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			tn := fmt.Sprintf("t-%d", i%8)
			for j := 0; j < 100; j++ {
				if b.Allow(tn, "gemini") {
					b.Record(tn, "gemini", j%3 == 0)
				}
			}
		}(i)
	}
	wg.Wait()
}

func TestMetricsRender(t *testing.T) {
	b, _ := newTestBreaker(1, time.Hour, 0)
	m := NewMetrics(b)
	m.ObserveCall("gemini", "fast", "timeout", 8.0)
	m.ObserveCall("gemini", "fast", "timeout", 0.3)
	m.ObserveCall("gemini", "", "ok", 1.2)
	b.Record("t-a", "gemini", true)
	var sb strings.Builder
	if err := m.Write(&sb); err != nil {
		t.Fatal(err)
	}
	out := sb.String()
	for _, want := range []string{
		`netops_ai_provider_call_seconds_bucket{provider="gemini",tier="fast",outcome="timeout",le="0.5"} 1`,
		`netops_ai_provider_call_seconds_bucket{provider="gemini",tier="fast",outcome="timeout",le="8"} 2`,
		`netops_ai_provider_call_seconds_bucket{provider="gemini",tier="fast",outcome="timeout",le="+Inf"} 2`,
		`netops_ai_provider_call_seconds_count{provider="gemini",tier="default",outcome="ok"} 1`,
		`netops_ai_provider_breaker_state{provider="gemini",state="open"} 1`,
		`netops_ai_provider_breaker_state{provider="gemini",state="closed"} 0`,
		`netops_ai_provider_breaker_transitions_total{provider="gemini",to="open"} 1`,
		"# TYPE netops_ai_provider_call_seconds histogram",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	var nm *Metrics
	nm.ObserveCall("x", "y", "z", 1)
	if err := nm.Write(&sb); err != nil {
		t.Fatal(err)
	}
}

func TestMetricsLabelSpaceIsBounded(t *testing.T) {
	m := NewMetrics(nil)
	for i := 0; i < maxCallSeries+10; i++ {
		m.ObserveCall(fmt.Sprintf("p%d", i), "fast", "ok", 1)
	}
	if len(m.calls) != maxCallSeries || m.dropped.Load() != 10 {
		t.Fatalf("series=%d dropped=%d", len(m.calls), m.dropped.Load())
	}
}
