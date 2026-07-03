package nms

import (
	"context"
	"net/http"
	"testing"
	"time"
)

func TestDedupeKey(t *testing.T) {
	// Vendor event id anchors the key.
	e := ControllerEvent{IntegrationID: "int1", EventID: "abc-123"}
	if got := DedupeKey(e); got != "int1:abc-123" {
		t.Fatalf("event-id key = %q", got)
	}
	// No event id → deterministic hash of identity tuple; same input, same key.
	e2 := ControllerEvent{IntegrationID: "int1", NormalizedEventType: "controller_tunnel_state", DeviceID: "r1", Message: "tunnel down"}
	k1, k2 := DedupeKey(e2), DedupeKey(e2)
	if k1 != k2 || k1 == "" {
		t.Fatalf("hash key not deterministic: %q %q", k1, k2)
	}
	// Different device → different key.
	e3 := e2
	e3.DeviceID = "r2"
	if DedupeKey(e3) == k1 {
		t.Fatal("different entity must yield a different key")
	}
}

func TestSeenSetLRUAndDedup(t *testing.T) {
	s := NewSeenSet(2)
	if s.Seen("a") {
		t.Fatal("first sighting of a must be false")
	}
	if !s.Seen("a") {
		t.Fatal("repeat of a must be true")
	}
	s.Seen("b")
	s.Seen("c") // evicts a (LRU: a is oldest after b,c)
	if s.Len() != 2 {
		t.Fatalf("cap not enforced: len=%d", s.Len())
	}
	if s.Seen("a") {
		t.Fatal("a was evicted → should be first-seen again")
	}

	// DedupeEvents drops repeats and stamps keys.
	s2 := NewSeenSet(100)
	evs := []ControllerEvent{
		{IntegrationID: "i", EventID: "1"},
		{IntegrationID: "i", EventID: "1"}, // dup
		{IntegrationID: "i", EventID: "2"},
	}
	out := s2.DedupeEvents(evs)
	if len(out) != 2 || out[0].DedupeKey == "" {
		t.Fatalf("dedupe wrong: %d %+v", len(out), out)
	}
}

func TestExpoRetryBackoffAndTerminal(t *testing.T) {
	r := ExpoRetry{Base: 500 * time.Millisecond, Max: 30 * time.Second, MaxTries: 5}
	// 5xx retriable, exponential.
	d1, ok1 := r.Next(1, 500, 0)
	d2, ok2 := r.Next(2, 503, 0)
	d3, _ := r.Next(3, 500, 0)
	if !ok1 || !ok2 || d1 != 500*time.Millisecond || d2 != 1*time.Second || d3 != 2*time.Second {
		t.Fatalf("backoff wrong: %v %v %v (%v %v)", d1, d2, d3, ok1, ok2)
	}
	// Exhausted after MaxTries.
	if _, ok := r.Next(5, 500, 0); ok {
		t.Fatal("must stop at MaxTries")
	}
	// 4xx (not 429) is terminal.
	if _, ok := r.Next(1, 400, 0); ok {
		t.Fatal("400 must not retry")
	}
	if _, ok := r.Next(1, 401, 0); ok {
		t.Fatal("401 must not retry (re-auth handles it)")
	}
	// Transport error (status 0) retries.
	if _, ok := r.Next(1, 0, 0); !ok {
		t.Fatal("transport error must retry")
	}
	// Cap respected.
	if d, _ := r.Next(4, 500, 0); d != 4*time.Second {
		t.Fatalf("attempt4 = %v", d)
	}
}

func TestExpoRetry429RetryAfterWins(t *testing.T) {
	r := DefaultRetry()
	d, ok := r.Next(1, http.StatusTooManyRequests, 7*time.Second)
	if !ok || d != 7*time.Second {
		t.Fatalf("429 Retry-After must win: %v %v", d, ok)
	}
	// Retry-After above Max is capped.
	if d, _ := r.Next(1, 429, 90*time.Second); d != 30*time.Second {
		t.Fatalf("retry-after not capped: %v", d)
	}
}

func TestParseRetryAfter(t *testing.T) {
	now := time.Date(2026, 7, 3, 12, 0, 0, 0, time.UTC)
	h := http.Header{}
	h.Set("Retry-After", "12")
	if d := ParseRetryAfter(h, now); d != 12*time.Second {
		t.Fatalf("delta-seconds: %v", d)
	}
	// HTTP-date form.
	h.Set("Retry-After", now.Add(5*time.Second).UTC().Format(http.TimeFormat))
	if d := ParseRetryAfter(h, now); d < 4*time.Second || d > 5*time.Second {
		t.Fatalf("http-date form: %v", d)
	}
	// Absent.
	if d := ParseRetryAfter(http.Header{}, now); d != 0 {
		t.Fatalf("absent must be 0: %v", d)
	}
}

func TestTokenBucketRateLimits(t *testing.T) {
	// Deterministic clock: virtual time advanced by the fake sleep.
	var vt time.Time = time.Unix(0, 0)
	b := NewTokenBucket(10) // 10/s, burst 10
	b.now = func() time.Time { return vt }
	b.sleep = func(_ context.Context, d time.Duration) error { vt = vt.Add(d); return nil }

	ctx := context.Background()
	// Burst of 10 is immediate (no time advance).
	for i := 0; i < 10; i++ {
		if err := b.Wait(ctx); err != nil {
			t.Fatalf("burst token %d: %v", i, err)
		}
	}
	if !vt.Equal(time.Unix(0, 0)) {
		t.Fatalf("burst should not advance time, vt=%v", vt)
	}
	// 11th must wait ~100ms (1/10s).
	if err := b.Wait(ctx); err != nil {
		t.Fatal(err)
	}
	if vt.Sub(time.Unix(0, 0)) < 90*time.Millisecond {
		t.Fatalf("11th token should have waited ~100ms, advanced %v", vt.Sub(time.Unix(0, 0)))
	}

	// rate<=0 → unlimited, never blocks.
	u := NewTokenBucket(0)
	for i := 0; i < 1000; i++ {
		_ = u.Wait(ctx)
	}
}

func TestTokenBucketContextCancel(t *testing.T) {
	b := NewTokenBucket(1)
	// Drain the single burst token.
	_ = b.Wait(context.Background())
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := b.Wait(ctx); err == nil {
		t.Fatal("cancelled context must return err")
	}
}
