package nms

import (
	"testing"
	"time"
)

// retry_jitter_test.go — jitter is a reliability requirement, not a nicety:
// without it every connector that failed during one upstream outage retries on
// an identical schedule and re-floods the controller as it recovers.

func TestDefaultRetryHasJitterWired(t *testing.T) {
	r := DefaultRetry()
	if r.Jitter == nil {
		t.Fatal("DefaultRetry has no Jitter — production backoff is bare exponential")
	}
	for i := 0; i < 1000; i++ {
		if f := r.Jitter(); f < 0 || f >= 1 {
			t.Fatalf("jitter fraction %v out of [0,1)", f)
		}
	}
}

// Two clients retrying at the same attempt must not land on the same delay.
func TestDefaultRetrySpreadsDelays(t *testing.T) {
	r := DefaultRetry()
	seen := map[time.Duration]int{}
	const samples = 500
	for i := 0; i < samples; i++ {
		d, ok := r.Next(3, 503, 0)
		if !ok {
			t.Fatal("503 must be retriable")
		}
		// attempt 3 → 2s base, plus 0-100% jitter.
		if d < 2*time.Second || d >= 4*time.Second {
			t.Fatalf("delay %v outside the jittered window [2s,4s)", d)
		}
		seen[d]++
	}
	if len(seen) < samples/10 {
		t.Fatalf("only %d distinct delays out of %d — the herd is not broken", len(seen), samples)
	}
}

// Jitter must never push a delay past the configured cap.
func TestJitterRespectsMax(t *testing.T) {
	r := ExpoRetry{Base: 20 * time.Second, Max: 30 * time.Second, MaxTries: 5, Jitter: func() float64 { return 0.999 }}
	for attempt := 1; attempt < 5; attempt++ {
		d, ok := r.Next(attempt, 500, 0)
		if !ok {
			t.Fatalf("attempt %d should retry", attempt)
		}
		if d > r.Max {
			t.Fatalf("attempt %d delay %v exceeds cap %v", attempt, d, r.Max)
		}
	}
}

// A server-supplied Retry-After is obeyed exactly — jitter must not perturb it.
func TestRetryAfterIsNotJittered(t *testing.T) {
	r := DefaultRetry()
	for i := 0; i < 50; i++ {
		if d, _ := r.Next(1, 429, 7*time.Second); d != 7*time.Second {
			t.Fatalf("Retry-After was jittered: %v", d)
		}
	}
}
