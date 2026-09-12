// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

import (
	"testing"
	"time"
)

// The jitter contract (TLS benchmark 2026-08-23 delta #1): every interval
// stays inside ±frac of base — never sooner than the safety margin allows,
// never late enough to erode the TTL/2 renewal point — and successive draws
// actually differ (a "jitter" that always returns base is the defect the
// vendors' stagger exists to prevent).
func TestJitteredIntervalBounds(t *testing.T) {
	base := 84 * time.Hour // deployed posture: TTL 7d, re-issue at TTL/2
	lo := time.Duration(float64(base) * 0.9)
	hi := time.Duration(float64(base) * 1.1)
	for i := 0; i < 2000; i++ {
		got := jitteredInterval(base, 0.10)
		if got < lo || got >= hi {
			t.Fatalf("draw %d: %v outside [%v, %v)", i, got, lo, hi)
		}
	}
}

func TestJitteredIntervalActuallyVaries(t *testing.T) {
	base := 84 * time.Hour
	seen := map[time.Duration]bool{}
	for i := 0; i < 64; i++ {
		seen[jitteredInterval(base, 0.10)] = true
	}
	if len(seen) < 2 {
		t.Fatalf("64 draws produced %d distinct interval(s) — jitter is inert", len(seen))
	}
}

func TestJitteredIntervalDegenerateInputs(t *testing.T) {
	cases := []struct {
		name string
		base time.Duration
		frac float64
	}{
		{"zero base", 0, 0.10},
		{"negative base", -time.Hour, 0.10},
		{"zero frac", time.Hour, 0},
		{"negative frac", time.Hour, -0.5},
		{"span rounds to zero", 4 * time.Nanosecond, 0.10},
	}
	for _, c := range cases {
		if got := jitteredInterval(c.base, c.frac); got != c.base {
			t.Fatalf("%s: got %v, want base %v unchanged", c.name, got, c.base)
		}
	}
}
