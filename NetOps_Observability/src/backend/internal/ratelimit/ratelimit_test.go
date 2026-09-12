// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package ratelimit

// White-box tests for the F-33 leak fix — they reach into the windows map, so
// they live inside the package (moved from package main's resource_bounds_test
// when the limiter was extracted, 2026-07-27).

import (
	"fmt"
	"testing"
	"time"
)

// TestRateLimiterReclaimsExpiredWindows: the windows map had no deletion path,
// so it grew with every principal that ever made one request.
func TestRateLimiterReclaimsExpiredWindows(t *testing.T) {
	l := New()
	// A day's worth of principals that each made one request and never came
	// back. Under the old code every one of them stayed in the map forever.
	for i := 0; i < sweepThreshold; i++ {
		l.AllowN(fmt.Sprintf("tenant-%d|user-%d", i, i), 10)
	}
	l.mu.Lock()
	for _, w := range l.windows {
		w.start = time.Now().Add(-2 * time.Minute) // their minute has long passed
	}
	l.mu.Unlock()

	// The next request crosses the sweep threshold and must reclaim them.
	l.AllowN("live|user", 10)
	if got := l.Size(); got > 2 {
		t.Fatalf("windows map holds %d entries; %d expired ones should have been reclaimed — "+
			"this map had NO deletion path at all (F-33)", got, sweepThreshold)
	}
}

// TestRateLimiterSweepDoesNotWeakenTheLimit: reclaiming memory must never hand
// out extra budget inside a live window.
func TestRateLimiterSweepDoesNotWeakenTheLimit(t *testing.T) {
	l := New()
	const key = "t1|u1"
	for i := 0; i < 3; i++ {
		if !l.AllowN(key, 3) {
			t.Fatalf("request %d refused inside budget", i+1)
		}
	}
	// Fill the map so the next call triggers a sweep, then re-check the limit.
	for i := 0; i < sweepThreshold; i++ {
		l.AllowN(fmt.Sprintf("filler-%d", i), 100)
	}
	if l.AllowN(key, 3) {
		t.Fatal("the sweep reset a LIVE window — the rate limit can be bypassed by filling the map")
	}
}
