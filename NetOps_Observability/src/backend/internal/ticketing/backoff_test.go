// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package ticketing

import (
	"fmt"
	"testing"
	"time"
)

// ticketing_backoff_test.go — the outbox retry schedule. Jitter derived from
// the attempt NUMBER gave every item at attempt N the same delay, so a full
// outbox retried in lockstep against the ServiceNow/Jira it had just failed
// against. It must be derived from the item instead — and stay deterministic,
// because a restart has to resume the same schedule.

func TestBackoffDelaySpreadsItemsAtSameAttempt(t *testing.T) {
	const items = 500
	for _, attempt := range []int{1, 2, 3, 5} {
		seen := map[time.Duration]int{}
		for i := 0; i < items; i++ {
			seen[backoffDelay(attempt, fmt.Sprintf("outbox-%04d", i))]++
		}
		if len(seen) < items/4 {
			t.Fatalf("attempt %d: only %d distinct delays across %d items — items retry in lockstep",
				attempt, len(seen), items)
		}
	}
}

func TestBackoffDelayIsDeterministicPerItem(t *testing.T) {
	for i := 0; i < 50; i++ {
		id := fmt.Sprintf("outbox-%d", i)
		first := backoffDelay(3, id)
		for r := 0; r < 5; r++ {
			if got := backoffDelay(3, id); got != first {
				t.Fatalf("%s: delay changed between calls (%v vs %v) — a restart would not resume the schedule", id, got, first)
			}
		}
	}
}

func TestBackoffDelayBounds(t *testing.T) {
	tests := []struct {
		name    string
		attempt int
		wantMin time.Duration
		wantMax time.Duration
	}{
		{"below one is treated as first", 0, 30 * time.Second, 45 * time.Second},
		{"first attempt", 1, 30 * time.Second, 45 * time.Second},
		{"second attempt doubles", 2, time.Minute, 90 * time.Second},
		{"fourth attempt", 4, 4 * time.Minute, 6 * time.Minute},
		{"capped at 30m", 12, 30 * time.Minute, 45 * time.Minute},
		{"absurd attempt stays capped", 9999, 30 * time.Minute, 45 * time.Minute},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			for i := 0; i < 200; i++ {
				d := backoffDelay(tc.attempt, fmt.Sprintf("id-%d", i))
				if d < tc.wantMin || d > tc.wantMax {
					t.Fatalf("delay %v outside [%v,%v]", d, tc.wantMin, tc.wantMax)
				}
			}
		})
	}
}

// Successive attempts of the SAME item must not repeat the same jitter offset,
// or a single item ping-pongs on a fixed sub-schedule.
func TestBackoffDelayVariesAcrossAttempts(t *testing.T) {
	id := "outbox-stable"
	fractions := map[float64]bool{}
	for attempt := 1; attempt <= 6; attempt++ {
		base := 30 * time.Second * time.Duration(1<<(attempt-1))
		if base > 30*time.Minute {
			base = 30 * time.Minute
		}
		frac := float64(backoffDelay(attempt, id)-base) / float64(base)
		fractions[frac] = true
	}
	if len(fractions) < 4 {
		t.Fatalf("jitter fraction repeats across attempts: %v", fractions)
	}
}
