// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package expbus

// lows_a_test.go — review finding 3.2-11.

import (
	"context"
	"strings"
	"testing"
	"time"

	"netops/backend/internal/dem/experience"
)

// deadCtxPublisher is what a real producer does once its context is cancelled:
// it fails. It is the publisher a shutdown actually has.
type deadCtxPublisher struct{}

func (deadCtxPublisher) Publish(ctx context.Context, _ string, recs []Record) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	return len(recs), nil
}

// 3.2-11 — NOTHING LEAVES THE QUEUE UNACCOUNTED FOR AT SHUTDOWN.
//
// Run returned the instant the context was cancelled WITHOUT draining q.ch, so
// every batch still queued vanished with no EventsDropped increment and no log
// line — the one thing an evidence lane exists not to do. Which batches are
// stranded is a race inside `select` (both cases are ready), so the property
// asserted here is the accounting identity that must hold whichever way that
// race falls: accepted == published + dropped.
func TestShutdownLeavesNoQueuedEventUnaccountedFor(t *testing.T) {
	q, logs := newTestQueue(t, deadCtxPublisher{})

	ctx, cancel := context.WithCancel(context.Background())
	const batches = 16
	for i := 0; i < batches; i++ {
		if err := q.WriteEvents(context.Background(), []experience.ExperienceEvent{
			sampleEvent("acme", "ev-"+string(rune('a'+i))),
		}); err != nil {
			t.Fatalf("enqueue %d: %v", i, err)
		}
	}
	cancel() // the process is going down with the queue still full

	done := make(chan struct{})
	go func() { q.Run(ctx); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return on a cancelled context")
	}

	snap := q.Metrics().Snapshot()
	accepted := snap["events_accepted_total"]
	settled := snap["events_published_total"] + snap["events_dropped_total"]
	if accepted != batches {
		t.Fatalf("events_accepted_total = %d, want %d", accepted, batches)
	}
	if settled != accepted {
		t.Fatalf("%d events entered the queue and only %d were accounted for — %d of a tenant's beacons were thrown away at shutdown with no counter and no log",
			accepted, settled, accepted-settled)
	}
	if snap["queue_depth"] != 0 {
		t.Fatalf("queue_depth = %d after shutdown", snap["queue_depth"])
	}
	if len(*logs) == 0 {
		t.Fatal("events were dropped and nothing was logged")
	}
}

// The drain itself, without the select race: what it counts and what it says.
func TestDiscardQueuedCountsAndNamesTheLoss(t *testing.T) {
	q, logs := newTestQueue(t, &capture{})
	for _, id := range []string{"ev-1", "ev-2", "ev-3"} {
		if err := q.WriteEvents(context.Background(), []experience.ExperienceEvent{
			sampleEvent("acme", id),
		}); err != nil {
			t.Fatalf("enqueue: %v", err)
		}
	}
	q.discardQueued()

	snap := q.Metrics().Snapshot()
	if snap["events_dropped_total"] != 3 {
		t.Fatalf("events_dropped_total = %d, want 3", snap["events_dropped_total"])
	}
	if q.Depth() != 0 || snap["queue_depth"] != 0 {
		t.Fatalf("the queue was not emptied: depth=%d gauge=%d", q.Depth(), snap["queue_depth"])
	}
	found := false
	for _, m := range *logs {
		if strings.Contains(m, "shut down") {
			found = true
		}
	}
	if !found {
		t.Fatalf("the loss left no log line saying a shutdown caused it: %v", *logs)
	}
	// A second call on an empty queue is silent: shutdown must not invent a loss.
	before := len(*logs)
	q.discardQueued()
	if len(*logs) != before {
		t.Fatal("an empty queue logged a loss at shutdown")
	}
}
