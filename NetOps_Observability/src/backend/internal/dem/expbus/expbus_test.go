// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package expbus

// expbus_test.go — tracker 254: the lane's contract.
//
// Everything here is about the ONE property that separates an evidence lane
// from a decorative one: nothing is lost in silence. A full queue refuses
// loudly, an unpublishable batch is counted and logged, and a record that could
// not be attributed to a tenant never reaches a table whose row policy would
// make it invisible to everyone.

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"netops/backend/internal/dem/experience"
)

var testNow = time.Date(2026, 9, 6, 12, 0, 0, 0, time.UTC)

func sampleEvent(tenant, id string) experience.ExperienceEvent {
	return experience.ExperienceEvent{
		ID: id, TenantID: tenant, App: "checkout", Type: experience.EventPageView,
		Success: true, ActorType: experience.ActorHuman,
		Cohort: experience.Cohort{Site: "dc1", Browser: "chrome"},
		Provenance: experience.Provenance{
			Source: experience.SourceRUM, Producer: "rum-key",
			EventAt: testNow, ObservedAt: testNow,
			Observation: experience.ObservationObserved,
		},
	}
}

func sampleBusiness(tenant, id string) experience.BusinessEvent {
	v := 42.5
	return experience.BusinessEvent{
		ID: id, TenantID: tenant, Type: "purchase", App: "checkout",
		Success: true, Value: &v, Currency: "USD",
		Provenance: experience.Provenance{
			Source: experience.SourceManual, Producer: "pipeline",
			EventAt: testNow, ObservedAt: testNow,
			Observation: experience.ObservationObserved,
		},
	}
}

// capture is a Publisher that records what it was asked to send.
type capture struct {
	mu    sync.Mutex
	sent  [][]Record
	fail  int // fail this many attempts before succeeding
	calls int
	err   error
}

func (c *capture) Publish(_ context.Context, _ string, recs []Record) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.calls++
	if c.err != nil {
		return 0, c.err
	}
	if c.fail > 0 {
		c.fail--
		return 0, errors.New("bridge unavailable")
	}
	c.sent = append(c.sent, append([]Record(nil), recs...))
	return len(recs), nil
}

func (c *capture) batches() [][]Record {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([][]Record(nil), c.sent...)
}

func newTestQueue(t *testing.T, pub Publisher, opts ...Option) (*Queue, *[]string) {
	t.Helper()
	var logs []string
	base := []Option{
		WithSleep(func(context.Context, time.Duration) error { return nil }), // no real waiting
		WithJitter(func() float64 { return 0.5 }),
	}
	q, err := New(pub, func(m string, _ map[string]any) { logs = append(logs, m) }, append(base, opts...)...)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return q, &logs
}

func TestNewFailsClosedWithoutATransportOrALogger(t *testing.T) {
	if _, err := New(nil, func(string, map[string]any) {}); err == nil {
		t.Fatal("a lane with no publisher was built — it would accept events and lose them")
	}
	if _, err := New(&capture{}, nil); err == nil {
		t.Fatal("a lane with no logger was built — a dropped batch would be invisible")
	}
}

func TestTheEnvelopeCarriesTheRoutingDiscriminatorAndTheTenantKey(t *testing.T) {
	pub := &capture{}
	q, _ := newTestQueue(t, pub)
	if err := q.WriteEvents(context.Background(), []experience.ExperienceEvent{sampleEvent("acme", "e1")}); err != nil {
		t.Fatal(err)
	}
	if err := q.WriteBusinessEvents(context.Background(), []experience.BusinessEvent{sampleBusiness("acme", "b1")}); err != nil {
		t.Fatal(err)
	}
	for q.DrainOnce(context.Background()) {
	}
	batches := pub.batches()
	if len(batches) != 2 {
		t.Fatalf("published %d batches, want 2", len(batches))
	}
	seen := map[string]bool{}
	for _, b := range batches {
		for _, rec := range b {
			if rec.Key != "acme" {
				t.Fatalf("partition key = %q, want the tenant — a mis-keyed record lands on the wrong partition", rec.Key)
			}
			raw, err := json.Marshal(rec.Value)
			if err != nil {
				t.Fatal(err)
			}
			var m map[string]any
			if err := json.Unmarshal(raw, &m); err != nil {
				t.Fatal(err)
			}
			rt, _ := m["record_type"].(string)
			if rt == "" {
				t.Fatalf("the envelope carries no record_type; the router would have to guess a table: %s", raw)
			}
			seen[rt] = true
			// The router's VRL reads provenance.* and cohort.* as NESTED
			// objects; a flattened envelope would silently produce untagged
			// rows in a STRICT-policy table.
			if _, ok := m["provenance"].(map[string]any); !ok {
				t.Fatalf("provenance is not a nested object: %s", raw)
			}
			if _, ok := m["tenant_id"].(string); !ok {
				t.Fatalf("the envelope carries no tenant_id: %s", raw)
			}
		}
	}
	if !seen[RecordExperienceEvent] || !seen[RecordBusinessEvent] {
		t.Fatalf("record types seen: %v", seen)
	}
}

func TestARecordWithNoConcreteTenantIsRefusedAtTheSink(t *testing.T) {
	pub := &capture{}
	q, _ := newTestQueue(t, pub)
	for _, tenant := range []string{"", "*"} {
		e := sampleEvent(tenant, "e1")
		if err := q.WriteEvents(context.Background(), []experience.ExperienceEvent{e}); err == nil {
			t.Fatalf("tenant %q was accepted — it would land as an untagged row no tenant can ever see", tenant)
		}
	}
	if q.Depth() != 0 {
		t.Fatal("a refused batch still reached the queue")
	}
	if q.Metrics().EventsRejected.Load() != 2 {
		t.Fatalf("rejected = %d, want 2", q.Metrics().EventsRejected.Load())
	}
}

func TestAFullQueueRefusesLoudlyInsteadOfDropping(t *testing.T) {
	pub := &capture{}
	q, _ := newTestQueue(t, pub, WithQueueDepth(2))
	for i := 0; i < 2; i++ {
		if err := q.WriteEvents(context.Background(), []experience.ExperienceEvent{sampleEvent("acme", "e"+string(rune('a'+i)))}); err != nil {
			t.Fatalf("batch %d: %v", i, err)
		}
	}
	err := q.WriteEvents(context.Background(), []experience.ExperienceEvent{sampleEvent("acme", "over")})
	if !errors.Is(err, ErrBusy) {
		t.Fatalf("a full queue returned %v, want ErrBusy — silent acceptance is data loss that looks healthy", err)
	}
	// The sentinel MUST be the one the HTTP layer maps onto 503.
	if !errors.Is(err, experience.ErrIngestBusy) {
		t.Fatal("ErrBusy is not experience.ErrIngestBusy; the route would answer 400 for backpressure")
	}
	if q.Metrics().EventsRefused.Load() != 1 {
		t.Fatalf("refused = %d, want 1", q.Metrics().EventsRefused.Load())
	}
	if q.Metrics().EventsAccepted.Load() != 2 {
		t.Fatalf("accepted = %d, want 2", q.Metrics().EventsAccepted.Load())
	}
	// Draining makes room again: backpressure is a state, not a latch.
	q.DrainOnce(context.Background())
	if err := q.WriteEvents(context.Background(), []experience.ExperienceEvent{sampleEvent("acme", "after")}); err != nil {
		t.Fatalf("the queue stayed busy after draining: %v", err)
	}
}

func TestTheEventBoundHoldsIndependentlyOfTheBatchBound(t *testing.T) {
	pub := &capture{}
	q, _ := newTestQueue(t, pub)
	big := make([]experience.ExperienceEvent, MaxEventsPerBatch)
	for i := range big {
		big[i] = sampleEvent("acme", "e"+itoa(i))
	}
	accepted := 0
	for {
		if err := q.WriteEvents(context.Background(), big); err != nil {
			if !errors.Is(err, ErrBusy) {
				t.Fatalf("unexpected error: %v", err)
			}
			break
		}
		accepted += len(big)
		if accepted > MaxQueuedEvents+MaxEventsPerBatch {
			t.Fatal("the event bound never bit — the queue is bounded in batches only")
		}
	}
	if accepted > MaxQueuedEvents {
		t.Fatalf("accepted %d events, above the %d bound", accepted, MaxQueuedEvents)
	}
}

func TestABatchLargerThanTheBoundIsRefusedNotTruncated(t *testing.T) {
	q, _ := newTestQueue(t, &capture{})
	big := make([]experience.ExperienceEvent, MaxEventsPerBatch+1)
	for i := range big {
		big[i] = sampleEvent("acme", "e"+itoa(i))
	}
	if err := q.WriteEvents(context.Background(), big); err == nil {
		t.Fatal("an oversized batch was accepted; it would have been silently truncated")
	}
}

func TestAFailedPublishRetriesAndThenDropsLoudly(t *testing.T) {
	pub := &capture{fail: 2}
	q, logs := newTestQueue(t, pub)
	if err := q.WriteEvents(context.Background(), []experience.ExperienceEvent{sampleEvent("acme", "e1")}); err != nil {
		t.Fatal(err)
	}
	q.DrainOnce(context.Background())
	if len(pub.batches()) != 1 {
		t.Fatalf("the batch did not survive two transient failures: %d published", len(pub.batches()))
	}
	if q.Metrics().PublishRetries.Load() != 2 {
		t.Fatalf("retries = %d, want 2", q.Metrics().PublishRetries.Load())
	}
	if q.Metrics().EventsDropped.Load() != 0 {
		t.Fatal("a batch that eventually published was counted as dropped")
	}
	if len(*logs) != 0 {
		t.Fatalf("a successful retry logged a loss: %v", *logs)
	}

	// Now a permanent failure: bounded attempts, then a LOUD drop.
	pub2 := &capture{err: errors.New("the bus is gone")}
	q2, logs2 := newTestQueue(t, pub2)
	if err := q2.WriteEvents(context.Background(), []experience.ExperienceEvent{
		sampleEvent("acme", "e1"), sampleEvent("acme", "e2"),
	}); err != nil {
		t.Fatal(err)
	}
	q2.DrainOnce(context.Background())
	if pub2.calls != DefaultAttempts {
		t.Fatalf("attempts = %d, want the bound %d — an unbounded retry wedges the lane", pub2.calls, DefaultAttempts)
	}
	if q2.Metrics().EventsDropped.Load() != 2 {
		t.Fatalf("dropped = %d, want 2", q2.Metrics().EventsDropped.Load())
	}
	if len(*logs2) != 1 || !strings.Contains((*logs2)[0], "dropped") {
		t.Fatalf("the drop was not reported: %v", *logs2)
	}
	if q2.Metrics().Snapshot()["events_dropped_total"] != 2 {
		t.Fatalf("the snapshot does not expose the loss: %v", q2.Metrics().Snapshot())
	}
}

func TestRunDrainsUntilTheContextIsDone(t *testing.T) {
	pub := &capture{}
	q, _ := newTestQueue(t, pub)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { q.Run(ctx); close(done) }()
	if err := q.WriteEvents(context.Background(), []experience.ExperienceEvent{sampleEvent("acme", "e1")}); err != nil {
		t.Fatal(err)
	}
	deadline := time.After(2 * time.Second)
	for len(pub.batches()) == 0 {
		select {
		case <-deadline:
			t.Fatal("the drain never published")
		default:
			time.Sleep(time.Millisecond)
		}
	}
	cancel()
	<-done
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	for i > 0 {
		b = append([]byte{byte('0' + i%10)}, b...)
		i /= 10
	}
	return string(b)
}
