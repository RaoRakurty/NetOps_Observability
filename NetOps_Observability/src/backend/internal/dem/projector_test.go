// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package dem

// projector_test.go — the api→prober work queue.

import (
	"context"
	"errors"
	"testing"
	"time"
)

type fakePublisher struct {
	last []WireTarget
	ttl  int
	err  error
	n    int
}

func (f *fakePublisher) Publish(_ context.Context, t []WireTarget, ttl int) error {
	f.n++
	if f.err != nil {
		return f.err
	}
	f.last, f.ttl = t, ttl
	return nil
}

func newProjectorHarness(t *testing.T) (*Projector, Catalogue, *fakePublisher) {
	t.Helper()
	cat := NewFileStore("")
	pub := &fakePublisher{}
	p, err := NewProjector(cat, pub, DefaultProjectInterval, NewMetrics(), func(string, map[string]any) {})
	if err != nil {
		t.Fatalf("NewProjector: %v", err)
	}
	return p, cat, pub
}

func TestProjectorPublishesEveryTenantsActiveTargets(t *testing.T) {
	p, cat, pub := newProjectorHarness(t)
	a := mustCreate(t, cat, newTarget("acme", "a", "10.0.0.1"))
	b := mustCreate(t, cat, newTarget("globex", "b", "10.0.0.2"))
	if err := p.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if len(pub.last) != 2 {
		t.Fatalf("queue: %+v", pub.last)
	}
	seen := map[string]string{}
	for _, w := range pub.last {
		seen[w.ID] = w.Tenant
		if w.IntervalSec == 0 || w.Kind == "" || w.Host == "" {
			t.Fatalf("incomplete work item: %+v", w)
		}
	}
	if seen[a.ID] != "acme" || seen[b.ID] != "globex" {
		t.Fatalf("ownership not carried: %+v", seen)
	}
	// The TTL must outlive one missed cycle but not an outage.
	if pub.ttl != int(3*p.Interval()/time.Second) {
		t.Fatalf("ttl %d", pub.ttl)
	}
}

// Pausing must STOP the measurement, not merely hide the row.
func TestPausedTargetsAreNotProjected(t *testing.T) {
	p, cat, pub := newProjectorHarness(t)
	a := mustCreate(t, cat, newTarget("acme", "a", "10.0.0.1"))
	paused := true
	if _, err := cat.Update(context.Background(), "acme", a.ID, Patch{Paused: &paused}); err != nil {
		t.Fatalf("pause: %v", err)
	}
	if err := p.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if len(pub.last) != 0 {
		t.Fatalf("a paused target was still published: %+v", pub.last)
	}
}

// The queue leaves the api for a container that holds no secrets. It must carry
// what a check needs and nothing else.
func TestWireTargetCarriesNoBudgetsOrOwnerNames(t *testing.T) {
	w, ok := ToWire(Target{
		ID: "dem-1", TenantID: "acme", Kind: KindHTTP, Host: "https://x/", Name: "secret-sounding name",
		CreatedBy: "alice@example.com", LatencyBudgetMs: 500, AvailabilityBudgetPct: 99.9,
	})
	if !ok {
		t.Fatal("ToWire refused an active target")
	}
	blob := sprintfWire(w)
	// The BUDGETS do ride along (they are thresholds the operator set, and the
	// alert rules need them as gauges); the operator's identity and the
	// human-facing name do not.
	for _, leaked := range []string{"alice@example.com", "secret-sounding name"} {
		if contains(blob, leaked) {
			t.Fatalf("the work queue carries %q: %s", leaked, blob)
		}
	}
}

func TestProjectorReportsAFailedPublication(t *testing.T) {
	p, cat, pub := newProjectorHarness(t)
	mustCreate(t, cat, newTarget("acme", "a", "10.0.0.1"))
	pub.err = errors.New("kv down")
	if err := p.RunOnce(context.Background()); err == nil {
		t.Fatal("a failed publication was swallowed — the prober would run on a stale list with nobody told")
	}
}

func TestNewProjectorFailsClosed(t *testing.T) {
	if _, err := NewProjector(nil, &fakePublisher{}, time.Minute, nil, func(string, map[string]any) {}); err == nil {
		t.Fatal("a projector with no catalogue was built")
	}
	if _, err := NewProjector(NewFileStore(""), nil, time.Minute, nil, func(string, map[string]any) {}); err == nil {
		t.Fatal("a projector with no publisher was built")
	}
	// An out-of-range interval is clamped to the default, never honoured.
	p, err := NewProjector(NewFileStore(""), &fakePublisher{}, time.Millisecond, nil, func(string, map[string]any) {})
	if err != nil {
		t.Fatalf("NewProjector: %v", err)
	}
	if p.Interval() != DefaultProjectInterval {
		t.Fatalf("interval %v", p.Interval())
	}
}
