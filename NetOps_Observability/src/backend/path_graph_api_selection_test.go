package backend

import (
	"testing"
	"time"

	"netops/backend/pathgraph"
)

// The case spine must show the MOST COMPLETE fresh measured view — a client-side
// vantage's 4-hop path outranks the co-located prober's newer 3-hop one (§10: the
// path starts at the client). Ties → newest; nothing fresh → newest history.
func TestPickSpineObservation(t *testing.T) {
	now := time.Date(2026, 7, 12, 18, 0, 0, 0, time.UTC)
	fresh := 15 * time.Minute
	ob := func(id, vantage string, hops int, age time.Duration) pathgraph.PathObservation {
		return pathgraph.PathObservation{ObservationID: id, VantageID: vantage, HopCount: hops,
			ObservedAt: now.Add(-age)}
	}
	if pickSpineObservation(nil, now, fresh) != nil {
		t.Fatal("empty list must return nil")
	}
	// Newest-first list: prober measured 1m ago (3 hops), LAN vantage 3m ago (4 hops).
	got := pickSpineObservation([]pathgraph.PathObservation{
		ob("o1", "prober", 3, time.Minute),
		ob("o2", "lan-vantage-1", 4, 3*time.Minute),
	}, now, fresh)
	if got.ObservationID != "o2" {
		t.Fatalf("most complete fresh view must win, got %s", got.ObservationID)
	}
	// Equal completeness → the newest wins.
	got = pickSpineObservation([]pathgraph.PathObservation{
		ob("o1", "prober", 4, time.Minute),
		ob("o2", "lan-vantage-1", 4, 3*time.Minute),
	}, now, fresh)
	if got.ObservationID != "o1" {
		t.Fatalf("tie must go to the newest, got %s", got.ObservationID)
	}
	// A stale-but-longer path never outranks a fresh one.
	got = pickSpineObservation([]pathgraph.PathObservation{
		ob("o1", "prober", 3, time.Minute),
		ob("o2", "lan-vantage-1", 9, 2*time.Hour),
	}, now, fresh)
	if got.ObservationID != "o1" {
		t.Fatalf("stale completeness must not outrank fresh, got %s", got.ObservationID)
	}
	// Nothing fresh → newest history still renders (caller marks it stale).
	got = pickSpineObservation([]pathgraph.PathObservation{
		ob("o1", "prober", 3, time.Hour),
		ob("o2", "lan-vantage-1", 4, 2*time.Hour),
	}, now, fresh)
	if got.ObservationID != "o1" {
		t.Fatalf("with nothing fresh the newest history is served, got %s", got.ObservationID)
	}
}
