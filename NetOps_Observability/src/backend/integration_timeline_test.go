package backend

import (
	"netops/backend/integration"
	"testing"
	"time"
)

// TestMergeTimeline verifies the pure merge: lifecycle + sync fold into one
// oldest-first stream, with a deterministic tie-break (lifecycle before sync,
// then by id) on equal timestamps. No DB — exercises the ordering contract the
// /timeline endpoint relies on.
func TestMergeTimeline(t *testing.T) {
	t0 := time.Date(2026, 6, 4, 12, 0, 0, 0, time.UTC)
	tie := t0.Add(2 * time.Minute) // a lifecycle and a sync event share this instant

	lifecycle := []IncidentEvent{
		{ID: "l1", EventType: "created", Actor: "engine", CreatedAt: t0},
		{ID: "l2", EventType: "acknowledged", Actor: "alice", CreatedAt: tie},
		{ID: "l3", EventType: "resolved", Actor: "itsm:servicenow", CreatedAt: t0.Add(5 * time.Minute)},
	}
	sync := []integration.TimelineEntry{
		{Kind: "sync", ID: "s1", Provider: "servicenow", Direction: "inbound", Status: "applied", At: tie},
		{Kind: "sync", ID: "s2", Provider: "servicenow", Direction: "inbound", Status: "dropped", At: t0.Add(time.Minute)},
	}

	got := integration.MergeTimeline(lifecycle, sync)
	if len(got) != 5 {
		t.Fatalf("want 5 merged entries, got %d", len(got))
	}
	wantIDs := []string{"l1", "s2", "l2", "s1", "l3"} // t0, +1m, tie(lifecycle first), tie(sync), +5m
	for i, id := range wantIDs {
		if got[i].ID != id {
			t.Fatalf("position %d: want id %q, got %q (order %+v)", i, id, got[i].ID, entryIDs(got))
		}
	}
	if got[0].Kind != "lifecycle" || got[1].Kind != "sync" {
		t.Fatalf("kind discriminator wrong: %q %q", got[0].Kind, got[1].Kind)
	}
}

func entryIDs(es []integration.TimelineEntry) []string {
	out := make([]string, len(es))
	for i, e := range es {
		out[i] = e.ID
	}
	return out
}
