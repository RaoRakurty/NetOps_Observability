package main

import (
	"context"
	"testing"
	"time"

	"netops/backend/timeintel"
)

func tev(tenant, corr string, et timeintel.EventType) incidentTimelineEvent {
	return incidentTimelineEvent{
		TenantID: tenant, ID: randID(), CorrelationID: corr, EventType: et,
		EventTime: time.Now().UTC(), Source: timeintel.SrcUserEntered, Confidence: 1,
		SourceSystem: "manual", CreatedBy: "u",
	}
}

// CLAUDE.md §3a mandatory: the store itself enforces tenant isolation — no caller
// can read, edit, or delete another tenant's manual lifecycle events.
func TestIncidentTimelineStoreIsolation(t *testing.T) {
	ctx := context.Background()
	st := &memIncidentTimelineStore{by: map[string]incidentTimelineEvent{}}
	const corr = "11111111-1111-1111-1111-111111111111"

	a := tev("org-a", corr, timeintel.EvRecovered)
	b := tev("org-b", corr, timeintel.EvRecovered)
	if err := st.Put(ctx, a); err != nil {
		t.Fatal(err)
	}
	if err := st.Put(ctx, b); err != nil {
		t.Fatal(err)
	}

	// 1) own-only list: org-a sees ONLY its event
	la, _ := st.List(ctx, "org-a", false, corr)
	if len(la) != 1 || la[0].ID != a.ID {
		t.Fatalf("org-a leak: %+v", la)
	}
	lb, _ := st.List(ctx, "org-b", false, corr)
	if len(lb) != 1 || lb[0].ID != b.ID {
		t.Fatalf("org-b leak: %+v", lb)
	}
	// 2) platform owner (cross) sees both
	all, _ := st.List(ctx, "", true, corr)
	if len(all) != 2 {
		t.Fatalf("cross list = %d, want 2", len(all))
	}
	// 3) cross-tenant DELETE is refused (org-b can't delete org-a's event)
	deleted, _ := st.Delete(ctx, "org-b", false, corr, a.ID)
	if deleted {
		t.Fatalf("org-b deleted org-a's event — cross-tenant leak")
	}
	// org-a CAN delete its own
	deleted, _ = st.Delete(ctx, "org-a", false, corr, a.ID)
	if !deleted {
		t.Fatalf("org-a could not delete its own event")
	}
	la, _ = st.List(ctx, "org-a", false, corr)
	if len(la) != 0 {
		t.Fatalf("org-a event survived delete: %+v", la)
	}
}

// An edit upserts on the unique guard (one row per incident/type/system/source ids).
func TestIncidentTimelineUpsertGuard(t *testing.T) {
	ctx := context.Background()
	st := &memIncidentTimelineStore{by: map[string]incidentTimelineEvent{}}
	const corr = "22222222-2222-2222-2222-222222222222"
	e1 := tev("org-a", corr, timeintel.EvRecovered)
	e1.EventTime = time.Unix(1000, 0).UTC()
	e2 := tev("org-a", corr, timeintel.EvRecovered) // same guard, new time
	e2.EventTime = time.Unix(2000, 0).UTC()
	_ = st.Put(ctx, e1)
	_ = st.Put(ctx, e2)
	list, _ := st.List(ctx, "org-a", false, corr)
	if len(list) != 1 {
		t.Fatalf("upsert should keep ONE row per guard, got %d", len(list))
	}
	if !list[0].EventTime.Equal(time.Unix(2000, 0).UTC()) {
		t.Fatalf("edit must update the time, got %v", list[0].EventTime)
	}
}
