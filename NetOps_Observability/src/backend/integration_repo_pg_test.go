package main

import (
	"context"
	"os"
	"testing"
	"time"

	"netops/backend/integration"
)

// TestIntegrationRepo exercises the mappings watermark roundtrip + the 3-level
// idempotency ledger against a real Postgres. Gated on DATABASE_URL_TEST.
func TestIntegrationRepo(t *testing.T) {
	adminDSN := os.Getenv("DATABASE_URL_TEST")
	if adminDSN == "" {
		t.Skip("set DATABASE_URL_TEST to run the Postgres integration-repo test")
	}
	ctx := context.Background()
	ps, err := newPgStore(ctx, provisionAppRole(ctx, t, adminDSN))
	if err != nil {
		t.Fatalf("newPgStore: %v", err)
	}
	defer ps.db.close()
	st := newIntegrationStore(ps.db)

	// --- mapping upsert + watermark roundtrip ---
	at := time.Now().UTC().Truncate(time.Second)
	m := integrationMapping{
		Tenant: "acme", Provider: "servicenow", ExternalID: "INC42",
		IncidentID: "inc-1", State: "acknowledged",
		Applied: integration.Watermark{Seq: 5, At: at},
	}
	if err := st.UpsertMapping(ctx, m); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	got, found, err := st.GetMapping(ctx, "acme", false, "servicenow", "INC42")
	if err != nil || !found {
		t.Fatalf("get: err=%v found=%v", err, found)
	}
	if got.IncidentID != "inc-1" || got.State != "acknowledged" || got.Applied.Seq != 5 {
		t.Fatalf("mapping roundtrip mismatch: %+v", got)
	}
	// Advance the watermark.
	m.Applied.Seq = 9
	m.State = "resolved"
	if err := st.UpsertMapping(ctx, m); err != nil {
		t.Fatalf("upsert2: %v", err)
	}
	got, _, _ = st.GetMapping(ctx, "acme", false, "servicenow", "INC42")
	if got.Applied.Seq != 9 || got.State != "resolved" {
		t.Fatalf("watermark not advanced: %+v", got)
	}
	// Cross-tenant isolation: another tenant can't see acme's mapping.
	if _, found, _ := st.GetMapping(ctx, "globex", false, "servicenow", "INC42"); found {
		t.Fatal("globex must not see acme's mapping")
	}

	// --- level-1 raw dedup: redelivery is a no-op insert ---
	ev := integration.IntegrationEvent{
		Tenant: "acme", Provider: "servicenow", ProviderEvtID: "evt-1",
		ExternalID: "INC42", ExternalSeq: 9, Type: integration.EventResolved,
		OccurredAt: at,
	}
	id1, cid1, ins1, err := st.RecordInbound(ctx, ev)
	if err != nil || !ins1 {
		t.Fatalf("first record should insert: err=%v inserted=%v", err, ins1)
	}
	if cid1 == "" {
		t.Fatal("RecordInbound must mint a correlation_id (§9 end-to-end trace)")
	}
	_, _, ins2, err := st.RecordInbound(ctx, ev) // same provider_evt_id
	if err != nil || ins2 {
		t.Fatalf("redelivery must be a no-op: err=%v inserted=%v", err, ins2)
	}
	if err := st.MarkEvent(ctx, id1, "applied", "applied"); err != nil {
		t.Fatalf("mark event: %v", err)
	}

	// An event with no provider_evt_id is NOT raw-deduped (always inserts).
	ev2 := ev
	ev2.ProviderEvtID = ""
	if _, _, ins, err := st.RecordInbound(ctx, ev2); err != nil || !ins {
		t.Fatalf("empty-evtid event should always insert: err=%v inserted=%v", err, ins)
	}
}
