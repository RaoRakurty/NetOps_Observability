package backend

import (
	"context"
	"netops/backend/internal/platformdb"
	"netops/backend/internal/vault"
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
	ps, err := platformdb.NewPGStore(ctx, provisionAppRole(ctx, t, adminDSN))
	if err != nil {
		t.Fatalf("newPgStore: %v", err)
	}
	defer ps.DB().Close()
	// Dormant vault.Vault (no SEAL_PROVIDER) → webhook_secret stays plaintext, exercising
	// the passthrough path; the vault.Vault's crypto is covered by secrets_test.go.
	st := integration.NewStore(ps.DB(), vault.Dormant())

	// --- mapping upsert + watermark roundtrip ---
	at := time.Now().UTC().Truncate(time.Second)
	m := integration.Mapping{
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
	rec1, ins1, err := st.RecordInbound(ctx, ev)
	if err != nil || !ins1 {
		t.Fatalf("first record should insert: err=%v inserted=%v", err, ins1)
	}
	if rec1.CorrelationID == "" {
		t.Fatal("RecordInbound must mint a correlation_id (§9 end-to-end trace)")
	}
	if rec1.Status != "received" || rec1.RecordedAt.IsZero() {
		t.Fatalf("fresh record = %+v, want status=received + a created_at", rec1)
	}
	rec2, ins2, err := st.RecordInbound(ctx, ev) // same provider_evt_id
	if err != nil || ins2 {
		t.Fatalf("redelivery must be a no-op: err=%v inserted=%v", err, ins2)
	}
	// M14: the redelivery must return the EXISTING row's identity — the old
	// code returned a freshly-minted id that matched nothing in the ledger, so
	// a recorded-but-never-enqueued event could not be recovered.
	if rec2.ID != rec1.ID || rec2.CorrelationID != rec1.CorrelationID {
		t.Fatalf("redelivery returned a phantom identity: first=%+v redelivery=%+v", rec1, rec2)
	}
	if !rec2.RecordedAt.Equal(rec1.RecordedAt) {
		t.Fatalf("redelivery RecordedAt drifted: %v vs %v (the apply job's idempotency key would change)", rec2.RecordedAt, rec1.RecordedAt)
	}
	if err := st.MarkEvent(ctx, rec1.ID, "applied", "applied"); err != nil {
		t.Fatalf("mark event: %v", err)
	}
	// After the verdict lands, a further redelivery reports it — the webhook
	// handler uses this to know the row no longer needs an apply job.
	if rec3, ins3, err := st.RecordInbound(ctx, ev); err != nil || ins3 || rec3.Status != "applied" {
		t.Fatalf("post-verdict redelivery = %+v ins=%v err=%v, want status=applied", rec3, ins3, err)
	}

	// An event with no provider_evt_id is NOT raw-deduped (always inserts).
	ev2 := ev
	ev2.ProviderEvtID = ""
	if _, ins, err := st.RecordInbound(ctx, ev2); err != nil || !ins {
		t.Fatalf("empty-evtid event should always insert: err=%v inserted=%v", err, ins)
	}
}

// TestUpsertMappingMonotonic pins the watermark's monotonicity (third-pass F2).
// UpsertMapping must NEVER let the persisted watermark REGRESS: under concurrent
// inbound applies (two events for one external incident, two workers, no
// per-external-id lock) an out-of-order upsert of an OLDER (seq, applied_at)
// must be a no-op, or a later redelivery of the newer event is no longer
// detected as stale and a stale transition re-applies. The ON CONFLICT guard
// mirrors compareOrder (seq primary, applied_at tie-break).
func TestUpsertMappingMonotonic(t *testing.T) {
	adminDSN := os.Getenv("DATABASE_URL_TEST")
	if adminDSN == "" {
		t.Skip("set DATABASE_URL_TEST to run the Postgres monotonic-upsert test")
	}
	ctx := context.Background()
	ps, err := platformdb.NewPGStore(ctx, provisionAppRole(ctx, t, adminDSN))
	if err != nil {
		t.Fatalf("newPgStore: %v", err)
	}
	defer ps.DB().Close()
	st := integration.NewStore(ps.DB(), vault.Dormant())

	at := time.Now().UTC().Truncate(time.Second)
	base := integration.Mapping{
		Tenant: "acme", Provider: "servicenow", ExternalID: "INC-MONO",
		IncidentID: "inc-mono", State: "acknowledged",
	}

	// Land the newer event first (seq=7).
	newer := base
	newer.State = "resolved"
	newer.Applied = integration.Watermark{Seq: 7, At: at}
	if err := st.UpsertMapping(ctx, newer); err != nil {
		t.Fatalf("upsert seq=7: %v", err)
	}

	// A racing OLDER event (seq=6) arrives second — it must NOT regress the
	// watermark (nor overwrite the state the newer event established).
	older := base
	older.State = "acknowledged"
	older.Applied = integration.Watermark{Seq: 6, At: at.Add(-time.Minute)}
	if err := st.UpsertMapping(ctx, older); err != nil {
		t.Fatalf("upsert seq=6: %v", err)
	}

	got, found, err := st.GetMapping(ctx, "acme", false, "servicenow", "INC-MONO")
	if err != nil || !found {
		t.Fatalf("get: err=%v found=%v", err, found)
	}
	if got.Applied.Seq != 7 {
		t.Fatalf("REGRESSED watermark: applied_seq=%d, want 7 (the older seq=6 upsert must be a no-op)", got.Applied.Seq)
	}
	if got.State != "resolved" {
		t.Fatalf("stale upsert overwrote state: %q, want \"resolved\"", got.State)
	}

	// A legitimately NEWER event (seq=8) still advances — the guard blocks only
	// regressions, never real progress.
	adv := base
	adv.State = "closed"
	adv.Applied = integration.Watermark{Seq: 8, At: at.Add(time.Minute)}
	if err := st.UpsertMapping(ctx, adv); err != nil {
		t.Fatalf("upsert seq=8: %v", err)
	}
	got, _, _ = st.GetMapping(ctx, "acme", false, "servicenow", "INC-MONO")
	if got.Applied.Seq != 8 || got.State != "closed" {
		t.Fatalf("legit advance blocked: %+v, want seq=8 state=closed", got)
	}
}
