package main

import (
	"context"
	"os"
	"testing"
	"time"
)

// ticketing_store_pg_test.go — the Postgres-backed ticketing store (#78) against
// a REAL PostgreSQL (gated on DATABASE_URL_TEST so the default `go test` stays
// offline). The in-memory store runs no SQL, so its tests cannot catch SQL-shape
// bugs; this is the guard that DOES. It exercises the outbox claim path
// (claimOutboxSQL with its UPDATE…FROM CTE + RETURNING) that shipped a latent
// `column reference "id" is ambiguous` bug only the live worker hit.
func TestPgTicketingStore_OutboxClaim(t *testing.T) {
	adminDSN := os.Getenv("DATABASE_URL_TEST")
	if adminDSN == "" {
		t.Skip("set DATABASE_URL_TEST to run the Postgres ticketing-store test")
	}
	ctx := context.Background()
	ps, err := newPgStore(ctx, provisionAppRole(ctx, t, adminDSN)) // runs migration 0016
	if err != nil {
		t.Fatalf("newPgStore: %v", err)
	}
	defer ps.db.close()
	st := &pgTicketingStore{db: ps.db}

	// A policy round-trips (PutPolicy → ListPolicies scoped to the tenant).
	if err := st.PutPolicy(ctx, incidentPolicy{ID: "p1", TenantID: "acme", Name: "n", ExternalSystem: "servicenow", Enabled: true, MinVerdict: "suspected"}); err != nil {
		t.Fatalf("PutPolicy: %v", err)
	}
	if ps, err := st.ListPolicies(ctx, "acme", false); err != nil || len(ps) != 1 {
		t.Fatalf("ListPolicies = %v err=%v, want 1", ps, err)
	}

	// Enqueue is idempotent on idempotency_key.
	item := ticketOutboxItem{TenantID: "acme", ID: "o1", CorrObjectID: "obj-a", ExternalSystem: "servicenow",
		Action: "create", IdempotencyKey: "servicenow:create:acme:obj-a", Status: "pending", Payload: map[string]any{"k": "v"}}
	if err := st.EnqueueOutbox(ctx, item); err != nil {
		t.Fatalf("EnqueueOutbox: %v", err)
	}
	dup := item
	dup.ID = "o1-dup"
	if err := st.EnqueueOutbox(ctx, dup); err != nil {
		t.Fatalf("EnqueueOutbox dup: %v", err)
	}
	if out, _ := st.ListOutbox(ctx, "acme", false); len(out) != 1 {
		t.Fatalf("idempotency: outbox has %d rows, want 1", len(out))
	}

	// ── the regression: ClaimDueOutbox must run without an ambiguous-id error and
	// return exactly the due row, leased (status retrying). ──
	claimed, err := st.ClaimDueOutbox(ctx, "w1", 10, 2*time.Minute)
	if err != nil {
		t.Fatalf("ClaimDueOutbox: %v", err) // the ambiguous-"id" bug failed HERE
	}
	if len(claimed) != 1 || claimed[0].ID != "o1" || claimed[0].CorrObjectID != "obj-a" {
		t.Fatalf("ClaimDueOutbox = %+v, want exactly o1/obj-a", claimed)
	}
	if claimed[0].Payload["k"] != "v" {
		t.Fatalf("claimed payload not round-tripped: %+v", claimed[0].Payload)
	}

	// A second immediate claim returns nothing — the lease pushed next_retry_at out.
	if again, err := st.ClaimDueOutbox(ctx, "w2", 10, 2*time.Minute); err != nil || len(again) != 0 {
		t.Fatalf("second claim = %v err=%v, want none (leased)", again, err)
	}

	// FinishOutbox writes terminal state back; a sent row is no longer due.
	fin := claimed[0]
	fin.Status = "sent"
	if err := st.FinishOutbox(ctx, fin); err != nil {
		t.Fatalf("FinishOutbox: %v", err)
	}
	out, _ := st.ListOutbox(ctx, "acme", false)
	if len(out) != 1 || out[0].Status != "sent" {
		t.Fatalf("after finish, outbox = %+v, want one row status=sent", out)
	}

	// Audit + link round-trip (the success-path writers).
	if err := st.AppendAudit(ctx, ticketAuditEntry{TenantID: "acme", ID: "au1", CorrObjectID: "obj-a", ExternalSystem: "servicenow", Action: "create", Result: "ok"}); err != nil {
		t.Fatalf("AppendAudit: %v", err)
	}
	if a, _ := st.ListAudit(ctx, "acme", false, "obj-a"); len(a) != 1 {
		t.Fatalf("ListAudit = %d, want 1", len(a))
	}
	now := time.Now().UTC()
	if err := st.PutLink(ctx, ticketLink{TenantID: "acme", CorrObjectID: "obj-a", ExternalSystem: "servicenow", Status: "open", TicketNumber: "INC1", SysID: "s1", LastSyncedAt: &now}); err != nil {
		t.Fatalf("PutLink: %v", err)
	}
	if l, found, _ := st.GetLink(ctx, "acme", false, "obj-a", "servicenow"); !found || l.TicketNumber != "INC1" {
		t.Fatalf("GetLink = %+v found=%v, want INC1", l, found)
	}

	// Tenant isolation through RLS: another tenant sees none of acme's rows.
	if out, _ := st.ListOutbox(ctx, "globex", false); len(out) != 0 {
		t.Fatalf("RLS leak: globex sees acme outbox: %+v", out)
	}
	if _, found, _ := st.GetLink(ctx, "globex", false, "obj-a", "servicenow"); found {
		t.Fatalf("RLS leak: globex fetched acme's ticket link")
	}
}
