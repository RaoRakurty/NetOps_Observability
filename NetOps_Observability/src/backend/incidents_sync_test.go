package main

import (
	"context"
	"netops/backend/internal/incident"
	"netops/backend/internal/platformdb"
	"netops/backend/reports"
	"os"
	"testing"
	"time"
)

// TestIncidentSyncFailureIsolation proves the ITSM projection is best-effort: a
// failed sync (no ITSM configured) never mutates the incident — it only flips
// sync_status to failed and bumps the failure metric — and once a ticket exists
// the sync is idempotent (no duplicate tickets on re-promote). Gated on
// DATABASE_URL_TEST.
func TestIncidentSyncFailureIsolation(t *testing.T) {
	adminDSN := os.Getenv("DATABASE_URL_TEST")
	if adminDSN == "" {
		t.Skip("set DATABASE_URL_TEST to run the Postgres incident-sync test")
	}
	ctx := context.Background()
	ps, err := platformdb.NewPGStore(ctx, provisionAppRole(ctx, t, adminDSN))
	if err != nil {
		t.Fatalf("newPgStore: %v", err)
	}
	defer ps.DB().Close()

	store := incident.NewPGStore(ps.DB())
	srv := &server{incidents: store, incMetrics: &incidentMetrics{}} // no ITSM configured
	p := &reportPipeline{srv: srv, queue: reports.NewPGJobQueue(ps.DB(), 3), execs: reports.NewPGExecStore(ps.DB()), maxAttempts: 3}

	inc, _, err := store.Ingest(ctx, IncidentInput{
		TenantID: "acme", Title: "Core down", Severity: "critical", SourceType: "alert", DedupKey: "core:down",
	})
	if err != nil {
		t.Fatalf("ingest: %v", err)
	}

	// Enqueue → incident marked pending (ticket id untouched).
	if _, err := p.EnqueueIncidentSync(ctx, "acme", inc.ID); err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	if got, _, _, _ := store.Get(ctx, "acme", false, inc.ID); got.SyncStatus != "pending" {
		t.Errorf("sync_status = %q, want pending", got.SyncStatus)
	}

	// Process with NO ITSM configured → projection fails.
	jobs, err := p.queue.Claim(ctx, "w1", 1, time.Minute)
	if err != nil || len(jobs) != 1 {
		t.Fatalf("claim: err=%v n=%d", err, len(jobs))
	}
	p.processIncidentSync(ctx, ctx, "w1", jobs[0], "acme", map[string]any{})

	// The incident itself must be untouched; only sync_status flips to failed.
	after, _, _, _ := store.Get(ctx, "acme", false, inc.ID)
	if after.Status != incident.StatusOpen || after.Severity != "critical" || after.Title != "Core down" {
		t.Errorf("ITSM failure mutated the incident: %+v", after)
	}
	if after.SyncStatus != "failed" {
		t.Errorf("sync_status = %q, want failed", after.SyncStatus)
	}
	if srv.incMetrics.syncFail.Load() != 1 {
		t.Errorf("syncFail metric = %d, want 1", srv.incMetrics.syncFail.Load())
	}

	// Idempotency: once a ticket exists, a re-promote must NOT attempt another.
	now := time.Now().UTC()
	if err := store.MarkSync(ctx, inc.ID, "servicenow", "INC0099", "https://itsm/INC0099", "synced", now); err != nil {
		t.Fatalf("mark synced: %v", err)
	}
	if _, err := p.EnqueueIncidentSync(ctx, "acme", inc.ID); err != nil {
		t.Fatalf("re-enqueue: %v", err)
	}
	// The pending mark must NOT have wiped the ticket id (COALESCE).
	pend, _, _, _ := store.Get(ctx, "acme", false, inc.ID)
	if pend.ExternalTicket != "INC0099" {
		t.Errorf("re-enqueue wiped ticket id: %q", pend.ExternalTicket)
	}
	jobs2, _ := p.queue.Claim(ctx, "w1", 1, time.Minute)
	if len(jobs2) == 1 {
		p.processIncidentSync(ctx, ctx, "w1", jobs2[0], "acme", map[string]any{})
	}
	// Idempotent: still INC0099, no new failure (the no-ITSM path was NOT taken).
	final, _, _, _ := store.Get(ctx, "acme", false, inc.ID)
	if final.ExternalTicket != "INC0099" {
		t.Errorf("idempotency broken: ticket = %q", final.ExternalTicket)
	}
	if srv.incMetrics.syncFail.Load() != 1 {
		t.Errorf("re-promote of a ticketed incident must be a no-op; syncFail = %d, want 1", srv.incMetrics.syncFail.Load())
	}
}
