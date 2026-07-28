package main

import (
	"context"
	"errors"
	"netops/backend/internal/incident"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// TestIncidentDedupAndRLS validates the Incident system's core guarantees against
// real Postgres: deterministic dedup (one incident per active dedup_key), severity
// escalation, terminal-status releasing the key for recurrences, lifecycle
// transition validation, the event timeline, and strict RLS tenant isolation.
// Gated on DATABASE_URL_TEST (a superuser DSN that provisions a throwaway role).
func TestIncidentDedupAndRLS(t *testing.T) {
	adminDSN := os.Getenv("DATABASE_URL_TEST")
	if adminDSN == "" {
		t.Skip("set DATABASE_URL_TEST to run the Postgres incident test")
	}
	ctx := context.Background()
	ps, err := newPgStore(ctx, provisionAppRole(ctx, t, adminDSN))
	if err != nil {
		t.Fatalf("newPgStore: %v", err)
	}
	defer ps.db.close()
	store := incident.NewPGStore(rlsPG{db: ps.db})

	base := IncidentInput{
		TenantID: "acme", Title: "High CPU on core-1", Description: "cpu > 90%",
		Severity: "high", SourceType: "alert", SourceID: "rule-cpu", DedupKey: "cpu:core-1", Actor: "engine",
	}

	// 1) dedup + severity escalation: a second detection folds in, doesn't duplicate.
	inc1, created1, err := store.Ingest(ctx, base)
	if err != nil || !created1 {
		t.Fatalf("first ingest: err=%v created=%v", err, created1)
	}
	esc := base
	esc.Severity = "critical"
	inc2, created2, err := store.Ingest(ctx, esc)
	if err != nil {
		t.Fatalf("second ingest: %v", err)
	}
	if created2 {
		t.Errorf("second detection of same dedup_key must NOT create a new incident")
	}
	if inc2.ID != inc1.ID {
		t.Errorf("dedup should return the same incident (%s != %s)", inc2.ID, inc1.ID)
	}
	if inc2.Occurrences != 2 {
		t.Errorf("occurrences = %d, want 2", inc2.Occurrences)
	}
	if inc2.Severity != "critical" {
		t.Errorf("severity should escalate high→critical, got %q", inc2.Severity)
	}

	// 2) RLS: another tenant can neither see nor transition acme's incident.
	if _, _, found, _ := store.Get(ctx, "globex", false, inc1.ID); found {
		t.Errorf("RLS leak: globex can see acme's incident")
	}
	if _, _, found, _ := store.Get(ctx, "", true, inc1.ID); !found {
		t.Errorf("platform owner should see the incident")
	}
	if _, err := store.Transition(ctx, "globex", false, inc1.ID, incident.StatusAcknowledged, "eve", ""); !errors.Is(err, incident.ErrNotFound) {
		t.Errorf("cross-tenant transition must fail not-found, got %v", err)
	}

	// 3) lifecycle: ack → resolve (stamps resolved_at), bad transition rejected.
	if _, err := store.Transition(ctx, "acme", false, inc1.ID, "bogus", "alice", ""); !errors.Is(err, incident.ErrBadTransition) {
		t.Errorf("invalid status must be rejected, got %v", err)
	}
	ack, err := store.Transition(ctx, "acme", false, inc1.ID, incident.StatusAcknowledged, "alice", "looking")
	if err != nil || ack.Status != incident.StatusAcknowledged {
		t.Fatalf("ack: err=%v status=%q", err, ack.Status)
	}
	res, err := store.Transition(ctx, "acme", false, inc1.ID, incident.StatusResolved, "alice", "fixed")
	if err != nil || res.Status != incident.StatusResolved || res.ResolvedAt == nil {
		t.Fatalf("resolve: err=%v status=%q resolved_at=%v", err, res.Status, res.ResolvedAt)
	}

	// 4) terminal status releases the dedup key → a recurrence opens a NEW incident.
	inc3, created3, err := store.Ingest(ctx, base)
	if err != nil || !created3 {
		t.Fatalf("recurrence ingest: err=%v created=%v", err, created3)
	}
	if inc3.ID == inc1.ID {
		t.Errorf("recurrence after resolve must be a NEW incident, got same id %s", inc1.ID)
	}

	// 5) timeline reconstructable: created + dedup + 2 status_change events.
	_, events, _, err := store.Get(ctx, "acme", false, inc1.ID)
	if err != nil {
		t.Fatalf("get events: %v", err)
	}
	var created, dedup, statusChanges int
	for _, e := range events {
		switch e.EventType {
		case "created":
			created++
		case "dedup":
			dedup++
		case "status_change":
			statusChanges++
		}
	}
	if created != 1 || dedup != 1 || statusChanges != 2 {
		t.Errorf("timeline: created=%d dedup=%d status_change=%d (want 1/1/2)", created, dedup, statusChanges)
	}

	// 6) List is tenant-scoped.
	if list, _ := store.List(ctx, "acme", false, IncidentQuery{}); len(list) != 2 {
		t.Errorf("acme List = %d incidents, want 2 (resolved + recurrence)", len(list))
	}
	if list, _ := store.List(ctx, "globex", false, IncidentQuery{}); len(list) != 0 {
		t.Errorf("globex List = %d incidents, want 0 (RLS)", len(list))
	}

	// 7) MarkSync records the ITSM projection without affecting incident state.
	if err := store.MarkSync(ctx, inc3.ID, "servicenow", "INC0012345", "https://itsm/INC0012345", "synced", time.Now().UTC()); err != nil {
		t.Fatalf("MarkSync: %v", err)
	}
	synced, _, _, _ := store.Get(ctx, "acme", false, inc3.ID)
	if synced.ExternalTicket != "INC0012345" || synced.SyncStatus != "synced" || synced.ExternalSystem != "servicenow" {
		t.Errorf("MarkSync not recorded: %+v", synced)
	}
}

// TestIncidentStormDedup proves an alert storm (many concurrent detections of the
// same root cause) collapses to exactly ONE incident — the DB partial-unique
// index arbitrates the race. This is the "no incident floods" guarantee.
func TestIncidentStormDedup(t *testing.T) {
	adminDSN := os.Getenv("DATABASE_URL_TEST")
	if adminDSN == "" {
		t.Skip("set DATABASE_URL_TEST to run the Postgres incident storm test")
	}
	ctx := context.Background()
	ps, err := newPgStore(ctx, provisionAppRole(ctx, t, adminDSN))
	if err != nil {
		t.Fatalf("newPgStore: %v", err)
	}
	defer ps.db.close()
	store := incident.NewPGStore(rlsPG{db: ps.db})

	const n = 24
	var createdCount int32
	var wg sync.WaitGroup
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, created, err := store.Ingest(ctx, IncidentInput{
				TenantID: "acme", Title: "Link flap on agg-2", Severity: "high",
				SourceType: "alert", SourceID: "rule-link", DedupKey: "link:agg-2", Actor: "engine",
			})
			if err != nil {
				errs <- err
				return
			}
			if created {
				atomic.AddInt32(&createdCount, 1)
			}
		}()
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		t.Fatalf("concurrent ingest error: %v", e)
	}
	if createdCount != 1 {
		t.Errorf("storm created %d incidents, want exactly 1", createdCount)
	}
	// And exactly one active incident exists for that dedup key.
	var active int
	if err := ps.db.withTenant(ctx, "acme", false, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM incidents WHERE dedup_key='link:agg-2' AND status NOT IN ('resolved','closed')`).Scan(&active)
	}); err != nil {
		t.Fatalf("count active: %v", err)
	}
	if active != 1 {
		t.Errorf("active incidents for dedup key = %d, want 1", active)
	}
}
