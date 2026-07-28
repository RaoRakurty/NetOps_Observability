package main

import (
	"context"
	"os"
	"testing"
	"time"

	"netops/backend/reports"
)

// TestPgExecStore exercises the execution history: append→running→completed/
// failed transitions, the phase-event timeline, RLS-scoped reads (tenant vs
// platform owner), schedule filter, and keyset pagination. Gated on
// DATABASE_URL_TEST (a superuser that provisions a non-superuser app role).
func TestPgExecStore(t *testing.T) {
	adminDSN := os.Getenv("DATABASE_URL_TEST")
	if adminDSN == "" {
		t.Skip("set DATABASE_URL_TEST to run the Postgres execution-store test")
	}
	ctx := context.Background()
	ps, err := newPgStore(ctx, provisionAppRole(ctx, t, adminDSN))
	if err != nil {
		t.Fatalf("newPgStore: %v", err)
	}
	defer ps.db.close()
	s := reports.NewPGExecStore(rlsPG{db: ps.db})
	base := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)

	// ---- lifecycle: append → running → completed, with events ----
	rec := reports.ExecutionRecord{ID: "e1", TenantID: "acme", ScheduleID: "rep-1", JobID: "j1", FireTime: base}
	if err := s.Append(ctx, rec); err != nil {
		t.Fatalf("append: %v", err)
	}
	_ = s.RecordEvent(ctx, "acme", "e1", reports.PhaseQueued, base, "")
	if err := s.MarkRunning(ctx, "e1", base.Add(2*time.Second)); err != nil {
		t.Fatalf("mark running: %v", err)
	}
	_ = s.RecordEvent(ctx, "acme", "e1", reports.PhaseRunning, base.Add(2*time.Second), "worker w1")
	_ = s.RecordEvent(ctx, "acme", "e1", reports.PhaseRendering, base.Add(3*time.Second), "")
	deliveries := []reports.DeliveryStatus{
		{Channel: "email", Recipient: "a@x.com", OK: true, Attempt: 1, At: base.Add(5 * time.Second)},
		{Channel: "email", Recipient: "b@x.com", OK: false, Attempt: 1, Error: "smtp 550", At: base.Add(5 * time.Second)},
	}
	refs := []reports.ArtifactRef{
		{Format: "html", ContentType: "text/html", SizeBytes: 1234, SHA256: "abc", Summary: "Stack health", Key: "e1_html"},
		{Format: "xlsx", ContentType: "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", SizeBytes: 999, SHA256: "def", Summary: "Stack health", Key: "e1_xlsx"},
	}
	if err := s.Complete(ctx, "e1", base.Add(6*time.Second), refs, deliveries); err != nil {
		t.Fatalf("complete: %v", err)
	}

	got, events, ok, err := s.Get(ctx, "acme", false, "e1")
	if err != nil || !ok {
		t.Fatalf("get e1: ok=%v err=%v", ok, err)
	}
	if got.Status != reports.StatusCompleted {
		t.Errorf("status = %q, want completed", got.Status)
	}
	if len(got.Artifacts) != 2 {
		t.Fatalf("artifacts not round-tripped: %+v", got.Artifacts)
	}
	if a := got.PrimaryArtifact(); a == nil || a.SizeBytes != 1234 || a.Format != "html" {
		t.Errorf("primary artifact wrong: %+v", a)
	}
	if got.ArtifactByFormat("xlsx") == nil {
		t.Errorf("xlsx artifact missing")
	}
	if len(got.Deliveries) != 2 || got.Deliveries[0].Recipient != "a@x.com" || got.Deliveries[1].OK {
		t.Errorf("deliveries not round-tripped: %+v", got.Deliveries)
	}
	if got.StartedAt.IsZero() || got.CompletedAt.IsZero() {
		t.Errorf("timestamps missing: started=%v completed=%v", got.StartedAt, got.CompletedAt)
	}
	if len(events) != 3 {
		t.Fatalf("events = %d, want 3 (queued,running,rendering)", len(events))
	}
	if events[0].Phase != reports.PhaseQueued || events[2].Phase != reports.PhaseRendering {
		t.Errorf("event order wrong: %v", events)
	}
	if !events[0].At.Before(events[2].At) {
		t.Errorf("event timestamps not monotonic: %v", events)
	}

	// ---- failed transition records partial deliveries ----
	rec2 := reports.ExecutionRecord{ID: "e2", TenantID: "acme", ScheduleID: "rep-1", JobID: "j2", FireTime: base.Add(time.Hour)}
	_ = s.Append(ctx, rec2)
	_ = s.MarkRunning(ctx, "e2", base.Add(time.Hour))
	if err := s.FailExec(ctx, "e2", base.Add(time.Hour+time.Second), "render timeout", deliveries[:1]); err != nil {
		t.Fatalf("fail e2: %v", err)
	}
	g2, _, _, _ := s.Get(ctx, "acme", false, "e2")
	if g2.Status != reports.StatusFailed || g2.Error != "render timeout" || len(g2.Deliveries) != 1 {
		t.Errorf("failed exec not recorded: status=%q err=%q deliveries=%d", g2.Status, g2.Error, len(g2.Deliveries))
	}

	// ---- RLS isolation: globex execution invisible to acme ----
	_ = s.Append(ctx, reports.ExecutionRecord{ID: "g1", TenantID: "globex", ScheduleID: "rep-9", FireTime: base})
	if _, _, ok, _ := s.Get(ctx, "acme", false, "g1"); ok {
		t.Errorf("EXEC LEAK: acme scope read globex execution g1")
	}
	// platform owner sees it.
	if _, _, ok, _ := s.Get(ctx, "", true, "g1"); !ok {
		t.Errorf("platform owner should see g1")
	}
	acme, err := s.List(ctx, "acme", false, reports.ExecQuery{})
	if err != nil {
		t.Fatalf("list acme: %v", err)
	}
	for _, r := range acme {
		if normTenant(r.TenantID) != "acme" {
			t.Errorf("EXEC LEAK: acme List saw tenant %q", r.TenantID)
		}
	}

	// ---- schedule filter + ordering (newest fire first) ----
	rep1, err := s.List(ctx, "acme", false, reports.ExecQuery{ScheduleID: "rep-1"})
	if err != nil {
		t.Fatalf("list rep-1: %v", err)
	}
	if len(rep1) != 2 || rep1[0].ID != "e2" || rep1[1].ID != "e1" {
		t.Fatalf("schedule list = %v, want [e2 e1] newest-first", execIDs(rep1))
	}

	// ---- keyset pagination via Before ----
	page, err := s.List(ctx, "acme", false, reports.ExecQuery{ScheduleID: "rep-1", Before: base.Add(time.Hour)})
	if err != nil {
		t.Fatalf("list before: %v", err)
	}
	if len(page) != 1 || page[0].ID != "e1" {
		t.Fatalf("before-page = %v, want [e1]", execIDs(page))
	}
}

func execIDs(rs []reports.ExecutionRecord) []string {
	out := make([]string, len(rs))
	for i, r := range rs {
		out[i] = r.ID
	}
	return out
}
