package main

import (
	"context"
	"encoding/json"
	"netops/backend/internal/platformdb"
	"os"
	"testing"
	"time"

	"netops/backend/reports"

	"netops/backend/internal/logexport"
)

// TestExportSubstratePG validates the shared-substrate generalization (migration
// 0004: job_type on report_jobs + kind on report_executions) against real
// Postgres: the queue round-trips job_type=export with its payload, the execution
// history round-trips kind=export and List filters by it, RLS keeps a tenant's
// exports private, and EnqueueExport records a queued export. Gated on
// DATABASE_URL_TEST (a superuser DSN that provisions a throwaway RLS role).
func TestExportSubstratePG(t *testing.T) {
	adminDSN := os.Getenv("DATABASE_URL_TEST")
	if adminDSN == "" {
		t.Skip("set DATABASE_URL_TEST to run the Postgres export-substrate test")
	}
	ctx := context.Background()
	appDSN := provisionAppRole(ctx, t, adminDSN)
	ps, err := platformdb.NewPGStore(ctx, appDSN)
	if err != nil {
		t.Fatalf("newPgStore: %v", err)
	}
	defer ps.DB().Close()

	q := reports.NewPGJobQueue(ps.DB(), 5)
	es := reports.NewPGExecStore(ps.DB())

	// 1) queue round-trips job_type=export + the frozen payload.
	spec := logexport.Spec{Query: "*", Signal: "applogs", Format: "csv", Cross: true}
	payload, _ := json.Marshal(spec)
	job := reports.Job{JobType: jobTypeExport, TenantID: "acme", ScheduleID: "exp1", ExecutionID: "ex1", FireTime: time.Now().UTC(), Payload: payload}
	if _, created, err := q.Enqueue(ctx, job, time.Now().UTC()); err != nil || !created {
		t.Fatalf("enqueue export: err=%v created=%v", err, created)
	}
	claimed, err := q.Claim(ctx, "w1", 5, time.Minute)
	if err != nil || len(claimed) != 1 {
		t.Fatalf("claim: err=%v n=%d", err, len(claimed))
	}
	if claimed[0].JobType != jobTypeExport {
		t.Errorf("claimed job_type=%q, want %q", claimed[0].JobType, jobTypeExport)
	}
	var got logexport.Spec
	if err := json.Unmarshal(claimed[0].Payload, &got); err != nil || got.Signal != "applogs" {
		t.Errorf("payload round-trip wrong: err=%v spec=%+v", err, got)
	}

	// 2) execution kind round-trips + List filters reports vs exports apart.
	mustAppend := func(id, kind, sched string) {
		if err := es.Append(ctx, reports.ExecutionRecord{ID: id, Kind: kind, TenantID: "acme", ScheduleID: sched, FireTime: time.Now().UTC(), Status: reports.StatusQueued}); err != nil {
			t.Fatalf("append %s: %v", id, err)
		}
	}
	mustAppend("ex1", jobTypeExport, "exp1")
	mustAppend("rx1", "report", "rep1")

	rec, _, found, err := es.Get(ctx, "acme", false, "ex1")
	if err != nil || !found || rec.Kind != jobTypeExport {
		t.Fatalf("get export exec: err=%v found=%v kind=%q", err, found, rec.Kind)
	}
	if ex, _ := es.List(ctx, "acme", false, reports.ExecQuery{Kind: jobTypeExport}); len(ex) != 1 || ex[0].ID != "ex1" {
		t.Errorf("List(kind=export) = %v, want [ex1]", ex)
	}
	if rp, _ := es.List(ctx, "acme", false, reports.ExecQuery{Kind: "report"}); len(rp) != 1 || rp[0].ID != "rx1" {
		t.Errorf("List(kind=report) = %v, want [rx1]", rp)
	}

	// 3) RLS: another tenant sees none of acme's exports.
	if other, _ := es.List(ctx, "globex", false, reports.ExecQuery{Kind: jobTypeExport}); len(other) != 0 {
		t.Errorf("cross-tenant leak: globex sees %d export execs, want 0", len(other))
	}

	// 4) EnqueueExport records a queued export owned by the requester's tenant.
	pipe := &reportPipeline{queue: q, execs: es}
	execID, err := pipe.EnqueueExport(ctx, "acme", spec)
	if err != nil {
		t.Fatalf("EnqueueExport: %v", err)
	}
	rec2, _, found2, err := es.Get(ctx, "acme", false, execID)
	if err != nil || !found2 || rec2.Kind != jobTypeExport || rec2.Status != reports.StatusQueued {
		t.Errorf("EnqueueExport exec wrong: found=%v kind=%q status=%q err=%v", found2, rec2.Kind, rec2.Status, err)
	}
}
