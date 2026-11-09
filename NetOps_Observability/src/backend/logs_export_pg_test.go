// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

import (
	"context"
	"encoding/json"
	"netops/backend/internal/platformdb"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

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

	rec, _, found, err := es.Get(ctx, reports.ExecScopeFor("acme", false), "ex1")
	if err != nil || !found || rec.Kind != jobTypeExport {
		t.Fatalf("get export exec: err=%v found=%v kind=%q", err, found, rec.Kind)
	}
	if ex, _ := es.List(ctx, reports.ExecScopeFor("acme", false), reports.ExecQuery{Kind: jobTypeExport}); len(ex) != 1 || ex[0].ID != "ex1" {
		t.Errorf("List(kind=export) = %v, want [ex1]", ex)
	}
	if rp, _ := es.List(ctx, reports.ExecScopeFor("acme", false), reports.ExecQuery{Kind: "report"}); len(rp) != 1 || rp[0].ID != "rx1" {
		t.Errorf("List(kind=report) = %v, want [rx1]", rp)
	}

	// 3) RLS: another tenant sees none of acme's exports.
	if other, _ := es.List(ctx, reports.ExecScopeFor("globex", false), reports.ExecQuery{Kind: jobTypeExport}); len(other) != 0 {
		t.Errorf("cross-tenant leak: globex sees %d export execs, want 0", len(other))
	}

	// 4) EnqueueExport records a queued export owned by the requester's tenant.
	pipe := &reportPipeline{queue: q, execs: es}
	execID, err := pipe.EnqueueExport(ctx, "acme", spec)
	if err != nil {
		t.Fatalf("EnqueueExport: %v", err)
	}
	rec2, _, found2, err := es.Get(ctx, reports.ExecScopeFor("acme", false), execID)
	if err != nil || !found2 || rec2.Kind != jobTypeExport || rec2.Status != reports.StatusQueued {
		t.Errorf("EnqueueExport exec wrong: found=%v kind=%q status=%q err=%v", found2, rec2.Kind, rec2.Status, err)
	}

	// 5) The retention sweep (D7) reads the history as the platform, so it reaches
	// every tenant's expired exports through FORCE RLS, leaves a fresh one alone
	// and never touches a report. Finished rows go in by Append, which is the one
	// write that takes a fire time, then finished by hand: Complete is
	// lease-guarded and is not what is under test here.
	now := time.Now().UTC()
	arts := newIDPArtifacts()
	for _, row := range []struct {
		id, tenant, kind string
		at               time.Time
	}{
		{"sweep-old-acme", "acme", jobTypeExport, now.Add(-72 * time.Hour)},
		{"sweep-old-globex", "globex", jobTypeExport, now.Add(-72 * time.Hour)},
		{"sweep-fresh", "acme", jobTypeExport, now.Add(-time.Hour)},
		{"sweep-report", "acme", "report", now.Add(-72 * time.Hour)},
	} {
		ref := reports.ArtifactRef{Format: "csv", Key: row.id}
		arts.files[row.id] = []byte("line")
		if err := es.Append(ctx, reports.ExecutionRecord{
			ID: row.id, Kind: row.kind, TenantID: row.tenant, ScheduleID: row.id, JobID: row.id,
			FireTime: row.at, Status: reports.StatusCompleted,
		}); err != nil {
			t.Fatalf("append %s: %v", row.id, err)
		}
		refJSON, err := json.Marshal([]reports.ArtifactRef{ref})
		if err != nil {
			t.Fatal(err)
		}
		if err := ps.DB().WithTenant(ctx, "", true, func(tx pgx.Tx) error {
			_, err := tx.Exec(ctx, `UPDATE report_executions SET completed_at=$2, artifact_ref=$3 WHERE id=$1`, row.id, row.at, refJSON)
			return err
		}); err != nil {
			t.Fatalf("finish %s: %v", row.id, err)
		}
	}
	sweep := &reportPipeline{execs: es, artifacts: arts}
	if _, err := sweep.sweepExportArtifacts(ctx, now); err != nil {
		t.Fatalf("sweep: %v", err)
	}
	for id, wantGone := range map[string]bool{"sweep-old-acme": true, "sweep-old-globex": true, "sweep-fresh": false, "sweep-report": false} {
		if gone := len(arts.files[id]) == 0; gone != wantGone {
			t.Errorf("%s: removed=%v, want %v", id, gone, wantGone)
		}
	}
}
