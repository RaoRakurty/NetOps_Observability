// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

import (
	"context"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"netops/backend/internal/platformdb"
	"netops/backend/nms"
)

// TestPgRunStreamsRoundTripUnderTenantIso proves migration 0064's streams
// column on the real FORCE-RLS table, run as the non-superuser app role: a
// run's per-stream results round-trip, "partial" counts as an error in the
// error rate and marks the connector unhealthy, two tenants with the SAME
// integration id (ids are unique only per tenant) each read only their own
// runs, and a write filed under another tenant is refused by WITH CHECK.
// Gated on DATABASE_URL_TEST.
func TestPgRunStreamsRoundTripUnderTenantIso(t *testing.T) {
	adminDSN := os.Getenv("DATABASE_URL_TEST")
	if adminDSN == "" {
		t.Skip("set DATABASE_URL_TEST to run the Postgres run-streams isolation test")
	}
	ctx := context.Background()
	ps, err := platformdb.NewPGStore(ctx, provisionAppRole(ctx, t, adminDSN))
	if err != nil {
		t.Fatalf("newPgStore: %v", err)
	}
	defer ps.DB().Close()
	st := nms.NewPGStore(ps.DB(), nil)

	const id = "nmsi-shared-id"
	for _, tenant := range []string{"t_runs_a", "t_runs_b"} {
		if err := st.Upsert(ctx, nms.Integration{Tenant: tenant, ID: id, Vendor: "vmanage", Product: "x",
			DisplayName: tenant, BaseURL: "https://" + tenant + ".example", Enabled: true, PollIntervalS: 120}); err != nil {
			t.Fatalf("upsert %s: %v", tenant, err)
		}
	}
	t0 := time.Now().UTC().Truncate(time.Millisecond)
	aStreams := []nms.StreamResult{
		{Stream: "alarms", Status: nms.ResultOK, Payloads: 3, DurationMS: 40},
		{Stream: "bfd", Status: nms.ResultTimeout, Error: "context deadline exceeded", DurationMS: 120000},
	}
	if err := st.RecordRun(ctx, nms.RunRecord{Tenant: "t_runs_a", IntegrationID: id, RunID: "ra-1",
		Started: t0, Finished: t0.Add(time.Second), Status: nms.RunStatusPartial, Error: "stream errors: bfd", Streams: aStreams}); err != nil {
		t.Fatalf("RecordRun a: %v", err)
	}
	bStreams := []nms.StreamResult{{Stream: "inventory", Status: nms.ResultOK, Payloads: 1}}
	if err := st.RecordRun(ctx, nms.RunRecord{Tenant: "t_runs_b", IntegrationID: id, RunID: "rb-1",
		Started: t0, Finished: t0.Add(time.Second), Status: nms.RunStatusOK, Streams: bStreams}); err != nil {
		t.Fatalf("RecordRun b: %v", err)
	}
	// A run with no stream list (webhook-only / pre-0064 shape) stores '[]'.
	if err := st.RecordRun(ctx, nms.RunRecord{Tenant: "t_runs_b", IntegrationID: id, RunID: "rb-0",
		Started: t0.Add(-time.Minute), Finished: t0.Add(-time.Minute), Status: nms.RunStatusOK}); err != nil {
		t.Fatalf("RecordRun b (no streams): %v", err)
	}

	ha, ok, err := st.Health(ctx, "t_runs_a", false, id)
	if err != nil || !ok || len(ha.Runs) != 1 {
		t.Fatalf("tenant a health: ok=%v err=%v runs=%+v", ok, err, ha.Runs)
	}
	if fmt.Sprint(ha.Runs[0].Streams) != fmt.Sprint(aStreams) {
		t.Fatalf("streams did not round-trip: %+v", ha.Runs[0].Streams)
	}
	if ha.Healthy || ha.ErrorRate != 1 {
		t.Fatalf("partial run: healthy=%v error_rate=%v (want false, 1)", ha.Healthy, ha.ErrorRate)
	}
	hb, ok, err := st.Health(ctx, "t_runs_b", false, id)
	if err != nil || !ok || len(hb.Runs) != 2 {
		t.Fatalf("tenant b health: ok=%v err=%v runs=%+v", ok, err, hb.Runs)
	}
	for _, r := range hb.Runs {
		if r.RunID == "ra-1" {
			t.Fatal("CROSS-TENANT LEAK: tenant b read tenant a's run under the shared integration id")
		}
	}
	if fmt.Sprint(hb.Runs[0].Streams) != fmt.Sprint(bStreams) || hb.Runs[1].Streams != nil {
		t.Fatalf("tenant b streams: %+v / %+v", hb.Runs[0].Streams, hb.Runs[1].Streams)
	}

	// Below the store: RLS itself hides a's rows from b's scope ...
	var n int
	if err := ps.DB().WithTenant(ctx, "t_runs_b", false, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM connector_run_history WHERE run_id='ra-1'`).Scan(&n)
	}); err != nil || n != 0 {
		t.Fatalf("RLS: tenant b scope sees %d of tenant a's runs (err %v)", n, err)
	}
	// ... and refuses a row filed under another tenant.
	err = ps.DB().WithTenant(ctx, "t_runs_b", false, func(tx pgx.Tx) error {
		_, e := tx.Exec(ctx, `INSERT INTO connector_run_history (tenant_id, integration_id, run_id, started_at, status, streams)
			VALUES ('t_runs_a', $1, 'forged', now(), 'ok', '[]')`, id)
		return e
	})
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "42501" {
		t.Fatalf("a run filed under another tenant must be RLS-denied (42501); got %v", err)
	}
}
