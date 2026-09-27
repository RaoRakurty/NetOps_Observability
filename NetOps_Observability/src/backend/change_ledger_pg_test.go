// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// change_ledger_pg_test.go — the change ledger (migration 0052) against a REAL
// Postgres, as the non-superuser app role FORCE RLS applies to. Gated on
// DATABASE_URL_TEST like the rest of the RLS corpus, so it runs in the
// pg-integration CI leg (backend-ci.yml), which runs the package unfiltered.
//
// Proven here, by the database itself:
//   - every N-D1 filter (actor by source/canonical/display, object, object kind,
//     source system, until, seam, exclusions) runs in SQL, own-tenant only, and
//     CountChanges answers the same predicate;
//   - a pre-N-D1 row reads back with the defaults the migration backfilled;
//   - age retention deletes ONLY the writing tenant's expired rows — both the
//     explicit PruneChanges and the bounded prune inside RecordChange — and
//     another tenant's expired rows survive until that tenant writes;
//   - a replayed change id is idempotent;
//   - the capture trigger round-trips through config_backup_versions.

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"netops/backend/internal/configstore"
	"netops/backend/internal/dem/experience"
	"netops/backend/internal/platformdb"
)

func TestChangeLedgerRLSAndFiltersPG(t *testing.T) {
	adminDSN := os.Getenv("DATABASE_URL_TEST")
	if adminDSN == "" {
		t.Skip("DATABASE_URL_TEST not set")
	}
	ctx := context.Background()
	ps, err := platformdb.NewPGStore(ctx, provisionAppRole(ctx, t, adminDSN))
	if err != nil {
		t.Fatal(err)
	}
	defer ps.DB().Close()
	st := experience.NewPGStore(ps.DB())
	now := time.Now().UTC().Truncate(time.Millisecond)

	rec := func(c experience.ChangeEvent, at time.Time) experience.ChangeEvent {
		t.Helper()
		if c.Summary == "" {
			c.Summary = "change " + c.ID
		}
		if c.Type == "" {
			c.Type = experience.ChangeConfig
		}
		c.Provenance = experience.Provenance{Source: experience.SourceConfigDrift, EventAt: at,
			ObservedAt: at.Add(time.Minute), Observation: experience.ObservationObserved,
			DataClass: experience.DataClassCustomerMetadata}
		out, err := st.RecordChange(ctx, c)
		if err != nil {
			t.Fatalf("record %s/%s: %v", c.TenantID, c.ID, err)
		}
		return out
	}
	id := func(n int) string { return "chg-" + strings.Repeat("0", 31) + string(rune('a'+n)) }

	// The SAME object and the SAME actor in two tenants: the shape a leak would
	// expose.
	for _, tenant := range []string{"acme", "globex"} {
		rec(experience.ChangeEvent{TenantID: tenant, ID: id(0), Object: "edge-1", ObjectKind: "device",
			Actor: "jsmith", ActorID: "u_7", ActorDisplay: "John Smith", ActorType: experience.ChangeActorUser,
			SourceSystem: experience.SourceSystemConfigCapture, TicketRef: "CHG-1", Automation: false,
			Seam: "SDWAN"}, now.Add(-30*time.Minute))
	}
	rec(experience.ChangeEvent{TenantID: "acme", ID: id(1), Object: "edge-2", ObjectKind: "cloud_resource",
		Actor: "ci", ActorType: experience.ChangeActorService, SourceSystem: experience.SourceSystemAudit,
		Automation: true}, now.Add(-10*time.Minute))
	// Idempotent replay: same id, different body — the first fact stands.
	rec(experience.ChangeEvent{TenantID: "acme", ID: id(1), Object: "rewritten"}, now.Add(-5*time.Minute))

	list := func(tenant string, q experience.ChangeQuery) []experience.ChangeEvent {
		t.Helper()
		rows, err := st.ListChanges(ctx, tenant, q)
		if err != nil {
			t.Fatalf("list %s %+v: %v", tenant, q, err)
		}
		n, err := st.CountChanges(ctx, tenant, q)
		if err != nil {
			t.Fatalf("count %s: %v", tenant, err)
		}
		if n != len(rows) {
			t.Fatalf("count %d disagrees with list %d for %+v", n, len(rows), q)
		}
		return rows
	}
	for name, tc := range map[string]struct {
		q    experience.ChangeQuery
		want string
	}{
		"actor by source identity": {experience.ChangeQuery{Actors: []string{"jsmith"}}, id(0)},
		"actor by canonical id":    {experience.ChangeQuery{Actors: []string{"U_7"}}, id(0)},
		"actor by display":         {experience.ChangeQuery{Actors: []string{"john smith"}}, id(0)},
		"object":                   {experience.ChangeQuery{Objects: []string{"edge-2"}}, id(1)},
		"object kind":              {experience.ChangeQuery{ObjectKinds: []string{"cloud_resource"}}, id(1)},
		"source":                   {experience.ChangeQuery{Sources: []string{"config_capture"}}, id(0)},
		"seam":                     {experience.ChangeQuery{Seams: []string{"SDWAN"}}, id(0)},
		"until":                    {experience.ChangeQuery{Until: now.Add(-20 * time.Minute)}, id(0)},
		"excluded":                 {experience.ChangeQuery{ExcludeIDs: []string{id(1)}}, id(0)},
	} {
		rows := list("acme", tc.q)
		if len(rows) != 1 || rows[0].ID != tc.want || rows[0].TenantID != "acme" {
			t.Errorf("%s: acme got %+v, want only %s", name, rows, tc.want)
		}
	}
	all := list("acme", experience.ChangeQuery{})
	if len(all) != 2 {
		t.Fatalf("acme holds %d rows, want 2 (the replay must not add or rewrite)", len(all))
	}
	for _, c := range all {
		if c.ID == id(1) && c.Object != "edge-2" {
			t.Fatalf("a replayed id rewrote the recorded change: %+v", c)
		}
		if c.ID == id(0) && (c.TicketRef != "CHG-1" || c.ActorDisplay != "John Smith" || c.ActorType != "user") {
			t.Fatalf("the N-D1 fields did not round-trip: %+v", c)
		}
	}
	if g := list("globex", experience.ChangeQuery{Objects: []string{"edge-2"}}); len(g) != 0 {
		t.Fatalf("RLS LEAK: globex sees acme's object: %+v", g)
	}
	if g := list("globex", experience.ChangeQuery{Actors: []string{"jsmith"}}); len(g) != 1 || g[0].TenantID != "globex" {
		t.Fatalf("RLS LEAK or loss: globex by shared actor = %+v", g)
	}
	if g, _ := st.ListChanges(ctx, "*", experience.ChangeQuery{}); len(g) != 0 {
		t.Fatalf("a wildcard tenant read %d rows", len(g))
	}

	// The typed columns hold what the JSON says (the filters read the columns).
	var srcSys, actorType, actorID, ticket string
	var automation bool
	var detected time.Time
	if err := ps.DB().WithTenant(ctx, "acme", false, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT source_system, actor_type, actor_id, ticket_ref, automation, detected_at
		                           FROM dem_change_events WHERE change_id = $1`, id(1)).
			Scan(&srcSys, &actorType, &actorID, &ticket, &automation, &detected)
	}); err != nil {
		t.Fatal(err)
	}
	if srcSys != "correlix_audit" || actorType != "service" || actorID != "ci" || !automation ||
		!detected.Equal(now.Add(-10*time.Minute).Add(time.Minute)) {
		t.Fatalf("columns: source=%q type=%q id=%q automation=%v detected=%v", srcSys, actorType, actorID, automation, detected)
	}

	// A pre-N-D1 row (only the 0044 columns, the column defaults for the rest)
	// reads back with the backfilled defaults and matches the ledger source.
	if err := ps.DB().WithTenant(ctx, "acme", false, func(tx pgx.Tx) error {
		_, e := tx.Exec(ctx, `INSERT INTO dem_change_events (tenant_id, change_id, change_type, app, site, event_at, data)
		    VALUES ('acme', $1, 'CONFIG_CHANGE', '', '', $2, $3)`, id(2), now.Add(-time.Minute),
			`{"id":"`+id(2)+`","tenant_id":"acme","type":"CONFIG_CHANGE","actor":"legacy-op","object":"edge-9","summary":"legacy","cohort":{},"provenance":{"source":"manual","event_at":"`+now.Add(-time.Minute).Format(time.RFC3339Nano)+`","observed_at":"`+now.Add(-time.Minute).Format(time.RFC3339Nano)+`","observation":"observed","data_class":"internal","schema_name":"correlix.dem.experience","schema_version":1}}`)
		return e
	}); err != nil {
		t.Fatal(err)
	}
	legacy := list("acme", experience.ChangeQuery{Sources: []string{"ledger"}})
	if len(legacy) != 1 || legacy[0].ID != id(2) || legacy[0].SourceSystem != "ledger" ||
		legacy[0].ActorID != "legacy-op" || legacy[0].ActorType != "unknown" {
		t.Fatalf("legacy row = %+v", legacy)
	}

	// ── retention: tenant-scoped, bounded ──────────────────────────────────
	old := now.Add(-experience.ChangeRetention - 24*time.Hour)
	seedOld := func(tenant string, n int) {
		t.Helper()
		if err := ps.DB().WithTenant(ctx, tenant, false, func(tx pgx.Tx) error {
			for i := 0; i < n; i++ {
				cid := "chg-" + strings.Repeat("f", 30) + string(rune('a'+i)) + string(rune('a'+len(tenant)))
				if _, e := tx.Exec(ctx, `INSERT INTO dem_change_events (tenant_id, change_id, change_type, event_at, data, object)
				    VALUES ($1, $2, 'CONFIG_CHANGE', $3, '{}'::jsonb, 'old')`, tenant, cid, old.Add(time.Duration(i)*time.Minute)); e != nil {
					return e
				}
			}
			return nil
		}); err != nil {
			t.Fatalf("seed old rows for %s: %v", tenant, err)
		}
	}
	countOld := func(tenant string) int {
		t.Helper()
		n := -1
		if err := ps.DB().WithTenant(ctx, tenant, false, func(tx pgx.Tx) error {
			return tx.QueryRow(ctx, `SELECT count(*) FROM dem_change_events WHERE object = 'old'`).Scan(&n)
		}); err != nil {
			t.Fatal(err)
		}
		return n
	}
	seedOld("acme", 3)
	seedOld("globex", 3)
	if pruned, err := st.PruneChanges(ctx, "acme", now.Add(-experience.ChangeRetention), 2); err != nil || pruned != 2 {
		t.Fatalf("a bounded prune of 2 removed %d (err %v)", pruned, err)
	}
	if countOld("acme") != 1 {
		t.Fatalf("a bounded prune of 2 left acme with %d old rows, want 1", countOld("acme"))
	}
	if countOld("globex") != 3 {
		t.Fatalf("pruning acme deleted globex rows: globex has %d old rows", countOld("globex"))
	}
	n, err := st.PruneChanges(ctx, "*", now, 10)
	if err == nil || n != 0 {
		t.Fatalf("a wildcard prune was allowed: n=%d err=%v", n, err)
	}
	// A write ages out the WRITER's expired rows, and only the writer's.
	rec(experience.ChangeEvent{TenantID: "acme", ID: id(3), Object: "edge-3"}, now)
	if countOld("acme") != 0 || countOld("globex") != 3 {
		t.Fatalf("after an acme write: acme old=%d (want 0), globex old=%d (want 3)", countOld("acme"), countOld("globex"))
	}
	// A change already past retention is refused, not stored-then-deleted.
	if _, err := st.RecordChange(ctx, experience.ChangeEvent{TenantID: "acme", ID: id(4), Type: experience.ChangeConfig,
		Object: "x", Summary: "too old", Provenance: experience.Provenance{Source: experience.SourceManual, EventAt: old,
			Observation: experience.ObservationObserved, DataClass: experience.DataClassInternal}}); err == nil {
		t.Fatal("a change older than retention was recorded")
	}

	// ── the capture trigger on the version row ─────────────────────────────
	vs := configstore.NewPGStore(ps.DB())
	sha := strings.Repeat("c", 64)
	if err := vs.Put(ctx, "acme", false, configstore.Version{TenantID: "acme", DeviceID: "edge-1", SHA: sha,
		CapturedAt: now, Status: configstore.StatusOK, Trigger: "manual:u_7"}); err != nil {
		t.Fatal(err)
	}
	got, err := vs.Get(ctx, "acme", false, "edge-1", sha)
	if err != nil || got.Trigger != "manual:u_7" {
		t.Fatalf("trigger round-trip = %q (err %v)", got.Trigger, err)
	}
	if _, err := vs.Get(ctx, "globex", false, "edge-1", sha); err == nil {
		t.Fatal("RLS LEAK: globex read acme's version row")
	}
}
