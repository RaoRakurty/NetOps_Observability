// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// report_executions_pg_restriction_test.go — the POSTGRES half of tracker 304.
//
// report_executions_restriction_test.go drives the HTTP surfaces over an
// in-memory execution store; this file proves the same rule where it actually
// executes on the default backend: in SQL, inside PGExecStore, with RLS live.
//
// The load-bearing assertion is the LIMIT one. The restriction is a WHERE clause
// rather than a filter over the result set, because List applies its bound in the
// same statement. A post-filter would spend page slots on rows the caller is
// never shown: ask for two rows while the two newest belong to a restricted
// tenant and a post-filter hands back an EMPTY page — which says "there are two
// rows here you may not see" just as loudly as printing them would.

import (
	"context"
	"os"
	"testing"
	"time"

	"netops/backend/internal/platformdb"
	"netops/backend/reports"
)

func TestPgExecStoreHonoursTheOperatorVisibilityRestriction(t *testing.T) {
	adminDSN := os.Getenv("DATABASE_URL_TEST")
	if adminDSN == "" {
		t.Skip("set DATABASE_URL_TEST to run the Postgres execution-store restriction test")
	}
	ctx := context.Background()
	ps, err := platformdb.NewPGStore(ctx, provisionAppRole(ctx, t, adminDSN))
	if err != nil {
		t.Fatalf("newPgStore: %v", err)
	}
	defer ps.DB().Close()
	s := reports.NewPGExecStore(ps.DB())

	base := time.Date(2026, 9, 12, 6, 0, 0, 0, time.UTC)
	// Newest first: acme's two runs, then globex's, then the platform's own. The
	// ordering is deliberate — it is what makes the LIMIT assertion below able to
	// tell an in-SQL exclusion from a post-filter.
	rows := []struct {
		id, tenant, sched string
		at                time.Time
	}{
		{"px-acme-2", "acme", "rep-acme", base.Add(3 * time.Hour)},
		{"px-acme-1", "acme", "rep-acme", base.Add(2 * time.Hour)},
		{"px-globex", "globex", "rep-globex", base.Add(time.Hour)},
		{"px-platform", "", "rep-platform", base},
	}
	for _, r := range rows {
		rec := reports.ExecutionRecord{
			ID: r.id, Kind: "report", TenantID: r.tenant, ScheduleID: r.sched,
			FireTime: r.at, Status: reports.StatusCompleted,
			Artifacts: []reports.ArtifactRef{{Format: "html", ContentType: "text/html",
				Key: r.id, Summary: r.tenant + " report summary"}},
		}
		if err := s.Append(ctx, rec); err != nil {
			t.Fatalf("append %s: %v", r.id, err)
		}
	}

	ids := func(list []reports.ExecutionRecord) []string {
		out := make([]string, 0, len(list))
		for _, r := range list {
			out = append(out, r.ID)
		}
		return out
	}
	listOK := func(sc reports.ExecScope, q reports.ExecQuery) []reports.ExecutionRecord {
		t.Helper()
		got, err := s.List(ctx, sc, q)
		if err != nil {
			t.Fatalf("list: %v", err)
		}
		return got
	}
	same := func(got []reports.ExecutionRecord, want ...string) bool {
		g := ids(got)
		if len(g) != len(want) {
			return false
		}
		for i := range g {
			if g[i] != want[i] {
				return false
			}
		}
		return true
	}

	global := reports.ExecScopeFor("", true)
	// ── baseline: the platform owner reads all four. ──
	if got := listOK(global, reports.ExecQuery{}); !same(got, "px-acme-2", "px-acme-1", "px-globex", "px-platform") {
		t.Fatalf("baseline: the owner should read all four executions newest-first, got %v", ids(got))
	}
	if _, _, found, err := s.Get(ctx, global, "px-acme-1"); err != nil || !found {
		t.Fatalf("baseline: the owner should read acme's execution by id: found=%v err=%v", found, err)
	}

	// ── half 1: the GLOBAL view with acme hidden. ──
	hidden := reports.ExecScope{Cross: true, Hidden: []string{"acme"}}
	if got := listOK(hidden, reports.ExecQuery{}); !same(got, "px-globex", "px-platform") {
		t.Errorf("RESTRICTION LEAK: the Global list with acme hidden returned %v, want [px-globex px-platform]", ids(got))
	}
	// The exclusion is case- and space-tolerant: a row's tenant id and the id in
	// the tenant store are minted by different writers.
	if got := listOK(reports.ExecScope{Cross: true, Hidden: []string{" ACME "}}, reports.ExecQuery{}); !same(got, "px-globex", "px-platform") {
		t.Errorf("the exclusion is case-sensitive: %v", ids(got))
	}
	// By-id is absent, not refused. Both of acme's rows.
	for _, id := range []string{"px-acme-1", "px-acme-2"} {
		rec, events, found, err := s.Get(ctx, hidden, id)
		if err != nil {
			t.Fatalf("get %s: %v", id, err)
		}
		if found {
			summary := ""
			if a := rec.PrimaryArtifact(); a != nil {
				summary = a.Summary
			}
			t.Errorf("RESTRICTION LEAK: Get(%s) with acme hidden returned the row (tenant %q, schedule %q, artifact summary %q)",
				id, rec.TenantID, rec.ScheduleID, summary)
		}
		if len(events) != 0 {
			t.Errorf("Get(%s) returned %d phase events for a row the scope may not see", id, len(events))
		}
	}
	// The platform's own execution and the unrestricted tenant's survive.
	if _, _, found, _ := s.Get(ctx, hidden, "px-platform"); !found {
		t.Error("hiding acme also hid the PLATFORM's own execution")
	}
	if _, _, found, _ := s.Get(ctx, hidden, "px-globex"); !found {
		t.Error("hiding acme also hid globex's execution")
	}

	// ── THE LIMIT: the exclusion and the bound are one pass. ──
	//
	// The two newest rows are acme's. A handler-side post-filter over a LIMIT 2
	// page would answer with NOTHING and leave the caller holding "there are two
	// rows here I am not allowed to see".
	if got := listOK(hidden, reports.ExecQuery{Limit: 2}); !same(got, "px-globex", "px-platform") {
		t.Errorf("THE BOUND DISCLOSES: LIMIT 2 with acme hidden returned %v, want the two VISIBLE rows "+
			"[px-globex px-platform] — a page shortened by rows the caller may not see is itself the disclosure", ids(got))
	}
	// Same for a schedule filter aimed straight at the hidden tenant.
	if got := listOK(hidden, reports.ExecQuery{ScheduleID: "rep-acme"}); len(got) != 0 {
		t.Errorf("RESTRICTION LEAK: naming the hidden tenant's schedule returned %v", ids(got))
	}

	// ── half 2: scoped INTO the restricted tenant reads nothing at all — not
	//    even the platform's own rows, which the ordinary tenant scope would not
	//    have served anyway, and not by issuing a query. ──
	deny := reports.ExecScope{Tenant: "acme", Deny: true, Hidden: []string{"acme"}}
	if got := listOK(deny, reports.ExecQuery{}); len(got) != 0 {
		t.Errorf("RESTRICTION LEAK: the denied scope listed %v", ids(got))
	}
	for _, id := range []string{"px-acme-1", "px-globex", "px-platform"} {
		if _, _, found, _ := s.Get(ctx, deny, id); found {
			t.Errorf("RESTRICTION LEAK: the denied scope read %s", id)
		}
	}

	// ── the restricted tenant's OWN users are unaffected: the switch hides a
	//    tenant from the platform, never from itself. ──
	own := reports.ExecScopeFor("acme", false)
	if got := listOK(own, reports.ExecQuery{}); !same(got, "px-acme-2", "px-acme-1") {
		t.Errorf("the restriction reached acme's OWN reads: %v", ids(got))
	}
	if _, _, found, _ := s.Get(ctx, own, "px-acme-1"); !found {
		t.Error("acme can no longer read its own execution by id")
	}
	// And RLS still isolates it from globex's row.
	if _, _, found, _ := s.Get(ctx, own, "px-globex"); found {
		t.Error("CROSS-TENANT LEAK: acme read globex's execution")
	}
}
