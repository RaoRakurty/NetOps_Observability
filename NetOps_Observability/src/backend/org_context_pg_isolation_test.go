// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// org_context_pg_isolation_test.go — storage-layer proof for the Network
// context store (migration 0058, tracker 337 N-F1): FORCE-RLS confines every
// statement to the tenant; the DATABASE refuses a self-approval, a rewrite of
// submitted text and the deletion of history even when the application is
// bypassed; the lifecycle round-trips through PGStore; concurrent approvals
// activate exactly once and the per-tenant cap holds under concurrent
// creates. Gated on DATABASE_URL_TEST like every pg-integration test here.

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"netops/backend/internal/orgcontext"
	"netops/backend/internal/platformdb"
)

func orgContextPG(t *testing.T) (*platformdb.PGStore, *orgcontext.PGStore) {
	t.Helper()
	adminDSN := os.Getenv("DATABASE_URL_TEST")
	if adminDSN == "" {
		t.Skip("DATABASE_URL_TEST not set")
	}
	ctx := context.Background()
	ps, err := platformdb.NewPGStore(ctx, provisionAppRole(ctx, t, adminDSN))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(ps.DB().Close)
	return ps, orgcontext.NewPGStore(ps.DB())
}

func pgFact(t *testing.T, st orgcontext.Store, tenant, author, key string) orgcontext.Doc {
	t.Helper()
	d, err := st.Create(context.Background(), tenant, author, orgcontext.NewDoc{Scope: orgcontext.ScopeTenant, Kind: orgcontext.KindTopologyNote, Key: key, Body: "core-02 is the DR site"})
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func pgDo(t *testing.T, st orgcontext.Store, tenant, id string, op orgcontext.Op) orgcontext.Doc {
	t.Helper()
	d, err := st.Do(context.Background(), tenant, id, op)
	if err != nil {
		t.Fatalf("%s by %s: %v", op.Kind, op.Actor, err)
	}
	return d
}

func pgActivate(t *testing.T, st orgcontext.Store, tenant, id, author, approver string) orgcontext.Doc {
	t.Helper()
	d := pgDo(t, st, tenant, id, orgcontext.Op{Kind: orgcontext.OpSubmit, Actor: author})
	v, _ := d.Open()
	return pgDo(t, st, tenant, id, orgcontext.Op{Kind: orgcontext.OpApprove, Actor: approver, Version: v.Version, BodySHA256: v.BodySHA256})
}

func orgCtxPGCode(err error) string {
	var pe *pgconn.PgError
	if errors.As(err, &pe) {
		return pe.Code
	}
	return ""
}

func TestOrgContextRLSIsolationPG(t *testing.T) {
	ps, st := orgContextPG(t)
	ctx := context.Background()
	d := pgFact(t, st, "acme", "alice", "dr")
	pgActivate(t, st, "acme", d.ID, "alice", "bob")

	if _, err := st.Get(ctx, "globex", d.ID); !errors.Is(err, orgcontext.ErrNotFound) {
		t.Fatalf("RLS LEAK: globex read acme's fact (%v)", err)
	}
	for _, k := range []orgcontext.OpKind{orgcontext.OpDraft, orgcontext.OpApprove, orgcontext.OpRollback, orgcontext.OpRetire} {
		if _, err := st.Do(ctx, "globex", d.ID, orgcontext.Op{Kind: k, Actor: "mallory", Body: "x", Version: 1, ToVersion: 1, Reason: "r"}); !errors.Is(err, orgcontext.ErrNotFound) {
			t.Fatalf("RLS LEAK: globex %s on acme's fact (%v)", k, err)
		}
	}
	if f, err := st.ActiveFacts(ctx, "globex"); err != nil || len(f) != 0 {
		t.Fatalf("RLS LEAK: globex's prompt would carry %v (%v)", f, err)
	}
	for _, table := range []string{"org_context_docs", "org_context_versions"} {
		var n int
		if err := ps.DB().WithTenant(ctx, "globex", false, func(tx pgx.Tx) error {
			return tx.QueryRow(ctx, `SELECT count(*) FROM `+table).Scan(&n)
		}); err != nil || n != 0 {
			t.Fatalf("RLS LEAK: globex's session counts %d rows in %s (%v)", n, table, err)
		}
	}
	forgeErr := ps.DB().WithTenant(ctx, "acme", false, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO org_context_docs (tenant_id, id, scope, kind, key, created_by)
		    VALUES ('globex', gen_random_uuid(), 'tenant', 'terminology', 'forged', 'mallory')`)
		return err
	})
	if orgCtxPGCode(forgeErr) != "42501" {
		t.Fatalf("WITH CHECK must refuse a forged tenant, got %v", forgeErr)
	}
}

// The database holds the two-person rule and the history even when the
// application is bypassed.
func TestOrgContextDatabaseGuardsPG(t *testing.T) {
	ps, st := orgContextPG(t)
	ctx := context.Background()
	d := pgFact(t, st, "acme", "alice", "dr")
	pgDo(t, st, "acme", d.ID, orgcontext.Op{Kind: orgcontext.OpSubmit, Actor: "alice"})
	raw := func(sql string) error {
		return ps.DB().WithTenant(ctx, "acme", false, func(tx pgx.Tx) error {
			_, err := tx.Exec(ctx, sql, d.ID)
			return err
		})
	}
	if code := orgCtxPGCode(raw(`UPDATE org_context_versions SET state = 'active', approver_sub = 'alice' WHERE doc_id = $1::uuid`)); code != "23514" {
		t.Fatalf("a self-approval written straight to the table: code %q, want 23514 (CHECK)", code)
	}
	if code := orgCtxPGCode(raw(`UPDATE org_context_versions SET state = 'active' WHERE doc_id = $1::uuid`)); code != "23514" {
		t.Fatalf("an active version with no approver: code %q, want 23514", code)
	}
	if code := orgCtxPGCode(raw(`UPDATE org_context_versions SET body = 'swapped after review' WHERE doc_id = $1::uuid`)); code != "42501" {
		t.Fatalf("rewriting a submitted text: code %q, want 42501 (trigger)", code)
	}
	if code := orgCtxPGCode(raw(`DELETE FROM org_context_versions WHERE doc_id = $1::uuid`)); code != "42501" {
		t.Fatalf("deleting a submitted version: code %q, want 42501", code)
	}
	pgDo(t, st, "acme", d.ID, orgcontext.Op{Kind: orgcontext.OpApprove, Actor: "bob", Version: 1, BodySHA256: orgcontext.BodySHA256("core-02 is the DR site")})
	if code := orgCtxPGCode(raw(`UPDATE org_context_versions SET approver_sub = 'carol' WHERE doc_id = $1::uuid`)); code != "42501" {
		t.Fatalf("re-attributing an approval: code %q, want 42501", code)
	}
	if code := orgCtxPGCode(raw(`UPDATE org_context_versions SET state = 'pending' WHERE doc_id = $1::uuid`)); code != "42501" {
		t.Fatalf("active → pending: code %q, want 42501", code)
	}
}

func TestOrgContextLifecyclePG(t *testing.T) {
	_, st := orgContextPG(t)
	ctx := context.Background()
	d := pgFact(t, st, "acme", "alice", "dr")
	if _, err := st.Do(ctx, "acme", d.ID, orgcontext.Op{Kind: orgcontext.OpSubmit, Actor: "alice"}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Do(ctx, "acme", d.ID, orgcontext.Op{Kind: orgcontext.OpApprove, Actor: "alice", Version: 1, BodySHA256: orgcontext.BodySHA256("core-02 is the DR site")}); !errors.Is(err, orgcontext.ErrSelfApproval) {
		t.Fatalf("self-approval: %v", err)
	}
	pgDo(t, st, "acme", d.ID, orgcontext.Op{Kind: orgcontext.OpApprove, Actor: "bob", Version: 1, BodySHA256: orgcontext.BodySHA256("core-02 is the DR site")})
	pgDo(t, st, "acme", d.ID, orgcontext.Op{Kind: orgcontext.OpDraft, Actor: "carol", Body: "core-03 is the DR site"})
	d = pgActivate(t, st, "acme", d.ID, "carol", "alice")
	if a, _ := d.Active(); a.Version != 2 || a.Body != "core-03 is the DR site" {
		t.Fatalf("v2: %+v", d.Versions)
	}
	d = pgDo(t, st, "acme", d.ID, orgcontext.Op{Kind: orgcontext.OpRollback, Actor: "carol", ToVersion: 1, Reason: "v2 was wrong"})
	got, err := st.Get(ctx, "acme", d.ID)
	if err != nil {
		t.Fatal(err)
	}
	a, _ := got.Active()
	if a.Version != 3 || a.RestoredFrom != 1 || a.Author != "alice" || a.Approver != "bob" || a.ActivatedBy != "carol" || len(got.Versions) != 3 {
		t.Fatalf("rollback round trip: %+v", got.Versions)
	}
	facts, err := st.ActiveFacts(ctx, "acme")
	if err != nil || len(facts) != 1 || facts[0].Body != "core-02 is the DR site" || facts[0].Version != 3 {
		t.Fatalf("active facts: %+v (%v)", facts, err)
	}
	pgDo(t, st, "acme", d.ID, orgcontext.Op{Kind: orgcontext.OpRetire, Actor: "bob", Reason: "decommissioned"})
	if facts, _ := st.ActiveFacts(ctx, "acme"); len(facts) != 0 {
		t.Fatal("a retired fact stayed active")
	}
	// Discarding a fact's only draft removes the fact.
	d2 := pgFact(t, st, "acme", "alice", "scratch")
	pgDo(t, st, "acme", d2.ID, orgcontext.Op{Kind: orgcontext.OpDiscard, Actor: "alice"})
	if _, err := st.Get(ctx, "acme", d2.ID); !errors.Is(err, orgcontext.ErrNotFound) {
		t.Fatalf("discarded fact: %v", err)
	}
	if _, err := st.Create(ctx, "acme", "bob", orgcontext.NewDoc{Scope: orgcontext.ScopeTenant, Kind: orgcontext.KindTopologyNote, Key: "dr", Body: "x"}); !errors.Is(err, orgcontext.ErrExists) {
		t.Fatalf("duplicate: %v", err)
	}
}

func TestOrgContextConcurrencyPG(t *testing.T) {
	_, st := orgContextPG(t)
	ctx := context.Background()
	d := pgFact(t, st, "acme", "alice", "dr")
	pgDo(t, st, "acme", d.ID, orgcontext.Op{Kind: orgcontext.OpSubmit, Actor: "alice"})
	var wg sync.WaitGroup
	var mu sync.Mutex
	wins := 0
	for i := 0; i < 6; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, err := st.Do(ctx, "acme", d.ID, orgcontext.Op{Kind: orgcontext.OpApprove, Actor: fmt.Sprintf("reviewer-%d", i), Version: 1, BodySHA256: orgcontext.BodySHA256("core-02 is the DR site")})
			if err == nil {
				mu.Lock()
				wins++
				mu.Unlock()
			}
		}(i)
	}
	wg.Wait()
	if wins != 1 {
		t.Fatalf("%d concurrent approvals succeeded, want 1", wins)
	}
	// The per-tenant cap holds under concurrent creates (advisory lock).
	created := 1
	for i := 0; i < orgcontext.MaxDocsPerTenant+10; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if _, err := st.Create(ctx, "acme", "alice", orgcontext.NewDoc{Scope: orgcontext.ScopeTenant, Kind: orgcontext.KindTerminology, Key: fmt.Sprintf("t%d", i), Body: "x"}); err == nil {
				mu.Lock()
				created++
				mu.Unlock()
			}
		}(i)
	}
	wg.Wait()
	if created != orgcontext.MaxDocsPerTenant {
		t.Fatalf("%d facts exist, the cap is %d", created, orgcontext.MaxDocsPerTenant)
	}
}
