// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// iris_querylog_pg_isolation_test.go — storage-layer proof for iris_query_log
// (migration 0054, tracker 337 N-C8): the FORCE-RLS tenant_iso policy confines
// every statement to the tenant, the store's principal filter confines
// corrections to the asker, records round-trip as counts and references (never
// rows), the per-record correction cap holds under concurrency, and expired
// rows are pruned on write. Gated on DATABASE_URL_TEST like every
// pg-integration test in this package.

import (
	"context"
	"errors"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"netops/backend/internal/irisquerylog"
	"netops/backend/internal/nlquery/ast"
	"netops/backend/internal/platformdb"
)

func qlogPGStore(t *testing.T) (*platformdb.PGStore, *irisquerylog.PGStore) {
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
	t.Cleanup(func() { ps.DB().Close() })
	return ps, irisquerylog.NewPGStore(ps.DB())
}

func TestIrisQueryLogRLSIsolationPG(t *testing.T) {
	ps, st := qlogPGStore(t)
	ctx := context.Background()
	conv := "11111111-2222-4333-8444-555555555555"
	in := irisquerylog.Record{Principal: "alice", ConversationID: conv, Source: irisquerylog.SourceConversation,
		Question: "cpu on edge-1 last hour", Intent: "metric_series", Outcome: irisquerylog.OutcomeAnswered,
		QueryType: "metric_series", ASTHash: "abc", CatalogVersion: "v1-x", ValidationCodes: []string{"window_too_large"},
		Entities: []irisquerylog.Entity{{Type: "device", ID: "device:edge-1", Method: "tenant_alias", Confidence: 0.9}},
		Rows:     0, Series: 3, DurationMs: 42}
	rec, err := st.Record(ctx, "acme", in)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.Record(ctx, "acme", irisquerylog.Record{Principal: "carol", Source: irisquerylog.SourceRouter, Outcome: irisquerylog.OutcomeUnparsed, Question: "carol's"}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Record(ctx, "globex", irisquerylog.Record{Principal: "alice", Source: irisquerylog.SourceRouter, Outcome: irisquerylog.OutcomeUnparsed, Question: "globex's"}); err != nil {
		t.Fatal(err)
	}

	mine, err := st.List(ctx, "acme", irisquerylog.ListFilter{Principal: "alice"})
	if err != nil {
		t.Fatal(err)
	}
	if len(mine) != 1 {
		t.Fatalf("own list: %+v", mine)
	}
	got := mine[0]
	if got.ID != rec.ID || got.ConversationID != conv || got.Series != 3 || got.DurationMs != 42 ||
		len(got.Entities) != 1 || got.Entities[0].Method != "tenant_alias" || got.ValidationCodes[0] != "window_too_large" {
		t.Fatalf("round trip: %+v", got)
	}
	all, err := st.List(ctx, "acme", irisquerylog.ListFilter{})
	if err != nil || len(all) != 2 {
		t.Fatalf("tenant list: %v %+v", err, all)
	}
	for _, r := range all {
		if r.Question == "globex's" {
			t.Fatal("RLS LEAK: another tenant's record listed")
		}
	}

	// Another tenant, a colleague: the same not-found on a correction.
	c := irisquerylog.Correction{Kind: irisquerylog.KindWrongEntity, By: "x", Note: "no"}
	for _, who := range [][2]string{{"globex", "alice"}, {"acme", "carol"}} {
		if _, err := st.Correct(ctx, who[0], who[1], rec.ID, c); !errors.Is(err, irisquerylog.ErrNotFound) {
			t.Fatalf("RLS/principal LEAK: %v corrected alice's record (%v)", who, err)
		}
	}
	q := &ast.AST{V: 1, Type: ast.ChangeList, Target: "change"}
	out, err := st.Correct(ctx, "acme", "alice", rec.ID, irisquerylog.Correction{Kind: irisquerylog.KindWrongFilter, By: "alice", CorrectedAST: q})
	if err != nil || len(out.Corrections) != 1 || out.Corrections[0].CorrectedHash != q.Hash() {
		t.Fatalf("own correction: %v %+v", err, out)
	}

	// Underneath the store: under globex's RLS session acme's rows do not exist.
	var n int
	if err := ps.DB().WithTenant(ctx, "globex", false, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM iris_query_log WHERE tenant_id = 'acme'`).Scan(&n)
	}); err != nil || n != 0 {
		t.Fatalf("RLS LEAK: globex's session counts %d acme records (%v)", n, err)
	}
	// WITH CHECK forge: a row claiming another tenant is refused by policy.
	forgeErr := ps.DB().WithTenant(ctx, "acme", false, func(tx pgx.Tx) error {
		_, execErr := tx.Exec(ctx, `INSERT INTO iris_query_log (tenant_id, id, principal_sub, source, outcome)
		    VALUES ('globex', gen_random_uuid(), 'mallory', 'router', 'answered')`)
		return execErr
	})
	var pgErr *pgconn.PgError
	if !errors.As(forgeErr, &pgErr) || pgErr.Code != "42501" {
		t.Fatalf("WITH CHECK must refuse a forged tenant, got %v", forgeErr)
	}
}

// Migration 0055 (tracker 337 N-C5): the validated query and its author
// round-trip, Get is tenant- and principal-scoped under RLS, and a stored
// query that does not decode strictly — or has no known author — is refused
// on read rather than trusted.
func TestIrisQueryLogGetAndStoredQueryPG(t *testing.T) {
	ps, st := qlogPGStore(t)
	ctx := context.Background()
	q := &ast.AST{V: 1, Type: ast.MetricSeries, Target: "device", Metric: "cpu_util_pct",
		Refs: []ast.EntityRef{{Type: "device", ID: "device:edge-1"}}, Time: ast.TimeRange{Kind: ast.TimeRelative, Last: "1h"}}
	rec, err := st.Record(ctx, "acme", irisquerylog.Record{Principal: "alice", Source: irisquerylog.SourceQueryCompile,
		Outcome: irisquerylog.OutcomeCompiled, Question: "cpu on edge-1", Query: q, CompiledBy: irisquerylog.CompiledByModel})
	if err != nil {
		t.Fatal(err)
	}
	plain, err := st.Record(ctx, "acme", irisquerylog.Record{Principal: "alice", Source: irisquerylog.SourceRouter,
		Outcome: irisquerylog.OutcomeUnparsed, Question: "huh"})
	if err != nil {
		t.Fatal(err)
	}

	got, err := st.Get(ctx, "acme", "alice", rec.ID)
	if err != nil || got.Query == nil || got.Query.Hash() != q.Hash() || got.CompiledBy != irisquerylog.CompiledByModel ||
		got.ASTHash != q.Hash() || got.Question != "cpu on edge-1" {
		t.Fatalf("own get: %v %+v", err, got)
	}
	if got, err := st.Get(ctx, "acme", "alice", plain.ID); err != nil || got.Query != nil || got.CompiledBy != "" {
		t.Fatalf("a record without a query reads back without one: %v %+v", err, got)
	}
	if _, err := st.Get(ctx, "acme", "", rec.ID); err != nil {
		t.Fatalf("tenant-wide get: %v", err)
	}
	for _, who := range [][2]string{{"globex", "alice"}, {"globex", ""}, {"acme", "carol"}} {
		if _, err := st.Get(ctx, who[0], who[1], rec.ID); !errors.Is(err, irisquerylog.ErrNotFound) {
			t.Fatalf("RLS/principal LEAK: %v read alice's record (%v)", who, err)
		}
	}
	if _, err := st.Get(ctx, "acme", "alice", "11111111-2222-4333-8444-555555555555"); !errors.Is(err, irisquerylog.ErrNotFound) {
		t.Fatalf("unknown id: %v", err)
	}
	if _, err := st.Get(ctx, "acme", "alice", "x' OR 1=1"); !errors.Is(err, irisquerylog.ErrNotFound) {
		t.Fatalf("malformed id: %v", err)
	}
	// The list carries the query too (the handler strips it from the summary).
	mine, err := st.List(ctx, "acme", irisquerylog.ListFilter{Principal: "alice"})
	if err != nil || len(mine) != 2 {
		t.Fatalf("list: %v %+v", err, mine)
	}

	// Tampered rows are refused on read, never trusted.
	for name, set := range map[string]string{
		"smuggled tenant in the query": `query = '{"v":1,"query_type":"change_list","target":"change","time_range":{"kind":"relative","last":"1h"},"tenant":"globex"}'::jsonb`,
		"query without a known author": `compiled_by = 'llm'`,
	} {
		if err := ps.DB().WithTenant(ctx, "acme", false, func(tx pgx.Tx) error {
			_, execErr := tx.Exec(ctx, `UPDATE iris_query_log SET `+set+` WHERE tenant_id = 'acme' AND id = $1::uuid`, rec.ID)
			return execErr
		}); err != nil {
			t.Fatal(err)
		}
		if _, err := st.Get(ctx, "acme", "alice", rec.ID); err == nil || errors.Is(err, irisquerylog.ErrNotFound) {
			t.Errorf("%s: a tampered row must be an error on read, got %v", name, err)
		}
		// Restore for the next case.
		enc, err := q.Canonical()
		if err != nil {
			t.Fatal(err)
		}
		if err := ps.DB().WithTenant(ctx, "acme", false, func(tx pgx.Tx) error {
			_, execErr := tx.Exec(ctx, `UPDATE iris_query_log SET query = $2::jsonb, compiled_by = 'model' WHERE tenant_id = 'acme' AND id = $1::uuid`, rec.ID, string(enc))
			return execErr
		}); err != nil {
			t.Fatal(err)
		}
	}
}

func TestIrisQueryLogBoundsPG(t *testing.T) {
	_, st := qlogPGStore(t)
	ctx := context.Background()
	rec, err := st.Record(ctx, "acme", irisquerylog.Record{Principal: "alice", Source: irisquerylog.SourceRouter, Outcome: irisquerylog.OutcomeAnswered, Question: "q"})
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	var mu sync.Mutex
	ok, full := 0, 0
	for i := 0; i < irisquerylog.MaxCorrections+5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := st.Correct(ctx, "acme", "alice", rec.ID, irisquerylog.Correction{Kind: irisquerylog.KindWrongWindow, By: "alice"})
			mu.Lock()
			defer mu.Unlock()
			switch {
			case err == nil:
				ok++
			case errors.Is(err, irisquerylog.ErrFull):
				full++
			default:
				t.Errorf("correct: %v", err)
			}
		}()
	}
	wg.Wait()
	if ok != irisquerylog.MaxCorrections || full != 5 {
		t.Fatalf("row lock must serialize the cap: %d stored, %d refused", ok, full)
	}

	// Retention: a record older than the window is pruned by the next write.
	old := irisquerylog.Record{Principal: "alice", Source: irisquerylog.SourceRouter, Outcome: irisquerylog.OutcomeAnswered,
		Question: "ancient", At: time.Now().UTC().Add(-irisquerylog.Retention - time.Hour)}
	if _, err := st.Record(ctx, "acme", old); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Record(ctx, "acme", irisquerylog.Record{Principal: "alice", Source: irisquerylog.SourceRouter, Outcome: irisquerylog.OutcomeAnswered, Question: "fresh"}); err != nil {
		t.Fatal(err)
	}
	all, err := st.List(ctx, "acme", irisquerylog.ListFilter{Limit: irisquerylog.MaxListLimit})
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range all {
		if r.Question == "ancient" {
			t.Fatal("an expired record survived a write")
		}
	}
}
