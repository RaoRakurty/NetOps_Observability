// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// iris_convo_pg_isolation_test.go — storage-layer proof for iris_conversations
// (migration 0053, tracker 337 N-C7): the FORCE-RLS tenant_iso policy confines
// every statement to the tenant, the store's owner filter confines it to the
// person, the state round-trips as structured references, and the turn cap
// holds under concurrent turns. Gated on DATABASE_URL_TEST like every
// pg-integration test in this package.

import (
	"context"
	"errors"
	"os"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"netops/backend/internal/irisconvo"
	"netops/backend/internal/nlquery/ast"
	"netops/backend/internal/platformdb"
)

func TestIrisConversationsRLSIsolationPG(t *testing.T) {
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
	st := irisconvo.NewPGStore(ps.DB())

	c, err := st.Create(ctx, "acme", "alice")
	if err != nil {
		t.Fatal(err)
	}
	state := irisconvo.State{
		LastAST:   &ast.AST{V: 1, Type: ast.ChangeList, Target: "change"},
		Entities:  []ast.EntityRef{{Type: "device", ID: "device:edge-1"}},
		Actors:    []string{"bob"},
		ChangeIDs: []string{"chg-1"},
	}
	if _, err := st.Append(ctx, "acme", "alice", c.ID, irisconvo.Turn{Question: "what changed today", Outcome: irisconvo.OutcomeAnswered, Rows: 1}, state); err != nil {
		t.Fatal(err)
	}

	got, err := st.Get(ctx, "acme", "alice", c.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Turns) != 1 || got.Turns[0].Question != "what changed today" || got.State.LastAST == nil ||
		got.State.LastAST.Type != ast.ChangeList || len(got.State.Entities) != 1 || got.State.Actors[0] != "bob" {
		t.Fatalf("round trip: %+v", got)
	}

	// Another tenant, a colleague in the same tenant: the same not-found.
	for _, who := range [][2]string{{"globex", "alice"}, {"acme", "carol"}} {
		if _, err := st.Get(ctx, who[0], who[1], c.ID); !errors.Is(err, irisconvo.ErrNotFound) {
			t.Fatalf("RLS/owner LEAK: %v read the conversation (%v)", who, err)
		}
		if _, err := st.Append(ctx, who[0], who[1], c.ID, irisconvo.Turn{Question: "x", Outcome: irisconvo.OutcomeUnparsed}, irisconvo.State{}); !errors.Is(err, irisconvo.ErrNotFound) {
			t.Fatalf("RLS/owner LEAK: %v extended the conversation (%v)", who, err)
		}
	}

	// Underneath the store: under globex's RLS session the row does not exist.
	var n int
	if err := ps.DB().WithTenant(ctx, "globex", false, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM iris_conversations`).Scan(&n)
	}); err != nil || n != 0 {
		t.Fatalf("RLS LEAK: globex's session counts %d conversations (%v)", n, err)
	}

	// WITH CHECK forge: a row claiming another tenant is refused by policy.
	forgeErr := ps.DB().WithTenant(ctx, "acme", false, func(tx pgx.Tx) error {
		_, execErr := tx.Exec(ctx, `INSERT INTO iris_conversations (tenant_id, id, owner_sub)
		    VALUES ('globex', gen_random_uuid(), 'mallory')`)
		return execErr
	})
	var pgErr *pgconn.PgError
	if !errors.As(forgeErr, &pgErr) || pgErr.Code != "42501" {
		t.Fatalf("WITH CHECK must refuse a forged tenant, got %v", forgeErr)
	}
}

func TestIrisConversationsTurnCapUnderConcurrencyPG(t *testing.T) {
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
	st := irisconvo.NewPGStore(ps.DB())
	c, err := st.Create(ctx, "acme", "alice")
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	var mu sync.Mutex
	ok, full := 0, 0
	for i := 0; i < irisconvo.MaxTurns+10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := st.Append(ctx, "acme", "alice", c.ID, irisconvo.Turn{Question: "q", Outcome: irisconvo.OutcomeUnparsed}, irisconvo.State{})
			mu.Lock()
			defer mu.Unlock()
			switch {
			case err == nil:
				ok++
			case errors.Is(err, irisconvo.ErrFull):
				full++
			default:
				t.Errorf("append: %v", err)
			}
		}()
	}
	wg.Wait()
	if ok != irisconvo.MaxTurns || full != 10 {
		t.Fatalf("row lock must serialize the cap: %d appended, %d refused", ok, full)
	}
}
