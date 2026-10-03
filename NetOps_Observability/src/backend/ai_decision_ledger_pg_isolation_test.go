// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// ai_decision_ledger_pg_isolation_test.go — storage-layer proof for
// ai_decision_ledger (migration 0055, tracker 337 N-A6): the FORCE-RLS
// tenant_iso policy confines every statement to the tenant (own-only list,
// another tenant's decision id lists nothing, a forged tenant is refused by
// WITH CHECK, only '*' reads across tenants); the table is APPEND-ONLY for the
// application role (no UPDATE/DELETE/TRUNCATE privilege) AND for a superuser
// (the trigger); and the closed event vocabulary and the hash shape are
// enforced by the database, not only by the store. Gated on DATABASE_URL_TEST
// like every pg-integration test in this package.

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"netops/backend/internal/aidecision"
	"netops/backend/internal/platformdb"
)

func decisionPGStore(t *testing.T) (string, *platformdb.PGStore, *aidecision.PGStore) {
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
	return adminDSN, ps, aidecision.NewPGStore(ps.DB())
}

// decisionPGEntries builds one decision of n entries for principal.
func decisionPGEntries(t *testing.T, principal string, n int) []aidecision.Entry {
	t.Helper()
	rec, err := aidecision.NewRecorder(principal, aidecision.SurfaceAsk)
	if err != nil {
		t.Fatal(err)
	}
	h := aidecision.SHA256Hex([]byte(principal))
	rec.Add(aidecision.Entry{EventType: aidecision.QuestionReceived, ArgsSHA256: h})
	for i := 1; i < n-1; i++ {
		rec.Add(aidecision.Entry{EventType: aidecision.ToolExecuted, Tool: "nl_query", ToolVersion: "v1+abc",
			ArgsSHA256: h, ResultSHA256: h, ItemCount: i, Outcome: "ok"})
	}
	rec.Add(aidecision.Entry{EventType: aidecision.AnswerReturned, ModelProvider: "anthropic", ModelName: "m-1",
		ModelTier: "standard", ResultSHA256: h, AnswerID: "ans-1", Outcome: "answered"})
	return rec.Entries()
}

// wantPGCode asserts err is a Postgres error with the given SQLSTATE.
func wantPGCode(t *testing.T, what string, err error, code string) {
	t.Helper()
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != code {
		t.Fatalf("%s: want SQLSTATE %s, got %v", what, code, err)
	}
}

func TestAIDecisionLedgerRLSIsolationPG(t *testing.T) {
	_, ps, st := decisionPGStore(t)
	ctx := context.Background()
	acme := decisionPGEntries(t, "alice", 4)
	globex := decisionPGEntries(t, "gina", 3)
	if err := st.Append(ctx, "acme", acme); err != nil {
		t.Fatal(err)
	}
	if err := st.Append(ctx, "globex", globex); err != nil {
		t.Fatal(err)
	}

	// Own-only list.
	mine, err := st.List(ctx, "acme", false, aidecision.ListFilter{})
	if err != nil || len(mine) != len(acme) {
		t.Fatalf("own list: %v %+v", err, mine)
	}
	for _, e := range mine {
		if e.TenantID != "acme" || e.DecisionID != acme[0].DecisionID {
			t.Fatalf("CROSS-TENANT LEAK: acme lists %+v", e)
		}
	}
	// One decision, in seq order, round-tripped field for field.
	one, err := st.List(ctx, "acme", false, aidecision.ListFilter{DecisionID: acme[0].DecisionID})
	if err != nil || len(one) != len(acme) {
		t.Fatalf("decision read: %v %+v", err, one)
	}
	for i, e := range one {
		if e.Seq != i || e.EventType != acme[i].EventType || e.ArgsSHA256 != acme[i].ArgsSHA256 || e.Principal != "alice" {
			t.Fatalf("entry %d round trip: %+v", i, e)
		}
	}
	last := one[len(one)-1]
	if last.ModelProvider != "anthropic" || last.ModelName != "m-1" || last.ModelTier != "standard" || last.AnswerID != "ans-1" {
		t.Fatalf("ANSWER_RETURNED round trip: %+v", last)
	}
	// Another tenant's decision id, by id: nothing.
	if got, err := st.List(ctx, "acme", false, aidecision.ListFilter{DecisionID: globex[0].DecisionID}); err != nil || len(got) != 0 {
		t.Fatalf("CROSS-TENANT LEAK: acme read globex's decision: %v %+v", err, got)
	}
	// The platform owner ('*') reads both.
	all, err := st.List(ctx, "*", true, aidecision.ListFilter{Limit: aidecision.MaxListLimit})
	if err != nil || len(all) != len(acme)+len(globex) {
		t.Fatalf("platform read: %v %d rows", err, len(all))
	}

	// Underneath the store: under globex's RLS session acme's rows do not exist.
	var n int
	if err := ps.DB().WithTenant(ctx, "globex", false, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM ai_decision_ledger WHERE tenant_id = 'acme'`).Scan(&n)
	}); err != nil || n != 0 {
		t.Fatalf("RLS LEAK: globex's session counts %d acme entries (%v)", n, err)
	}
	// The store refuses to write a forged tenant (Append always writes in the
	// caller's scope) — and the policy refuses it underneath the store too.
	forgeErr := ps.DB().WithTenant(ctx, "acme", false, func(tx pgx.Tx) error {
		_, execErr := tx.Exec(ctx, `INSERT INTO ai_decision_ledger (tenant_id, id, decision_id, seq, event_type, principal_sub, surface)
		    VALUES ('globex', gen_random_uuid(), gen_random_uuid(), 0, 'QUESTION_RECEIVED', 'mallory', 'ask')`)
		return execErr
	})
	wantPGCode(t, "WITH CHECK on a forged tenant", forgeErr, "42501")
}

func TestAIDecisionLedgerIsAppendOnlyPG(t *testing.T) {
	adminDSN, ps, st := decisionPGStore(t)
	ctx := context.Background()
	es := decisionPGEntries(t, "alice", 3)
	if err := st.Append(ctx, "acme", es); err != nil {
		t.Fatal(err)
	}

	// (1) The application role holds no rewrite privilege at all.
	for _, priv := range []string{"UPDATE", "DELETE", "TRUNCATE"} {
		var has bool
		if err := ps.DB().WithTenant(ctx, "acme", false, func(tx pgx.Tx) error {
			return tx.QueryRow(ctx, `SELECT has_table_privilege(current_user, 'ai_decision_ledger', $1)`, priv).Scan(&has)
		}); err != nil {
			t.Fatal(err)
		}
		if has {
			t.Errorf("the application role holds %s on ai_decision_ledger — the migration must revoke it", priv)
		}
	}
	// … so every rewrite from the application is refused (each in its own
	// transaction: a refused statement aborts the one it ran in).
	for _, stmt := range []string{
		`UPDATE ai_decision_ledger SET outcome = 'rewritten'`,
		`DELETE FROM ai_decision_ledger`,
		`TRUNCATE ai_decision_ledger`,
	} {
		err := ps.DB().WithTenant(ctx, "acme", false, func(tx pgx.Tx) error {
			_, execErr := tx.Exec(ctx, stmt)
			return execErr
		})
		wantPGCode(t, "app role: "+stmt, err, "42501")
	}

	// (2) A superuser bypasses grants and RLS — the trigger still refuses.
	admin, err := pgx.Connect(ctx, adminDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if cerr := admin.Close(ctx); cerr != nil {
			t.Logf("admin close: %v", cerr)
		}
	}()
	for _, stmt := range []string{
		`UPDATE ai_decision_ledger SET outcome = 'rewritten'`,
		`DELETE FROM ai_decision_ledger`,
		`TRUNCATE ai_decision_ledger`,
	} {
		_, execErr := admin.Exec(ctx, stmt)
		wantPGCode(t, "superuser: "+stmt, execErr, "42501")
	}

	// (3) The closed vocabulary and the hash shape hold below the store.
	for what, stmt := range map[string]string{
		"invented event type": `INSERT INTO ai_decision_ledger (tenant_id, id, decision_id, seq, event_type, principal_sub, surface)
		    VALUES ('acme', gen_random_uuid(), gen_random_uuid(), 0, 'MADE_UP', 'alice', 'ask')`,
		"raw value as a hash": `INSERT INTO ai_decision_ledger (tenant_id, id, decision_id, seq, event_type, principal_sub, surface, args_sha256)
		    VALUES ('acme', gen_random_uuid(), gen_random_uuid(), 0, 'TOOL_EXECUTED', 'alice', 'ask', 'device=edge-1')`,
	} {
		err := ps.DB().WithTenant(ctx, "acme", false, func(tx pgx.Tx) error {
			_, execErr := tx.Exec(ctx, stmt)
			return execErr
		})
		wantPGCode(t, what, err, "23514")
	}

	// Nothing above changed a row.
	got, err := st.List(ctx, "acme", false, aidecision.ListFilter{DecisionID: es[0].DecisionID})
	if err != nil || len(got) != len(es) {
		t.Fatalf("the ledger changed under refused rewrites: %v %+v", err, got)
	}
	for _, e := range got {
		if e.Outcome == "rewritten" {
			t.Fatalf("an entry was rewritten: %+v", e)
		}
	}
}
