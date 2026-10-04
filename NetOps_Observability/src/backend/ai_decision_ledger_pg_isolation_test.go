// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// ai_decision_ledger_pg_isolation_test.go — storage-layer proof for
// ai_decision_ledger (migration 0056, tracker 337 N-A6): the FORCE-RLS
// tenant_iso policy confines reads and writes to the tenant (a forged tenant
// is refused by WITH CHECK), the platform owner's '*' scope reads every
// tenant, the ledger is APPEND-ONLY in the database itself — the application
// role holds no UPDATE/DELETE/TRUNCATE grant and a trigger refuses all three
// even for a superuser — the closed vocabulary and hash shape are CHECKed, a
// decision is appended all-or-nothing, and an /api/ai/ask answered over the
// Postgres store is readable by its own tenant's admin only. Gated on
// DATABASE_URL_TEST like every pg-integration test in this package.

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"netops/backend/internal/aidecision"
	"netops/backend/internal/platformdb"
)

func ledgerPGStore(t *testing.T) (string, *platformdb.PGStore, *aidecision.PGStore) {
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

// ledgerDecision is one short, valid decision for principal.
func ledgerDecision(t *testing.T, principal string) []aidecision.Entry {
	t.Helper()
	id, err := aidecision.NewID()
	if err != nil {
		t.Fatal(err)
	}
	h := aidecision.SHA256Hex([]byte(principal))
	return []aidecision.Entry{
		{DecisionID: id, Seq: 0, EventType: aidecision.QuestionReceived, Principal: principal, Surface: aidecision.SurfaceAsk, ArgsSHA256: h},
		{DecisionID: id, Seq: 1, EventType: aidecision.ToolExecuted, Principal: principal, Surface: aidecision.SurfaceAsk,
			Tool: "nl_query", ToolVersion: "catalog:v1", ArgsSHA256: h, ResultSHA256: h, ItemCount: 2, Outcome: "ok"},
		{DecisionID: id, Seq: 2, EventType: aidecision.AnswerReturned, Principal: principal, Surface: aidecision.SurfaceAsk,
			Mode: "data_query", ModelProvider: "anthropic", ModelName: "m-1", ModelTier: "strong", ResultSHA256: h,
			Outcome: "answered", AnswerID: "a-1", QueryLogID: "q-1"},
	}
}

func pgCode(err error) string {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		return pgErr.Code
	}
	return ""
}

func TestAIDecisionLedgerRLSIsolationPG(t *testing.T) {
	_, ps, st := ledgerPGStore(t)
	ctx := context.Background()
	a, b := ledgerDecision(t, "alice"), ledgerDecision(t, "bob")
	if err := st.Append(ctx, "acme", a); err != nil {
		t.Fatal(err)
	}
	if err := st.Append(ctx, "globex", b); err != nil {
		t.Fatal(err)
	}

	// Own decision, round trip, seq order.
	got, err := st.List(ctx, "acme", false, aidecision.ListFilter{DecisionID: a[0].DecisionID})
	if err != nil || len(got) != 3 {
		t.Fatalf("own decision: %v %+v", err, got)
	}
	for i, e := range got {
		if e.Seq != i || e.TenantID != "acme" || e.Principal != "alice" {
			t.Fatalf("entry %d: %+v", i, e)
		}
	}
	if fin := got[2]; fin.ModelName != "m-1" || fin.ModelTier != "strong" || fin.AnswerID != "a-1" || fin.QueryLogID != "q-1" ||
		fin.Mode != "data_query" || fin.ResultSHA256 != a[2].ResultSHA256 {
		t.Fatalf("ANSWER_RETURNED round trip: %+v", fin)
	}
	if run := got[1]; run.Tool != "nl_query" || run.ToolVersion != "catalog:v1" || run.ItemCount != 2 || run.ArgsSHA256 != a[1].ArgsSHA256 {
		t.Fatalf("TOOL_EXECUTED round trip: %+v", run)
	}

	// Own-only list; another tenant's decision by id is simply absent.
	all, err := st.List(ctx, "acme", false, aidecision.ListFilter{Limit: aidecision.MaxListLimit})
	if err != nil || len(all) != 3 {
		t.Fatalf("tenant list: %v %+v", err, all)
	}
	for _, e := range all {
		if e.TenantID != "acme" {
			t.Fatalf("RLS LEAK: acme lists %+v", e)
		}
	}
	if other, err := st.List(ctx, "acme", false, aidecision.ListFilter{DecisionID: b[0].DecisionID}); err != nil || len(other) != 0 {
		t.Fatalf("RLS LEAK: acme read globex's decision: %v %+v", err, other)
	}

	// The platform owner's '*' scope reads both tenants.
	every, err := st.List(ctx, "*", true, aidecision.ListFilter{Limit: aidecision.MaxListLimit})
	if err != nil || len(every) != 6 {
		t.Fatalf("platform view: %v %d entries", err, len(every))
	}

	// Underneath the store: under globex's RLS session acme's rows do not exist.
	var n int
	if err := ps.DB().WithTenant(ctx, "globex", false, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM ai_decision_ledger WHERE tenant_id = 'acme'`).Scan(&n)
	}); err != nil || n != 0 {
		t.Fatalf("RLS LEAK: globex's session counts %d acme entries (%v)", n, err)
	}
	// WITH CHECK forge: a row claiming another tenant is refused by policy.
	forgeErr := ps.DB().WithTenant(ctx, "acme", false, func(tx pgx.Tx) error {
		_, execErr := tx.Exec(ctx, `INSERT INTO ai_decision_ledger (tenant_id, id, decision_id, seq, event_type, principal_sub, surface)
		    VALUES ('globex', gen_random_uuid(), gen_random_uuid(), 0, 'QUESTION_RECEIVED', 'mallory', 'ask')`)
		return execErr
	})
	if pgCode(forgeErr) != "42501" {
		t.Fatalf("WITH CHECK must refuse a forged tenant, got %v", forgeErr)
	}
	// The store itself never writes outside the caller's tenant: a stamped
	// TenantID on the entry is overwritten by the scope.
	forged := ledgerDecision(t, "mallory")
	for i := range forged {
		forged[i].TenantID = "globex"
	}
	if err := st.Append(ctx, "acme", forged); err != nil {
		t.Fatal(err)
	}
	if mine, _ := st.List(ctx, "globex", false, aidecision.ListFilter{DecisionID: forged[0].DecisionID}); len(mine) != 0 {
		t.Fatalf("a caller-stamped tenant reached globex: %+v", mine)
	}
}

func TestAIDecisionLedgerIsAppendOnlyPG(t *testing.T) {
	adminDSN, ps, st := ledgerPGStore(t)
	ctx := context.Background()
	d := ledgerDecision(t, "alice")
	if err := st.Append(ctx, "acme", d); err != nil {
		t.Fatal(err)
	}

	// The application role: INSERT and SELECT, nothing that rewrites.
	if err := ps.DB().WithTenant(ctx, "acme", false, func(tx pgx.Tx) error {
		for priv, want := range map[string]bool{"INSERT": true, "SELECT": true, "UPDATE": false, "DELETE": false, "TRUNCATE": false} {
			var has bool
			if err := tx.QueryRow(ctx, `SELECT has_table_privilege(current_user, 'ai_decision_ledger', $1)`, priv).Scan(&has); err != nil {
				return err
			}
			if has != want {
				t.Errorf("app role %s privilege = %v, want %v", priv, has, want)
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	for _, stmt := range []string{
		`UPDATE ai_decision_ledger SET outcome = 'rewritten'`,
		`DELETE FROM ai_decision_ledger`,
		`TRUNCATE ai_decision_ledger`,
	} {
		err := ps.DB().WithTenant(ctx, "acme", false, func(tx pgx.Tx) error {
			_, execErr := tx.Exec(ctx, stmt)
			return execErr
		})
		if pgCode(err) != "42501" {
			t.Errorf("app role %q must be refused (42501), got %v", stmt, err)
		}
	}

	// A superuser holds every grant; the trigger still refuses.
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
		_, err := admin.Exec(ctx, stmt)
		if pgCode(err) != "42501" || !strings.Contains(err.Error(), "append-only") {
			t.Errorf("superuser %q must be refused by the trigger, got %v", stmt, err)
		}
	}

	// Nothing changed.
	got, err := st.List(ctx, "acme", false, aidecision.ListFilter{DecisionID: d[0].DecisionID})
	if err != nil || len(got) != 3 {
		t.Fatalf("after refused rewrites: %v %+v", err, got)
	}
	for _, e := range got {
		if e.Outcome == "rewritten" {
			t.Fatalf("an entry was rewritten: %+v", e)
		}
	}
}

func TestAIDecisionLedgerConstraintsAndAtomicityPG(t *testing.T) {
	_, ps, st := ledgerPGStore(t)
	ctx := context.Background()

	// The database CHECKs the vocabulary and the hash shape — a writer that
	// bypasses the store cannot invent an event or store a value as a "hash".
	for name, stmt := range map[string]string{
		"event type": `INSERT INTO ai_decision_ledger (tenant_id, id, decision_id, seq, event_type, principal_sub, surface)
		    VALUES ('acme', gen_random_uuid(), gen_random_uuid(), 0, 'TOOL_DELETED', 'u', 'ask')`,
		"args hash": `INSERT INTO ai_decision_ledger (tenant_id, id, decision_id, seq, event_type, principal_sub, surface, args_sha256)
		    VALUES ('acme', gen_random_uuid(), gen_random_uuid(), 0, 'TOOL_EXECUTED', 'u', 'ask', 'show cpu on edge-a')`,
		"result hash": `INSERT INTO ai_decision_ledger (tenant_id, id, decision_id, seq, event_type, principal_sub, surface, result_sha256)
		    VALUES ('acme', gen_random_uuid(), gen_random_uuid(), 0, 'TOOL_EXECUTED', 'u', 'ask', 'ABCDEF')`,
		"negative seq": `INSERT INTO ai_decision_ledger (tenant_id, id, decision_id, seq, event_type, principal_sub, surface)
		    VALUES ('acme', gen_random_uuid(), gen_random_uuid(), -1, 'TOOL_EXECUTED', 'u', 'ask')`,
	} {
		err := ps.DB().WithTenant(ctx, "acme", false, func(tx pgx.Tx) error {
			_, execErr := tx.Exec(ctx, stmt)
			return execErr
		})
		if pgCode(err) != "23514" {
			t.Errorf("%s: want CHECK violation 23514, got %v", name, err)
		}
	}

	// All-or-nothing: a decision whose last entry collides with an existing
	// entry id is refused whole — no partial decision is left behind.
	first := ledgerDecision(t, "alice")
	first[0].ID = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
	if err := st.Append(ctx, "acme", first); err != nil {
		t.Fatal(err)
	}
	second := ledgerDecision(t, "alice")
	second[2].ID = first[0].ID
	if err := st.Append(ctx, "acme", second); err == nil {
		t.Fatal("a colliding entry id must refuse the append")
	}
	if got, err := st.List(ctx, "acme", false, aidecision.ListFilter{DecisionID: second[0].DecisionID}); err != nil || len(got) != 0 {
		t.Fatalf("a refused decision left %d entries behind (%v)", len(got), err)
	}

	// The keyset cursor pages strictly older entries.
	old := ledgerDecision(t, "alice")
	at := time.Now().UTC().Add(-time.Hour)
	for i := range old {
		old[i].At = at
	}
	if err := st.Append(ctx, "acme", old); err != nil {
		t.Fatal(err)
	}
	page, err := st.List(ctx, "acme", false, aidecision.ListFilter{Before: at.Add(time.Second), Limit: aidecision.MaxListLimit})
	if err != nil || len(page) != 3 || page[0].DecisionID != old[0].DecisionID {
		t.Fatalf("before cursor: %v %+v", err, page)
	}
}

// The handler over the Postgres store: an /api/ai/ask is ledgered in the
// asker's tenant, its admin reads it, the other tenant's admin cannot — by
// list, by id, or by an as_tenant walk.
func TestAIDecisionLedgerAskOverPGIsolation(t *testing.T) {
	_, _, st := ledgerPGStore(t)
	s, a, b := ledgerFixture(t)
	s.aiDecisions = st
	idA, _ := askIris(t, s, a, "show cpu on edge-a for the last hour")["decision_id"].(string) // absence fails ValidID below
	if !aidecision.ValidID(idA) {
		t.Fatal("the answer must name a decision stored in Postgres")
	}
	es := ledgerEntries(t, s, a, "?decision_id="+idA)
	if len(es) < 4 || es[0]["event_type"] != aidecision.QuestionReceived || es[len(es)-1]["event_type"] != aidecision.AnswerReturned {
		t.Fatalf("the PG decision: %v", es)
	}
	if got := ledgerEntries(t, s, b, "?decision_id="+idA); len(got) != 0 {
		t.Fatalf("CROSS-TENANT LEAK over PG by id: %v", got)
	}
	walker := b
	walker.ActingTenant = a.Tenant
	for _, e := range ledgerEntries(t, s, walker, "?as_tenant="+a.Tenant) {
		if e["decision_id"] == idA {
			t.Fatalf("CROSS-TENANT LEAK over PG: as_tenant walk listed %v", e)
		}
	}
}
