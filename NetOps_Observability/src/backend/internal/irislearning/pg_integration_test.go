// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

//go:build pgintegration

package irislearning

// pg_integration_test.go — storage-layer proof for migration 0073, against a real
// PostgreSQL as a NOBYPASSRLS role: FORCE-RLS confines every statement to the
// tenant; the DATABASE refuses an alias applied by the person who adopted it and
// a dismissal without a reason even when the application is bypassed; a proposal
// round-trips; a refresh is idempotent and keeps a decided proposal as decided;
// the open-proposal cap holds.

import (
	"context"
	"errors"
	"net/url"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"netops/backend/internal/platformdb"
)

// provisionAppRole is the root package's helper of the same name: tests there are
// not importable from here. It leaves a clean schema and a non-superuser DSN.
func provisionAppRole(ctx context.Context, t *testing.T, adminDSN string) string {
	t.Helper()
	admin, err := pgx.Connect(ctx, adminDSN)
	if err != nil {
		t.Fatalf("admin connect: %v", err)
	}
	defer func() {
		if err := admin.Close(ctx); err != nil {
			t.Logf("admin close: %v", err)
		}
	}()
	const role, pass = "netops_app_test", "apppw"
	for _, s := range []string{
		"SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = current_database() AND pid <> pg_backend_pid()",
		"DO $do$ BEGIN IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '" + role + "') THEN EXECUTE 'DROP OWNED BY " + role + "'; END IF; END $do$",
		"DROP SCHEMA IF EXISTS public CASCADE",
		"CREATE SCHEMA public",
		"GRANT USAGE, CREATE ON SCHEMA public TO PUBLIC",
		"DROP ROLE IF EXISTS " + role,
		"CREATE ROLE " + role + " LOGIN PASSWORD '" + pass + "' NOSUPERUSER",
		"GRANT ALL ON SCHEMA public TO " + role,
	} {
		if _, err := admin.Exec(ctx, s); err != nil {
			t.Fatalf("provision (%s): %v", s, err)
		}
	}
	u, err := url.Parse(adminDSN)
	if err != nil {
		t.Fatalf("parse adminDSN: %v", err)
	}
	u.User = url.UserPassword(role, pass)
	return u.String()
}

func pgFixture(t *testing.T) (*platformdb.PGStore, *PGStore) {
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
	return ps, NewPGStore(ps.DB())
}

func pgCode(err error) string {
	var pe *pgconn.PgError
	if errors.As(err, &pe) {
		return pe.Code
	}
	return ""
}

var pgNow = time.Date(2026, 11, 14, 12, 0, 0, 0, time.UTC)

func offered(t *testing.T, st *PGStore, tenant string) []Proposal {
	t.Helper()
	ctx := context.Background()
	if _, _, err := st.Offer(ctx, tenant, Generate(labInputs()), pgNow); err != nil {
		t.Fatal(err)
	}
	ps, err := st.List(ctx, tenant)
	if err != nil {
		t.Fatal(err)
	}
	return ps
}

func TestLearningRoundTripAndIdempotentRefreshPG(t *testing.T) {
	_, st := pgFixture(t)
	ctx := context.Background()
	ps := offered(t, st, "acme")
	if len(ps) != 3 {
		t.Fatalf("stored %d proposals, want 3", len(ps))
	}
	for _, want := range Generate(labInputs()) {
		got, ok := find(ps, want.Generator, want.Subject)
		if !ok {
			t.Fatalf("missing %s", want.Subject)
		}
		if !reflect.DeepEqual(got.Context, want.Context) || !reflect.DeepEqual(got.Alias, want.Alias) ||
			!reflect.DeepEqual(got.Runbook, want.Runbook) || got.EvidenceCount != want.EvidenceCount || len(got.Evidence) != len(want.Evidence) {
			t.Fatalf("%s did not round-trip:\n got %+v\nwant %+v", want.Subject, got, want)
		}
	}
	p, _ := find(ps, GenMissCluster, "")
	if _, err := Dismiss(ctx, st, "acme", "u-bob", p.ID, "documented elsewhere", pgNow); err != nil {
		t.Fatal(err)
	}
	added, refreshed, err := st.Offer(ctx, "acme", Generate(labInputs()), pgNow.Add(time.Hour))
	if err != nil || added != 0 || refreshed != 0 {
		t.Fatalf("second refresh: added=%d refreshed=%d err=%v", added, refreshed, err)
	}
	got, err := st.Get(ctx, "acme", p.ID)
	if err != nil || got.State != StateDismissed || got.Reason != "documented elsewhere" {
		t.Fatalf("after refresh: %+v %v", got, err)
	}
}

func TestLearningRLSIsolationPG(t *testing.T) {
	ps, st := pgFixture(t)
	ctx := context.Background()
	p := offered(t, st, "acme")[0]
	if _, err := st.Get(ctx, "globex", p.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("RLS LEAK: globex read acme's proposal (%v)", err)
	}
	if _, err := st.Update(ctx, "globex", p.ID, func(cur *Proposal) error { cur.Title = "hijacked"; return nil }); !errors.Is(err, ErrNotFound) {
		t.Fatalf("RLS LEAK: globex updated acme's proposal (%v)", err)
	}
	if got, err := st.List(ctx, "globex"); err != nil || len(got) != 0 {
		t.Fatalf("RLS LEAK: globex listed %d proposals (%v)", len(got), err)
	}
	// Even an unfiltered statement sees nothing of another tenant.
	err := ps.DB().WithTenant(ctx, "globex", false, func(tx pgx.Tx) error {
		var n int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM iris_learning_proposals`).Scan(&n); err != nil {
			return err
		}
		if n != 0 {
			t.Fatalf("RLS LEAK: an unfiltered SELECT as globex saw %d rows", n)
		}
		_, err := tx.Exec(ctx, `UPDATE iris_learning_proposals SET title = 'x'`)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := st.Get(ctx, "acme", p.ID); got.Title == "x" {
		t.Fatal("RLS LEAK: an unfiltered UPDATE as globex changed acme's proposal")
	}
}

func TestLearningDatabaseRefusesWhatTheCodeWouldNotDoPG(t *testing.T) {
	_, st := pgFixture(t)
	ctx := context.Background()
	ps := offered(t, st, "acme")
	alias, _ := find(ps, GenEntityCorrection, "dallas")
	_, err := st.Update(ctx, "acme", alias.ID, func(cur *Proposal) error {
		cur.State, cur.AdoptedBy, cur.DecidedBy = StateApplied, "u-alice", "u-alice"
		return nil
	})
	if pgCode(err) != "23514" {
		t.Fatalf("an alias applied by its own adopter: %v, want check_violation 23514", err)
	}
	fact, _ := find(ps, GenResolutionPattern, "cedge-80")
	_, err = st.Update(ctx, "acme", fact.ID, func(cur *Proposal) error {
		cur.State, cur.Reason = StateDismissed, ""
		return nil
	})
	if pgCode(err) != "23514" {
		t.Fatalf("a dismissal without a reason: %v, want check_violation 23514", err)
	}
}

func TestLearningOpenCapPG(t *testing.T) {
	_, st := pgFixture(t)
	ctx := context.Background()
	var many []Proposal
	for i := 0; i < MaxOpenPerTenant+5; i++ {
		many = append(many, Proposal{Target: TargetAlias, Generator: GenEntityCorrection,
			Subject: "alias|site|site:s" + string(rune('a'+i/26)) + string(rune('a'+i%26)), Title: "t", Why: "w",
			Alias: &AliasDraft{EntityType: "site", EntityID: "site:x", Alias: "x"}})
	}
	added, _, err := st.Offer(ctx, "acme", many, pgNow)
	if err != nil {
		t.Fatal(err)
	}
	if added != MaxOpenPerTenant {
		t.Fatalf("added %d, want the cap %d", added, MaxOpenPerTenant)
	}
}
