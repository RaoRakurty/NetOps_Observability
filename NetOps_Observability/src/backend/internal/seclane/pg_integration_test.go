// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

//go:build pgintegration

package seclane

// pg_integration_test.go — storage-layer proof for migration 0069 (finding
// episode state, owner D2), against a real PostgreSQL as a NOBYPASSRLS role:
// FORCE-RLS confines every statement to the tenant (written as A, read as B,
// nothing; WITH CHECK refuses a B row under A's scope; a query that forgets its
// WHERE still sees one tenant), the CHECKs refuse a platform-owned or malformed
// row, Commit/Load round-trip including the seed mark, and the migration goes
// down and up again.

import (
	"context"
	"errors"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"netops/backend/internal/platformdb"
	"netops/backend/internal/secbus"
)

// provisionAppRole is the root package's helper of the same name (tests there
// are not importable from here): a clean schema and a non-superuser DSN.
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

func pgFixture(t *testing.T) (*platformdb.PGStore, *PGEpisodes) {
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
	return ps, NewPGEpisodes(ps.DB())
}

func pgCode(err error) string {
	var pe *pgconn.PgError
	if errors.As(err, &pe) {
		return pe.Code
	}
	return ""
}

func pgEpisode(sev string, at time.Time) Episode {
	return Episode{FirstSeen: at, Basis: secbus.BasisObserved, Subject: EpisodeSubject{
		Kind: "security_posture", EntityID: "core", Severity: sev, StatusID: 3,
		ProviderSource: "correlix-netrule", RawRuleID: "telnet-vty-enabled",
		EntityTokens: []string{"core", "device:core"},
	}}
}

func TestFindingEpisodesRLSIsolationPG(t *testing.T) {
	ps, st := pgFixture(t)
	ctx := context.Background()
	t0 := time.Date(2026, 11, 11, 4, 0, 0, 0, time.UTC)

	// Same native-id SHAPE in both tenants (the tenant is in the real key, but
	// RLS must hold even if two tenants' keys collided).
	if err := st.Commit(ctx, "t_a", EpisodeCommit{
		Upserts:    map[string]Episode{"nid-1": pgEpisode("medium", t0), "nid-2": pgEpisode("low", t0)},
		SeedSource: SeedSourceIndex,
	}); err != nil {
		t.Fatalf("commit t_a: %v", err)
	}
	if err := st.Commit(ctx, "t_b", EpisodeCommit{
		Upserts: map[string]Episode{"nid-1": pgEpisode("high", t0.Add(time.Hour))},
	}); err != nil {
		t.Fatalf("commit t_b: %v", err)
	}

	a, err := st.Load(ctx, "t_a")
	if err != nil || !a.Seeded || len(a.Open) != 2 || a.Open["nid-1"].Subject.Severity != "medium" {
		t.Fatalf("t_a round-trip: seeded=%v open=%+v err=%v", a.Seeded, a.Open, err)
	}
	if got := a.Open["nid-1"]; !got.FirstSeen.Equal(t0) || got.Basis != secbus.BasisObserved ||
		len(got.Subject.EntityTokens) != 2 || got.Subject.StatusID != 3 {
		t.Fatalf("t_a episode did not round-trip: %+v", got)
	}
	b, err := st.Load(ctx, "t_b")
	if err != nil || b.Seeded || len(b.Open) != 1 || b.Open["nid-1"].Subject.Severity != "high" {
		t.Fatalf("RLS LEAK or wrong row for t_b: seeded=%v open=%+v err=%v", b.Seeded, b.Open, err)
	}
	if c, err := st.Load(ctx, "t_c"); err != nil || c.Seeded || len(c.Open) != 0 {
		t.Fatalf("RLS LEAK: an unknown tenant loaded %+v (%v)", c, err)
	}

	// A delete in B never touches A.
	if err := st.Commit(ctx, "t_b", EpisodeCommit{Deletes: []string{"nid-1", "nid-2"}}); err != nil {
		t.Fatal(err)
	}
	if a, _ := st.Load(ctx, "t_a"); len(a.Open) != 2 {
		t.Fatalf("t_b's delete removed t_a's episodes: %+v", a.Open)
	}

	// RLS is the backstop even for a query that forgets its WHERE.
	var n int
	if err := ps.DB().WithTenant(ctx, "t_a", false, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM security_finding_episodes`).Scan(&n)
	}); err != nil || n != 2 {
		t.Fatalf("an unfiltered read in t_a's scope counted %d rows (%v), want 2", n, err)
	}
	// WITH CHECK: a B row under A's scope is refused, on both tables.
	for _, q := range []string{
		`INSERT INTO security_finding_episodes (tenant_id, native_id, first_seen, subject) VALUES ('t_b', 'x', now(), '{}')`,
		`INSERT INTO security_finding_episode_seeds (tenant_id, source) VALUES ('t_b', 'index')`,
	} {
		err := ps.DB().WithTenant(ctx, "t_a", false, func(tx pgx.Tx) error { _, e := tx.Exec(ctx, q); return e })
		if pgCode(err) != "42501" {
			t.Fatalf("a write into another tenant must be RLS-denied (42501); got %v for %s", err, q)
		}
	}
	// Nor can A's scope rewrite B's rows.
	if err := ps.DB().WithTenant(ctx, "t_a", false, func(tx pgx.Tx) error {
		tag, e := tx.Exec(ctx, `UPDATE security_finding_episode_seeds SET source = 'scan' WHERE tenant_id = 't_b'`)
		if e == nil && tag.RowsAffected() != 0 {
			return errors.New("updated another tenant's row")
		}
		return e
	}); err != nil {
		t.Fatalf("cross-tenant update: %v", err)
	}

	// The CHECKs refuse what the lane never writes.
	for name, q := range map[string]string{
		"platform owner": `INSERT INTO security_finding_episodes (tenant_id, native_id, first_seen) VALUES ('', 'p1', now())`,
		"global owner":   `INSERT INTO security_finding_episodes (tenant_id, native_id, first_seen) VALUES ('global', 'p2', now())`,
		"bad basis":      `INSERT INTO security_finding_episodes (tenant_id, native_id, first_seen, first_seen_basis) VALUES ('t_a', 'p3', now(), 'guess')`,
		"empty id":       `INSERT INTO security_finding_episodes (tenant_id, native_id, first_seen) VALUES ('t_a', '', now())`,
		"array subject":  `INSERT INTO security_finding_episodes (tenant_id, native_id, first_seen, subject) VALUES ('t_a', 'p4', now(), '[]')`,
		"bad seed":       `INSERT INTO security_finding_episode_seeds (tenant_id, source) VALUES ('t_z', 'guess')`,
		"global seed":    `INSERT INTO security_finding_episode_seeds (tenant_id, source) VALUES ('global', 'index')`,
	} {
		err := ps.DB().WithTenant(ctx, "", true, func(tx pgx.Tx) error { _, e := tx.Exec(ctx, q); return e })
		if pgCode(err) != "23514" {
			t.Errorf("%s: want a CHECK violation (23514), got %v", name, err)
		}
	}

	// An upsert updates in place; the seed mark is written once.
	if err := st.Commit(ctx, "t_a", EpisodeCommit{
		Upserts: map[string]Episode{"nid-1": pgEpisode("critical", t0)}, SeedSource: SeedSourceScan,
	}); err != nil {
		t.Fatal(err)
	}
	var src string
	if err := ps.DB().WithTenant(ctx, "t_a", false, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT source FROM security_finding_episode_seeds WHERE tenant_id = 't_a'`).Scan(&src)
	}); err != nil || src != SeedSourceIndex {
		t.Fatalf("the first seed source must stand: %q (%v)", src, err)
	}
	if a, _ := st.Load(ctx, "t_a"); a.Open["nid-1"].Subject.Severity != "critical" || len(a.Open) != 2 {
		t.Fatalf("upsert in place: %+v", a.Open)
	}
}

// The lane end to end on Postgres: a restart (a new store over the same DB)
// re-emits nothing.
func TestFindingEpisodesSurviveARestartPG(t *testing.T) {
	ps, st := pgFixture(t)
	before := newEpisodeFixture(t, st, nil)
	before.cfg["acme-core"] = cfgTelnet
	before.devices["acme"] = []Device{dev("acme-core", "acme")}
	if n := len(onTopic(before.scan(t, "acme", fixedNow), secbus.TopicSecurityEvidence)); n == 0 {
		t.Fatal("first scan opened nothing")
	}
	after := newEpisodeFixture(t, NewPGEpisodes(ps.DB()), nil)
	after.cfg["acme-core"] = cfgTelnet
	after.devices["acme"] = []Device{dev("acme-core", "acme")}
	after.index.down = true
	if n := len(onTopic(after.scan(t, "acme", fixedNow.Add(time.Hour)), secbus.TopicSecurityEvidence)); n != 0 {
		t.Fatalf("a restart on Postgres re-announced %d findings", n)
	}
}

func TestFindingEpisodesMigrationDownUpPG(t *testing.T) {
	ps, st := pgFixture(t)
	ctx := context.Background()
	if err := st.Commit(ctx, "t_a", EpisodeCommit{
		Upserts: map[string]Episode{"nid-1": pgEpisode("low", fixedNow)}, SeedSource: SeedSourceIndex,
	}); err != nil {
		t.Fatal(err)
	}
	down, err := os.ReadFile("../platformdb/migrations/rollback/0069_security_finding_episodes.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	tx, err := ps.DB().BeginForTest(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, string(down)); err != nil {
		t.Fatalf("rollback: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Load(ctx, "t_a"); err == nil {
		t.Fatal("the tables must be gone after the rollback")
	}
	ps2, err := platformdb.NewPGStore(ctx, ps.DB().PoolForTest().Config().ConnString())
	if err != nil {
		t.Fatalf("re-migrate: %v", err)
	}
	t.Cleanup(ps2.DB().Close)
	got, err := NewPGEpisodes(ps2.DB()).Load(ctx, "t_a")
	if err != nil || got.Seeded || len(got.Open) != 0 {
		t.Fatalf("after re-apply the tables are back and empty: %+v %v", got, err)
	}
}
