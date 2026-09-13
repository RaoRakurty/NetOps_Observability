// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package users

// identity_migration_test.go — design §3: expand → backfill, and the property
// that makes it safe to ship: IDEMPOTENCY. Re-running the backfill (a second
// boot, a replayed migration, a re-applied file-store load) must produce
// IDENTICAL state and zero duplicate rows.
//
// It also pins the two halves of §3 that are easy to get wrong in opposite
// directions:
//   - a LOCAL row's identity IS derivable offline with certainty, so it is
//     backfilled;
//   - a FEDERATED row's is NOT, so it is left PENDING. Guessing one would be the
//     username-merge the owner's rule 4 forbids, and destroying the row would be
//     the F-58 mistake. It waits.

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"netops/backend/internal/platformdb"

	"github.com/jackc/pgx/v5"
)

// legacyBlob is a users.json as the pre-tracker-300 code wrote it: no `id`, no
// `identity`, and a bootstrap admin whose auth_source was never stamped (the H1
// shape).
const legacyBlob = `[
  {"username":"Admin","role":"admin","password_hash":"x","created_at":"2025-01-01T00:00:00Z"},
  {"username":"scoped","role":"operator","tenant_id":"T_ACME","auth_source":"local","password_hash":"y","created_at":"2025-02-01T00:00:00Z"},
  {"username":"fed-user","role":"read-only","tenant_id":"t_acme","auth_source":"oidc","created_at":"2025-03-01T00:00:00Z"},
  {"username":"tac-user","role":"read-only","auth_source":"tacacs","created_at":"2025-04-01T00:00:00Z"}
]`

func TestFileStoreBackfillsIdentitiesAtLoad(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "users.json")
	if err := os.WriteFile(path, []byte(legacyBlob), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := NewFileStore(path, testDeps())
	if err != nil {
		t.Fatalf("NewFileStore: %v", err)
	}

	// Legacy rows keep the id they have always effectively had — lower(username) —
	// so every session, binding, audit actor and API handle that references them
	// keeps its value (design §2.1). Nothing is re-keyed by this migration.
	for _, tc := range []struct {
		id, wantIssuer, wantSubject, wantTenant, wantProvenance string
		wantPending                                             bool
	}{
		{id: "admin", wantIssuer: LocalIssuer, wantSubject: "admin", wantTenant: "", wantProvenance: ProvenanceBackfilledLocal},
		{id: "scoped", wantIssuer: LocalIssuer, wantSubject: "scoped", wantTenant: "t_acme", wantProvenance: ProvenanceBackfilledLocal},
		// The two federated rows carry no issuer/subject and nothing may be
		// guessed, so they stay PENDING.
		{id: "fed-user", wantPending: true},
		{id: "tac-user", wantPending: true},
	} {
		u, ok := s.Get(tc.id)
		if !ok {
			t.Fatalf("%s: not found by its legacy id", tc.id)
		}
		if u.ID != tc.id {
			t.Errorf("%s: id = %q — a legacy id must NOT change value", tc.id, u.ID)
		}
		if tc.wantPending {
			if u.IdentityBound() {
				t.Errorf("%s: got identity %+v, want PENDING (nothing is derivable offline for a federated row)", tc.id, *u.Identity)
			}
			continue
		}
		id := identityOf(t, u)
		if id.Issuer != tc.wantIssuer || id.Subject != tc.wantSubject || id.TenantID != tc.wantTenant {
			t.Errorf("%s: identity = %+v, want (%s, %s, %s)", tc.id, id.key(), tc.wantTenant, tc.wantIssuer, tc.wantSubject)
		}
		if id.Provenance != tc.wantProvenance {
			t.Errorf("%s: provenance = %q, want %q", tc.id, id.Provenance, tc.wantProvenance)
		}
		if id.Protocol != ProtocolLocal {
			t.Errorf("%s: protocol = %q, want %q", tc.id, id.Protocol, ProtocolLocal)
		}
	}
	// H1 is preserved: the unstamped bootstrap admin is LOCAL, not federated.
	if u, _ := s.Get("admin"); u.AuthSource != ProtocolLocal {
		t.Errorf("bootstrap admin AuthSource = %q, want %q", u.AuthSource, ProtocolLocal)
	}
	// The backfilled local names are resolvable per tenant, which is the point.
	if got, ok := s.LookupLocal("t_acme", "SCOPED"); !ok || got.ID != "scoped" {
		t.Errorf("LookupLocal(t_acme, scoped) = %q/%v, want \"scoped\"", got.ID, ok)
	}
	// And §3 Enforce passes: every LOCAL account has its identity.
	if err := s.VerifyIdentityInvariants(); err != nil {
		t.Fatalf("enforce check after backfill: %v", err)
	}
}

func TestFileStoreBackfillIsIdempotent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "users.json")
	if err := os.WriteFile(path, []byte(legacyBlob), 0o600); err != nil {
		t.Fatal(err)
	}
	// First load converts and PERSISTS…
	if _, err := NewFileStore(path, testDeps()); err != nil {
		t.Fatalf("first load: %v", err)
	}
	first, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	markerPath := identityMarkerKey(path)
	firstMarker, err := os.ReadFile(markerPath)
	if err != nil {
		t.Fatalf("the migration epoch was not written: %v", err)
	}

	// …and every load after it is a NO-OP. Byte equality is the strongest
	// statement available here: not merely "converges", but "does not rewrite".
	for i := 0; i < 3; i++ {
		s, err := NewFileStore(path, testDeps())
		if err != nil {
			t.Fatalf("load %d: %v", i+2, err)
		}
		again, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if string(again) != string(first) {
			t.Fatalf("load %d rewrote the blob:\n--- first ---\n%s\n--- again ---\n%s", i+2, first, again)
		}
		nowMarker, err := os.ReadFile(markerPath)
		if err != nil {
			t.Fatal(err)
		}
		// Write-once: a re-run that moved the epoch forward would silently widen
		// the §2.6 adoption window to every account created since.
		if string(nowMarker) != string(firstMarker) {
			t.Fatalf("load %d moved the migration epoch: %s → %s", i+2, firstMarker, nowMarker)
		}
		if s.Count() != 4 {
			t.Fatalf("load %d: count = %d, want 4 (no duplicates)", i+2, s.Count())
		}
	}

	// The persisted shape is what a later release reads, so pin it.
	var list []User
	if err := json.Unmarshal(first, &list); err != nil {
		t.Fatalf("persisted blob does not parse: %v", err)
	}
	locals := 0
	for _, u := range list {
		if u.ID == "" {
			t.Errorf("persisted account %q has no id", u.Username)
		}
		if IsLocalSource(u.AuthSource) {
			locals++
			if u.Identity == nil {
				t.Errorf("persisted local account %q has no identity", u.ID)
			}
		}
	}
	if locals != 2 {
		t.Fatalf("found %d local accounts in the blob, want 2", locals)
	}
}

// A fresh install establishes its epoch at first open, so nothing can be adopted
// by the §2.6 rule on a deployment that never had legacy rows.
func TestFileStoreFreshInstallEstablishesTheEpoch(t *testing.T) {
	path := filepath.Join(t.TempDir(), "users.json")
	before := time.Now().UTC().Add(-time.Second)
	s, err := NewFileStore(path, testDeps())
	if err != nil {
		t.Fatalf("NewFileStore: %v", err)
	}
	if s.markerAt.Before(before) {
		t.Fatalf("epoch %v predates this test — a fresh install must stamp install time", s.markerAt)
	}
	if _, err := os.Stat(identityMarkerKey(path)); err != nil {
		t.Fatalf("epoch not persisted: %v", err)
	}
}

// A blob that already violates the constraints must FAIL THE OPEN rather than
// silently dropping a row: the file backend refuses exactly what the database's
// PRIMARY KEY refuses.
func TestFileStoreRefusesADuplicateIdentityAtLoad(t *testing.T) {
	for name, blob := range map[string]string{
		"duplicate local identity in one tenant": `[
		  {"id":"a","username":"dup","tenant_id":"t_a","auth_source":"local","password_hash":"x",
		   "identity":{"tenant_id":"t_a","issuer":"local","subject":"dup","protocol":"local","provenance":"asserted"}},
		  {"id":"b","username":"dup","tenant_id":"t_a","auth_source":"local","password_hash":"x",
		   "identity":{"tenant_id":"t_a","issuer":"local","subject":"dup","protocol":"local","provenance":"asserted"}}
		]`,
		"duplicate federated tuple": `[
		  {"id":"a","username":"a","auth_source":"oidc",
		   "identity":{"tenant_id":"t_a","issuer":"https://kc/realms/r","subject":"s","protocol":"oidc","provenance":"asserted"}},
		  {"id":"b","username":"b","auth_source":"oidc",
		   "identity":{"tenant_id":"t_a","issuer":"https://kc/realms/r","subject":"s","protocol":"oidc","provenance":"asserted"}}
		]`,
		"duplicate account id": `[
		  {"id":"a","username":"a","auth_source":"oidc"},
		  {"id":"a","username":"b","auth_source":"oidc"}
		]`,
		"identity with no subject": `[
		  {"id":"a","username":"a","auth_source":"oidc",
		   "identity":{"tenant_id":"t_a","issuer":"https://kc/realms/r","protocol":"oidc","provenance":"asserted"}}
		]`,
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "users.json")
			if err := os.WriteFile(path, []byte(blob), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := NewFileStore(path, testDeps()); err == nil {
				t.Fatal("the store opened over a blob that violates the identity constraints")
			}
			// And it refused without touching the file — nothing is repaired or
			// deleted by a load that fails (F-58).
			after, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if string(after) != blob {
				t.Fatalf("a failed load rewrote the blob:\n%s", after)
			}
		})
	}
}

// MintID's staging seam, pinned so nobody "fixes" it by accident: with no minter
// the store keeps the LEGACY id shape (what every existing row carries), which is
// what lets Phase 2/3 land before the doors stop keying on the username.
func TestMintIDStagingSeam(t *testing.T) {
	legacy, err := NewFileStore(filepath.Join(t.TempDir(), "users.json"), testDeps())
	if err != nil {
		t.Fatal(err)
	}
	u, err := legacy.Create("Alice", strongPass, "admin")
	if err != nil {
		t.Fatal(err)
	}
	if u.ID != "alice" {
		t.Errorf("with no MintID, id = %q, want the legacy lower(username) shape", u.ID)
	}
	if got, ok := legacy.Get("ALICE"); !ok || got.ID != "alice" {
		t.Errorf("a legacy-shaped id must still resolve case-insensitively: %q/%v", got.ID, ok)
	}

	d, _ := identityTestDeps(contractEpoch)
	opaque, err := NewFileStore(filepath.Join(t.TempDir(), "users.json"), d)
	if err != nil {
		t.Fatal(err)
	}
	v, err := opaque.Create("Alice", strongPass, "admin")
	if err != nil {
		t.Fatal(err)
	}
	if v.ID == "alice" || !strings.HasPrefix(v.ID, "u_") {
		t.Errorf("with a MintID, id = %q, want an opaque minted id", v.ID)
	}
	if _, ok := opaque.Get("alice"); ok {
		t.Error("an opaque-id account resolved by its username — the username is not a key")
	}
}

// A federated account may not be CREATED administratively: only a verified
// assertion knows an issuer and a subject (§2.5).
func TestCreateRefusesAFederatedAccount(t *testing.T) {
	s, err := NewFileStore(filepath.Join(t.TempDir(), "users.json"), testDeps())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateFull(User{Username: "x", AuthSource: ProtocolOIDC}, ""); !errors.Is(err, ErrFederatedCreate) {
		t.Fatalf("err = %v, want ErrFederatedCreate", err)
	}
}

// ---------------------------------------------------------------------------
// Postgres: migrations 0049/0050, applied twice
// ---------------------------------------------------------------------------

// TestPGIdentityMigrationIsIdempotent applies the identity migrations to a
// database that ALREADY holds legacy rows, twice, and proves the second apply
// changes nothing.
//
// It is also the only place the `SELECT set_config('app.tenant_id','*',true)` at
// the top of 0050 is proven to be necessary: `users` and `user_identities` are
// FORCE ROW LEVEL SECURITY and the migrator connects as the non-superuser role
// that owns them, so without that line the backfill's SELECT sees zero rows and
// this test finds zero identities — a migration that "succeeded" while doing
// nothing.
func TestPGIdentityMigrationIsIdempotent(t *testing.T) {
	adminDSN := os.Getenv("DATABASE_URL_TEST")
	if adminDSN == "" {
		t.Skip("set DATABASE_URL_TEST to run the Postgres identity-migration test")
	}
	ctx := context.Background()
	appDSN := provisionAppRole(ctx, t, adminDSN)
	ps, err := platformdb.NewPGStore(ctx, appDSN) // applies every migration once
	if err != nil {
		t.Fatalf("newPgStore: %v", err)
	}
	defer ps.DB().Close()

	// Seed LEGACY rows directly: no `id` in the JSON, no identity row, and a
	// bootstrap admin whose auth_source was never stamped. Platform scope
	// satisfies the FORCE-RLS tenant_iso policy.
	conn, err := pgx.Connect(ctx, appDSN)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	if _, err := conn.Exec(ctx, `SET app.tenant_id = '*'`); err != nil {
		t.Fatalf("set tenant: %v", err)
	}
	for _, row := range []struct{ id, tenant, data string }{
		{"legacyadmin", "", `{"username":"legacyadmin","role":"admin","password_hash":"x"}`},
		{"scoped", "t_acme", `{"username":"scoped","role":"operator","tenant_id":"t_acme","auth_source":"local","password_hash":"y"}`},
		{"fed-user", "t_acme", `{"username":"fed-user","role":"read-only","tenant_id":"t_acme","auth_source":"oidc"}`},
		{"tac-user", "", `{"username":"tac-user","role":"read-only","auth_source":"tacacs"}`},
	} {
		if _, err := conn.Exec(ctx, `INSERT INTO users (id, tenant_id, data) VALUES ($1,$2,$3)`,
			row.id, row.tenant, row.data); err != nil {
			t.Fatalf("seed %s: %v", row.id, err)
		}
	}
	if err := conn.Close(ctx); err != nil {
		t.Fatalf("close: %v", err)
	}

	type state struct {
		identities int
		locals     int
		pending    int
		epoch      time.Time
		rowsFor    map[string]string // user_id → "tenant|issuer|subject|provenance"
	}
	read := func(t *testing.T) state {
		t.Helper()
		st := state{rowsFor: map[string]string{}}
		if err := ps.DB().WithTenant(ctx, "", true, func(tx pgx.Tx) error {
			rows, err := tx.Query(ctx,
				`SELECT user_id, tenant_id, issuer, subject, provenance FROM user_identities ORDER BY user_id`)
			if err != nil {
				return err
			}
			for rows.Next() {
				var uid, tenant, issuer, subject, prov string
				if err := rows.Scan(&uid, &tenant, &issuer, &subject, &prov); err != nil {
					rows.Close()
					return err
				}
				st.rowsFor[uid] = strings.Join([]string{tenant, issuer, subject, prov}, "|")
				st.identities++
			}
			rows.Close()
			if err := rows.Err(); err != nil {
				return err
			}
			if err := tx.QueryRow(ctx, `SELECT count(*) FROM users
				WHERE COALESCE(data->>'auth_source','') IN ('','local')`).Scan(&st.locals); err != nil {
				return err
			}
			if err := tx.QueryRow(ctx, `SELECT count(*) FROM users u
				LEFT JOIN user_identities i ON i.user_id=u.id WHERE i.user_id IS NULL`).Scan(&st.pending); err != nil {
				return err
			}
			return tx.QueryRow(ctx, `SELECT started_at FROM identity_migration WHERE singleton`).Scan(&st.epoch)
		}); err != nil {
			t.Fatalf("read state: %v", err)
		}
		return st
	}

	// reapply forces 0049/0050 to run again by removing their version rows — the
	// only way to replay a forward-only migrator.
	reapply := func(t *testing.T) {
		t.Helper()
		if err := ps.DB().WithTenant(ctx, "", true, func(tx pgx.Tx) error {
			_, err := tx.Exec(ctx, `DELETE FROM schema_migrations WHERE version IN
				('0049_user_identities.sql','0050_user_identities_backfill_local.sql')`)
			return err
		}); err != nil {
			t.Fatalf("clear migration versions: %v", err)
		}
		if err := ps.DB().Migrate(ctx); err != nil {
			t.Fatalf("re-apply migrations: %v", err)
		}
	}

	// The rows were seeded AFTER the first apply, so the backfill has not seen
	// them yet: replay it.
	reapply(t)
	first := read(t)
	if first.locals != 2 {
		t.Fatalf("expected 2 local rows in the fixture, found %d", first.locals)
	}
	if first.identities != 2 {
		t.Fatalf("backfill produced %d identities, want 2 (the local rows only) — "+
			"anything less means 0050's set_config is missing and FORCE RLS silently ate part of "+
			"the INSERT (it converts only the blank-tenant rows on a reused pooled connection)", first.identities)
	}
	if got, want := first.rowsFor["legacyadmin"], "|local|legacyadmin|backfilled-local"; got != want {
		t.Errorf("legacyadmin identity = %q, want %q", got, want)
	}
	if got, want := first.rowsFor["scoped"], "t_acme|local|scoped|backfilled-local"; got != want {
		t.Errorf("scoped identity = %q, want %q", got, want)
	}
	// The FEDERATED rows are deliberately untouched: nothing may be guessed.
	for _, id := range []string{"fed-user", "tac-user"} {
		if got, bad := first.rowsFor[id]; bad {
			t.Errorf("federated row %s was backfilled to %q — its issuer/subject are not derivable offline", id, got)
		}
	}
	if first.pending != 2 {
		t.Errorf("pending accounts = %d, want 2 (the federated rows)", first.pending)
	}

	// …and the second apply changes NOTHING.
	reapply(t)
	second := read(t)
	if second.identities != first.identities || second.pending != first.pending {
		t.Fatalf("a second apply changed the row counts: %+v → %+v", first, second)
	}
	if !second.epoch.Equal(first.epoch) {
		t.Fatalf("a second apply MOVED the migration epoch %v → %v — that would widen the §2.6 adoption window",
			first.epoch, second.epoch)
	}
	for uid, want := range first.rowsFor {
		if got := second.rowsFor[uid]; got != want {
			t.Errorf("%s: identity changed on re-apply: %q → %q", uid, want, got)
		}
	}
	if len(second.rowsFor) != len(first.rowsFor) {
		t.Fatalf("re-apply changed the identity set: %v → %v", first.rowsFor, second.rowsFor)
	}

	// The store reads the same epoch the migration wrote, and the enforce check
	// passes on the converged estate (every LOCAL account has an identity; the
	// pending federated rows are the documented waiting state, not a failure).
	d := testDeps()
	s, err := NewPGStore(ps.DB(), d)
	if err != nil {
		t.Fatalf("NewPGStore: %v", err)
	}
	if !s.markerAt.Equal(first.epoch.UTC()) {
		t.Errorf("store epoch = %v, want the migration's %v", s.markerAt, first.epoch.UTC())
	}
	if err := s.VerifyIdentityInvariants(); err != nil {
		t.Fatalf("enforce check after backfill: %v", err)
	}
	// The backfilled identity is what makes a legacy local name resolvable, and
	// the id it resolves to is unchanged.
	if got, ok := s.LookupLocal("t_acme", "SCOPED"); !ok || got.ID != "scoped" {
		t.Errorf("LookupLocal(t_acme, scoped) = %q/%v, want \"scoped\"", got.ID, ok)
	}
	if got, ok := s.Get("legacyadmin"); !ok || got.ID != "legacyadmin" || got.AuthSource != ProtocolLocal {
		t.Errorf("legacy admin = %+v, want an unchanged id and AuthSource=local", got)
	}
}

// TestPGIdentityConstraintsAreInTheDatabase proves the two constraints are the
// DATABASE's, not the application's — the owner's rule 2 ("enforced at the DB,
// not only in code"). It writes raw SQL, bypassing every Go guard.
func TestPGIdentityConstraintsAreInTheDatabase(t *testing.T) {
	adminDSN := os.Getenv("DATABASE_URL_TEST")
	if adminDSN == "" {
		t.Skip("set DATABASE_URL_TEST to run the Postgres identity-constraint test")
	}
	ctx := context.Background()
	appDSN := provisionAppRole(ctx, t, adminDSN)
	ps, err := platformdb.NewPGStore(ctx, appDSN)
	if err != nil {
		t.Fatalf("newPgStore: %v", err)
	}
	defer ps.DB().Close()

	exec := func(t *testing.T, sql string, args ...any) error {
		t.Helper()
		return ps.DB().WithTenant(ctx, "", true, func(tx pgx.Tx) error {
			_, err := tx.Exec(ctx, sql, args...)
			return err
		})
	}
	for _, id := range []string{"u1", "u2"} {
		if err := exec(t, `INSERT INTO users (id, tenant_id, data) VALUES ($1,'t_a',$2)`,
			id, `{"username":"`+id+`","auth_source":"oidc"}`); err != nil {
			t.Fatalf("seed %s: %v", id, err)
		}
	}
	base := `INSERT INTO user_identities (tenant_id, issuer, subject, user_id, protocol, provenance)
		VALUES ($1,$2,$3,$4,'oidc','asserted')`
	if err := exec(t, base, "t_a", "https://kc/realms/r", "s1", "u1"); err != nil {
		t.Fatalf("first identity: %v", err)
	}

	t.Run("1 the PK refuses a duplicate tuple", func(t *testing.T) {
		if err := exec(t, base, "t_a", "https://kc/realms/r", "s1", "u2"); !isUniqueViolation(err) {
			t.Fatalf("err = %v, want a unique_violation from PRIMARY KEY (tenant_id, issuer, subject)", err)
		}
	})
	t.Run("2 UNIQUE(user_id) refuses a second identity for one account", func(t *testing.T) {
		if err := exec(t, base, "t_a", "https://kc/realms/other", "s2", "u1"); !isUniqueViolation(err) {
			t.Fatalf("err = %v, want a unique_violation from UNIQUE (user_id) — this is the DB-level 'no auto-linking'", err)
		}
	})
	t.Run("the same tuple in another tenant is NOT a duplicate", func(t *testing.T) {
		if err := exec(t, `INSERT INTO users (id, tenant_id, data) VALUES ('u3','t_b','{"username":"u3","auth_source":"oidc"}')`); err != nil {
			t.Fatal(err)
		}
		if err := exec(t, base, "t_b", "https://kc/realms/r", "s1", "u3"); err != nil {
			t.Fatalf("the tenant is part of the key, so this must be allowed: %v", err)
		}
	})
	t.Run("the CHECKs refuse an incomplete tuple", func(t *testing.T) {
		for name, args := range map[string][]any{
			"empty issuer":  {"t_a", "", "s9", "u2"},
			"empty subject": {"t_a", "https://kc/realms/r", "", "u2"},
		} {
			if err := exec(t, base, args...); err == nil {
				t.Errorf("%s: accepted — migration 0049's CHECK constraints are missing", name)
			}
		}
	})
	t.Run("ON DELETE CASCADE removes the identity with the account", func(t *testing.T) {
		if err := exec(t, `DELETE FROM users WHERE id='u1'`); err != nil {
			t.Fatalf("delete: %v", err)
		}
		var n int
		if err := ps.DB().WithTenant(ctx, "", true, func(tx pgx.Tx) error {
			return tx.QueryRow(ctx, `SELECT count(*) FROM user_identities WHERE user_id='u1'`).Scan(&n)
		}); err != nil {
			t.Fatal(err)
		}
		if n != 0 {
			t.Fatalf("%d orphaned identity rows survived the account", n)
		}
	})
}
