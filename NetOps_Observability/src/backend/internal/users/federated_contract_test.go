package users

import (
	"context"
	"errors"
	"net/url"
	"netops/backend/internal/platformdb"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// SR-025 authorization contract for UpsertFederated, run against BOTH backends
// through the Repo seam so the file and Postgres stores cannot drift (the pg
// backend shipped without the guard once — this contract is the structural fix).
//
// The guard POLICY (global tenant + super-admin ⇒ downgrade unless the
// FEDERATION_ALLOW_PLATFORM_OWNER opt-in) lives at the wiring layer
// (guardFederatedRole), along with its audit warn; here a recording fake with
// the same shape proves the STORE-side wiring: the guard is invoked with the
// right (role, tenant, user, source), its verdict — not the raw IdP role — is
// what persists, and the paths that must not consult it don't.

type guardCall struct{ role, tenant, username, source string }

// contractGuard mimics guardFederatedRole's deny shape while recording calls.
type contractGuard struct{ calls []guardCall }

func (g *contractGuard) guard(role, tenant, username, source string) string {
	g.calls = append(g.calls, guardCall{role, tenant, username, source})
	if tenant == "global" && role == "super-admin" {
		return "read-only" // the SR-025 downgrade verdict
	}
	return role
}

func runUserStoreAuthorizationContract(t *testing.T, newStore func(t *testing.T, d Deps) Repo) {
	t.Helper()
	g := &contractGuard{}
	var errorfCalls int
	d := Deps{
		KV:           fileKV{},
		Errorf:       func(string, string, map[string]any) { errorfCalls++ },
		GuardRole:    g.guard,
		IsSuperAdmin: func(role string) bool { return role == "super-admin" || role == "admin" },
		ApplyPasswordChange: func(u *User, hash string, now time.Time) {
			u.PasswordHash = hash
			u.PasswordChangedAt = now
		},
		DefaultTenant: "global",
	}
	s := newStore(t, d)

	t.Run("create denies platform-owner mapping before persistence", func(t *testing.T) {
		u, err := s.UpsertFederated("fed-owner", "o@x.com", "Owner", "super-admin", "oidc", "")
		if err != nil {
			t.Fatalf("upsert: %v", err)
		}
		// Empty tenant arg must fall back to deps.DefaultTenant — both on the
		// stored user and in what the guard was asked to judge.
		if len(g.calls) != 1 || g.calls[0] != (guardCall{"super-admin", "global", "fed-owner", "oidc"}) {
			t.Fatalf("guard calls = %+v, want one call with the raw role + default tenant", g.calls)
		}
		if u.Role != "read-only" || u.TenantID != "global" || u.AuthSource != "oidc" {
			t.Errorf("returned user = %+v, want the guard's downgraded role in the global tenant", u)
		}
		got, ok := s.Get("fed-owner")
		if !ok || got.Role != "read-only" {
			t.Errorf("persisted role = %q (ok=%v) — the raw super-admin role must never be written", got.Role, ok)
		}
	})

	t.Run("merge guards with the existing account's tenant", func(t *testing.T) {
		if _, err := s.UpsertFederated("fed-merge", "", "", "operator", "oidc", "global"); err != nil {
			t.Fatalf("provision: %v", err)
		}
		g.calls = nil
		// Escalation attempt on refresh: the tenant ARG is deliberately different —
		// the guard must judge against the account's stored tenant, not the arg.
		u, err := s.UpsertFederated("fed-merge", "new@x.com", "New", "super-admin", "oidc", "acme")
		if err != nil {
			t.Fatalf("merge: %v", err)
		}
		if len(g.calls) != 1 || g.calls[0] != (guardCall{"super-admin", "global", "fed-merge", "oidc"}) {
			t.Fatalf("guard calls = %+v, want one call with the EXISTING account's tenant", g.calls)
		}
		if u.Role != "read-only" || u.TenantID != "global" || u.Email != "new@x.com" {
			t.Errorf("merged user = %+v, want downgraded role, original tenant, refreshed profile", u)
		}
		if got, _ := s.Get("fed-merge"); got.Role != "read-only" {
			t.Errorf("persisted role = %q — the raw super-admin role must never be written", got.Role)
		}
	})

	t.Run("local account is refused, never converted or re-roled", func(t *testing.T) {
		// H1: a colliding LOCAL account is a typed REFUSAL (ErrLocalAccount) —
		// accepting the IdP's verdict against it would bypass the local password
		// and its MFA enrollment. The record must come through untouched.
		if _, err := s.CreateFull(User{Username: "locadmin", Role: "admin", TenantID: "acme"}, "Passw0rd!2345"); err != nil {
			t.Fatalf("create local: %v", err)
		}
		g.calls = nil
		_, err := s.UpsertFederated("locadmin", "idp@x.com", "IdP", "super-admin", "oidc", "global")
		if !errors.Is(err, ErrLocalAccount) {
			t.Fatalf("federated login against local account: err = %v, want ErrLocalAccount", err)
		}
		if len(g.calls) != 0 {
			t.Errorf("guard consulted %d times on a local account — its verdict is irrelevant here", len(g.calls))
		}
		if got, _ := s.Get("locadmin"); got.Role != "admin" || got.AuthSource != "local" || got.Email != "" {
			t.Errorf("persisted local account mutated by refused federated login: %+v", got)
		}
	})

	t.Run("H1: bootstrap/seeded admin counts as local", func(t *testing.T) {
		// SeedAdmin/Create historically left AuthSource "" — which used to count
		// as federated, letting a TACACS/LDAP/OIDC identity of the same name be
		// MERGED into the bootstrap admin (re-role, re-source, MFA bypass). The
		// stamp + the ""-is-local predicate close it; this pins both.
		if _, err := s.Create("boot-admin", "Passw0rd!2345", "admin"); err != nil {
			t.Fatalf("create: %v", err)
		}
		if got, _ := s.Get("boot-admin"); got.AuthSource != "local" {
			t.Fatalf("Create stamped AuthSource=%q, want %q", got.AuthSource, "local")
		}
		if _, err := s.UpsertFederated("boot-admin", "a@idp", "IdP Admin", "super-admin", "tacacs", ""); !errors.Is(err, ErrLocalAccount) {
			t.Fatalf("federated login against seeded admin: err = %v, want ErrLocalAccount", err)
		}
		if got, _ := s.Get("boot-admin"); got.Role != "admin" || got.AuthSource != "local" {
			t.Errorf("seeded admin mutated by refused federated login: %+v", got)
		}
	})

	// The store seam emits no audit line of its own on the deny path — that
	// (sanitized: user + source only) lives with the policy at the wiring layer.
	if errorfCalls != 0 {
		t.Errorf("store emitted %d error logs during the contract, want 0", errorfCalls)
	}
}

func TestFileStoreAuthorizationContract(t *testing.T) {
	runUserStoreAuthorizationContract(t, func(t *testing.T, d Deps) Repo {
		s, err := NewFileStore(filepath.Join(t.TempDir(), "users.json"), d)
		if err != nil {
			t.Fatalf("NewFileStore: %v", err)
		}
		return s
	})
}

// Gated on DATABASE_URL_TEST like every pg-backed test (a superuser DSN; the
// fixture provisions the non-superuser app role FORCE RLS actually applies to).
func TestPGStoreAuthorizationContract(t *testing.T) {
	adminDSN := os.Getenv("DATABASE_URL_TEST")
	if adminDSN == "" {
		t.Skip("set DATABASE_URL_TEST to run the Postgres authorization-contract test")
	}
	ctx := context.Background()
	ps, err := platformdb.NewPGStore(ctx, provisionAppRole(ctx, t, adminDSN))
	if err != nil {
		t.Fatalf("newPgStore: %v", err)
	}
	defer ps.DB().Close()
	runUserStoreAuthorizationContract(t, func(t *testing.T, d Deps) Repo {
		s, err := NewPGStore(ps.DB(), d)
		if err != nil {
			t.Fatalf("NewPGStore: %v", err)
		}
		return s
	})
}

// TestPGStoreMigratesEmptyAuthSource — pg twin of the FileStore load migration
// (H1): a row written before the AuthSource stamp (auth_source "") is
// normalized to "local" when the store opens, so UpsertFederated's
// local-account refusal covers the pre-existing bootstrap admin. Gated on
// DATABASE_URL_TEST like every pg-backed test.
func TestPGStoreMigratesEmptyAuthSource(t *testing.T) {
	adminDSN := os.Getenv("DATABASE_URL_TEST")
	if adminDSN == "" {
		t.Skip("set DATABASE_URL_TEST to run the Postgres auth-source migration test")
	}
	ctx := context.Background()
	appDSN := provisionAppRole(ctx, t, adminDSN)
	ps, err := platformdb.NewPGStore(ctx, appDSN)
	if err != nil {
		t.Fatalf("newPgStore: %v", err)
	}
	defer ps.DB().Close()

	// Seed a LEGACY row directly (no exported write path can produce "" any
	// more). Platform scope satisfies the FORCE-RLS tenant_iso policy.
	conn, err := pgx.Connect(ctx, appDSN)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	if _, err := conn.Exec(ctx, `SET app.tenant_id = '*'`); err != nil {
		t.Fatalf("set tenant: %v", err)
	}
	if _, err := conn.Exec(ctx, `INSERT INTO users (id, tenant_id, data) VALUES
		('legacyadmin', '', '{"username":"legacyadmin","role":"admin","password_hash":"x"}')`); err != nil {
		t.Fatalf("seed legacy row: %v", err)
	}
	if err := conn.Close(ctx); err != nil {
		t.Fatalf("close: %v", err)
	}

	d := Deps{
		KV:           fileKV{},
		Errorf:       func(string, string, map[string]any) {},
		GuardRole:    func(role, _, _, _ string) string { return role },
		IsSuperAdmin: func(role string) bool { return role == "super-admin" || role == "admin" },
		ApplyPasswordChange: func(u *User, hash string, now time.Time) {
			u.PasswordHash = hash
			u.PasswordChangedAt = now
		},
		DefaultTenant: "global",
	}
	s, err := NewPGStore(ps.DB(), d) // constructor runs the one-time migration
	if err != nil {
		t.Fatalf("NewPGStore: %v", err)
	}
	u, ok := s.Get("legacyadmin")
	if !ok || u.AuthSource != "local" {
		t.Fatalf("legacy row after open: AuthSource=%q ok=%v, want \"local\"", u.AuthSource, ok)
	}
	if _, err := s.UpsertFederated("legacyadmin", "a@idp", "IdP", "super-admin", "oidc", ""); !errors.Is(err, ErrLocalAccount) {
		t.Fatalf("federated login against migrated local admin: err = %v, want ErrLocalAccount", err)
	}
}

// provisionAppRole duplicates the platformdb test fixture (test files cannot
// cross packages): from a superuser DSN it provisions the non-superuser app
// role FORCE RLS actually applies to, returning its DSN.
func provisionAppRole(ctx context.Context, t *testing.T, adminDSN string) string {
	t.Helper()
	admin, err := pgx.Connect(ctx, adminDSN)
	if err != nil {
		t.Fatalf("admin connect: %v", err)
	}
	defer admin.Close(ctx)

	const role, pass = "netops_app_test", "apppw"
	stmts := []string{
		// Clear residue from a prior package's tests on this shared database
		// BEFORE dropping: the pg-integration CI job runs the whole corpus with
		// `-p 1 ./...` against ONE database, and a leaked/late-closing connection
		// as the app role would otherwise block DROP ROLE / hold the objects the
		// schema drop needs. Terminate other backends, then drop what the role
		// still owns, so provisioning is deterministic regardless of run order.
		"SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = current_database() AND pid <> pg_backend_pid()",
		"DO $do$ BEGIN IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '" + role + "') THEN EXECUTE 'DROP OWNED BY " + role + "'; END IF; END $do$",
		"DROP SCHEMA IF EXISTS public CASCADE",
		"CREATE SCHEMA public",
		// Recreating public leaves it owned by the superuser with no CREATE for
		// anyone else (PG15+ dropped the public-CREATE-to-PUBLIC default), which
		// strips the persistent CI app role's (PG_TEST_DSN) grant and makes the
		// next non-provisioning test fail "no schema has been selected to create
		// in". Restore usability for every role on this shared test database.
		"GRANT USAGE, CREATE ON SCHEMA public TO PUBLIC",
		"DROP ROLE IF EXISTS " + role,
		"CREATE ROLE " + role + " LOGIN PASSWORD '" + pass + "' NOSUPERUSER",
		"GRANT ALL ON SCHEMA public TO " + role,
	}
	for _, s := range stmts {
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
