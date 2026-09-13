// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package users

// identity_guard_contract_test.go — the properties the deleted
// federated_contract_test.go / federated_realm_test.go pinned on the
// USERNAME-keyed UpsertFederated surface, re-asserted on the TUPLE path that
// replaced it (tracker 300). Nothing they proved is lost:
//
//   - SR-025: the guard is consulted with (role, tenant, principal, source) on
//     every federated write, its VERDICT — never the raw IdP role — is what
//     persists, and it is NOT consulted when the write is refused outright;
//   - H1 keeps its own typed answer and the realm check does not shadow it;
//   - the pre-stamp (`auth_source = ""`) legacy row is normalised to `local` when
//     the Postgres store opens, so H1's refusal covers the bootstrap admin.
//
// Both backends, through the Repo seam, so the file store and Postgres cannot
// drift.

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"netops/backend/internal/platformdb"
)

// guardDeps is identityTestDeps with a guard that applies the REAL SR-025 deny
// shape (global tenant + super-admin ⇒ downgrade) so the store-side wiring can be
// judged by what it persists, not only by what it calls.
func guardDeps() (Deps, *[]guardCall) {
	calls := &[]guardCall{}
	d, _ := identityTestDeps(contractEpoch)
	d.GuardRole = func(role, tenant, principal, source string) string {
		*calls = append(*calls, guardCall{role, tenant, principal, source})
		if tenant == "global" && role == "super-admin" {
			return "read-only" // the SR-025 downgrade verdict
		}
		return role
	}
	return d, calls
}

func runIdentityGuardContract(t *testing.T, newStore func(t *testing.T, d Deps) Repo) {
	t.Helper()

	t.Run("provisioning persists the guard's verdict, never the raw IdP role", func(t *testing.T) {
		d, calls := guardDeps()
		s := newStore(t, d)
		// A platform-owner mapping arriving from an IdP: the guard downgrades it,
		// and the DOWNGRADED role is what reaches the store.
		u, err := s.ResolveFederated(oidcA("global", kcIssuer, "sub-guard-new", "o@x.com", "Owner", "super-admin"), Realm{}, true)
		if err != nil {
			t.Fatalf("provision: %v", err)
		}
		if u.Role != "read-only" {
			t.Fatalf("role = %q, want the guard's downgraded verdict", u.Role)
		}
		if stored, _ := s.Get(u.ID); stored.Role != "read-only" {
			t.Fatalf("persisted role = %q — the raw super-admin role must never be written", stored.Role)
		}
		if len(*calls) == 0 {
			t.Fatal("the guard was never consulted on a federated provision")
		}
		last := (*calls)[len(*calls)-1]
		if last.role != "super-admin" || last.tenant != "global" || last.source != ProtocolOIDC {
			t.Errorf("guard call = %+v, want the raw role judged against the provisioning tenant and door", last)
		}
		// The PRINCIPAL handed to the guard is the opaque id — an audit line must
		// never carry an IdP-derived handle (§4.9).
		if last.username != u.ID {
			t.Errorf("guard principal = %q, want the account id %q", last.username, u.ID)
		}
	})

	t.Run("a refresh judges the role against the account's EXISTING tenant", func(t *testing.T) {
		d, calls := guardDeps()
		s := newStore(t, d)
		first, err := s.ResolveFederated(oidcA(tenantA, kcIssuer, "sub-guard-refresh", "", "", "read-only"), Realm{}, true)
		if err != nil {
			t.Fatalf("seed: %v", err)
		}
		*calls = nil
		// The UNBOUND door (one platform config signing in every tenant) is where
		// the assertion's tenant and the ACCOUNT's tenant legitimately differ. The
		// IdP now maps super-admin and the assertion carries the GLOBAL tenant:
		// neither may move the account, and the guard must judge against tenant A
		// — where the grant would actually apply — not against the claim. Judging
		// against the claim would hand out the platform-owner downgrade (or fail
		// to) for the wrong realm.
		again, err := s.ResolveFederatedUnbound(oidcA("global", kcIssuer, "sub-guard-refresh", "", "", "super-admin"))
		if err != nil {
			t.Fatalf("refresh: %v", err)
		}
		if again.ID != first.ID || again.TenantID != tenantA {
			t.Fatalf("the assertion moved the account: %+v", again)
		}
		if len(*calls) != 1 {
			t.Fatalf("guard consulted %d times on one refresh, want 1", len(*calls))
		}
		if (*calls)[0].tenant != tenantA {
			t.Errorf("guard tenant = %q, want the account's existing %q", (*calls)[0].tenant, tenantA)
		}
		if again.Role != "super-admin" {
			t.Errorf("role = %q — tenant A is not the platform realm, so the guard permits the mapping", again.Role)
		}
	})

	t.Run("the guard is not consulted when the write is refused", func(t *testing.T) {
		d, calls := guardDeps()
		s := newStore(t, d)
		if _, err := s.CreateFull(User{Username: "locadmin", Role: "admin", TenantID: tenantA}, strongPass); err != nil {
			t.Fatalf("create local: %v", err)
		}
		*calls = nil
		// H1 at the key level: an assertion cannot even NAME the local namespace.
		// Its verdict is irrelevant, so it must not be asked for one.
		bad := Assertion{Identity: Identity{TenantID: tenantA, Issuer: LocalIssuer, Subject: "locadmin", Protocol: ProtocolOIDC},
			Role: "super-admin"}
		if _, err := s.ResolveFederated(bad, Realm{}, true); !errors.Is(err, ErrLocalAccount) {
			t.Fatalf("err = %v, want ErrLocalAccount", err)
		}
		if len(*calls) != 0 {
			t.Errorf("guard consulted %d times on a refused write", len(*calls))
		}
		if got, _ := s.Get("locadmin"); got.Role != "" && got.Role != "admin" {
			t.Errorf("the local account was mutated: %+v", got)
		}
	})

	t.Run("H1 keeps its own typed answer under a foreign realm", func(t *testing.T) {
		// The realm check must not SHADOW the local-account refusal: the caller's
		// message for the two cases is different (one says "sign in locally", the
		// other says nothing at all).
		d, _ := guardDeps()
		s := newStore(t, d)
		if _, err := s.CreateFull(User{Username: "dave", Role: "admin", TenantID: tenantA}, strongPass); err != nil {
			t.Fatalf("create local: %v", err)
		}
		bad := Assertion{Identity: Identity{TenantID: tenantB, Issuer: LocalIssuer, Subject: "dave", Protocol: ProtocolOIDC}}
		if _, err := s.ResolveFederated(bad, realmOf(tenantB), true); !errors.Is(err, ErrLocalAccount) {
			t.Fatalf("local namespace under a foreign realm: err = %v, want ErrLocalAccount", err)
		}
	})

	t.Run("an administratively created FEDERATED account is refused", func(t *testing.T) {
		// A federated account exists only as the result of a verified assertion
		// (§2.5): only a door can know its issuer and subject.
		d, _ := guardDeps()
		s := newStore(t, d)
		_, err := s.CreateFull(User{Username: "fed-by-hand", Role: "admin", TenantID: tenantA, AuthSource: ProtocolOIDC}, strongPass)
		if !errors.Is(err, ErrFederatedCreate) {
			t.Fatalf("err = %v, want ErrFederatedCreate", err)
		}
	})
}

func TestFileStoreIdentityGuardContract(t *testing.T) {
	runIdentityGuardContract(t, newFileStoreForContract)
}

func TestPGStoreIdentityGuardContract(t *testing.T) {
	adminDSN := os.Getenv("DATABASE_URL_TEST")
	if adminDSN == "" {
		t.Skip("set DATABASE_URL_TEST to run the Postgres identity guard contract")
	}
	ctx := context.Background()
	ps, err := platformdb.NewPGStore(ctx, provisionAppRole(ctx, t, adminDSN))
	if err != nil {
		t.Fatalf("newPgStore: %v", err)
	}
	defer ps.DB().Close()
	runIdentityGuardContract(t, func(t *testing.T, d Deps) Repo {
		s, err := NewPGStore(ps.DB(), d)
		if err != nil {
			t.Fatalf("NewPGStore: %v", err)
		}
		return s
	})
}

// TestPGStoreMigratesEmptyAuthSource — pg twin of the FileStore load migration
// (H1): a row written before the AuthSource stamp (auth_source "") is normalized
// to "local" when the store opens, so the local-account refusal covers the
// pre-existing bootstrap admin. Ported from the deleted
// federated_contract_test.go onto the resolve path. Gated on DATABASE_URL_TEST.
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
		DefaultTenant:   "global",
		MigrationMarker: contractEpoch,
	}
	s, err := NewPGStore(ps.DB(), d) // constructor runs the one-time migration
	if err != nil {
		t.Fatalf("NewPGStore: %v", err)
	}
	u, ok := s.Get("legacyadmin")
	if !ok || u.AuthSource != "local" {
		t.Fatalf("legacy row after open: AuthSource=%q ok=%v, want \"local\"", u.AuthSource, ok)
	}
	// …and no federated assertion can reach it, even carrying the strongest claim
	// available: that very login name, which is the ONE string §2.6 consults.
	// Condition 2 refuses it because the account is LOCAL, so a fresh account is
	// provisioned instead — the "flagged, never guessed" outcome.
	//
	// (The row stays identity-PENDING here only because it is seeded AFTER
	// migration 0050 has already run; in production the local backfill is that
	// migration, and any local row created later inserts its identity in the same
	// statement as the account. Which is exactly why H1 may not depend on the
	// identity row existing — and does not.)
	a := oidcA("global", kcIssuer, "legacyadmin", "a@idp", "IdP", "super-admin")
	a.LegacyUsername = "legacyadmin"
	fed, err := s.ResolveFederated(a, Realm{}, true)
	if err != nil {
		t.Fatalf("federated assertion naming the migrated admin's handle: %v", err)
	}
	if fed.ID == u.ID {
		t.Fatalf("a federated assertion reached the migrated LOCAL admin %q", u.ID)
	}
	if after, _ := s.Get(u.ID); after.Role != "admin" || after.AuthSource != "local" {
		t.Fatalf("the migrated local admin was mutated: %+v", after)
	}
}
