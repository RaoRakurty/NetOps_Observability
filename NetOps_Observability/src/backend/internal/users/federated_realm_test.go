// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package users

// federated_realm_test.go — the realm contract for UpsertFederatedInRealm, run
// against BOTH backends through the Repo seam so the file and Postgres stores
// cannot drift.
//
// THE DEFECT THIS CLOSES. Per-tenant SSO URLs validated the CONNECTION against
// the realm in the URL and never the ACCOUNT. UpsertFederated keys on a GLOBAL
// username: for an account that already existed it merged the IdP's profile in
// and returned the STORED user with its ORIGINAL tenant, so an administrator of
// tenant B — who may register an IdP of their own — could name a username owned
// by tenant A and be handed a session in A. The merge write was damage of its
// own: it rewrote the victim's role and auth source.
//
// The realm is enforced HERE, inside the lock (file) and the row-locking
// transaction (pg), because a caller-side pre-check leaves that write racing.

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"netops/backend/internal/platformdb"
)

// realmOf builds the constraint a tenant-bound flow hands down: this realm
// reaches exactly these tenants. The real one is derived from the tenant
// directory (an /org/{id} locator reaches every tenant its org owns); the store
// only ever sees the answer.
func realmOf(tenants ...string) Realm {
	return Realm{Reaches: func(accountTenant string) bool {
		for _, t := range tenants {
			if t == accountTenant {
				return true
			}
		}
		return false
	}}
}

func runFederatedRealmContract(t *testing.T, newStore func(t *testing.T, d Deps) Repo) {
	t.Helper()
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
	s := newStore(t, d)

	// The victim: tenant A's federated account, provisioned by LDAP.
	if _, err := s.UpsertFederatedInRealm("alice", "alice@a.example", "Alice", "read-only", "ldap", "t_a", Realm{}); err != nil {
		t.Fatalf("seed victim: %v", err)
	}

	t.Run("another realm cannot take over an existing account", func(t *testing.T) {
		_, err := s.UpsertFederatedInRealm("alice", "attacker@b.example", "Not Alice", "super-admin", "oidc", "t_b", realmOf("t_b"))
		if !errors.Is(err, ErrForeignTenant) {
			t.Fatalf("cross-realm federated sign-in: err = %v, want ErrForeignTenant", err)
		}
		// AND the record is untouched. The merge write is itself the damage:
		// refusing the session but rewriting the role would still be a breach.
		got, ok := s.Get("alice")
		if !ok {
			t.Fatal("victim account vanished")
		}
		if got.TenantID != "t_a" || got.Role != "read-only" || got.AuthSource != "ldap" ||
			got.Email != "alice@a.example" || got.DisplayName != "Alice" {
			t.Fatalf("REFUSED SIGN-IN STILL WROTE: %+v, want the untouched tenant t_a / read-only / ldap record", got)
		}
	})

	t.Run("the account's own realm still signs in", func(t *testing.T) {
		u, err := s.UpsertFederatedInRealm("alice", "alice2@a.example", "Alice A", "operator", "oidc", "t_a", realmOf("t_a"))
		if err != nil {
			t.Fatalf("own-realm sign-in: %v", err)
		}
		if u.TenantID != "t_a" || u.Role != "operator" || u.Email != "alice2@a.example" {
			t.Fatalf("own-realm merge = %+v, want the refreshed profile in t_a", u)
		}
	})

	t.Run("an org realm reaches every tenant it owns", func(t *testing.T) {
		// The /org/{id} locator: one realm, several member tenants. String
		// equality on the flow's tenant would refuse this legitimate sign-in.
		u, err := s.UpsertFederatedInRealm("alice", "", "", "read-only", "oidc", "t_a2", realmOf("t_a", "t_a2"))
		if err != nil {
			t.Fatalf("org-realm sign-in: %v", err)
		}
		if u.TenantID != "t_a" {
			t.Fatalf("org-realm merge moved the account to %q — a realm never moves anyone", u.TenantID)
		}
	})

	t.Run("no constraint keeps signing in users of every tenant", func(t *testing.T) {
		// The platform-realm connection: the generic callback, unchanged. This
		// is the regression guard against the easiest wrong fix.
		u, err := s.UpsertFederatedInRealm("alice", "", "", "read-only", "oidc", "global", Realm{})
		if err != nil {
			t.Fatalf("unbound sign-in: %v", err)
		}
		if u.TenantID != "t_a" {
			t.Fatalf("unbound merge = tenant %q, want the account's own t_a", u.TenantID)
		}
	})

	t.Run("a new account is created in the realm", func(t *testing.T) {
		u, err := s.UpsertFederatedInRealm("bob", "bob@b.example", "Bob", "operator", "oidc", "t_b", realmOf("t_b"))
		if err != nil {
			t.Fatalf("create in realm: %v", err)
		}
		if u.TenantID != "t_b" || u.Role != "operator" || u.Status != "active" {
			t.Fatalf("created user = %+v, want an active operator in t_b", u)
		}
	})

	t.Run("a new account outside the realm is refused", func(t *testing.T) {
		// Defence in depth: the caller derives the provisioning tenant from the
		// connection it already checked, so the two must never disagree.
		if _, err := s.UpsertFederatedInRealm("carol", "", "", "operator", "oidc", "t_a", realmOf("t_b")); !errors.Is(err, ErrForeignTenant) {
			t.Fatalf("create outside the realm: err = %v, want ErrForeignTenant", err)
		}
		if _, ok := s.Get("carol"); ok {
			t.Fatal("a refused creation still wrote an account")
		}
	})

	t.Run("a local account is still refused as a local account", func(t *testing.T) {
		// H1 must keep its own typed answer: the realm check must not shadow it,
		// because the caller's message for the two cases is different.
		if _, err := s.CreateFull(User{Username: "dave", Role: "admin", TenantID: "t_a"}, "Passw0rd!2345"); err != nil {
			t.Fatalf("create local: %v", err)
		}
		if _, err := s.UpsertFederatedInRealm("dave", "", "", "operator", "oidc", "t_b", realmOf("t_b")); !errors.Is(err, ErrLocalAccount) {
			t.Fatalf("local account under a foreign realm: err = %v, want ErrLocalAccount", err)
		}
	})

	t.Run("UpsertFederated stays unconstrained", func(t *testing.T) {
		// The legacy signature is the unbound flow's door and must keep behaving
		// exactly as it did (federated_contract_test.go pins that as an
		// anti-escalation property: the tenant argument never moves an account).
		u, err := s.UpsertFederated("alice", "", "", "read-only", "oidc", "t_b")
		if err != nil {
			t.Fatalf("UpsertFederated: %v", err)
		}
		if u.TenantID != "t_a" {
			t.Fatalf("UpsertFederated moved the account to %q", u.TenantID)
		}
	})
}

func TestFileStoreFederatedRealmContract(t *testing.T) {
	runFederatedRealmContract(t, func(t *testing.T, d Deps) Repo {
		s, err := NewFileStore(filepath.Join(t.TempDir(), "users.json"), d)
		if err != nil {
			t.Fatalf("NewFileStore: %v", err)
		}
		return s
	})
}

// Gated on DATABASE_URL_TEST like every pg-backed test (a superuser DSN; the
// fixture provisions the non-superuser app role FORCE RLS actually applies to).
func TestPGStoreFederatedRealmContract(t *testing.T) {
	adminDSN := os.Getenv("DATABASE_URL_TEST")
	if adminDSN == "" {
		t.Skip("set DATABASE_URL_TEST to run the Postgres federated-realm contract test")
	}
	ctx := context.Background()
	ps, err := platformdb.NewPGStore(ctx, provisionAppRole(ctx, t, adminDSN))
	if err != nil {
		t.Fatalf("newPgStore: %v", err)
	}
	defer ps.DB().Close()
	runFederatedRealmContract(t, func(t *testing.T, d Deps) Repo {
		s, err := NewPGStore(ps.DB(), d)
		if err != nil {
			t.Fatalf("NewPGStore: %v", err)
		}
		return s
	})
}
