// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package users

// identity_contract_test.go — the tracker 300 security contract, run against
// BOTH backends through the Repo seam so the file store and Postgres cannot
// drift. It is design §5 tests 1–6 (the store half of 7 and 8, and all of 9's
// store half) plus the JIT/disabled and read-only-door rules.
//
// THE PREMISE IT RETIRES. Before this change the username was one GLOBAL,
// case-insensitive identity key. Proven red on the pre-change code:
//
//	CreateFull(admin @ t_aaaaaaa) → ok
//	CreateFull(admin @ t_bbbbbbb) → `user "admin" already exists`
//	UpsertFederated("jdoe", …, "oidc", t_a) then ("jdoe", …, "ldap", t_b)
//	  → count=1, role="operator", email="jdoe@b.example", tenant="t_aaaaaaa"
//	  — two unrelated directories MERGED into one account.
//
// Both are now impossible, and every assertion below says so in one direction or
// the other.
//
// FIXTURE RULE (design §5): every account the contract creates has ID !=
// Username, so any path still keying on the username fails loudly rather than
// passing by coincidence.

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"netops/backend/internal/platformdb"
)

// The pinned migration epochs. Pinning them (Deps.MigrationMarker) is what lets
// the §2.6 conditions be proven without sleeping or backdating a clock: a fixture
// account simply carries a CreatedAt on one side of the epoch.
var (
	// identityEpoch sits between the legacy-bind contract's "pre" and "post"
	// fixtures.
	identityEpoch = time.Date(2026, 9, 13, 12, 0, 0, 0, time.UTC)
	// contractEpoch is far in the future, so every account the main contract
	// creates counts as pre-migration. That is deliberate: it makes §2.6
	// condition 3 (created before the epoch) PASS, so the refusals the main
	// contract asserts come from the conditions it is actually testing —
	// "already bound", "not the same door" — rather than passing vacuously.
	contractEpoch = time.Date(2099, 1, 1, 0, 0, 0, 0, time.UTC)
)

const (
	kcIssuer   = "https://kc.example.com/realms/correlix"
	kcIssuer2  = "https://kc.example.com/realms/other"
	dirIssuer  = "ldap:dir.example.com:389"
	tacIssuer  = "tacacs:tac1.example.com:49"
	tenantA    = "t_aaaaaaaa1111"
	tenantB    = "t_bbbbbbbb2222"
	strongPass = "Passw0rd!2345"
)

// identityEvents records everything the store REPORTS rather than does itself:
// the SR-025 role-guard calls, the §2.6 legacy-bind notifications, and the error
// sink. The store must not import audit, so these are how it tells the
// integrator what happened.
type identityEvents struct {
	guard  []guardCall
	bound  []string // ids adopted by the lazy bind
	errors []string
}

func identityTestDeps(marker time.Time) (Deps, *identityEvents) {
	ev := &identityEvents{}
	seed, n := time.Now().UnixNano(), 0
	return Deps{
		KV:     fileKV{},
		Errorf: func(_, msg string, _ map[string]any) { ev.errors = append(ev.errors, msg) },
		GuardRole: func(role, tenant, principal, source string) string {
			ev.guard = append(ev.guard, guardCall{role, tenant, principal, source})
			return role
		},
		IsSuperAdmin: func(role string) bool { return role == "super-admin" || role == "admin" },
		ApplyPasswordChange: func(u *User, hash string, now time.Time) {
			u.PasswordHash = hash
			u.PasswordChangedAt = now
		},
		DefaultTenant: "global",
		// The fixture rule: an opaque id that can never equal a username.
		MintID:          func() string { n++; return fmt.Sprintf("u_%013x%04d", seed, n) },
		MigrationMarker: marker,
		OnLegacyBound:   func(u User, _ Assertion) { ev.bound = append(ev.bound, u.ID) },
	}, ev
}

// oidcA builds the assertion the OIDC callback would hand down: the verified
// issuer and `sub`, with the profile attributes beside them.
func oidcA(tenant, issuer, sub, email, name, role string) Assertion {
	return Assertion{
		Identity:    Identity{TenantID: tenant, Issuer: issuer, Subject: sub, Protocol: ProtocolOIDC},
		Email:       email,
		DisplayName: name,
		Role:        role,
	}
}

func identityOf(t *testing.T, u User) Identity {
	t.Helper()
	if u.Identity == nil {
		t.Fatalf("account %q has no identity (identity_status: pending)", u.ID)
	}
	return *u.Identity
}

// ---------------------------------------------------------------------------
// The contract
// ---------------------------------------------------------------------------

func runIdentityContract(t *testing.T, newStore func(t *testing.T, d Deps) Repo) {
	t.Helper()
	d, ev := identityTestDeps(contractEpoch)
	s := newStore(t, d)

	// ---- design §5.6 — local auth is its own namespace, per tenant ---------
	t.Run("6 a local username is per-tenant, not global", func(t *testing.T) {
		a, err := s.CreateFull(User{Username: "admin", Role: "admin", TenantID: tenantA}, strongPass)
		if err != nil {
			t.Fatalf("tenant A admin: %v", err)
		}
		// THE RED-BEFORE CASE: this line used to fail with `user "admin" already
		// exists`, because the username was one global key.
		b, err := s.CreateFull(User{Username: "admin", Role: "admin", TenantID: tenantB}, strongPass)
		if err != nil {
			t.Fatalf("tenant B must own its own admin: %v", err)
		}
		if a.ID == b.ID || a.ID == "" || b.ID == "" {
			t.Fatalf("two tenants' admins share an id: %q / %q", a.ID, b.ID)
		}
		// The fixture rule, asserted rather than assumed.
		if a.ID == a.Username || b.ID == b.Username {
			t.Fatalf("fixture rule broken: id equals username (%q / %q)", a.ID, b.ID)
		}
		for _, tc := range []struct {
			u    User
			want identityKey
		}{
			{a, identityKey{tenantA, LocalIssuer, "admin"}},
			{b, identityKey{tenantB, LocalIssuer, "admin"}},
		} {
			if got := identityOf(t, tc.u).key(); got != tc.want {
				t.Errorf("identity of %q = %+v, want %+v", tc.u.ID, got, tc.want)
			}
			if got := identityOf(t, tc.u).Provenance; got != ProvenanceAsserted {
				t.Errorf("provenance = %q, want %q", got, ProvenanceAsserted)
			}
		}
		// …and WITHIN a tenant the name is still unique. This is the PK refusing,
		// not an app-layer check: the same row shape the database rejects.
		if _, err := s.CreateFull(User{Username: "ADMIN", Role: "admin", TenantID: tenantA}, strongPass); !errors.Is(err, ErrUsernameTaken) {
			t.Fatalf("duplicate local username in one tenant: err = %v, want ErrUsernameTaken", err)
		}
		// Resolution by handle is tenant-scoped…
		if got, ok := s.LookupLocal(tenantA, "ADMIN"); !ok || got.ID != a.ID {
			t.Errorf("LookupLocal(%s, ADMIN) = %q/%v, want %q", tenantA, got.ID, ok, a.ID)
		}
		if _, ok := s.LookupLocal("t_nobody", "admin"); ok {
			t.Error("LookupLocal found an account in a tenant that has none")
		}
		// …and the unbound form reports the AMBIGUITY rather than picking one.
		many, ok := s.LookupLocalAny("admin")
		if !ok || len(many) != 2 {
			t.Fatalf("LookupLocalAny(admin) = %d accounts, want 2 (the caller refuses generically)", len(many))
		}
		// The username is no longer a key: Get resolves ids only.
		if _, ok := s.Get("admin"); ok {
			t.Error("Get(\"admin\") resolved — the username must not be a principal id any more")
		}
		if got, ok := s.Get(a.ID); !ok || got.Username != "admin" {
			t.Errorf("Get(%q) = %+v/%v, want the tenant-A admin", a.ID, got, ok)
		}
	})

	// ---- design §5.3/5.4/5.5 — no linking, ever ---------------------------
	t.Run("3 the same subject from two issuers is two accounts", func(t *testing.T) {
		const sub = "3f0a1b2c-dead-beef"
		one, err := s.ResolveFederated(oidcA(tenantA, kcIssuer, sub, "x@example.com", "X", "read-only"), Realm{}, true)
		if err != nil {
			t.Fatalf("issuer 1: %v", err)
		}
		two, err := s.ResolveFederated(oidcA(tenantA, kcIssuer2, sub, "x@example.com", "X", "read-only"), Realm{}, true)
		if err != nil {
			t.Fatalf("issuer 2: %v", err)
		}
		if one.ID == two.ID {
			t.Fatalf("the same sub from two issuers was LINKED into one account (%q)", one.ID)
		}
		if identityOf(t, one).Issuer == identityOf(t, two).Issuer {
			t.Fatal("the two accounts share an issuer — the fixture is wrong")
		}
		// And the tenant is in the key too: the same tuple in another tenant is
		// another principal.
		three, err := s.ResolveFederated(oidcA(tenantB, kcIssuer, sub, "x@example.com", "X", "read-only"), Realm{}, true)
		if err != nil {
			t.Fatalf("tenant B: %v", err)
		}
		if three.ID == one.ID {
			t.Fatalf("the same (issuer, subject) in another tenant resolved to tenant A's account %q", one.ID)
		}
	})

	t.Run("4 the same email from two issuers is two accounts", func(t *testing.T) {
		const email = "shared@example.com"
		one, err := s.ResolveFederated(oidcA(tenantA, kcIssuer, "sub-email-1", email, "One", "read-only"), Realm{}, true)
		if err != nil {
			t.Fatalf("issuer 1: %v", err)
		}
		two, err := s.ResolveFederated(oidcA(tenantA, kcIssuer2, "sub-email-2", email, "Two", "read-only"), Realm{}, true)
		if err != nil {
			t.Fatalf("issuer 2: %v", err)
		}
		if one.ID == two.ID {
			t.Fatalf("two issuers sharing an email were LINKED into %q", one.ID)
		}
		// Email is a PROFILE attribute: refreshed on the way past, never a key.
		again, err := s.ResolveFederated(oidcA(tenantA, kcIssuer, "sub-email-1", "moved@example.com", "One", "read-only"), Realm{}, true)
		if err != nil {
			t.Fatalf("refresh: %v", err)
		}
		if again.ID != one.ID {
			t.Fatalf("a changed email moved the account from %q to %q", one.ID, again.ID)
		}
		if again.Email != "moved@example.com" {
			t.Errorf("email = %q, want the refreshed profile value", again.Email)
		}
	})

	t.Run("5 the same login name across oidc, ldap and tacacs is three accounts", func(t *testing.T) {
		const login = "jdoe"
		mk := func(issuer, protocol, subject string) Assertion {
			return Assertion{
				Identity:    Identity{TenantID: tenantA, Issuer: issuer, Subject: subject, Protocol: protocol},
				Email:       login + "@example.com",
				DisplayName: "J Doe",
				Role:        "read-only",
				// The legacy derivation of each door is the SAME string — which is
				// exactly what used to fuse them. It may not link them now.
				LegacyUsername: login,
			}
		}
		ids := map[string]string{}
		for _, tc := range []struct{ name, issuer, protocol, subject string }{
			{"oidc", kcIssuer, ProtocolOIDC, "oidc-sub-jdoe"},
			{"ldap", dirIssuer, ProtocolLDAP, "cn=jdoe,ou=people,dc=example,dc=com"},
			{"tacacs", tacIssuer, ProtocolTACACS, login},
		} {
			u, err := s.ResolveFederated(mk(tc.issuer, tc.protocol, tc.subject), Realm{}, true)
			if err != nil {
				t.Fatalf("%s: %v", tc.name, err)
			}
			for prev, id := range ids {
				if id == u.ID {
					t.Fatalf("%s and %s were LINKED into one account (%q)", prev, tc.name, u.ID)
				}
			}
			ids[tc.name] = u.ID
			if u.Username != u.ID {
				t.Errorf("%s: federated username = %q, want the opaque id (it is never displayed or typed)", tc.name, u.Username)
			}
			if got := identityOf(t, u).Protocol; got != tc.protocol {
				t.Errorf("%s: protocol = %q, want %q", tc.name, got, tc.protocol)
			}
		}
		if len(ids) != 3 {
			t.Fatalf("got %d accounts, want 3", len(ids))
		}
	})

	t.Run("6 a federated assertion can never name the local namespace", func(t *testing.T) {
		// H1 at the KEY level: the local namespace is not addressable from a
		// federated door, however the subject is spelled.
		for name, a := range map[string]Assertion{
			"local issuer":   {Identity: Identity{TenantID: tenantA, Issuer: LocalIssuer, Subject: "admin", Protocol: ProtocolOIDC}},
			"local protocol": {Identity: Identity{TenantID: tenantA, Issuer: kcIssuer, Subject: "admin", Protocol: ProtocolLocal}},
		} {
			if _, err := s.ResolveFederated(a, Realm{}, true); !errors.Is(err, ErrLocalAccount) {
				t.Errorf("%s: err = %v, want ErrLocalAccount", name, err)
			}
		}
		// And a federated subject that happens to EQUAL a local username gets its
		// own account; the local record is untouched.
		local, ok := s.LookupLocal(tenantA, "admin")
		if !ok {
			t.Fatal("fixture: tenant A admin missing")
		}
		fed, err := s.ResolveFederated(oidcA(tenantA, kcIssuer, "admin", "", "", "super-admin"), Realm{}, true)
		if err != nil {
			t.Fatalf("federated subject == local username: %v", err)
		}
		if fed.ID == local.ID {
			t.Fatalf("a federated assertion reached the LOCAL account %q", local.ID)
		}
		after, _ := s.Get(local.ID)
		if after.Role != local.Role || after.AuthSource != ProtocolLocal || after.Email != local.Email {
			t.Fatalf("the local account was mutated by a federated sign-in: %+v", after)
		}
	})

	// ---- design §5.1/5.2 — the two database constraints --------------------
	t.Run("1 the same tuple always resolves to the same account", func(t *testing.T) {
		a := oidcA(tenantA, kcIssuer, "sub-stable", "s@example.com", "S", "read-only")
		first, err := s.ResolveFederated(a, Realm{}, true)
		if err != nil {
			t.Fatalf("first: %v", err)
		}
		before := s.Count()
		for i := 0; i < 3; i++ {
			again, err := s.ResolveFederated(a, Realm{}, true)
			if err != nil {
				t.Fatalf("repeat %d: %v", i, err)
			}
			if again.ID != first.ID {
				t.Fatalf("repeat %d resolved to %q, want %q", i, again.ID, first.ID)
			}
		}
		if s.Count() != before {
			t.Fatalf("repeated resolution created rows: count %d → %d", before, s.Count())
		}
		// The id is the deterministic function of the tuple (§2.4), so a re-run
		// migration and a JIT race converge without coordination.
		if want := FederatedID(tenantA, kcIssuer, "sub-stable"); first.ID != want {
			t.Errorf("id = %q, want the derived %q", first.ID, want)
		}
	})

	t.Run("2 a second identity cannot be attached to an account", func(t *testing.T) {
		// The account is already bound, so the §2.6 adoption path (the ONLY path
		// that could ever attach a tuple to an existing account) must refuse it —
		// and the new assertion gets its own account instead.
		bound, err := s.ResolveFederated(oidcA(tenantA, kcIssuer, "sub-onlyone", "", "", "read-only"), Realm{}, true)
		if err != nil {
			t.Fatalf("provision: %v", err)
		}
		second := oidcA(tenantA, kcIssuer2, "sub-onlyone-b", "", "", "read-only")
		second.LegacyUsername = bound.Username // == bound.ID: the strongest claim available
		other, err := s.ResolveFederated(second, Realm{}, true)
		if err != nil {
			t.Fatalf("second assertion: %v", err)
		}
		if other.ID == bound.ID {
			t.Fatalf("a second identity was attached to %q", bound.ID)
		}
		if got := identityOf(t, other).Issuer; got != kcIssuer2 {
			t.Errorf("second account issuer = %q, want %q", got, kcIssuer2)
		}
		// The first account's identity is unchanged.
		reread, _ := s.Get(bound.ID)
		if got := identityOf(t, reread).key(); got != (identityKey{tenantA, kcIssuer, "sub-onlyone"}) {
			t.Errorf("the bound account's identity changed: %+v", got)
		}
		// A profile patch cannot edit the tuple either — an identity is asserted,
		// never edited.
		patched, err := s.Update(bound.ID, User{DisplayName: "Renamed"})
		if err != nil {
			t.Fatalf("update: %v", err)
		}
		if got := identityOf(t, patched).key(); got != (identityKey{tenantA, kcIssuer, "sub-onlyone"}) {
			t.Errorf("Update rewrote the identity: %+v", got)
		}
	})

	// ---- design §5.8 — the C3 realm rule, re-asserted on the tuple path ---
	t.Run("8 another realm cannot take over an account, and writes nothing", func(t *testing.T) {
		victim, err := s.ResolveFederated(
			oidcA(tenantA, kcIssuer, "sub-victim", "alice@a.example", "Alice", "read-only"), Realm{}, true)
		if err != nil {
			t.Fatalf("seed victim: %v", err)
		}
		attack := oidcA(tenantA, kcIssuer, "sub-victim", "attacker@b.example", "Not Alice", "super-admin")
		if _, err := s.ResolveFederated(attack, realmOf(tenantB), true); !errors.Is(err, ErrForeignTenant) {
			t.Fatalf("cross-realm sign-in: err = %v, want ErrForeignTenant", err)
		}
		// The merge write is ITSELF the damage: refusing the session but rewriting
		// the role would still be a breach.
		after, ok := s.Get(victim.ID)
		if !ok {
			t.Fatal("victim vanished")
		}
		if after.Role != "read-only" || after.Email != "alice@a.example" || after.DisplayName != "Alice" || after.TenantID != tenantA {
			t.Fatalf("REFUSED SIGN-IN STILL WROTE: %+v", after)
		}
		// An org realm that owns the tenant still signs in.
		if _, err := s.ResolveFederated(
			oidcA(tenantA, kcIssuer, "sub-victim", "", "", "read-only"), realmOf(tenantA, "t_a2"), true); err != nil {
			t.Fatalf("own-realm sign-in refused: %v", err)
		}
	})

	t.Run("8 provisioning outside the realm writes nothing", func(t *testing.T) {
		before := s.Count()
		if _, err := s.ResolveFederated(
			oidcA(tenantA, kcIssuer, "sub-outside", "", "", "read-only"), realmOf(tenantB), true); !errors.Is(err, ErrForeignTenant) {
			t.Fatalf("err = %v, want ErrForeignTenant", err)
		}
		if s.Count() != before {
			t.Fatalf("a refused provision still wrote: count %d → %d", before, s.Count())
		}
	})

	// ---- JIT never resurrects a disabled account (design §4.2.5) ----------
	t.Run("JIT never resurrects a disabled account", func(t *testing.T) {
		u, err := s.ResolveFederated(oidcA(tenantA, kcIssuer, "sub-disabled", "", "", "read-only"), Realm{}, true)
		if err != nil {
			t.Fatalf("provision: %v", err)
		}
		if _, err := s.Update(u.ID, User{Status: "disabled"}); err != nil {
			t.Fatalf("disable: %v", err)
		}
		again, err := s.ResolveFederated(oidcA(tenantA, kcIssuer, "sub-disabled", "", "", "super-admin"), Realm{}, true)
		if err != nil {
			t.Fatalf("re-login: %v", err)
		}
		if again.ID != u.ID {
			t.Fatalf("a second account was provisioned for a disabled principal: %q", again.ID)
		}
		if again.Status != "disabled" {
			t.Fatalf("status = %q — JIT must return the account AS IS so the caller refuses it", again.Status)
		}
		if stored, _ := s.Get(u.ID); stored.Status != "disabled" {
			t.Fatalf("the stored account was re-enabled by a sign-in: %+v", stored)
		}
	})

	// ---- the read-only (elevation) door ----------------------------------
	t.Run("the read-only door never provisions and never binds by username", func(t *testing.T) {
		before := s.Count()
		a := oidcA(tenantA, kcIssuer, "sub-elevation-unknown", "", "", "read-only")
		a.LegacyUsername = "admin" // the tenant-A local admin: must not help
		if _, err := s.ResolveFederated(a, Realm{}, false); !errors.Is(err, ErrNoSuchUser) {
			t.Fatalf("find-only on a tuple miss: err = %v, want ErrNoSuchUser", err)
		}
		if s.Count() != before {
			t.Fatalf("the read-only door wrote: count %d → %d", before, s.Count())
		}
		// A tuple HIT still resolves, which is what elevation needs.
		known, err := s.ResolveFederated(oidcA(tenantA, kcIssuer, "sub-elevation", "", "", "read-only"), Realm{}, true)
		if err != nil {
			t.Fatalf("seed: %v", err)
		}
		got, err := s.ResolveFederated(oidcA(tenantA, kcIssuer, "sub-elevation", "", "", "read-only"), Realm{}, false)
		if err != nil {
			t.Fatalf("find-only on a tuple hit: %v", err)
		}
		if got.ID != known.ID {
			t.Fatalf("find-only resolved %q, want %q", got.ID, known.ID)
		}
	})

	// ---- the unbound (platform-default connection) form -------------------
	t.Run("unbound resolution refuses an ambiguous identity", func(t *testing.T) {
		const sub = "sub-ambiguous"
		a1, err := s.ResolveFederated(oidcA(tenantA, kcIssuer, sub, "", "", "read-only"), Realm{}, true)
		if err != nil {
			t.Fatalf("tenant A: %v", err)
		}
		a2, err := s.ResolveFederated(oidcA(tenantB, kcIssuer, sub, "", "", "read-only"), Realm{}, true)
		if err != nil {
			t.Fatalf("tenant B: %v", err)
		}
		if a1.ID == a2.ID {
			t.Fatal("fixture: the two tenants share an account")
		}
		unbound := oidcA("", kcIssuer, sub, "", "", "read-only")
		if _, err := s.ResolveFederatedUnbound(unbound); !errors.Is(err, ErrAmbiguousIdentity) {
			t.Fatalf("unbound lookup over two tenants: err = %v, want ErrAmbiguousIdentity", err)
		}
	})

	t.Run("unbound resolution finds the one account across tenants", func(t *testing.T) {
		const sub = "sub-unbound-single"
		made, err := s.ResolveFederated(oidcA(tenantA, kcIssuer, sub, "", "", "read-only"), Realm{}, true)
		if err != nil {
			t.Fatalf("seed: %v", err)
		}
		got, err := s.ResolveFederatedUnbound(oidcA("", kcIssuer, sub, "", "", "read-only"))
		if err != nil {
			t.Fatalf("unbound: %v", err)
		}
		if got.ID != made.ID {
			t.Fatalf("unbound resolved %q, want %q (the account's own tenant is authoritative)", got.ID, made.ID)
		}
		if got.TenantID != tenantA {
			t.Errorf("unbound sign-in moved the account to %q", got.TenantID)
		}
		// A first sight through the unbound door provisions into the assertion's
		// tenant, falling back to the platform default.
		fresh, err := s.ResolveFederatedUnbound(oidcA("", kcIssuer, "sub-unbound-new", "", "", "read-only"))
		if err != nil {
			t.Fatalf("unbound provision: %v", err)
		}
		if fresh.TenantID != "global" {
			t.Errorf("unbound provisioning tenant = %q, want the DefaultTenant", fresh.TenantID)
		}
	})

	// ---- SR-025 is still wired, now on the opaque principal --------------
	t.Run("the role guard judges every federated write and sees the opaque id", func(t *testing.T) {
		if len(ev.guard) == 0 {
			t.Fatal("the SR-025 guard was never consulted on a federated write")
		}
		for _, c := range ev.guard {
			if strings.Contains(c.username, "@") {
				t.Errorf("the guard was handed an IdP-derived handle %q — it must receive the opaque principal id", c.username)
			}
		}
	})

	// ---- §3 Enforce -------------------------------------------------------
	t.Run("VerifyIdentityInvariants passes on a converged store", func(t *testing.T) {
		if err := s.VerifyIdentityInvariants(); err != nil {
			t.Fatalf("a store built entirely through the new API failed the enforce check: %v", err)
		}
	})

	if len(ev.errors) != 0 {
		t.Errorf("the store logged %d errors during the contract: %v", len(ev.errors), ev.errors)
	}
}

// ---------------------------------------------------------------------------
// design §5.9 — the legacy lazy bind is BOUNDED (the store half)
// ---------------------------------------------------------------------------

func runLegacyBindContract(t *testing.T, newStore func(t *testing.T, d Deps) Repo) {
	t.Helper()
	pre := identityEpoch.Add(-24 * time.Hour) // created before the migration
	post := identityEpoch.Add(24 * time.Hour) // created after it
	ldapSub := "cn=legacy,ou=people,dc=example,dc=com"

	// seedLegacy plants a PRE-TRACKER-300 row: id == lower(username), an
	// auth_source, and NO identity — the shape the username-keyed code left behind.
	seedLegacy := func(t *testing.T, s Repo, name, source, tenant, status string, created time.Time) User {
		t.Helper()
		sd, ok := s.(LegacySeeder)
		if !ok {
			t.Fatalf("%T cannot seed a legacy row — the contract cannot run", s)
		}
		u := User{Username: name, Role: "read-only", TenantID: tenant, Status: status,
			AuthSource: source, Email: name + "@old.example", CreatedAt: created}
		if err := sd.SeedLegacyForTest(u); err != nil {
			t.Fatalf("seed %s: %v", name, err)
		}
		got, ok := s.Get(strings.ToLower(name))
		if !ok {
			t.Fatalf("seeded %s is not readable by its legacy id", name)
		}
		if !got.IdentityPending() {
			t.Fatalf("seeded %s already has an identity — the fixture is wrong", name)
		}
		return got
	}

	// ldapAssertion is what the LDAP door verified, plus the legacy derivation
	// (§2.6 condition 4): for LDAP that is the typed login name.
	ldapAssertion := func(tenant, subject, legacy string) Assertion {
		return Assertion{
			Identity: Identity{TenantID: tenant, Issuer: dirIssuer, Subject: subject,
				Protocol: ProtocolLDAP, SubjectKind: SubjectKindDN, ConnectionID: ""},
			Email: "new@dir.example", DisplayName: "Legacy User", Role: "read-only",
			LegacyUsername: legacy,
		}
	}

	t.Run("binds exactly once, then never again", func(t *testing.T) {
		d, ev := identityTestDeps(identityEpoch)
		s := newStore(t, d)
		legacy := seedLegacy(t, s, "lb-once", ProtocolLDAP, tenantA, "active", pre)
		before := s.Count()

		got, err := s.ResolveFederated(ldapAssertion(tenantA, ldapSub, "lb-once"), realmOf(tenantA), true)
		if err != nil {
			t.Fatalf("bind: %v", err)
		}
		if got.ID != legacy.ID {
			t.Fatalf("the legacy account was NOT adopted: resolved %q, want %q", got.ID, legacy.ID)
		}
		if s.Count() != before {
			t.Fatalf("adoption created a row: count %d → %d", before, s.Count())
		}
		id := identityOf(t, got)
		if id.Provenance != ProvenanceLegacyLazyBound {
			t.Errorf("provenance = %q, want %q — an operator must be able to see every adoption", id.Provenance, ProvenanceLegacyLazyBound)
		}
		if id.key() != (identityKey{tenantA, dirIssuer, ldapSub}) {
			t.Errorf("bound identity = %+v, want the asserted tuple", id.key())
		}
		if id.SubjectKind != SubjectKindDN {
			t.Errorf("subject_kind = %q, want %q recorded so a later DN-vs-login change is visible", id.SubjectKind, SubjectKindDN)
		}
		if len(ev.bound) != 1 || ev.bound[0] != legacy.ID {
			t.Fatalf("OnLegacyBound fired %v, want exactly one notification for %q (audit + counter)", ev.bound, legacy.ID)
		}
		// A SECOND, DIFFERENT subject presenting the SAME legacy username gets a
		// FRESH account: the one-shot claim is spent.
		other, err := s.ResolveFederated(ldapAssertion(tenantA, "cn=impostor,dc=example,dc=com", "lb-once"), realmOf(tenantA), true)
		if err != nil {
			t.Fatalf("second subject: %v", err)
		}
		if other.ID == legacy.ID {
			t.Fatalf("a second subject adopted the already-bound account %q", legacy.ID)
		}
		if len(ev.bound) != 1 {
			t.Fatalf("OnLegacyBound fired %d times, want 1", len(ev.bound))
		}
		// And the next sign-in of the bound principal hits the TUPLE, not the name.
		again, err := s.ResolveFederated(ldapAssertion(tenantA, ldapSub, ""), realmOf(tenantA), true)
		if err != nil {
			t.Fatalf("re-login: %v", err)
		}
		if again.ID != legacy.ID {
			t.Fatalf("re-login resolved %q, want the bound %q", again.ID, legacy.ID)
		}
	})

	t.Run("the unbound door adopts and then resolves by tuple", func(t *testing.T) {
		// This is the LDAP/TACACS+ reality today: ONE platform-global directory
		// config, so the door has no per-connection tenant and resolves by
		// (issuer, subject) across tenants. The adopted identity must land in the
		// ACCOUNT's tenant — if it landed in the assertion's provisioning tenant,
		// the next sign-in would miss the tuple and duplicate the account.
		d, ev := identityTestDeps(identityEpoch)
		s := newStore(t, d)
		legacy := seedLegacy(t, s, "lb-unbound", ProtocolLDAP, tenantA, "active", pre)
		before := s.Count()

		a := ldapAssertion("", "cn=unbound,dc=example,dc=com", "lb-unbound")
		got, err := s.ResolveFederatedUnbound(a)
		if err != nil {
			t.Fatalf("unbound bind: %v", err)
		}
		if got.ID != legacy.ID {
			t.Fatalf("the legacy account was NOT adopted: resolved %q, want %q", got.ID, legacy.ID)
		}
		if s.Count() != before {
			t.Fatalf("adoption created a row: count %d → %d", before, s.Count())
		}
		id := identityOf(t, got)
		if id.TenantID != tenantA {
			t.Fatalf("identity tenant = %q, want the account's own %q", id.TenantID, tenantA)
		}
		if id.Provenance != ProvenanceLegacyLazyBound {
			t.Errorf("provenance = %q, want %q", id.Provenance, ProvenanceLegacyLazyBound)
		}
		if got.TenantID != tenantA {
			t.Errorf("the adoption MOVED the account to %q", got.TenantID)
		}
		if len(ev.bound) != 1 {
			t.Fatalf("OnLegacyBound fired %v, want one notification", ev.bound)
		}
		// And the round trip: the next sign-in hits the tuple, in the same tenant,
		// with no legacy username at all.
		again, err := s.ResolveFederatedUnbound(ldapAssertion("", "cn=unbound,dc=example,dc=com", ""))
		if err != nil {
			t.Fatalf("re-login: %v", err)
		}
		if again.ID != legacy.ID {
			t.Fatalf("re-login resolved %q, want the bound %q — the tuple did not land where the lookup looks", again.ID, legacy.ID)
		}
		if s.Count() != before {
			t.Fatalf("re-login duplicated the account: count %d → %d", before, s.Count())
		}
	})

	// Each refusal below provisions a FRESH account instead — which is exactly
	// design §2.6's "flagged, never guessed" outcome for ambiguous provenance.
	// Every case is ONE condition failing, with the rest satisfied.
	for _, tc := range []struct {
		name, why  string
		user       string
		source     string
		tenant     string
		status     string
		created    time.Time
		aTenant    string
		realm      Realm
		withLegacy bool
	}{
		{
			name: "a post-marker account is never adopted",
			why:  "condition 3 — it was created by code that already records its identity",
			user: "lb-post", source: ProtocolLDAP, tenant: tenantA, status: "active", created: post,
			aTenant: tenantA, realm: realmOf(tenantA), withLegacy: true,
		},
		{
			name: "a different auth_source never adopts",
			why:  "condition 2 — an LDAP assertion cannot claim an account OIDC created",
			user: "lb-source", source: ProtocolOIDC, tenant: tenantA, status: "active", created: pre,
			aTenant: tenantA, realm: realmOf(tenantA), withLegacy: true,
		},
		{
			name: "a LOCAL account is never adopted",
			why:  "condition 2 / H1 — adoption would bypass the local password and its MFA enrollment",
			user: "lb-local", source: ProtocolLocal, tenant: tenantA, status: "active", created: pre,
			aTenant: tenantA, realm: realmOf(tenantA), withLegacy: true,
		},
		{
			name: "a disabled account is never adopted",
			why:  "condition 6 — JIT never resurrects a disabled principal",
			user: "lb-disabled", source: ProtocolLDAP, tenant: tenantA, status: "disabled", created: pre,
			aTenant: tenantA, realm: realmOf(tenantA), withLegacy: true,
		},
		{
			name: "an account outside the flow's realm is never adopted",
			why:  "condition 5a",
			user: "lb-realm", source: ProtocolLDAP, tenant: tenantA, status: "active", created: pre,
			aTenant: tenantB, realm: realmOf(tenantB), withLegacy: true,
		},
		{
			name: "an account in another tenant of the same realm is never adopted",
			why:  "condition 5b — the identity row must land in the account's OWN tenant, or the next sign-in misses the tuple and duplicates the account",
			user: "lb-tenant", source: ProtocolLDAP, tenant: tenantA, status: "active", created: pre,
			aTenant: tenantB, realm: realmOf(tenantA, tenantB), withLegacy: true,
		},
		{
			name: "an assertion with no legacy username never adopts",
			why:  "condition 4 — a new door supplies none, and must not reach an old account",
			user: "lb-nolegacy", source: ProtocolLDAP, tenant: tenantA, status: "active", created: pre,
			aTenant: tenantA, realm: realmOf(tenantA), withLegacy: false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d, ev := identityTestDeps(identityEpoch)
			s := newStore(t, d)
			legacy := seedLegacy(t, s, tc.user, tc.source, tc.tenant, tc.status, tc.created)
			assertion := ldapAssertion(tc.aTenant, "cn="+tc.user+",dc=example,dc=com", "")
			if tc.withLegacy {
				assertion.LegacyUsername = tc.user
			}
			before := s.Count()
			got, err := s.ResolveFederated(assertion, tc.realm, true)
			if err != nil {
				t.Fatalf("%s (%s): %v", tc.name, tc.why, err)
			}
			if got.ID == legacy.ID {
				t.Fatalf("ADOPTED when it must not have been (%s): %s", tc.why, legacy.ID)
			}
			if s.Count() != before+1 {
				t.Fatalf("want exactly one fresh account, count %d → %d", before, s.Count())
			}
			if len(ev.bound) != 0 {
				t.Fatalf("OnLegacyBound fired %v on a refused adoption", ev.bound)
			}
			// The legacy row is left EXACTLY as found — still pending, still its own
			// role, source, tenant and status. Nothing is guessed and nothing is
			// damaged; the operator remediates it.
			after, ok := s.Get(legacy.ID)
			if !ok {
				t.Fatal("the legacy row vanished")
			}
			if !after.IdentityPending() || after.Role != legacy.Role ||
				after.AuthSource != legacy.AuthSource || after.TenantID != legacy.TenantID ||
				after.Status != legacy.Status || after.Email != legacy.Email {
				t.Fatalf("the refused adoption still wrote to the legacy row: %+v", after)
			}
		})
	}

	t.Run("VerifyIdentityInvariants refuses a store with an unbackfilled local account", func(t *testing.T) {
		// It REFUSES; it does not repair. A converge step must not destroy the
		// estate it is converging (the F-58 lesson).
		d, _ := identityTestDeps(identityEpoch)
		s := newStore(t, d)
		seedLegacy(t, s, "lb-enforce", ProtocolLocal, tenantA, "active", pre)
		err := s.VerifyIdentityInvariants()
		if !errors.Is(err, ErrIdentityBackfillIncomplete) {
			t.Fatalf("err = %v, want ErrIdentityBackfillIncomplete", err)
		}
		// A PENDING FEDERATED row is not a failure — that is the documented
		// waiting state, not a broken one.
		if got, ok := s.Get("lb-enforce"); !ok || !got.IdentityPending() {
			t.Fatalf("the seeded row was silently repaired: %+v", got)
		}
	})
}

// ---------------------------------------------------------------------------
// backends
// ---------------------------------------------------------------------------

func newFileStoreForContract(t *testing.T, d Deps) Repo {
	t.Helper()
	s, err := NewFileStore(filepath.Join(t.TempDir(), "users.json"), d)
	if err != nil {
		t.Fatalf("NewFileStore: %v", err)
	}
	return s
}

func TestFileStoreIdentityContract(t *testing.T) {
	runIdentityContract(t, newFileStoreForContract)
}

func TestFileStoreLegacyBindContract(t *testing.T) {
	runLegacyBindContract(t, newFileStoreForContract)
}

// Gated on DATABASE_URL_TEST like every pg-backed test (a superuser DSN; the
// fixture provisions the non-superuser app role FORCE RLS actually applies to).
func TestPGStoreIdentityContract(t *testing.T) {
	adminDSN := os.Getenv("DATABASE_URL_TEST")
	if adminDSN == "" {
		t.Skip("set DATABASE_URL_TEST to run the Postgres identity contract")
	}
	ctx := context.Background()
	ps, err := platformdb.NewPGStore(ctx, provisionAppRole(ctx, t, adminDSN))
	if err != nil {
		t.Fatalf("newPgStore: %v", err)
	}
	defer ps.DB().Close()
	runIdentityContract(t, func(t *testing.T, d Deps) Repo {
		s, err := NewPGStore(ps.DB(), d)
		if err != nil {
			t.Fatalf("NewPGStore: %v", err)
		}
		return s
	})
}

func TestPGStoreLegacyBindContract(t *testing.T) {
	adminDSN := os.Getenv("DATABASE_URL_TEST")
	if adminDSN == "" {
		t.Skip("set DATABASE_URL_TEST to run the Postgres legacy-bind contract")
	}
	ctx := context.Background()
	ps, err := platformdb.NewPGStore(ctx, provisionAppRole(ctx, t, adminDSN))
	if err != nil {
		t.Fatalf("newPgStore: %v", err)
	}
	defer ps.DB().Close()
	runLegacyBindContract(t, func(t *testing.T, d Deps) Repo {
		s, err := NewPGStore(ps.DB(), d)
		if err != nil {
			t.Fatalf("NewPGStore: %v", err)
		}
		return s
	})
}

// Both backends must implement the WHOLE Repo seam. The composition root
// (users_wiring.newUsersStore) proves this too, but it does so a package away —
// and the point of the seam is that a method added to Repo is a method BOTH
// stores owe, which is the thing a reviewer should see fail here first.
func TestBothBackendsImplementRepo(t *testing.T) {
	// The assignments ARE the assertion: a Repo method either store is missing is
	// a compile error on these two lines.
	for name, r := range map[string]Repo{
		"FileStore": (*FileStore)(nil),
		"PGStore":   (*PGStore)(nil),
	} {
		// And both must be able to seed the legacy shape the migration has to cope
		// with, or the cross-backend §2.6 contract silently covers only one of them.
		if _, ok := r.(LegacySeeder); !ok {
			t.Errorf("%s does not implement LegacySeeder", name)
		}
	}
}
