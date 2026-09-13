// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package users

// identity_realm_scope_test.go — the §2.5 AMENDMENT (architect ruling,
// 2026-09-13), pinned on both backends through the Repo seam.
//
// THE RULE. A person is not duplicated per tenant inside one org. On a
// realm-BOUND connection, an exact (tenant, issuer, subject) miss looks the same
// canonical (issuer, subject) up across the tenants that sign-in realm reaches:
// exactly one account → sign in to it; more than one → refuse; none → provision.
//
// THE BOUND. `Realm.Reaches`, never wider. The two tests the amendment names are
// the two halves of that bound:
//   - two connections in ONE org, one person   → ONE account;
//   - two connections in two UNRELATED orgs, the same Keycloak subject → TWO
//     accounts, because neither realm reaches the other.
//
// It is neither email- nor username-linking: the tuple is identical and only the
// tenant differs, PK(tenant, issuer, subject) and UNIQUE(user_id) both still
// hold, and nothing crosses a realm.

import (
	"context"
	"errors"
	"os"
	"testing"

	"netops/backend/internal/platformdb"
)

// The org in these fixtures is expressed the way the store sees one: a realm
// that reaches several tenants. Which tenants an org owns is the tenant
// directory's business, and this package must not import it.
const (
	orgTenantA1 = "t_org1aaaa1111" // org 1, tenant 1
	orgTenantA2 = "t_org1bbbb2222" // org 1, tenant 2 — same org
	orgTenantB1 = "t_org2cccc3333" // org 2 — unrelated
)

func runRealmScopedResolutionContract(t *testing.T, newStore func(t *testing.T, d Deps) Repo) {
	t.Helper()

	t.Run("two connections in one org resolve one person to one account", func(t *testing.T) {
		d, _ := identityTestDeps(contractEpoch)
		s := newStore(t, d)
		// The org's realm reaches both of its tenants — this is what an
		// /org/{org_public_id} sign-in URL hands down.
		org := realmOf(orgTenantA1, orgTenantA2)
		const sub = "kc-sub-one-person"

		// Connection 1 is registered to tenant 1: first sight provisions there.
		first, err := s.ResolveFederated(
			connA(orgTenantA1, kcIssuer, sub, "conn-one", "p@org1.example", "One Person"), org, true)
		if err != nil {
			t.Fatalf("connection 1: %v", err)
		}
		if first.TenantID != orgTenantA1 {
			t.Fatalf("provisioned into %q, want the connection's tenant %q", first.TenantID, orgTenantA1)
		}
		before := s.Count()

		// Connection 2 is registered to tenant 2 of the SAME org. The exact tuple
		// (tenant 2, iss, sub) does not exist — and the person must not be
		// duplicated.
		second, err := s.ResolveFederated(
			connA(orgTenantA2, kcIssuer, sub, "conn-two", "p@org1.example", "One Person"), org, true)
		if err != nil {
			t.Fatalf("connection 2: %v", err)
		}
		if second.ID != first.ID {
			t.Fatalf("one person became two accounts inside one org: %q and %q", first.ID, second.ID)
		}
		if s.Count() != before {
			t.Fatalf("the sibling-tenant sign-in created a row: count %d → %d", before, s.Count())
		}
		// The account stays where it was provisioned: a claim never moves a tenant.
		if second.TenantID != orgTenantA1 {
			t.Fatalf("the second connection MOVED the account to %q", second.TenantID)
		}
		// And its identity keeps its own tenant, so the next sign-in through
		// connection 1 still hits the exact tuple.
		if got := identityOf(t, second).TenantID; got != orgTenantA1 {
			t.Fatalf("identity tenant = %q, want the account's own %q", got, orgTenantA1)
		}
		// The connection the person came through IS recorded — an operator can see
		// which door was used without it becoming part of the key.
		if got := identityOf(t, second).ConnectionID; got != "conn-two" {
			t.Errorf("connection_id = %q, want the refreshed %q", got, "conn-two")
		}
	})

	t.Run("the same subject in two unrelated orgs is two accounts", func(t *testing.T) {
		d, _ := identityTestDeps(contractEpoch)
		s := newStore(t, d)
		const sub = "kc-sub-shared-across-orgs"

		one, err := s.ResolveFederated(
			connA(orgTenantA1, kcIssuer, sub, "conn-org1", "", ""), realmOf(orgTenantA1, orgTenantA2), true)
		if err != nil {
			t.Fatalf("org 1: %v", err)
		}
		two, err := s.ResolveFederated(
			connA(orgTenantB1, kcIssuer, sub, "conn-org2", "", ""), realmOf(orgTenantB1), true)
		if err != nil {
			t.Fatalf("org 2: %v", err)
		}
		if two.ID == one.ID {
			t.Fatalf("a subject asserted in an UNRELATED org reached account %q — a realm was crossed", one.ID)
		}
		if two.TenantID != orgTenantB1 {
			t.Errorf("org 2's account landed in %q", two.TenantID)
		}
	})

	t.Run("an ambiguous realm-scoped match is refused, never guessed", func(t *testing.T) {
		d, _ := identityTestDeps(contractEpoch)
		s := newStore(t, d)
		const sub = "kc-sub-ambiguous-in-org"
		// Two accounts for one (issuer, subject) already exist in two tenants —
		// the pre-amendment estate, or two orgs later merged into one.
		if _, err := s.ResolveFederated(connA(orgTenantA1, kcIssuer, sub, "c1", "", ""), realmOf(orgTenantA1), true); err != nil {
			t.Fatalf("seed tenant 1: %v", err)
		}
		if _, err := s.ResolveFederated(connA(orgTenantA2, kcIssuer, sub, "c2", "", ""), realmOf(orgTenantA2), true); err != nil {
			t.Fatalf("seed tenant 2: %v", err)
		}
		before := s.Count()
		// A third tenant of the SAME org now signs the person in: two reachable
		// accounts hold the tuple, so there is no answer to guess.
		_, err := s.ResolveFederated(
			connA(orgTenantB1, kcIssuer, sub, "c3", "", ""), realmOf(orgTenantA1, orgTenantA2, orgTenantB1), true)
		if !errors.Is(err, ErrAmbiguousIdentity) {
			t.Fatalf("err = %v, want ErrAmbiguousIdentity", err)
		}
		if s.Count() != before {
			t.Fatalf("the refusal still wrote: count %d → %d", before, s.Count())
		}
	})

	t.Run("an UNCONSTRAINED realm gets no cross-tenant reach", func(t *testing.T) {
		// "Everything" is wider than any realm, so the platform front door keeps
		// exact-tuple semantics — which is also what keeps the TENANT part of the
		// key meaningful. The deliberately cross-tenant door is
		// ResolveFederatedUnbound, and it says so in its name.
		d, _ := identityTestDeps(contractEpoch)
		s := newStore(t, d)
		const sub = "kc-sub-unconstrained"
		one, err := s.ResolveFederated(connA(orgTenantA1, kcIssuer, sub, "", "", ""), Realm{}, true)
		if err != nil {
			t.Fatalf("first: %v", err)
		}
		two, err := s.ResolveFederated(connA(orgTenantA2, kcIssuer, sub, "", "", ""), Realm{}, true)
		if err != nil {
			t.Fatalf("second: %v", err)
		}
		if two.ID == one.ID {
			t.Fatalf("an unconstrained realm reached across tenants into %q", one.ID)
		}
	})

	t.Run("the realm-scoped path never reaches a LOCAL account", func(t *testing.T) {
		// H1 at the key level, re-asserted on the widened lookup: the local
		// namespace is not addressable from a federated door, so widening the
		// lookup cannot widen it INTO a local account.
		d, _ := identityTestDeps(contractEpoch)
		s := newStore(t, d)
		local, err := s.CreateFull(User{Username: "orgadmin", Role: "admin", TenantID: orgTenantA1}, strongPass)
		if err != nil {
			t.Fatalf("seed local: %v", err)
		}
		got, err := s.ResolveFederated(
			connA(orgTenantA2, kcIssuer, "orgadmin", "c", "orgadmin@org1.example", "Org Admin"),
			realmOf(orgTenantA1, orgTenantA2), true)
		if err != nil {
			t.Fatalf("federated subject == a local username: %v", err)
		}
		if got.ID == local.ID {
			t.Fatalf("the realm-scoped lookup reached the LOCAL account %q", local.ID)
		}
		after, _ := s.Get(local.ID)
		if after.Role != local.Role || after.AuthSource != ProtocolLocal || after.Email != "" {
			t.Fatalf("the local account was mutated: %+v", after)
		}
	})
}

// connA is an OIDC assertion as the callback hands it down for ONE registered
// connection: the broker's verified issuer and `sub`, plus the connection alias.
func connA(tenant, issuer, sub, connID, email, name string) Assertion {
	a := oidcA(tenant, issuer, sub, email, name, "read-only")
	a.ConnectionID = connID
	return a
}

func TestFileStoreRealmScopedResolution(t *testing.T) {
	runRealmScopedResolutionContract(t, newFileStoreForContract)
}

func TestPGStoreRealmScopedResolution(t *testing.T) {
	adminDSN := os.Getenv("DATABASE_URL_TEST")
	if adminDSN == "" {
		t.Skip("set DATABASE_URL_TEST to run the Postgres realm-scoped resolution contract")
	}
	ctx := context.Background()
	ps, err := platformdb.NewPGStore(ctx, provisionAppRole(ctx, t, adminDSN))
	if err != nil {
		t.Fatalf("newPgStore: %v", err)
	}
	defer ps.DB().Close()
	runRealmScopedResolutionContract(t, func(t *testing.T, d Deps) Repo {
		s, err := NewPGStore(ps.DB(), d)
		if err != nil {
			t.Fatalf("NewPGStore: %v", err)
		}
		return s
	})
}
