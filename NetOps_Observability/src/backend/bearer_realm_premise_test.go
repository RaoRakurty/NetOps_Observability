// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// bearer_realm_premise_test.go — tracker 279(d): the GLOBAL-USERNAME shape on
// the three non-interactive federated entry points, pinned as a premise.
//
// `bearerPrincipal` (auth.go), the LDAP login (ldap_wiring.go) and the TACACS+
// login (tacacs_wiring.go) all resolve an identity by USERNAME ALONE —
// `users.Get(sub)` / `completeFederatedLogin(…, username, …)` — with no realm
// beside it. C3 fixed that shape where a realm WAS in play; these three were
// left because they are UNBOUND BY CONSTRUCTION:
//
//   - the bearer path consults `s.oidcProvider()`, the single platform relying-
//     party connection. Per-tenant IdPs are BROKERED through it, so there is no
//     per-tenant provider for this branch to pick;
//   - LDAP and TACACS+ each have exactly one platform-global configuration
//     (`s.ldap.effective()`, `s.tacacs`), so there is one directory and one
//     username namespace.
//
// "Unbound by construction" is a claim about today's wiring, and a claim nobody
// checks is a claim that stops being true. This test states the CONSEQUENCE of
// the shape — one username, one account, whatever asserted it — so that the
// first change making any of these realm-bearing fails here and reads the
// instruction rather than shipping a cross-realm account takeover.
//
// If you are here because this test failed: you have given one of these paths
// more than one realm. The username is no longer a key. Thread the realm down
// to the account lookup (the C3 pattern) before going further.

import (
	"net/http"
	"testing"
)

func TestBearerUsernameIsOneGlobalNamespace(t *testing.T) {
	h := newBearerHarness(t, TenantGlobal)

	if _, err := h.s.tenants.Create("Acme", "acme", "", "", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := h.s.tenants.Create("Globex", "globex", "", "", ""); err != nil {
		t.Fatal(err)
	}

	// An account already exists for this name, owned by acme.
	if _, err := h.s.users.UpsertFederated(
		"alice", "alice@acme.example", "Alice", RoleReadOnly, "oidc", "acme"); err != nil {
		t.Fatal(err)
	}

	// A bearer asserting the SAME preferred_username arrives. There is exactly
	// one platform realm today, so this is the same Alice — and the STORED
	// account is what she acts as, never the provider's DefaultTenant.
	tok := h.mintBearer(t, "alice")
	st, claims, reached := bearerRequest(t, h, tok)
	if st != http.StatusOK || !reached {
		t.Fatalf("bearer for an existing federated account: status %d reached=%v, want 200/true", st, reached)
	}
	if claims.Tenant != "acme" {
		t.Fatalf("bearer acted as tenant %q, want the STORED %q", claims.Tenant, "acme")
	}

	// THE PREMISE. The lookup is keyed on the username alone, so a second
	// account of the same name cannot exist beside the first: the store answers
	// with the one that is already there, in ITS tenant.
	//
	// That is safe only while one realm can assert this name. The moment two
	// can, this same call is a cross-realm account takeover — globex's alice
	// signing in and receiving acme's account, role and tenant — and it will
	// look exactly like a successful login.
	u, err := h.s.users.UpsertFederated(
		"alice", "alice@globex.example", "Alice", RoleReadOnly, "oidc", "globex")
	if err != nil {
		t.Fatalf("second upsert of the same username: %v", err)
	}
	if u.TenantID != "acme" {
		t.Fatalf("a second realm's upsert of %q produced tenant %q — the username namespace is no longer "+
			"global, so every caller that treats it as a key (bearerPrincipal, ldap_wiring, tacacs_wiring) "+
			"must now carry a realm; see this file's header", "alice", u.TenantID)
	}
	named := 0
	for _, existing := range h.s.users.List("", true) {
		if existing.Username == "alice" {
			named++
		}
	}
	if named != 1 {
		t.Fatalf("the store holds %d accounts named alice, want 1 — see this file's header", named)
	}
}
