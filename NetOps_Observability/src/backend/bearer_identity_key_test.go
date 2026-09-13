// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// bearer_identity_key_test.go — design §5.7, and the retirement of tracker
// 279(d)'s TestBearerUsernameIsOneGlobalNamespace.
//
// WHAT THE OLD TEST PINNED, and why it is gone. The three non-interactive
// federated entry points — `bearerPrincipal`, the LDAP login and the TACACS+
// login — resolved an identity by USERNAME ALONE (`users.Get(sub)` where `sub`
// was firstNonEmpty(preferred_username, email, sub)). 279(d) pinned that shape
// deliberately, as a premise with an instruction attached: the first change that
// gave any of these paths a second realm had to fail there and read the note
// rather than ship a cross-realm account takeover. Tracker 300 is that change,
// and it did not thread a realm through a username — it removed the username
// from the key entirely.
//
// WHAT IS PINNED NOW. The bearer door is keyed by (tenant, issuer, subject):
//
//	same preferred_username, different `sub`  → DIFFERENT accounts
//	same `sub`, different issuer              → DIFFERENT accounts
//	same tuple twice                          → the SAME account, no second row
//	the STORED account stays authoritative (H2): its tenant, role and status
//	decide what the request acts as, never the token's claims.
//
// The old test's live property — one platform realm, so the stored account wins
// over the provider's DefaultTenant — is the last assertion below, now proven on
// the tuple rather than on a global username.

import (
	"net/http"
	"strings"
	"testing"

	"netops/backend/internal/users"
)

func TestBearerIdentityIsTenantIssuerSubject(t *testing.T) {
	h := newBearerHarness(t, TenantGlobal)
	if _, err := h.s.tenants.Create("Acme", "acme", "", "", ""); err != nil {
		t.Fatal(err)
	}

	// An account already exists for this person, owned by acme, resolved from the
	// tuple the broker asserts. Note the FIXTURE RULE (design §5): its id is the
	// deterministic fed_… derivation and is nothing like any username.
	existing, err := h.s.users.ResolveFederatedUnbound(users.Assertion{
		Identity: users.Identity{
			TenantID: "acme", Issuer: h.p.Issuer(), Subject: "kc-sub-alice", Protocol: users.ProtocolOIDC,
		},
		Email: "alice@acme.example", DisplayName: "Alice", Role: RoleReadOnly,
	})
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	// A federated account's username IS its opaque id, and neither is the login
	// name the token happens to carry — which is the whole point.
	if existing.Username != existing.ID || existing.ID == "alice" || !strings.HasPrefix(existing.ID, "fed_") {
		t.Fatalf("fixture rule broken: a federated account must be keyed by its opaque id (%+v)", existing)
	}

	// The same person's bearer token arrives. `preferred_username` is "alice" and
	// `sub` is the tuple's subject: the STORED account is what she acts as, never
	// the provider's DefaultTenant (H2).
	st, claims, reached := bearerRequest(t, h, mintBearerClaims(t, h, h.baseClaims("kc-sub-alice", "alice")))
	if st != http.StatusOK || !reached {
		t.Fatalf("bearer for an existing federated account: status %d reached=%v, want 200/true", st, reached)
	}
	if claims.Tenant != "acme" {
		t.Fatalf("bearer acted as tenant %q, want the STORED %q", claims.Tenant, "acme")
	}
	if claims.Sub != existing.ID {
		t.Fatalf("JWT sub = %q, want the internal principal id %q (tracker 300 §4.1)", claims.Sub, existing.ID)
	}

	// THE RED-BEFORE CASE. A DIFFERENT principal whose IdP happens to hand out the
	// same `preferred_username` — a rename, a second directory behind the broker,
	// a deliberate impersonation attempt. Before tracker 300 this landed in the
	// account above, with acme's tenant and acme's role. Now it is its own
	// account.
	st, other, reached := bearerRequest(t, h, mintBearerClaims(t, h, h.baseClaims("kc-sub-impostor", "alice")))
	if st != http.StatusOK || !reached {
		t.Fatalf("bearer for a new subject: status %d reached=%v", st, reached)
	}
	if other.Sub == claims.Sub {
		t.Fatalf("two different subjects sharing a preferred_username reached ONE account (%q)", claims.Sub)
	}
	if other.Tenant == "acme" {
		t.Fatalf("a fresh identity inherited acme's tenant — it must be provisioned in the provider default")
	}

	// And the same `sub` asserted by a DIFFERENT issuer is a different principal
	// too. Proven at the store seam: the bearer branch verifies exactly one
	// issuer's signature, so a second issuer cannot be expressed as a token here —
	// which is the property itself, and the reason the issuer belongs in the key.
	foreign, err := h.s.users.ResolveFederatedUnbound(users.Assertion{
		Identity: users.Identity{
			TenantID: TenantGlobal, Issuer: "https://other-idp.example.test/realms/netops",
			Subject: "kc-sub-alice", Protocol: users.ProtocolOIDC,
		},
		Role: RoleReadOnly,
	})
	if err != nil {
		t.Fatalf("second issuer: %v", err)
	}
	if foreign.ID == existing.ID {
		t.Fatalf("the same subject from two issuers was LINKED into one account (%q)", existing.ID)
	}

	// Repeating the FIRST token creates nothing: the tuple already resolves.
	before := h.s.users.Count()
	if st, again, _ := bearerRequest(t, h, mintBearerClaims(t, h, h.baseClaims("kc-sub-alice", "alice"))); st != http.StatusOK || again.Sub != existing.ID {
		t.Fatalf("repeat bearer: status %d sub %q, want 200 and %q", st, again.Sub, existing.ID)
	}
	if h.s.users.Count() != before {
		t.Fatalf("a repeated bearer created an account: count %d → %d", before, h.s.users.Count())
	}
}
