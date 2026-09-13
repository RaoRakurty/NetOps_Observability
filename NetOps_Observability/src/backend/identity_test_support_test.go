// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// identity_test_support_test.go — the two lookups this corpus needs now that a
// login name is not a principal id (tracker 300 §2.1).
//
// Tests name people the way an operator does — "admin", "alice" — while the
// store, the sessions, the bindings and the audit trail are all keyed by the
// account's OPAQUE id. These helpers are the bridge, and they are deliberately
// thin: they resolve through the SAME public store methods the doors use, so a
// test cannot accidentally prove a property the product does not have.

import (
	"encoding/json"
	"net/http/httptest"
	"testing"

	"netops/backend/internal/users"
)

// principalID resolves a LOCAL login handle to the account's principal id,
// requiring it to be unambiguous. A test that needs the id of a name held by
// several tenants must say which tenant (principalIDIn).
func principalID(t *testing.T, s *server, username string) string {
	t.Helper()
	matches, ok := s.users.LookupLocalAny(username)
	if !ok || len(matches) == 0 {
		t.Fatalf("no local account named %q", username)
	}
	if len(matches) > 1 {
		t.Fatalf("%d tenants hold a local account named %q — name the tenant", len(matches), username)
	}
	return matches[0].ID
}

// principalIDIn resolves a LOCAL login handle inside ONE tenant.
func principalIDIn(t *testing.T, s *server, tenant, username string) string {
	t.Helper()
	u, ok := s.users.LookupLocal(tenant, username)
	if !ok {
		t.Fatalf("no local account named %q in tenant %q", username, tenant)
	}
	return u.ID
}

// createUserID posts a user through the real admin API and returns the PRINCIPAL
// ID the response carries — the handle every later mutation, binding and audit
// actor uses (tracker 300 §4.5/§4.7).
func createUserID(t *testing.T, srv *httptest.Server, adminTok string, body map[string]any) string {
	t.Helper()
	st, b := do(t, srv, "POST", "/api/users", adminTok, body)
	if st != 201 && st != 200 {
		t.Fatalf("create user %v: %d %s", body["username"], st, b)
	}
	var out publicUser
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("decode create response: %v (%s)", err, b)
	}
	if out.ID == "" {
		t.Fatalf("/api/users returned no id: %s", b)
	}
	return out.ID
}

// federatedPrincipalID finds the account holding a federated identity tuple —
// the only way to name a federated account, whose login handle IS its opaque id
// (tracker 300 §2.1). Scanning the directory rather than deriving the id keeps
// the helper honest about which tenant the account was provisioned into.
func federatedPrincipalID(t *testing.T, s *server, issuer, subject string) string {
	t.Helper()
	var found []string
	for _, u := range s.users.List("", true) {
		if u.Identity == nil {
			continue
		}
		if u.Identity.Issuer == users.NormalizeIssuer(issuer) && u.Identity.Subject == subject {
			found = append(found, u.ID)
		}
	}
	switch len(found) {
	case 0:
		t.Fatalf("no account holds the identity (%s, %s)", issuer, subject)
	case 1:
		return found[0]
	}
	t.Fatalf("%d accounts hold the identity (%s, %s): %v", len(found), issuer, subject, found)
	return ""
}
