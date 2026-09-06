// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

import (
	"net/http"
	"testing"
)

// M7: the acting-tenant switcher must not bypass tenant suspension. The
// middleware's suspension gate used to run on the TOKEN claims only, before
// withActingTenant rewrote a non-owner's effective tenant — so an org-admin/
// MSP/SRE principal switching (as_tenant / X-Acting-Tenant) into a reachable
// tenant kept full access after the platform suspended it. Suspension is now
// re-evaluated on the EFFECTIVE tenant, end-to-end through the real router +
// auth middleware.
func TestActingTenantSuspensionEnforced(t *testing.T) {
	srv, s := newTestServerState(t)
	if _, err := s.tenants.Create("Acme", "acme", "", "", ""); err != nil {
		t.Fatal(err)
	}
	glob, err := s.tenants.Create("Globex", "globex", "", "", "")
	if err != nil {
		t.Fatal(err)
	}
	// A multi-tenant operator: home in acme, bound (reachable) into globex.
	if _, err := s.users.CreateFull(User{Username: "sre", Role: RoleOperator, TenantID: "acme"}, "Passw0rd!2345"); err != nil {
		t.Fatal(err)
	}
	s.backfillBindings()
	if _, err := s.bindings.Add(RoleBinding{PrincipalID: "sre", RoleID: RoleOperator, ScopeID: scopeTenant(glob.ID), Effect: EffectAllow}); err != nil {
		t.Fatal(err)
	}
	tok := login(t, srv, "sre", "Passw0rd!2345").Token

	// Sanity: while globex is active, the switcher works.
	if st, b := do(t, srv, "GET", "/api/devices?as_tenant=globex", tok, nil); st != 200 {
		t.Fatalf("switch into active tenant: status %d (%s), want 200", st, b)
	}

	if _, err := s.tenants.SetStatus(glob.ID, TenantStatusSuspended); err != nil {
		t.Fatal(err)
	}
	// Switching into the suspended tenant is refused — query param and header alike.
	if st, b := do(t, srv, "GET", "/api/devices?as_tenant=globex", tok, nil); st != 403 {
		t.Fatalf("switch into SUSPENDED tenant: status %d (%s), want 403", st, b)
	}
	req, err := http.NewRequest("GET", srv.URL+"/api/devices", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("X-Acting-Tenant", "globex")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 403 {
		t.Fatalf("X-Acting-Tenant into SUSPENDED tenant: status %d, want 403", resp.StatusCode)
	}

	// The principal's HOME tenant is untouched — no collateral lockout.
	if st, b := do(t, srv, "GET", "/api/devices", tok, nil); st != 200 {
		t.Fatalf("home-tenant request after foreign suspension: status %d (%s), want 200", st, b)
	}
	// The platform owner still reaches the suspended tenant (reactivation path).
	admin := login(t, srv, "admin", "Passw0rd!2345").Token
	if st, b := do(t, srv, "GET", "/api/devices?as_tenant=globex", admin, nil); st != 200 {
		t.Fatalf("platform owner into suspended tenant: status %d (%s), want 200", st, b)
	}
}
