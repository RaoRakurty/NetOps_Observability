package backend

import (
	"encoding/json"
	"testing"
	"time"
)

// TestBreakGlassUnhidesRestricted: a restricted tenant is hidden from the
// operator until it opens a break-glass session, then hidden again on expiry.
func TestBreakGlassUnhidesRestricted(t *testing.T) {
	s := newPBACTestServer(t)
	// Identity is the OPAQUE tenant id; "acme" is only the slug. We bind/scope by
	// slug on purpose (it canonicalizes to the id) and assert on the id.
	acme, err := s.tenants.Create("Acme", "acme", "", "", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.tenants.SetOperatorRestricted("acme", true); err != nil {
		t.Fatal(err)
	}
	owner := jwtClaims{Sub: "root", Role: RoleSuperAdmin, Tenant: TenantGlobal}

	// Default: acme is hidden from the operator (by opaque id).
	if got := s.effectiveRestrictedIDs("root"); len(got) != 1 || got[0] != acme.ID {
		t.Fatalf("default effectiveRestricted=%v, want [%s]", got, acme.ID)
	}
	if ex, deny := s.operatorTelemetryRestriction(owner, TenantGlobal, true); deny || len(ex) != 1 {
		t.Fatalf("cross view should exclude acme, got exclude=%v deny=%v", ex, deny)
	}
	// Scoped into acme (no break-glass) → denied.
	if _, deny := s.operatorTelemetryRestriction(owner, acme.ID, false); !deny {
		t.Error("operator scoped into restricted tenant without break-glass should be denied")
	}

	// Open a break-glass session (binding by slug → canonicalizes to the id).
	exp := time.Now().UTC().Add(30 * time.Minute)
	if _, err := s.bindings.Add(RoleBinding{
		PrincipalID: "root", RoleID: RoleSuperAdmin, ScopeID: scopeTenant("acme"),
		Effect: EffectAllow, Condition: map[string]any{conditionBreakGlass: true}, ExpiresAt: &exp,
	}); err != nil {
		t.Fatal(err)
	}
	if !s.hasBreakGlass("root", acme.ID) {
		t.Fatal("hasBreakGlass should be true after opening a session")
	}
	if got := s.effectiveRestrictedIDs("root"); len(got) != 0 {
		t.Errorf("with break-glass, acme should not be hidden, got %v", got)
	}
	if _, deny := s.operatorTelemetryRestriction(owner, acme.ID, false); deny {
		t.Error("operator with break-glass should NOT be denied in acme")
	}

	// Expire the session → hidden again.
	past := time.Now().UTC().Add(-time.Minute)
	if _, err := s.bindings.Add(RoleBinding{
		PrincipalID: "root", RoleID: RoleSuperAdmin, ScopeID: scopeTenant("acme"),
		Effect: EffectAllow, Condition: map[string]any{conditionBreakGlass: true}, ExpiresAt: &past,
	}); err != nil {
		t.Fatal(err)
	}
	if s.hasBreakGlass("root", acme.ID) {
		t.Error("expired break-glass session must not grant access")
	}
	if got := s.effectiveRestrictedIDs("root"); len(got) != 1 {
		t.Errorf("after expiry acme should be hidden again, got %v", got)
	}
}

// TestBreakGlassHTTP exercises the API: open → list → end, and the guards.
func TestBreakGlassHTTP(t *testing.T) {
	srv := newTestServer(t)
	admin := login(t, srv, "admin", "Passw0rd!2345").Token
	if st, _ := do(t, srv, "POST", "/api/tenants", admin, map[string]any{"name": "Acme", "operator_restricted": true}); st != 201 {
		t.Fatal("create restricted tenant")
	}

	// reason required
	if st, _ := do(t, srv, "POST", "/api/breakglass", admin, map[string]any{"tenant_id": "acme"}); st != 400 {
		t.Errorf("break-glass without reason: got %d, want 400", st)
	}
	// open
	st, _ := do(t, srv, "POST", "/api/breakglass", admin, map[string]any{"tenant_id": "acme", "reason": "INC-42 investigation", "duration_minutes": 15})
	if st != 201 {
		t.Fatalf("open break-glass: got %d", st)
	}
	// list shows one active session
	_, b := do(t, srv, "GET", "/api/breakglass", admin, nil)
	var sessions []RoleBinding
	if err := json.Unmarshal(b, &sessions); err != nil || len(sessions) != 1 {
		t.Fatalf("expected 1 active session, got %s (err %v)", b, err)
	}
	// a non-owner cannot open break-glass
	if st, b := do(t, srv, "POST", "/api/users", admin, map[string]any{"username": "tu", "password": "Passw0rd!2345", "role": "super-admin", "tenant_id": "acme"}); st != 201 {
		t.Fatalf("create tenant user: %d %s", st, b)
	}
	tu := login(t, srv, "tu", "Passw0rd!2345").Token
	if st, _ := do(t, srv, "POST", "/api/breakglass", tu, map[string]any{"tenant_id": "acme", "reason": "x"}); st != 403 {
		t.Errorf("non-owner break-glass: got %d, want 403", st)
	}
	// end the session
	if st, _ := do(t, srv, "DELETE", "/api/breakglass/"+sessions[0].ID, admin, nil); st != 204 {
		t.Errorf("end break-glass: got %d, want 204", st)
	}
}
