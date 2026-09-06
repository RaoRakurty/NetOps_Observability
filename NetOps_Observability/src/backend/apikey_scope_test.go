// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// apikey_scope_test.go — tracker 226: the API-key mint surface can issue WRITE
// and ADMINISTRATIVE keys, and cannot be used to escalate.
//
// Three properties are pinned here, all through the REAL router + auth
// middleware (the way the running system behaves):
//
//  1. CAPABILITY — an administrator can mint `write:*` and `admin:*` keys, and
//     the minted key really acts under the derived role.
//  2. NO ESCALATION — the scope list is a closed vocabulary; a key may never
//     out-rank the principal that minted it; a PLATFORM-realm administrative key
//     is platform-admin-only (§3a.3: platform-global plumbing is not a
//     tenant-admin capability).
//  3. ISOLATION — keys are tenant-scoped end to end: own-only list, cross-tenant
//     revoke → 404, `as_tenant` into another org ignored (§3a.5). This is the
//     dedicated HTTP isolation test route_isolation_coverage_test.go carried as
//     backlog for /api/apikeys/.

import (
	"encoding/json"
	"net/http/httptest"
	"testing"

	"netops/backend/internal/apikey"
	"netops/backend/internal/rbac"
)

// mintKey POSTs /api/apikeys and returns (status, secret, key tenant, scopes).
func mintKey(t *testing.T, srv *httptest.Server, token string, body map[string]any) (int, string, string, []string) {
	t.Helper()
	st, b := do(t, srv, "POST", "/api/apikeys", token, body)
	if st != 201 {
		return st, "", "", nil
	}
	var out struct {
		Key struct {
			TenantID string   `json:"tenant_id"`
			Scopes   []string `json:"scopes"`
		} `json:"key"`
		Secret string `json:"secret"`
	}
	if err := json.Unmarshal(b, &out); err != nil || out.Secret == "" {
		t.Fatalf("mint response unusable: %v %s", err, b)
	}
	return st, out.Secret, out.Key.TenantID, out.Key.Scopes
}

func TestAPIKeyAdministrativeScopeCapability(t *testing.T) {
	srv, _ := newTestServerState(t)
	admin := login(t, srv, "admin", "Passw0rd!2345").Token

	// write:* → operator authority: may write infrastructure, may NOT administer.
	st, writeKey, _, scopes := mintKey(t, srv, admin, map[string]any{
		"label": "ci-write", "scopes": []string{apikey.ScopeWriteAll},
	})
	if st != 201 {
		t.Fatalf("mint write key: %d", st)
	}
	if len(scopes) != 1 || scopes[0] != apikey.ScopeWriteAll {
		t.Fatalf("scopes not stored/normalized: %v", scopes)
	}
	if st, b := do(t, srv, "GET", "/api/auth/permissions", writeKey, nil); st != 200 {
		t.Fatalf("write key GET permissions: %d %s", st, b)
	} else {
		var pr struct {
			Role        string         `json:"role"`
			Permissions map[string]int `json:"permissions"`
		}
		if err := json.Unmarshal(b, &pr); err != nil {
			t.Fatal(err)
		}
		if pr.Role != RoleOperator || pr.Permissions["infrastructure"] != LevelWrite {
			t.Fatalf("write:* key did not act as operator: %+v", pr)
		}
	}
	// Still not an administrator — this is the capability boundary of write:*.
	if st, _ := do(t, srv, "GET", "/api/users", writeKey, nil); st != 403 {
		t.Errorf("write:* key GET /api/users: %d, want 403", st)
	}

	// admin:* → the capability tracker 226 was about: a key that can automate
	// tenant + device creation.
	st, adminKey, keyTenant, _ := mintKey(t, srv, admin, map[string]any{
		"label": "platform-automation", "scopes": []string{apikey.ScopeAdminAll},
	})
	if st != 201 {
		t.Fatalf("mint admin key: %d", st)
	}
	if keyTenant != TenantGlobal {
		t.Fatalf("platform admin's key bound to %q, want the platform realm %q", keyTenant, TenantGlobal)
	}
	if st, b := do(t, srv, "GET", "/api/users", adminKey, nil); st != 200 {
		t.Fatalf("admin:* key GET /api/users: %d %s", st, b)
	}
	if st, b := do(t, srv, "POST", "/api/tenants", adminKey, map[string]any{"name": "Minted By Key"}); st != 201 {
		t.Fatalf("admin:* key POST /api/tenants: %d %s", st, b)
	}
}

func TestAPIKeyScopeVocabularyIsClosed(t *testing.T) {
	srv := newTestServer(t)
	admin := login(t, srv, "admin", "Passw0rd!2345").Token

	// A scope the backend does not honour is refused, not silently stored: a
	// typo'd "write:tenants" key would otherwise look administrative and act
	// operator-only.
	for _, bad := range []string{"write:tenants", "admin:tenants", "read:everything", "*"} {
		st, b := do(t, srv, "POST", "/api/apikeys", admin, map[string]any{"label": "typo", "scopes": []string{bad}})
		if st != 400 {
			t.Errorf("scope %q: status %d, want 400 (%s)", bad, st, b)
		}
	}
	// Case/whitespace are normalized and duplicates collapsed, so the stored
	// list is exactly what was authorized.
	st, b := do(t, srv, "POST", "/api/apikeys", admin, map[string]any{
		"label": "normalize", "scopes": []string{" READ:Metrics ", "read:metrics", ""},
	})
	if st != 201 {
		t.Fatalf("normalize mint: %d %s", st, b)
	}
	var out struct {
		Key struct {
			Scopes []string `json:"scopes"`
		} `json:"key"`
	}
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	if len(out.Key.Scopes) != 1 || out.Key.Scopes[0] != "read:metrics" {
		t.Fatalf("scopes not normalized: %v", out.Key.Scopes)
	}
}

// A tenant administrator may mint keys — bounded by its own tenant and its own
// role. It must never obtain a platform-wide credential that way.
func TestAPIKeyTenantAdminCannotMintPlatformKey(t *testing.T) {
	srv, s := newTestServerState(t)
	admin := login(t, srv, "admin", "Passw0rd!2345").Token
	tenantID := mkTenantForKeys(t, srv, admin, "Acme")

	st, b := do(t, srv, "POST", "/api/users", admin, map[string]any{
		"username": "acme-admin", "password": "Passw0rd!2345",
		"role": rbac.RoleOrgAdmin, "tenant_id": tenantID,
	})
	if st != 201 {
		t.Fatalf("create tenant admin: %d %s", st, b)
	}
	tenantAdmin := login(t, srv, "acme-admin", "Passw0rd!2345").Token

	// The tenant admin CAN mint an administrative key — the mint capability is
	// not platform-only — but the key is stamped with ITS tenant, whatever the
	// payload asks for (owner from the token, never the body: §3a.2).
	st, tenantKey, keyTenant, _ := mintKey(t, srv, tenantAdmin, map[string]any{
		"label": "acme-automation", "scopes": []string{apikey.ScopeAdminAll}, "tenant_id": TenantGlobal,
	})
	if st != 201 {
		t.Fatalf("tenant admin mint: %d", st)
	}
	if keyTenant != tenantID {
		t.Fatalf("key bound to %q, want the minting admin's tenant %q", keyTenant, tenantID)
	}
	// ...and the resulting credential is NOT the platform owner: platform-global
	// plumbing stays closed to it.
	if st, _ := do(t, srv, "POST", "/api/roles", tenantKey, map[string]any{"name": "sneaky"}); st != 403 {
		t.Errorf("tenant-bound admin key POST /api/roles: %d, want 403", st)
	}

	// The rule itself, at the unit boundary: a non-platform-owner principal may
	// not mint an administrative key in the PLATFORM realm, however it gets there.
	if err := s.authorizeKeyScopes(jwtClaims{Sub: "acme-admin", Role: rbac.RoleOrgAdmin, Tenant: tenantID},
		[]string{apikey.ScopeAdminAll}, TenantGlobal); err == nil {
		t.Error("org admin allowed to mint a PLATFORM administrative key")
	}
	if err := s.authorizeKeyScopes(jwtClaims{Sub: "admin", Role: RoleSuperAdmin, Tenant: TenantGlobal},
		[]string{apikey.ScopeAdminAll}, TenantGlobal); err != nil {
		t.Errorf("platform owner refused its own administrative key: %v", err)
	}
}

// A key may never out-rank the principal that minted it. The mint surface is
// administration:admin-gated, so the escalation attempt is exercised at the
// authority boundary itself (authorizeKeyScopes) with real stored roles, plus
// the HTTP proof that a non-administrator cannot mint at all.
func TestAPIKeyScopeEscalationRefused(t *testing.T) {
	srv, s := newTestServerState(t)
	admin := login(t, srv, "admin", "Passw0rd!2345").Token

	// A custom role that reads the product but administers nothing.
	st, b := do(t, srv, "POST", "/api/roles", admin, map[string]any{
		"name": "narrow-reader",
		"permissions": map[string]int{
			"overview": LevelRead, "explore": LevelRead, "alerts": LevelRead,
			"infrastructure": LevelRead, "topology": LevelRead, "reports": LevelRead,
			rbac.ModuleSensitiveData: LevelRead, "administration": LevelNone,
		},
	})
	if st != 201 {
		t.Fatalf("create custom role: %d %s", st, b)
	}
	var role struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(b, &role); err != nil || role.ID == "" {
		t.Fatalf("custom role has no id: %v %s", err, b)
	}
	narrow := jwtClaims{Sub: "reader", Role: role.ID, Tenant: TenantGlobal}

	// It may mint a read key (exactly its own authority)...
	if err := s.authorizeKeyScopes(narrow, []string{"read:alerts", "read:metrics"}, TenantGlobal); err != nil {
		t.Errorf("reader refused a read-only key it could itself use: %v", err)
	}
	// ...but never one that writes or administers.
	for _, scope := range []string{"write:incidents", apikey.ScopeWriteAll, apikey.ScopeAdminAll} {
		if err := s.authorizeKeyScopes(narrow, []string{scope}, TenantGlobal); err == nil {
			t.Errorf("reader allowed to mint %q — escalation", scope)
		}
	}
	// An operator may write, so a write key is within its authority; an
	// administrative one is not.
	op := jwtClaims{Sub: "op", Role: RoleOperator, Tenant: TenantGlobal}
	if err := s.authorizeKeyScopes(op, []string{apikey.ScopeWriteAll}, TenantGlobal); err != nil {
		t.Errorf("operator refused a write key: %v", err)
	}
	if err := s.authorizeKeyScopes(op, []string{apikey.ScopeAdminAll}, TenantGlobal); err == nil {
		t.Error("operator allowed to mint an administrative key — escalation")
	}

	// And the surface itself stays administration:admin-gated: an operator never
	// gets as far as the scope check.
	if st, b := do(t, srv, "POST", "/api/users", admin, map[string]any{
		"username": "op", "password": "Passw0rd!2345", "role": RoleOperator,
	}); st != 201 {
		t.Fatalf("create operator: %d %s", st, b)
	}
	opTok := login(t, srv, "op", "Passw0rd!2345").Token
	if st, _ := do(t, srv, "POST", "/api/apikeys", opTok, map[string]any{
		"label": "nope", "scopes": []string{apikey.ScopeAdminAll},
	}); st != 403 {
		t.Errorf("operator POST /api/apikeys: %d, want 403", st)
	}
}

// Tenant isolation of the key surface itself (§3a.5): own-only list, cross-tenant
// revoke → 404, as_tenant into another org ignored.
func TestAPIKeyTenantIsolation(t *testing.T) {
	srv := newTestServer(t)
	admin := login(t, srv, "admin", "Passw0rd!2345").Token

	tenantA := mkTenantForKeys(t, srv, admin, "Alpha")
	tenantB := mkTenantForKeys(t, srv, admin, "Bravo")
	for _, tc := range []struct{ user, tenant string }{{"alpha-admin", tenantA}, {"bravo-admin", tenantB}} {
		if st, b := do(t, srv, "POST", "/api/users", admin, map[string]any{
			"username": tc.user, "password": "Passw0rd!2345", "role": rbac.RoleOrgAdmin, "tenant_id": tc.tenant,
		}); st != 201 {
			t.Fatalf("create %s: %d %s", tc.user, st, b)
		}
	}
	aTok := login(t, srv, "alpha-admin", "Passw0rd!2345").Token
	bTok := login(t, srv, "bravo-admin", "Passw0rd!2345").Token

	if st, _, _, _ := mintKey(t, srv, aTok, map[string]any{"label": "alpha-key", "scopes": []string{"read:metrics"}}); st != 201 {
		t.Fatalf("alpha mint: %d", st)
	}
	aKeyID := onlyKeyID(t, srv, aTok)

	// B sees none of A's keys, with or without an as_tenant selector pointed at A.
	for _, path := range []string{"/api/apikeys", "/api/apikeys?as_tenant=" + tenantA} {
		st, b := do(t, srv, "GET", path, bTok, nil)
		if st != 200 {
			t.Fatalf("B GET %s: %d %s", path, st, b)
		}
		var keys []map[string]any
		if err := json.Unmarshal(b, &keys); err != nil {
			t.Fatal(err)
		}
		if len(keys) != 0 {
			t.Errorf("cross-tenant leak on %s: %s", path, b)
		}
	}
	// Cross-tenant revoke is a 404 — never a 403, which would confirm the id.
	if st, _ := do(t, srv, "DELETE", "/api/apikeys/"+aKeyID, bTok, nil); st != 404 {
		t.Errorf("B revoking A's key: %d, want 404", st)
	}
	// A still owns its key.
	if got := onlyKeyID(t, srv, aTok); got != aKeyID {
		t.Errorf("A's key changed under a cross-tenant delete: %q", got)
	}
}

// mkTenantForKeys creates a tenant and returns its id.
func mkTenantForKeys(t *testing.T, srv *httptest.Server, admin, name string) string {
	t.Helper()
	st, b := do(t, srv, "POST", "/api/tenants", admin, map[string]any{"name": name})
	if st != 201 {
		t.Fatalf("create tenant %s: %d %s", name, st, b)
	}
	var out struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(b, &out); err != nil || out.ID == "" {
		t.Fatalf("tenant %s has no id: %v %s", name, err, b)
	}
	return out.ID
}

// onlyKeyID asserts the caller sees exactly one key and returns its id.
func onlyKeyID(t *testing.T, srv *httptest.Server, token string) string {
	t.Helper()
	st, b := do(t, srv, "GET", "/api/apikeys", token, nil)
	if st != 200 {
		t.Fatalf("list keys: %d %s", st, b)
	}
	var keys []struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(b, &keys); err != nil {
		t.Fatal(err)
	}
	if len(keys) != 1 {
		t.Fatalf("want exactly 1 visible key, got %d: %s", len(keys), b)
	}
	return keys[0].ID
}
