package main

import (
	"encoding/json"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"netops/backend/policy"
)

// policy_http_test.go — Phase 3 HTTP surface: catalog, effective/simulator,
// per-scope editing, and the authorization boundary that decides who may
// read/write which scope (system + global policy = platform owner only; a
// scoped tenant admin is confined to its own tenant). The pure resolution /
// write-gate behaviour is covered by policy/ and policy_store_test.go; these
// tests assert the HTTP wiring + authz.

func policyServer(t *testing.T) *server {
	t.Helper()
	roles, err := newRoleStore(filepath.Join(t.TempDir(), "roles.json"))
	if err != nil {
		t.Fatalf("roleStore: %v", err)
	}
	return &server{
		roles:     roles,
		secPolicy: newSecurityPolicyStore(filepath.Join(t.TempDir(), "security_policies.json")),
	}
}

// claim helpers (super-admin in the global tenant = cross-tenant platform owner;
// super-admin in a named tenant = scoped tenant admin).
func platformOwner() jwtClaims {
	return jwtClaims{Sub: "root", Role: RoleSuperAdmin, Tenant: TenantGlobal}
}
func tAdmin(ten string) jwtClaims {
	return jwtClaims{Sub: "adm@" + ten, Role: RoleSuperAdmin, Tenant: ten}
}
func tViewer(ten string) jwtClaims {
	return jwtClaims{Sub: "ro@" + ten, Role: RoleReadOnly, Tenant: ten}
}

func putBody(key string, num int64, locked bool) string {
	b, _ := json.Marshal(policyOverrideRequest{
		Key:    key,
		Value:  policy.Value{Kind: policy.KindInt, Num: num},
		Locked: locked,
	})
	return string(b)
}

func TestPolicyHTTP_CatalogRequiresAdmin(t *testing.T) {
	s := policyServer(t)

	// read-only is rejected
	w := httptest.NewRecorder()
	s.handlePolicyCatalog(w, req("GET", "/api/policy/catalog", "", tViewer("acme")))
	if w.Code != 403 {
		t.Fatalf("read-only should be forbidden, got %d", w.Code)
	}

	// admin gets the grouped catalog
	w = httptest.NewRecorder()
	s.handlePolicyCatalog(w, req("GET", "/api/policy/catalog", "", platformOwner()))
	if w.Code != 200 {
		t.Fatalf("admin catalog: %d", w.Code)
	}
	var resp policyCatalogResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(resp.Domains) != 4 || len(resp.Scopes) != 4 {
		t.Fatalf("want 4 domains + 4 scopes, got %d domains %d scopes", len(resp.Domains), len(resp.Scopes))
	}
}

// The platform owner authors the system baseline; a tenant tightens it; the
// effective endpoint (the simulator) reflects the cascade.
func TestPolicyHTTP_WriteAndEffectiveCascade(t *testing.T) {
	s := policyServer(t)

	// System baseline (platform owner only).
	w := httptest.NewRecorder()
	s.handlePolicyDocument(w, req("PUT", "/api/policy/document?scope=system", putBody(keyMinLen, 14, false), platformOwner()))
	if w.Code != 200 {
		t.Fatalf("system PUT: %d (%s)", w.Code, w.Body)
	}

	// Tenant admin tightens within its own tenant.
	w = httptest.NewRecorder()
	s.handlePolicyDocument(w, req("PUT", "/api/policy/document?scope=tenant&selector=acme", putBody(keyMinLen, 16, false), tAdmin("acme")))
	if w.Code != 200 {
		t.Fatalf("tenant PUT: %d (%s)", w.Code, w.Body)
	}

	// Effective for an acme subject is the tenant value.
	got := effectiveValue(t, s, tAdmin("acme"), "acme", keyMinLen)
	if got != 16 {
		t.Fatalf("acme effective min_length want 16, got %d", got)
	}
	// A different tenant still sees the system baseline.
	if v := effectiveValue(t, s, platformOwner(), "globex", keyMinLen); v != 14 {
		t.Fatalf("globex effective min_length want 14 (system), got %d", v)
	}
}

func TestPolicyHTTP_WriteAuthzBoundary(t *testing.T) {
	s := policyServer(t)

	// A tenant admin may NOT write system policy.
	w := httptest.NewRecorder()
	s.handlePolicyDocument(w, req("PUT", "/api/policy/document?scope=system", putBody(keyMinLen, 16, false), tAdmin("acme")))
	if w.Code != 403 {
		t.Fatalf("tenant admin writing system should be 403, got %d", w.Code)
	}

	// A tenant admin may NOT write another tenant's policy.
	w = httptest.NewRecorder()
	s.handlePolicyDocument(w, req("PUT", "/api/policy/document?scope=tenant&selector=globex", putBody(keyMinLen, 16, false), tAdmin("acme")))
	if w.Code != 403 {
		t.Fatalf("acme writing globex should be 403, got %d", w.Code)
	}

	// The platform owner may write system policy.
	w = httptest.NewRecorder()
	s.handlePolicyDocument(w, req("PUT", "/api/policy/document?scope=system", putBody(keyMinLen, 14, false), platformOwner()))
	if w.Code != 200 {
		t.Fatalf("platform owner writing system: %d (%s)", w.Code, w.Body)
	}
}

// A scoped admin cannot simulate another tenant's effective policy.
func TestPolicyHTTP_EffectiveTenantIsolation(t *testing.T) {
	s := policyServer(t)
	w := httptest.NewRecorder()
	s.handlePolicyEffective(w, req("GET", "/api/policy/effective?tenant=globex", "", tAdmin("acme")))
	if w.Code != 403 {
		t.Fatalf("acme simulating globex should be 403, got %d", w.Code)
	}
}

// A weakening tenant override is rejected by the write gate (400).
func TestPolicyHTTP_WeakeningRejected(t *testing.T) {
	s := policyServer(t)
	mustPUT(t, s, platformOwner(), "/api/policy/document?scope=system", putBody(keyMinLen, 14, false))

	w := httptest.NewRecorder()
	s.handlePolicyDocument(w, req("PUT", "/api/policy/document?scope=tenant&selector=acme", putBody(keyMinLen, 10, false), tAdmin("acme")))
	if w.Code != 400 {
		t.Fatalf("weakening override should be 400, got %d (%s)", w.Code, w.Body)
	}
}

// The validate endpoint is a non-persisting pre-flight: it reports acceptance
// without creating any document.
func TestPolicyHTTP_ValidateDryRun(t *testing.T) {
	s := policyServer(t)
	mustPUT(t, s, platformOwner(), "/api/policy/document?scope=system", putBody(keyMinLen, 14, false))

	body, _ := json.Marshal(policyValidateRequest{
		Scope: policy.ScopeTenant, Selector: "acme",
		Key: keyMinLen, Value: policy.Value{Kind: policy.KindInt, Num: 10}, // weaker → invalid
	})
	w := httptest.NewRecorder()
	s.handlePolicyValidate(w, req("POST", "/api/policy/validate", string(body), tAdmin("acme")))
	if w.Code != 200 {
		t.Fatalf("validate: %d", w.Code)
	}
	var resp struct {
		OK    bool   `json:"ok"`
		Error string `json:"error"`
	}
	json.NewDecoder(w.Body).Decode(&resp)
	if resp.OK || resp.Error == "" {
		t.Fatalf("weaker value should be ok=false with a reason, got %+v", resp)
	}
	// No document was created by the dry-run.
	if docs := s.secPolicy.Documents("acme"); len(docs) != 1 { // system only
		t.Fatalf("validate must not persist; got %d docs", len(docs))
	}
}

// DELETE clears an override, reverting to the inherited value.
func TestPolicyHTTP_DeleteReverts(t *testing.T) {
	s := policyServer(t)
	mustPUT(t, s, platformOwner(), "/api/policy/document?scope=system", putBody(keyMinLen, 14, false))
	mustPUT(t, s, tAdmin("acme"), "/api/policy/document?scope=tenant&selector=acme", putBody(keyMinLen, 18, false))

	w := httptest.NewRecorder()
	s.handlePolicyDocument(w, req("DELETE", "/api/policy/document?scope=tenant&selector=acme&key="+keyMinLen+"&prune=true", "", tAdmin("acme")))
	if w.Code != 204 {
		t.Fatalf("delete: %d (%s)", w.Code, w.Body)
	}
	if v := effectiveValue(t, s, tAdmin("acme"), "acme", keyMinLen); v != 14 {
		t.Fatalf("after delete want inherited 14, got %d", v)
	}
}

// Documents listing is tenant-scoped: the platform owner sees all, a tenant
// admin sees system + its own.
func TestPolicyHTTP_DocumentsListing(t *testing.T) {
	s := policyServer(t)
	mustPUT(t, s, platformOwner(), "/api/policy/document?scope=system", putBody(keyMinLen, 14, false))
	mustPUT(t, s, tAdmin("acme"), "/api/policy/document?scope=tenant&selector=acme", putBody(keyMinLen, 16, false))
	mustPUT(t, s, tAdmin("globex"), "/api/policy/document?scope=tenant&selector=globex", putBody(keyMinLen, 16, false))

	if n := documentsCount(t, s, platformOwner()); n != 3 {
		t.Fatalf("platform owner should see all 3 docs, got %d", n)
	}
	if n := documentsCount(t, s, tAdmin("acme")); n != 2 { // system + acme
		t.Fatalf("acme should see system + own, got %d", n)
	}
}

// ---- helpers ----------------------------------------------------------------

func effectiveValue(t *testing.T, s *server, claims jwtClaims, tenant, key string) int64 {
	t.Helper()
	w := httptest.NewRecorder()
	s.handlePolicyEffective(w, req("GET", "/api/policy/effective?tenant="+tenant, "", claims))
	if w.Code != 200 {
		t.Fatalf("effective %s: %d (%s)", tenant, w.Code, w.Body)
	}
	var resp struct {
		Resolved []policy.Resolved `json:"resolved"`
	}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode effective: %v", err)
	}
	for _, r := range resp.Resolved {
		if r.Key == key {
			return r.Value.Num
		}
	}
	t.Fatalf("key %q not in effective response", key)
	return 0
}

func documentsCount(t *testing.T, s *server, claims jwtClaims) int {
	t.Helper()
	w := httptest.NewRecorder()
	s.handlePolicyDocuments(w, req("GET", "/api/policy/documents", "", claims))
	if w.Code != 200 {
		t.Fatalf("documents: %d", w.Code)
	}
	var resp struct {
		Documents []policy.Document `json:"documents"`
	}
	json.NewDecoder(w.Body).Decode(&resp)
	return len(resp.Documents)
}

func mustPUT(t *testing.T, s *server, claims jwtClaims, path, body string) {
	t.Helper()
	w := httptest.NewRecorder()
	s.handlePolicyDocument(w, req("PUT", path, body, claims))
	if w.Code != 200 {
		t.Fatalf("PUT %s: %d (%s)", path, w.Code, w.Body)
	}
}
