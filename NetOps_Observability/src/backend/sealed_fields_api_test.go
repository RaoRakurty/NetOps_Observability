package backend

// sealed_fields_api_test.go — the reveal endpoint's security contract.
//
// This is the one route in the product that turns protected data back into
// plaintext, so the tests here are about REFUSAL far more than about success:
// who is turned away, what they learn when they are, and what ends up in the
// audit trail either way.
//
// Includes the cross-org isolation test CLAUDE.md §3a requires of every
// data-returning surface.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"netops/backend/internal/rbac"
	"netops/backend/internal/sealedfields"
	"netops/backend/internal/vault"
	"netops/backend/processors"
	"netops/backend/sealing"
)

const unsealPath = "/api/pipeline/processors/unseal"

// createTenantFor makes an org + tenant and returns the tenant id. Same shape
// the other isolation tests build by hand; factored out here because this file
// needs it three times.
func createTenantFor(t *testing.T, ts *httptest.Server, adminToken, name string) string {
	t.Helper()
	st, b := do(t, ts, "POST", "/api/orgs", adminToken, map[string]any{"name": "Org " + name})
	if st != 201 {
		t.Fatalf("create org %s: %d %s", name, st, b)
	}
	orgID := idOf(t, b)
	st, b = do(t, ts, "POST", "/api/tenants", adminToken, map[string]any{"name": "Tenant " + name, "org_id": orgID})
	if st != 201 {
		t.Fatalf("create tenant %s: %d %s", name, st, b)
	}
	return idOf(t, b)
}

// createUserFor makes a tenant-scoped user and returns their token.
func createUserFor(t *testing.T, ts *httptest.Server, adminToken, user, role, tenantID string) string {
	t.Helper()
	st, b := do(t, ts, "POST", "/api/users", adminToken, map[string]any{
		"username": user, "password": "Passw0rd!2345", "role": role, "tenant_id": tenantID,
	})
	if st != 201 {
		t.Fatalf("create user %s: %d %s", user, st, b)
	}
	return login(t, ts, user, "Passw0rd!2345").Token
}

// sealTestServer wires a server with live sealing over an in-memory vault.
func sealTestServer(t *testing.T) (*httptest.Server, *server, sealing.CryptoProvider) {
	t.Helper()
	srv, s := newTestServerState(t)
	v, err := vault.NewWithProvider(context.Background(), &memSealing{},
		&memVaultStore{data: map[string][]byte{}}, func(string, string, map[string]any) {})
	if err != nil {
		t.Fatalf("vault: %v", err)
	}
	provider := sealedfields.NewProvider(v)
	s.sealProvider = provider
	s.sealMetrics = &sealMetrics{}
	s.processors = processors.NewFileStore(filepath.Join(t.TempDir(), "p.json"))
	processors.SetSealEngine(sealedfields.NewEngine(provider))
	t.Cleanup(func() { processors.SetSealEngine(nil) })
	return srv, s, provider
}

// sealFor seals a value as `tenant` through a processor the tenant owns, and
// registers that processor so the reveal path can resolve its context.
func sealFor(t *testing.T, s *server, p sealing.CryptoProvider, tenant, _, field, value string) string {
	t.Helper()
	// Create FIRST and seal with the id the STORE assigned. Processor ids are
	// server-generated, so sealing under a client-chosen id would bind a context
	// that no stored processor reproduces — which is exactly the mismatch that
	// makes a value unrecoverable, and exactly what this must not model wrongly.
	created, err := s.processors.Create(context.Background(), tenant, false, processors.Processor{
		Name: "seal " + field, TenantID: tenant, Lane: "applogs",
		Type: processors.TypeSeal, Enabled: true, Field: field, DataType: field, Order: 10,
	})
	if err != nil {
		t.Fatalf("create processor: %v", err)
	}
	tok, err := p.Seal(context.Background(), sealing.Context{
		Tenant: created.TenantID, ProcessorID: created.ID, Field: field, DataType: field,
	}, value)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	return tok
}

// A caller WITHOUT sensitive_data:admin must be refused — and an operator is
// exactly that caller: they can run the platform without being able to read
// the data it protects.
func TestUnsealRequiresSensitiveDataAdmin(t *testing.T) {
	ts, s, p := sealTestServer(t)
	admin := login(t, ts, "admin", "Passw0rd!2345").Token

	tenantID := createTenantFor(t, ts, admin, "acme")
	operator := createUserFor(t, ts, admin, "seal-op", "operator", tenantID)
	tok := sealFor(t, s, p, tenantID, "p-1", "card", "4111111111111111")

	st, body := do(t, ts, "POST", unsealPath, operator, map[string]any{"value": tok})
	if st != http.StatusForbidden {
		t.Fatalf("an operator must not reveal sealed data: %d %s", st, body)
	}
	if strings.Contains(string(body), "4111") {
		t.Fatalf("a DENIED response leaked plaintext: %s", body)
	}
	if s.sealMetrics.granted.Load() != 0 {
		t.Fatal("a denied attempt was counted as granted")
	}
	if s.sealMetrics.forbidden.Load() != 1 {
		t.Fatalf("denied attempts must be counted, got %d", s.sealMetrics.forbidden.Load())
	}
}

// The happy path, and the audit record it must leave.
func TestUnsealRevealsAndAudits(t *testing.T) {
	ts, s, p := sealTestServer(t)
	admin := login(t, ts, "admin", "Passw0rd!2345").Token
	tok := sealFor(t, s, p, TenantGlobal, "p-1", "card", "4111111111111111")

	st, body := do(t, ts, "POST", unsealPath, admin, map[string]any{
		"value": tok, "reason": "PCI dispute #4471",
	})
	if st != http.StatusOK {
		t.Fatalf("super-admin reveal: %d %s", st, body)
	}
	var out unsealResponse
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if out.Value != "4111111111111111" {
		t.Fatalf("reveal returned %q", out.Value)
	}
	// The response must name the binding so the operator knows WHAT they read.
	if out.Field != "card" || out.Processor == "" {
		t.Fatalf("reveal did not report its context: %+v", out)
	}
	if s.sealMetrics.granted.Load() != 1 {
		t.Fatal("a granted reveal was not counted")
	}

	// The audit entry must record the act WITHOUT recording the secret.
	events, err := s.audit.List(TenantGlobal, true, auditQuery{Limit: 50})
	if err != nil {
		t.Fatalf("audit list: %v", err)
	}
	var found bool
	for _, e := range events {
		if e.Path != unsealPath || e.Detail == nil {
			continue
		}
		if e.Detail["outcome"] != "granted" {
			continue
		}
		found = true
		if e.Detail["reason"] != "PCI dispute #4471" {
			t.Errorf("audit lost the justification: %v", e.Detail["reason"])
		}
		if fp, _ := e.Detail["token_preview"].(string); fp == "" || strings.Contains(fp, "enc:") {
			t.Errorf("token fingerprint missing or is the raw token: %q", fp)
		}
		blob, _ := json.Marshal(e)
		if strings.Contains(string(blob), "4111111111111111") {
			t.Fatalf("THE AUDIT TRAIL RECORDED THE PLAINTEXT: %s", blob)
		}
	}
	if !found {
		t.Fatal("a successful reveal left no audit record")
	}
}

// A tampered token must be refused, and refused as unreadable rather than as
// "forbidden" — the caller was allowed; the value is broken.
func TestUnsealRejectsTamperedValue(t *testing.T) {
	ts, s, p := sealTestServer(t)
	admin := login(t, ts, "admin", "Passw0rd!2345").Token
	tok := sealFor(t, s, p, TenantGlobal, "p-1", "card", "4111111111111111")

	// Flip a character inside the ciphertext segment.
	parts := strings.Split(tok, ":")
	if len(parts) < 6 {
		t.Fatalf("unexpected token shape: %s", tok)
	}
	if parts[4][0] == 'A' {
		parts[4] = "B" + parts[4][1:]
	} else {
		parts[4] = "A" + parts[4][1:]
	}
	st, body := do(t, ts, "POST", unsealPath, admin, map[string]any{"value": strings.Join(parts, ":")})
	if st != http.StatusBadRequest {
		t.Fatalf("tampered token: want 400, got %d %s", st, body)
	}
	if strings.Contains(string(body), "4111") {
		t.Fatalf("failure path leaked plaintext: %s", body)
	}
	if s.sealMetrics.granted.Load() != 0 {
		t.Fatal("a tampered token was counted as granted")
	}
}

func TestUnsealRejectsNonTokens(t *testing.T) {
	ts, _, _ := sealTestServer(t)
	admin := login(t, ts, "admin", "Passw0rd!2345").Token
	for _, bad := range []string{"", "not a token", "<enc:>", "<enc:v9:x:1:a:b:c>"} {
		st, _ := do(t, ts, "POST", unsealPath, admin, map[string]any{"value": bad})
		if st == http.StatusOK {
			t.Errorf("%q was accepted as a sealed value", bad)
		}
	}
}

// When sealing is not enabled the endpoint must say so, not 404 or 500.
func TestUnsealUnavailableWhenDisabled(t *testing.T) {
	ts, s, _ := sealTestServer(t)
	s.sealProvider = nil
	admin := login(t, ts, "admin", "Passw0rd!2345").Token
	st, _ := do(t, ts, "POST", unsealPath, admin, map[string]any{"value": "<enc:v1:x:1:a:b:c>"})
	if st != http.StatusNotImplemented {
		t.Fatalf("want 501 when sealing is off, got %d", st)
	}
}

// §3a: cross-org isolation. One tenant's admin must never reveal another
// tenant's value, and must not learn that it exists.
func TestUnsealCrossOrgIsolation(t *testing.T) {
	ts, s, p := sealTestServer(t)
	admin := login(t, ts, "admin", "Passw0rd!2345").Token

	tenantA := createTenantFor(t, ts, admin, "org-a")
	tenantB := createTenantFor(t, ts, admin, "org-b")
	adminA := createUserFor(t, ts, admin, "admin-a", "admin", tenantA)

	tokA := sealFor(t, s, p, tenantA, "p-a", "card", "4111111111111111")
	tokB := sealFor(t, s, p, tenantB, "p-b", "card", "5500000000000004")

	// A's admin reveals A's own value.
	if st, body := do(t, ts, "POST", unsealPath, adminA, map[string]any{"value": tokA}); st != http.StatusOK {
		t.Fatalf("tenant admin must reveal their OWN value: %d %s", st, body)
	}

	// A's admin must NOT reveal B's — and gets 404, not 403: confirming the
	// value exists is itself a disclosure.
	st, body := do(t, ts, "POST", unsealPath, adminA, map[string]any{"value": tokB})
	if st != http.StatusNotFound {
		t.Fatalf("cross-tenant reveal must 404 (existence hidden), got %d %s", st, body)
	}
	if strings.Contains(string(body), "5500") {
		t.Fatalf("CROSS-TENANT PLAINTEXT LEAK: %s", body)
	}

	// Naming another tenant's processor as a hint must not help either.
	st, body = do(t, ts, "POST", unsealPath, adminA, map[string]any{
		"value": tokB, "processor_id": "p-b", "field": "card", "data_type": "card",
	})
	if st != http.StatusNotFound {
		t.Fatalf("hinting another tenant's processor must still 404, got %d %s", st, body)
	}
}

// The crypto is the backstop: even if a caller reaches the unseal path for a
// foreign token, the MAC binds the tenant and refuses.
func TestSealingRefusesForeignTokenAtTheCryptoLayer(t *testing.T) {
	_, _, p := sealTestServer(t)
	ctx := context.Background()
	tok, err := p.Seal(ctx, sealing.Context{
		Tenant: "tenant-a", ProcessorID: "p-1", Field: "card", DataType: "card",
	}, "4111111111111111")
	if err != nil {
		t.Fatal(err)
	}
	_, err = p.Unseal(ctx, sealing.Context{
		Tenant: "tenant-b", ProcessorID: "p-1", Field: "card", DataType: "card",
	}, tok)
	if err == nil {
		t.Fatal("a foreign tenant opened a sealed value at the crypto layer")
	}
}

// The reveal permission must not be reachable by being an admin of something
// else. This is a POLICY test: it documents which built-in roles hold it, so a
// future grid edit that widens it fails here rather than in production.
func TestOnlyAdminRolesHoldTheRevealPermission(t *testing.T) {
	ts, _, _ := sealTestServer(t)
	_ = ts
	store, err := newRoleStore(filepath.Join(t.TempDir(), "roles.json"))
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{
		rbac.RoleSuperAdmin: true,
		rbac.RoleOrgAdmin:   true,
		rbac.RoleOperator:   false,
		rbac.RoleReadOnly:   false,
		rbac.RoleAuditor:    false, // an auditor reads the TRAIL, never the secrets
		rbac.RoleAPIClient:  false,
	}
	for role, shouldHold := range want {
		got := store.Allows(role, rbac.ModuleSensitiveData, rbac.LevelAdmin)
		if got != shouldHold {
			t.Errorf("role %q reveal permission: got %v want %v", role, got, shouldHold)
		}
	}
}
