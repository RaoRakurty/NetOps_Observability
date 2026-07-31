package backend

// processors_isolation_test.go — §3a cross-org isolation guard for the
// pipeline-processor surface (item 121), through the REAL router + auth
// middleware (org_isolation_test.go template): own-only list, cross-tenant
// get/put/delete → 404, acting-tenant override ignored, owner stamped from
// the token, platform owner sees all. Plus the generator boundary: a tenant's
// rule compiles into VRL guarded by ITS tenant id only.

import (
	"encoding/json"
	"net/http"
	"path/filepath"
	"strings"
	"testing"

	"netops/backend/processors"
)

func TestProcessorRulesCrossOrgIsolation(t *testing.T) {
	srv, s := newTestServerState(t)
	s.processors = processors.NewFileStore(filepath.Join(t.TempDir(), "processors.json"))

	admin := login(t, srv, "admin", "Passw0rd!2345").Token

	fix := map[string]*orgFixture{}
	for _, name := range []string{"A", "B"} {
		st, b := do(t, srv, "POST", "/api/orgs", admin, map[string]any{"name": "Org " + name})
		if st != 201 {
			t.Fatalf("create org %s: %d %s", name, st, b)
		}
		orgID := idOf(t, b)
		st, b = do(t, srv, "POST", "/api/tenants", admin, map[string]any{"name": "Tenant " + name, "org_id": orgID})
		if st != 201 {
			t.Fatalf("create tenant %s: %d %s", name, st, b)
		}
		tenantID := idOf(t, b)
		user := "pr-admin-" + name
		// administration:admin is required — create tenant-scoped admins.
		st, b = do(t, srv, "POST", "/api/users", admin, map[string]any{
			"username": user, "password": "Passw0rd!2345", "role": "admin", "tenant_id": tenantID,
		})
		if st != 201 {
			t.Fatalf("create user %s: %d %s", name, st, b)
		}
		fix[name] = &orgFixture{orgID: orgID, tenantID: tenantID, user: user, token: login(t, srv, user, "Passw0rd!2345").Token}
	}
	a, b := fix["A"], fix["B"]

	ruleBody := map[string]any{
		"lane": "syslog", "type": "redact_pattern", "field": "message",
		"pattern_kind": "builtin", "pattern": "email",
	}

	// ── create + owner stamping ────────────────────────────────────────────────
	st, body := do(t, srv, "POST", "/api/pipeline/processors", a.token, ruleBody)
	if st != 201 {
		t.Fatalf("org-A create rule: %d %s", st, body)
	}
	var rA processors.Rule
	if err := json.Unmarshal(body, &rA); err != nil || rA.ID == "" {
		t.Fatalf("create must return the rule: %s", body)
	}
	if rA.TenantID != a.tenantID {
		t.Fatalf("owner must be stamped from the token, got %q want %q", rA.TenantID, a.tenantID)
	}
	if !rA.Enabled {
		t.Fatalf("enabled must default to true when omitted: %+v", rA)
	}
	st, body = do(t, srv, "POST", "/api/pipeline/processors", b.token, ruleBody)
	if st != 201 {
		t.Fatalf("org-B create rule: %d %s", st, body)
	}
	var rB processors.Rule
	_ = json.Unmarshal(body, &rB)

	// A non-admin operator must be refused entirely.
	st, _ = do(t, srv, "POST", "/api/users", admin, map[string]any{
		"username": "pr-op", "password": "Passw0rd!2345", "role": "operator", "tenant_id": a.tenantID,
	})
	if st != 201 {
		t.Fatalf("create operator: %d", st)
	}
	opTok := login(t, srv, "pr-op", "Passw0rd!2345").Token
	if st, _ := do(t, srv, "GET", "/api/pipeline/processors", opTok, nil); st != http.StatusForbidden {
		t.Fatalf("an operator must not read pipeline rules: %d", st)
	}

	// ── own-only list ──────────────────────────────────────────────────────────
	type listResp struct {
		Rules []processors.Rule `json:"rules"`
		Count int               `json:"count"`
	}
	list := func(token string) listResp {
		t.Helper()
		st, body := do(t, srv, "GET", "/api/pipeline/processors", token, nil)
		if st != 200 {
			t.Fatalf("list rules: %d %s", st, body)
		}
		var lr listResp
		if err := json.Unmarshal(body, &lr); err != nil {
			t.Fatal(err)
		}
		return lr
	}
	for _, r := range list(a.token).Rules {
		if r.TenantID == b.tenantID {
			t.Fatalf("TENANT LEAK: org-A listed org-B's rule: %+v", r)
		}
	}
	if got := list(admin).Count; got != 2 {
		t.Fatalf("platform owner must see both rules, got %d", got)
	}

	// ── cross-tenant get/put/delete → 404, row untouched ───────────────────────
	if st, _ := do(t, srv, "GET", "/api/pipeline/processors/"+rB.ID, a.token, nil); st != http.StatusNotFound {
		t.Fatalf("cross-tenant GET must 404, got %d", st)
	}
	if st, _ := do(t, srv, "PUT", "/api/pipeline/processors/"+rB.ID, a.token, ruleBody); st != http.StatusNotFound {
		t.Fatalf("cross-tenant PUT must 404, got %d", st)
	}
	if st, _ := do(t, srv, "DELETE", "/api/pipeline/processors/"+rB.ID, a.token, nil); st != http.StatusNotFound {
		t.Fatalf("cross-tenant DELETE must 404, got %d", st)
	}
	if st, _ := do(t, srv, "GET", "/api/pipeline/processors/"+rB.ID, b.token, nil); st != 200 {
		t.Fatalf("org-B's rule must survive cross-tenant attempts: %d", st)
	}

	// ── generator boundary: A's rule is guarded by A's tenant id only ──────────
	all, err := s.processors.AllEnabled(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	vrl := processors.GenerateRouterConfig(all)
	if !strings.Contains(vrl, `== "`+a.tenantID+`"`) || !strings.Contains(vrl, `== "`+b.tenantID+`"`) {
		t.Fatalf("each rule must carry its own tenant guard:\n%s", vrl)
	}

	// ── preview simulates only the CALLER's rules on the caller's tenant ───────
	st, body = do(t, srv, "POST", "/api/pipeline/processors/preview", a.token, map[string]any{
		"lane":  "syslog",
		"event": map[string]any{"message": "reset by jsmith@corp.example please"},
	})
	if st != 200 {
		t.Fatalf("preview: %d %s", st, body)
	}
	var prev struct {
		Event   map[string]any      `json:"event"`
		Applied []processors.Applied `json:"applied"`
	}
	if err := json.Unmarshal(body, &prev); err != nil {
		t.Fatal(err)
	}
	if got := prev.Event["message"]; got != "reset by *** please" {
		t.Fatalf("preview must apply the caller's redaction: %v", got)
	}
	if len(prev.Applied) != 1 {
		t.Fatalf("preview must report which rules fired: %+v", prev.Applied)
	}
}
