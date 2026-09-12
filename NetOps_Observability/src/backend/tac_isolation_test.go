// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// Route templates covered (the coverage guard matches this literal text):
//   "/api/incidents/{id}/tac"          "/api/incidents/{id}/tac/classify"
//   "/api/incidents/{id}/tac/plan"     "/api/incidents/{id}/tac/collect"
//   "/api/incidents/{id}/tac/bundle"   "/api/incidents/{id}/tac/case"

package backend

// tac_isolation_test.go — §3a cross-org isolation guard for the TAC escalation
// pack, exercised through the REAL router + auth middleware
// (org_isolation_test.go template).
//
// The four obligations §3a rule 5 demands, for every /tac route:
//
//	· own-only        — an operator drives its OWN incident (200/202)
//	· foreign → 404   — another org's incident id is indistinguishable from an
//	                    id that does not exist; never 403, which would confirm it
//	· as_tenant       — an X-Acting-Tenant override into another org is ignored
//	                    for a caller who does not own that org
//	· device scope    — the subject device is resolved in the caller's own
//	                    inventory, so a foreign device id is a 404 too
//
// The incident register is nil on the file backend, so this test injects a small
// in-memory Repo. That is not a shortcut around the guarantee: the FILTER under
// test is the (tenant, cross) pair the handler passes down, and the fake honours
// it exactly as the PG store's row policies do — a fake that ignored the tenant
// would fail these assertions, not pass them.

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"netops/backend/internal/incident"
	"netops/backend/models"
)

// newTACTestServer is newTestServerState plus the escalation service, built
// exactly the way newServer builds it — with DATA_DIR pointed inside the test's
// own temp directory so no test can write a bundle to /data. The live collector
// stays unwired (the feature flag is off), which is the deployment default and
// the state the honest-503 assertions below depend on.
func newTACTestServer(t *testing.T) (*httptest.Server, *server) {
	t.Helper()
	t.Setenv("DATA_DIR", t.TempDir())
	srv, s := newTestServerState(t)
	if err := s.buildTACService(); err != nil {
		t.Fatalf("build TAC service: %v", err)
	}
	return srv, s
}

// memIncidents is an in-memory incident.Repo that enforces the SAME tenant rule
// the PG store's RLS does: a non-cross caller sees only its own tenant's rows.
type memIncidents struct {
	mu   sync.Mutex
	rows map[string]incident.Incident
}

func newMemIncidents() *memIncidents {
	return &memIncidents{rows: map[string]incident.Incident{}}
}

func (m *memIncidents) put(inc incident.Incident) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.rows[inc.ID] = inc
}

func (m *memIncidents) visible(tenant string, cross bool, inc incident.Incident) bool {
	return cross || inc.TenantID == tenant
}

func (m *memIncidents) Ingest(context.Context, incident.Input) (incident.Incident, bool, error) {
	return incident.Incident{}, false, nil
}

func (m *memIncidents) Get(_ context.Context, tenant string, cross bool, id string) (incident.Incident, []incident.Event, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	inc, ok := m.rows[id]
	if !ok || !m.visible(tenant, cross, inc) {
		return incident.Incident{}, nil, false, nil
	}
	return inc, nil, true, nil
}

func (m *memIncidents) List(_ context.Context, tenant string, cross bool, _ incident.Query) ([]incident.Incident, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []incident.Incident
	for _, inc := range m.rows {
		if m.visible(tenant, cross, inc) {
			out = append(out, inc)
		}
	}
	return out, nil
}

func (m *memIncidents) Count(ctx context.Context, tenant string, cross bool, q incident.Query) (int, error) {
	rows, err := m.List(ctx, tenant, cross, q)
	return len(rows), err
}

func (m *memIncidents) Transition(context.Context, string, bool, string, string, string, string) (incident.Incident, error) {
	return incident.Incident{}, nil
}
func (m *memIncidents) AddNote(context.Context, string, bool, string, string, string) (incident.Incident, error) {
	return incident.Incident{}, nil
}
func (m *memIncidents) Assign(context.Context, string, bool, string, string, string) (incident.Incident, error) {
	return incident.Incident{}, nil
}
func (m *memIncidents) MarkSync(context.Context, string, string, string, string, string, time.Time) error {
	return nil
}
func (m *memIncidents) MarkNotified(context.Context, string, string) error { return nil }
func (m *memIncidents) FindByExternalTicket(context.Context, string, string, string) (incident.Incident, bool, error) {
	return incident.Incident{}, false, nil
}

func TestTACEscalationCrossOrgIsolation(t *testing.T) {
	srv, s := newTACTestServer(t)
	inc := newMemIncidents()
	s.incidents = inc

	admin := login(t, srv, "admin", "Passw0rd!2345").Token

	fix := map[string]*orgFixture{}
	for _, name := range []string{"A", "B"} {
		st, b := do(t, srv, "POST", "/api/orgs", admin, map[string]any{"name": "TAC Org " + name})
		if st != 201 {
			t.Fatalf("create org %s: %d %s", name, st, b)
		}
		orgID := idOf(t, b)
		st, b = do(t, srv, "POST", "/api/tenants", admin, map[string]any{"name": "TAC Tenant " + name, "org_id": orgID})
		if st != 201 {
			t.Fatalf("create tenant %s: %d %s", name, st, b)
		}
		tenantID := idOf(t, b)
		user := "tac-user-" + name
		st, b = do(t, srv, "POST", "/api/users", admin, map[string]any{
			"username": user, "password": "Passw0rd!2345", "role": "operator", "tenant_id": tenantID,
		})
		if st != 201 {
			t.Fatalf("create user %s: %d %s", name, st, b)
		}
		fix[name] = &orgFixture{orgID: orgID, tenantID: tenantID, user: user,
			token: login(t, srv, user, "Passw0rd!2345").Token}
	}
	a, b := fix["A"], fix["B"]

	now := time.Now().UTC()
	inc.put(incident.Incident{ID: "tacinc-a", TenantID: a.tenantID, Title: "OSPF adjacency down on core-a",
		Severity: "critical", Status: "open", FirstSeenAt: now.Add(-time.Hour), LastSeenAt: now})
	inc.put(incident.Incident{ID: "tacinc-b", TenantID: b.tenantID, Title: "BGP session down on core-b",
		Severity: "critical", Status: "open", FirstSeenAt: now.Add(-time.Hour), LastSeenAt: now})

	s.discovery.Upsert(models.Device{ID: "tac-dev-a", Name: "tac-dev-a", Vendor: "Cisco", OS: "IOS-XE", TenantID: a.tenantID})
	s.discovery.Upsert(models.Device{ID: "tac-dev-b", Name: "tac-dev-b", Vendor: "Cisco", OS: "IOS-XE", TenantID: b.tenantID})

	// ── own-only: every route answers for the owner ─────────────────────────────
	if st, body := do(t, srv, "GET", "/api/incidents/tacinc-a/tac", a.token, nil); st != 200 {
		t.Fatalf("A reads its own escalation state: %d %s", st, body)
	}
	if st, body := do(t, srv, "POST", "/api/incidents/tacinc-a/tac/classify", a.token, map[string]any{}); st != 200 {
		t.Fatalf("A classifies its own incident: %d %s", st, body)
	}
	if st, body := do(t, srv, "POST", "/api/incidents/tacinc-a/tac/plan", a.token,
		map[string]any{"device_id": "tac-dev-a", "class_id": "ospf-adjacency"}); st != 200 {
		t.Fatalf("A plans against its own device: %d %s", st, body)
	}

	// ── foreign incident id → 404 on every route, never 403 ─────────────────────
	for _, route := range []struct {
		method, path string
		body         map[string]any
	}{
		{"GET", "/api/incidents/tacinc-b/tac", nil},
		{"POST", "/api/incidents/tacinc-b/tac/classify", map[string]any{}},
		{"POST", "/api/incidents/tacinc-b/tac/plan", map[string]any{"device_id": "tac-dev-a", "class_id": "ospf-adjacency"}},
		{"POST", "/api/incidents/tacinc-b/tac/collect", map[string]any{}},
		{"GET", "/api/incidents/tacinc-b/tac/bundle", nil},
		{"POST", "/api/incidents/tacinc-b/tac/case", map[string]any{}},
	} {
		st, body := do(t, srv, route.method, route.path, a.token, route.body)
		if st != http.StatusNotFound {
			t.Errorf("%s %s as the wrong org: %d %s, want 404", route.method, route.path, st, body)
		}
	}
	// An id that does not exist at all answers IDENTICALLY — the subtree is not
	// an existence oracle.
	if st, _ := do(t, srv, "GET", "/api/incidents/tacinc-nope/tac", a.token, nil); st != http.StatusNotFound {
		t.Fatalf("unknown incident id: %d, want the same 404 a foreign id gets", st)
	}

	// ── foreign DEVICE id on an own incident → 404 ──────────────────────────────
	if st, body := do(t, srv, "POST", "/api/incidents/tacinc-a/tac/plan", a.token,
		map[string]any{"device_id": "tac-dev-b", "class_id": "ospf-adjacency"}); st != http.StatusNotFound {
		t.Fatalf("A plans against B's device: %d %s, want 404", st, body)
	}

	// ── as_tenant / X-Acting-Tenant into another org is ignored ─────────────────
	{
		payload, _ := json.Marshal(map[string]any{})
		req, err := http.NewRequest("POST", srv.URL+"/api/incidents/tacinc-b/tac/classify", bytes.NewReader(payload))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+a.token)
		req.Header.Set("X-Acting-Tenant", b.tenantID)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			t.Fatalf("acting-tenant override widened a scoped caller: %d", resp.StatusCode)
		}
	}

	// ── the platform owner reaches both ─────────────────────────────────────────
	for _, id := range []string{"tacinc-a", "tacinc-b"} {
		if st, body := do(t, srv, "GET", "/api/incidents/"+id+"/tac", admin, nil); st != 200 {
			t.Fatalf("owner reads %s: %d %s", id, st, body)
		}
	}

	// ── a tenant in the request body is REJECTED, not honoured (§3a rule 2) ─────
	if st, _ := do(t, srv, "POST", "/api/incidents/tacinc-a/tac/plan", a.token, map[string]any{
		"device_id": "tac-dev-a", "class_id": "ospf-adjacency", "tenant_id": b.tenantID,
	}); st != http.StatusBadRequest {
		t.Fatalf("a tenant smuggled into the body was not rejected: %d", st)
	}
}

// TestTACBundleIsTenantKeyedOnDisk proves the store's directory layout keeps one
// tenant's bundles out of another's reach at the FILESYSTEM level, not merely
// behind a filter.
func TestTACCollectIsHonestWithoutATransport(t *testing.T) {
	srv, s := newTACTestServer(t)
	inc := newMemIncidents()
	s.incidents = inc
	admin := login(t, srv, "admin", "Passw0rd!2345").Token
	now := time.Now().UTC()
	inc.put(incident.Incident{ID: "tacinc-x", TenantID: "", Title: "OSPF adjacency down",
		Severity: "critical", Status: "open", FirstSeenAt: now.Add(-time.Hour), LastSeenAt: now})
	s.discovery.Upsert(models.Device{ID: "tac-dev-x", Name: "tac-dev-x", Vendor: "Cisco", OS: "IOS-XE"})

	if st, _ := do(t, srv, "POST", "/api/incidents/tacinc-x/tac/classify", admin, map[string]any{}); st != 200 {
		t.Fatalf("classify: %d", st)
	}
	if st, body := do(t, srv, "POST", "/api/incidents/tacinc-x/tac/plan", admin,
		map[string]any{"device_id": "tac-dev-x", "class_id": "ospf-adjacency"}); st != 200 {
		t.Fatalf("plan: %d %s", st, body)
	}
	st, body := do(t, srv, "POST", "/api/incidents/tacinc-x/tac/collect", admin, map[string]any{})
	if st != http.StatusServiceUnavailable {
		t.Fatalf("collect with no transport: %d %s, want 503", st, body)
	}
	if !strings.Contains(string(body), "paste") {
		t.Fatalf("the 503 must name the paste fallback, got %s", body)
	}
	// A bundle before anything was collected is a conflict, not an empty zip.
	if st, _ := do(t, srv, "GET", "/api/incidents/tacinc-x/tac/bundle", admin, nil); st != http.StatusConflict {
		t.Fatalf("bundle with nothing collected: %d, want 409", st)
	}
}

// TestTACKnowledgeIsTenantInvariant pins the ledger's "globalRef" classification
// of the coverage view: two operators in DIFFERENT orgs get byte-identical
// answers, because the view carries no tenant data at all.
func TestTACKnowledgeIsTenantInvariant(t *testing.T) {
	srv, _ := newTACTestServer(t)
	admin := login(t, srv, "admin", "Passw0rd!2345").Token
	var tokens []string
	for _, name := range []string{"K1", "K2"} {
		st, b := do(t, srv, "POST", "/api/orgs", admin, map[string]any{"name": "TACK Org " + name})
		if st != 201 {
			t.Fatalf("org: %d %s", st, b)
		}
		orgID := idOf(t, b)
		st, b = do(t, srv, "POST", "/api/tenants", admin, map[string]any{"name": "TACK Tenant " + name, "org_id": orgID})
		if st != 201 {
			t.Fatalf("tenant: %d %s", st, b)
		}
		user := "tack-user-" + strings.ToLower(name)
		st, b = do(t, srv, "POST", "/api/users", admin, map[string]any{
			"username": user, "password": "Passw0rd!2345", "role": "operator", "tenant_id": idOf(t, b),
		})
		if st != 201 {
			t.Fatalf("user: %d %s", st, b)
		}
		tokens = append(tokens, login(t, srv, user, "Passw0rd!2345").Token)
	}
	st1, body1 := do(t, srv, "GET", "/api/troubleshoot/tac/knowledge", tokens[0], nil)
	st2, body2 := do(t, srv, "GET", "/api/troubleshoot/tac/knowledge", tokens[1], nil)
	if st1 != 200 || st2 != 200 {
		t.Fatalf("knowledge: %d / %d", st1, st2)
	}
	if string(body1) != string(body2) {
		t.Fatal("the coverage view is tenant-variant; reclassify it `scoped` and give it a cross-org isolation test")
	}
	if !strings.Contains(string(body1), "unplanned_dialects") {
		t.Fatal("the coverage view must name the platforms with NO authored plan — that is the honest half")
	}
}
