// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// §3a for GET /api/dem/rum/sources (the real-user setup page's "Is it
// working?" step). The ClickHouse stub LIES: whatever scope it is asked for, it
// returns both orgs' rows. Each caller must still see only its own apps.

type rumFakes struct {
	mu     sync.Mutex
	scopes []string
	sql    []string
	down   bool
}

func rumWorld(t *testing.T) (*server, *rumFakes, string, string) {
	t.Helper()
	ts, err := newTenantStore(filepath.Join(t.TempDir(), "tenants.json"))
	if err != nil {
		t.Fatalf("newTenantStore: %v", err)
	}
	acme, err := ts.Create("Acme", "acme", "", "", "")
	if err != nil {
		t.Fatal(err)
	}
	globex, err := ts.Create("Globex", "globex", "", "", "")
	if err != nil {
		t.Fatal(err)
	}
	roles, err := newRoleStore(filepath.Join(t.TempDir(), "roles.json"))
	if err != nil {
		t.Fatal(err)
	}
	s := &server{tenants: ts, roles: roles}
	f := &rumFakes{}
	ch := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		f.mu.Lock()
		f.scopes = append(f.scopes, r.URL.Query().Get("tenant_scope"))
		f.sql = append(f.sql, string(b))
		down := f.down
		f.mu.Unlock()
		if down {
			http.Error(w, "down", http.StatusServiceUnavailable)
			return
		}
		rows := []map[string]any{
			{"tenant_id": acme.ID, "app": "acme-checkout", "app_source": "attribute", "events_24h": "10", "page_views_24h": "4", "errors_24h": "0", "last_seen_ms": "1800000000000"},
			{"tenant_id": globex.ID, "app": "globex-portal", "app_source": "hostname", "events_24h": "7", "page_views_24h": "2", "errors_24h": "1", "last_seen_ms": "1800000000000"},
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"meta": []any{}, "data": rows, "rows": len(rows)})
	}))
	t.Cleanup(ch.Close)
	t.Setenv("CLICKHOUSE_URL", ch.URL)
	t.Setenv("CLICKHOUSE_PASSWORD", "")
	return s, f, acme.ID, globex.ID
}

func rumGet(t *testing.T, s *server, path string, c jwtClaims) (int, map[string]any, string) {
	t.Helper()
	w := httptest.NewRecorder()
	s.handleDEMRUMSources(w, req(http.MethodGet, path, "", c))
	var body map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &body)
	return w.Code, body, w.Body.String()
}

func TestRUMSourcesAreTheCallersOwnOnly(t *testing.T) {
	s, f, acmeID, globexID := rumWorld(t)
	for _, c := range []struct{ tenant, own, foreign string }{
		{acmeID, "acme-checkout", "globex-portal"},
		{globexID, "globex-portal", "acme-checkout"},
	} {
		code, _, raw := rumGet(t, s, "/api/dem/rum/sources", jwtClaims{Sub: "op@" + c.tenant, Role: RoleOperator, Tenant: c.tenant})
		if code != http.StatusOK {
			t.Fatalf("%s: %d %s", c.tenant, code, raw)
		}
		if !strings.Contains(raw, c.own) || strings.Contains(raw, c.foreign) {
			t.Fatalf("%s saw another org's app through a lying store: %s", c.tenant, raw)
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.scopes) != 2 || f.scopes[0] != acmeID || f.scopes[1] != globexID {
		t.Fatalf("each read must run at the caller's own ClickHouse scope: %v", f.scopes)
	}
	if !strings.Contains(f.sql[0], "tenant_id = '"+acmeID+"'") {
		t.Fatalf("the query does not filter the caller's tenant itself: %s", f.sql[0])
	}
}

func TestRUMSourcesIgnoreAsTenantForAScopedCaller(t *testing.T) {
	s, _, acmeID, globexID := rumWorld(t)
	c := jwtClaims{Sub: "op@acme", Role: RoleOperator, Tenant: acmeID, ActingTenant: globexID}
	_, _, raw := rumGet(t, s, "/api/dem/rum/sources?as_tenant="+globexID, c)
	if strings.Contains(raw, "globex-portal") || !strings.Contains(raw, "acme-checkout") {
		t.Fatalf("as_tenant moved a scoped caller into another org: %s", raw)
	}
}

func TestRUMSourcesRefuseTheCrossTenantViewAndANonReader(t *testing.T) {
	s, f, _, _ := rumWorld(t)
	if code, _, raw := rumGet(t, s, "/api/dem/rum/sources", jwtClaims{Sub: "root", Role: RoleSuperAdmin}); code != http.StatusBadRequest {
		t.Fatalf("the all-tenants view must be refused, got %d %s", code, raw)
	}
	if code, _, _ := rumGet(t, s, "/api/dem/rum/sources", jwtClaims{Sub: "k", Role: RoleIngest, Tenant: "acme"}); code != http.StatusForbidden {
		t.Fatalf("an ingest key read the feed list: %d", code)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.sql) != 0 {
		t.Fatalf("a refused caller still reached ClickHouse: %v", f.sql)
	}
}

func TestRUMSourcesOfARestrictedTenantReadAsNothing(t *testing.T) {
	s, f, acmeID, _ := rumWorld(t)
	if _, err := s.tenants.SetOperatorRestricted(acmeID, true); err != nil {
		t.Fatal(err)
	}
	code, body, raw := rumGet(t, s, "/api/dem/rum/sources", jwtClaims{Sub: "root", Role: RoleSuperAdmin, ActingTenant: acmeID})
	if code != http.StatusOK || body["restricted"] != true || strings.Contains(raw, "acme-checkout") {
		t.Fatalf("a restricted tenant's feeds reached the platform owner: %d %s", code, raw)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.sql) != 0 {
		t.Fatalf("a restricted read still queried ClickHouse: %v", f.sql)
	}
}

func TestRUMSourcesSayUnavailableWhenTheStoreIsDown(t *testing.T) {
	s, f, acmeID, _ := rumWorld(t)
	f.mu.Lock()
	f.down = true
	f.mu.Unlock()
	code, body, raw := rumGet(t, s, "/api/dem/rum/sources", jwtClaims{Sub: "op", Role: RoleOperator, Tenant: acmeID})
	if code != http.StatusOK || body["status"] != "unavailable" {
		t.Fatalf("a dead store must say unavailable, never an empty ok: %d %s", code, raw)
	}
}
