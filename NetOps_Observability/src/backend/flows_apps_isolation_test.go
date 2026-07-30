package main

// Cross-tenant isolation for the flow attribution scans (§3a.5). The flows row
// policy is HYBRID — untagged rows are shared to every tenant scope — so the
// app-layer address clause is the ONLY isolation for untagged telemetry. These
// tests pin that contract for /api/flows/apps and the /api/flows/services scan:
// a scoped principal's query is bounded to its own device addresses, a scoped
// principal with no devices never reaches ClickHouse, and a cross-tenant
// principal stays unrestricted.

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"netops/backend/internal/servicecat"
)

func flowsAppsTestServer(t *testing.T) *server {
	t.Helper()
	s := flowsTestServer(t) // acme-core 10.1.0.1 (acme) · globex-core 10.2.0.1 (globex) · shared-dns 10.9.0.1 (untagged)
	s.appCatalog = newAppCatalogHolder()
	s.ngfw = newNgfwAppResolver()
	roles, err := newRoleStore(t.TempDir() + "/roles.json")
	if err != nil {
		t.Fatalf("roleStore: %v", err)
	}
	s.roles = roles
	return s
}

// fakeCH stands in for ClickHouse, capturing every SQL body it receives.
func fakeCH(t *testing.T) (queries *[]string) {
	t.Helper()
	var got []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		got = append(got, string(b))
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"meta":[],"data":[],"rows":0}`))
	}))
	t.Cleanup(srv.Close)
	t.Setenv("CLICKHOUSE_URL", srv.URL)
	t.Setenv("CLICKHOUSE_PASSWORD", "")
	return &got
}

func TestFlowsAppsScopedTenantBoundsScan(t *testing.T) {
	queries := fakeCH(t)
	s := flowsAppsTestServer(t)

	w := httptest.NewRecorder()
	s.handleFlowsApps(w, req(http.MethodGet, "/api/flows/apps", "", acme()))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body %s)", w.Code, w.Body.String())
	}
	if len(*queries) != 1 {
		t.Fatalf("want exactly 1 CH query, got %d", len(*queries))
	}
	sql := (*queries)[0]
	if !strings.Contains(sql, "src_addr IN ('10.1.0.1') OR dst_addr IN ('10.1.0.1')") {
		t.Errorf("scoped scan missing acme address clause:\n%s", sql)
	}
	if strings.Contains(sql, "10.2.0.1") || strings.Contains(sql, "10.9.0.1") {
		t.Errorf("TENANT LEAK: acme scan mentions foreign/untagged addresses:\n%s", sql)
	}
}

func TestFlowsAppsNoDeviceTenantNeverQueries(t *testing.T) {
	queries := fakeCH(t)
	s := flowsAppsTestServer(t)

	w := httptest.NewRecorder()
	nobody := jwtClaims{Sub: "n@nobody", Role: RoleOperator, Tenant: "nobody"}
	s.handleFlowsApps(w, req(http.MethodGet, "/api/flows/apps", "", nobody))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body %s)", w.Code, w.Body.String())
	}
	if len(*queries) != 0 {
		t.Fatalf("default-closed: tenant with no devices must not reach ClickHouse, got %d queries", len(*queries))
	}
	if !strings.Contains(w.Body.String(), `"count":0`) {
		t.Errorf("empty tenant should get an empty app list, got %s", w.Body.String())
	}
}

func TestFlowsAppsCrossTenantUnrestricted(t *testing.T) {
	queries := fakeCH(t)
	s := flowsAppsTestServer(t)

	w := httptest.NewRecorder()
	s.handleFlowsApps(w, req(http.MethodGet, "/api/flows/apps", "", superA()))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	if len(*queries) != 1 {
		t.Fatalf("want exactly 1 CH query, got %d", len(*queries))
	}
	if strings.Contains((*queries)[0], "IN (") {
		t.Errorf("cross-tenant scan must not carry an address restriction:\n%s", (*queries)[0])
	}
}

func TestFlowsServicesScanSQLCarriesTenantClause(t *testing.T) {
	sel := []string{"sumIf(bytes, dst_port IN (443)) AS b0", "countIf(dst_port IN (443)) AS f0"}
	clause := " AND (src_addr IN ('10.1.0.1') OR dst_addr IN ('10.1.0.1'))"
	sql := servicecat.FlowScanSQL(sel, 3600, clause)
	for _, want := range []string{
		"FROM netops.flows",
		"INTERVAL 3600 SECOND",
		clause,
		"FORMAT JSON",
	} {
		if !strings.Contains(sql, want) {
			t.Errorf("services scan SQL missing %q:\n%s", want, sql)
		}
	}
	if got := servicecat.FlowScanSQL(sel, 3600, ""); strings.Contains(got, "src_addr IN") {
		t.Errorf("cross-tenant services scan must not carry an address clause:\n%s", got)
	}
}
