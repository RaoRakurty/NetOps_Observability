package main

// Cross-tenant isolation for the Wave 6 #20 surfaces (CLAUDE.md §3a.5):
//   · /api/search — a scoped principal's results NEVER contain another
//     tenant's rows, in ANY kind (device / resource / app / account), and the
//     correlation-case sub-search carries the caller's tenant_scope to
//     ClickHouse (the row policy is the enforcement point, as everywhere).
//   · /api/cloud/resources/{id} — own-tenant get works; a cross-tenant id and
//     an unknown id are the SAME 404 (never reveal another tenant's id).

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"netops/backend/cloud"
)

// fakeCHURL is fakeCH plus URL capture, so tests can assert the tenant_scope
// each ClickHouse read was issued under.
func fakeCHURL(t *testing.T) (urls *[]string) {
	t.Helper()
	var got []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = append(got, r.URL.String())
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"meta":[],"data":[],"rows":0}`))
	}))
	t.Cleanup(srv.Close)
	t.Setenv("CLICKHOUSE_URL", srv.URL)
	t.Setenv("CLICKHOUSE_PASSWORD", "")
	return &got
}

// TestUnifiedSearchTenantIsolation: every seeded noun contains "checkout" or
// "core"-ish overlaps across tenants; acme must see ONLY acme rows, globex
// ONLY globex rows, and a cross-tenant platform principal sees both.
func TestUnifiedSearchTenantIsolation(t *testing.T) {
	fakeCH(t)
	s := searchTestServer(t)

	globexOwned := map[string]bool{
		"globex-core": true, "vm-globex01": true, "gx-shop": true, "sub-globex": true, "ccn-globex": true,
	}
	acmeOwned := map[string]bool{
		"acme-core": true, "acme-edge": true, "i-0acme01": true, "i-0acme02": true,
		"checkout": true, "111122223333": true,
	}

	// Queries chosen to match BOTH tenants' data if isolation were absent.
	for _, q := range []string{"core", "checkout", "globex", "sub-globex", "10.60.1.10"} {
		for _, h := range searchGet(t, s, url.QueryEscape(q), acme()) {
			if globexOwned[h.ID] || strings.Contains(strings.ToLower(h.Label), "globex") {
				t.Errorf("TENANT LEAK: acme search %q returned globex row %+v", q, h)
			}
		}
	}
	for _, q := range []string{"core", "checkout", "acme", "111122223333", "10.50.1.10"} {
		for _, h := range searchGet(t, s, url.QueryEscape(q), globex()) {
			if acmeOwned[h.ID] || strings.Contains(strings.ToLower(h.Label), "acme") {
				t.Errorf("TENANT LEAK: globex search %q returned acme row %+v", q, h)
			}
		}
	}

	// Cross-tenant platform principal sees both tenants (sanity: the filter is
	// scope-driven, not a hardcoded hide).
	seen := map[string]bool{}
	for _, h := range searchGet(t, s, "core", superA()) {
		seen[h.ID] = true
	}
	if !seen["acme-core"] || !seen["globex-core"] {
		t.Errorf("cross-tenant principal should see both tenants' devices, got %v", seen)
	}
}

// TestUnifiedSearchCaseScopePinned: the case sub-search must be issued under
// the CALLER's tenant_scope — the ClickHouse row policy is the isolation.
func TestUnifiedSearchCaseScopePinned(t *testing.T) {
	urls := fakeCHURL(t)
	s := searchTestServer(t)
	_ = searchGet(t, s, "P-5564D1", acme())
	if len(*urls) != 1 {
		t.Fatalf("want exactly 1 ClickHouse call, got %d", len(*urls))
	}
	u, err := url.Parse((*urls)[0])
	if err != nil {
		t.Fatalf("parse captured URL: %v", err)
	}
	if got := u.Query().Get("tenant_scope"); got != "acme" {
		t.Fatalf("case search tenant_scope = %q, want %q", got, "acme")
	}
}

func getResourceByID(t *testing.T, s *server, id string, claims jwtClaims) *httptest.ResponseRecorder {
	t.Helper()
	w := httptest.NewRecorder()
	s.handleCloudResourceByID(w, req(http.MethodGet, "/api/cloud/resources/"+id, "", claims))
	return w
}

func TestCloudResourceByIDOwnTenant(t *testing.T) {
	fakeCH(t)
	s := searchTestServer(t)
	w := getResourceByID(t, s, "i-0acme01", acme())
	if w.Code != http.StatusOK {
		t.Fatalf("own-tenant get = %d (body %s)", w.Code, w.Body.String())
	}
	var body struct {
		Resource cloud.CloudResource `json:"resource"`
	}
	if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.Resource.ResourceID != "i-0acme01" || body.Resource.ResourceName != "checkout-web-1" {
		t.Fatalf("resource = %+v", body.Resource)
	}
}

func TestCloudResourceByIDCrossTenant404(t *testing.T) {
	fakeCH(t)
	s := searchTestServer(t)
	cross := getResourceByID(t, s, "vm-globex01", acme()) // globex's id, acme caller
	unknown := getResourceByID(t, s, "i-does-not-exist", acme())
	if cross.Code != http.StatusNotFound {
		t.Fatalf("cross-tenant id = %d, want 404", cross.Code)
	}
	if unknown.Code != http.StatusNotFound {
		t.Fatalf("unknown id = %d, want 404", unknown.Code)
	}
	// Indistinguishable: same status AND same body — existence is never leaked.
	if cross.Body.String() != unknown.Body.String() {
		t.Errorf("cross-tenant (%s) and unknown (%s) responses must be identical", cross.Body.String(), unknown.Body.String())
	}
	// Cross-tenant platform principal CAN read it (scope-driven, not hidden).
	if w := getResourceByID(t, s, "vm-globex01", superA()); w.Code != http.StatusOK {
		t.Errorf("platform principal get = %d, want 200", w.Code)
	}
}
