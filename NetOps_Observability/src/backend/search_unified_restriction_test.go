// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// search_unified_restriction_test.go — the CLAUDE.md §3a rule-5 isolation test for
// the operator-visibility restriction (Tenant.OperatorRestricted) on the unified
// search lane.
//
// Global search reaches four kinds at once: devices, cloud resources, the app
// registry derived from them, connector account scopes and correlation cases. A
// tenant that has switched the restriction on is invisible to the platform owner
// in logs, flows, metrics, igpmon and the BMP feed. It must be invisible here too,
// in every kind, and the operator must not be able to walk around it with
// ?as_tenant.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"netops/backend/cloud"
	"netops/backend/cloudconn"
	"netops/backend/internal/discovery"
	"netops/backend/models"

	"netops/backend/internal/searchrank"
)

// restrictedSearchFixture is searchTestServer plus a REAL tenant store, so the
// switch under test is the production one (Tenant.OperatorRestricted →
// effectiveRestrictedIDs → operatorTelemetryRestriction) and every seeded row is
// keyed on the OPAQUE tenant id the store mints, never the human slug.
type restrictedSearchFixture struct {
	t      *testing.T
	s      *server
	acme   string
	globex string
	// chQueries is every SQL body ClickHouse was asked for, in order.
	chQueries *[]string
}

func newRestrictedSearchFixture(t *testing.T) *restrictedSearchFixture {
	t.Helper()
	queries := fakeCH(t)

	ts, err := newTenantStore(filepath.Join(t.TempDir(), "tenants.json"))
	if err != nil {
		t.Fatalf("newTenantStore: %v", err)
	}
	acme, err := ts.Create("Acme", "acme", "", "", "")
	if err != nil {
		t.Fatalf("create acme: %v", err)
	}
	globex, err := ts.Create("Globex", "globex", "", "", "")
	if err != nil {
		t.Fatalf("create globex: %v", err)
	}
	roles, err := newRoleStore(t.TempDir() + "/roles.json")
	if err != nil {
		t.Fatalf("roleStore: %v", err)
	}

	d := discovery.NewDiscoveryAggregator()
	d.Upsert(models.Device{ID: "acme-core", Name: "acme-core", Address: "10.1.0.1", Vendor: "cisco", TenantID: acme.ID})
	d.Upsert(models.Device{ID: "globex-core", Name: "globex-core", Address: "10.2.0.1", TenantID: globex.ID})

	s := &server{discovery: d, roles: roles, tenants: ts}
	s.cloud = cloud.NewMemStore()
	if err := s.cloud.ReplaceInventory(context.Background(), acme.ID, []cloud.CloudResource{
		{Provider: cloud.AWS, AccountID: "111122223333", Region: "us-east-1", ResourceID: "i-0acme01",
			ResourceType: "ec2_instance", ResourceName: "core-checkout-acme", PrivateIPs: []string{"10.50.1.10"},
			AppID: "acme-checkout", AppName: "Acme Checkout", Confidence: cloud.Confirmed},
	}, nil); err != nil {
		t.Fatalf("seed acme inventory: %v", err)
	}
	if err := s.cloud.ReplaceInventory(context.Background(), globex.ID, []cloud.CloudResource{
		{Provider: cloud.Azure, AccountID: "sub-globex", Region: "eastus", ResourceID: "vm-globex01",
			ResourceType: "vm", ResourceName: "core-checkout-globex", PrivateIPs: []string{"10.60.1.10"},
			AppID: "globex-shop", AppName: "Globex Shop", Confidence: cloud.Strong},
	}, nil); err != nil {
		t.Fatalf("seed globex inventory: %v", err)
	}
	s.cloudConn = cloudconn.NewMemStore()
	mustCreateConnector(t, s, acme.ID, "ccn-acme", "AWS core", "111122223333", "Acme Core Account")
	mustCreateConnector(t, s, globex.ID, "ccn-globex", "Azure core", "sub-globex", "Globex Core Sub")

	return &restrictedSearchFixture{t: t, s: s, acme: acme.ID, globex: globex.ID, chQueries: queries}
}

// search runs one /api/search request and returns BOTH the decoded hits and the
// raw body — a leak test must be able to grep bytes, not only typed ids.
func (f *restrictedSearchFixture) search(q string, claims jwtClaims) ([]searchrank.Hit, string) {
	f.t.Helper()
	w := httptest.NewRecorder()
	f.s.handleUnifiedSearch(w, req(http.MethodGet, "/api/search?q="+q, "", claims))
	if w.Code != http.StatusOK {
		f.t.Fatalf("GET /api/search?q=%s = %d (%s)", q, w.Code, w.Body.String())
	}
	var resp struct {
		Results []searchrank.Hit `json:"results"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		f.t.Fatalf("decode: %v", err)
	}
	return resp.Results, w.Body.String()
}

func hitIDs(hits []searchrank.Hit) map[string]bool {
	out := map[string]bool{}
	for _, h := range hits {
		out[h.ID] = true
	}
	return out
}

// TestUnifiedSearchHonoursTheOperatorVisibilityRestriction is the §3a rule-5 test.
// Both halves: the platform owner's Global search, and the owner scoped into the
// restricted tenant with ?as_tenant.
func TestUnifiedSearchHonoursTheOperatorVisibilityRestriction(t *testing.T) {
	f := newRestrictedSearchFixture(t)
	owner := jwtClaims{Sub: "root", Role: RoleSuperAdmin, Tenant: TenantGlobal}

	// Before anything is restricted the owner reads both tenants, so this test
	// cannot pass by serving nothing.
	before, _ := f.search("core", owner)
	got := hitIDs(before)
	for _, want := range []string{"acme-core", "globex-core", "i-0acme01", "vm-globex01", "111122223333", "sub-globex"} {
		if !got[want] {
			t.Fatalf("baseline: owner Global search does not contain %q (got %v)", want, got)
		}
	}

	if _, err := f.s.tenants.SetOperatorRestricted("acme", true); err != nil {
		t.Fatalf("restrict acme: %v", err)
	}

	// ── half 1: the Global view. Acme is gone from EVERY kind; globex is intact.
	hits, raw := f.search("core", owner)
	got = hitIDs(hits)
	for _, hidden := range []string{"acme-core", "i-0acme01", "acme-checkout", "111122223333"} {
		if got[hidden] {
			t.Errorf("RESTRICTION LEAK: the platform owner's Global search returned acme's %q: %s", hidden, raw)
		}
	}
	for _, leak := range []string{"acme-core", "i-0acme01", "core-checkout-acme", "Acme Checkout", "111122223333", "Acme Core Account", "10.1.0.1", "10.50.1.10"} {
		if strings.Contains(raw, leak) {
			t.Errorf("RESTRICTION LEAK: acme's %q appears in the owner's Global search body: %s", leak, raw)
		}
	}
	for _, want := range []string{"globex-core", "vm-globex01", "sub-globex"} {
		if !got[want] {
			t.Errorf("restricting acme also hid globex's %q (got %v)", want, got)
		}
	}

	// The correlation-case sub-search runs on ClickHouse, whose row policies
	// cannot express this rule under the '__all__' scope — so the exclusion has
	// to be in the SQL. Assert it is, naming the restricted tenant's opaque id.
	*f.chQueries = nil
	if _, raw := f.search("P-5564D1", owner); strings.Contains(raw, "acme") {
		t.Errorf("case search leaked acme: %s", raw)
	}
	if len(*f.chQueries) != 1 {
		t.Fatalf("want exactly one ClickHouse read for a case handle, got %d", len(*f.chQueries))
	}
	sql := (*f.chQueries)[0]
	if !strings.Contains(sql, "tenant_id NOT IN ('"+f.acme+"')") {
		t.Errorf("RESTRICTION LEAK: the case lookup does not exclude the restricted tenant.\nSQL: %s", sql)
	}
	if strings.Contains(sql, f.globex) {
		t.Errorf("the case lookup excluded globex, which is not restricted.\nSQL: %s", sql)
	}

	// ── half 2: ?as_tenant into the restricted tenant. Nothing, in every kind,
	// and NO storage is read at all — the answer is decided before the first row.
	*f.chQueries = nil
	scoped := ownerActing(owner, f.acme)
	for _, q := range []string{"core", "checkout", "10.1.0.1", "P-5564D1"} {
		hits, raw := f.search(q, scoped)
		if len(hits) != 0 {
			t.Errorf("RESTRICTION LEAK: owner→acme search %q returned %d rows: %s", q, len(hits), raw)
		}
	}
	if len(*f.chQueries) != 0 {
		t.Errorf("owner→acme still read ClickHouse %d times: %v", len(*f.chQueries), *f.chQueries)
	}

	// The owner scoped into the UNRESTRICTED tenant still reads it.
	hits, _ = f.search("core", ownerActing(owner, f.globex))
	if got = hitIDs(hits); !got["globex-core"] || !got["vm-globex01"] {
		t.Errorf("owner→globex = %v, want globex's own rows", got)
	}

	// And acme's OWN user is never restricted from acme's own search — the switch
	// hides a tenant from the PLATFORM, never from itself.
	acmeUser := jwtClaims{Sub: "a@acme", Role: RoleOperator, Tenant: f.acme}
	hits, raw = f.search("core", acmeUser)
	got = hitIDs(hits)
	if !got["acme-core"] || !got["i-0acme01"] || !got["111122223333"] {
		t.Fatalf("acme's own user lost its own search results: %v (%s)", got, raw)
	}
	if got["globex-core"] || got["vm-globex01"] {
		t.Fatalf("acme's own user saw globex rows: %v", got)
	}
}
