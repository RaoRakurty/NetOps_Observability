package main

// Unit tests for the Wave 6 #20 unified search: ranking (exact > prefix >
// substring), the case-handle parser, bounds (short query, per-kind cap) and
// the deep-link hrefs the UI navigates by.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"netops/backend/internal/discovery"
	"strings"
	"testing"

	"netops/backend/cloud"
	"netops/backend/cloudconn"
	"netops/backend/models"

	"netops/backend/internal/searchrank"
)

func TestSearchRank(t *testing.T) {
	cases := []struct {
		q      string
		fields []string
		want   int
	}{
		{"edge-1", []string{"edge-1", "edge-10"}, 0},    // exact beats prefix
		{"edge", []string{"edge-1"}, 1},                 // prefix
		{"dge-1", []string{"edge-1"}, 2},                // substring
		{"10.1.0.1", []string{"edge-1", "10.1.0.1"}, 0}, // exact IP
		{"zzz", []string{"edge-1", "10.1.0.1"}, -1},     // no match
		{"edge", []string{"", "EDGE-ROUTER"}, 1},        // case-fold, empty skipped
	}
	for _, c := range cases {
		if got := searchrank.Rank(c.q, c.fields...); got != c.want {
			t.Errorf("searchrank.Rank(%q, %v) = %d, want %d", c.q, c.fields, got, c.want)
		}
	}
}

func TestCaseSearchHex(t *testing.T) {
	cases := []struct{ in, want string }{
		{"P-5564D1", "5564D1"},
		{"p-55", "55"},           // explicit handle: ≥2 hex accepted
		{"P-", ""},               // nothing after the prefix
		{"5564d1a0", "5564D1A0"}, // bare hex ≥4
		{"ab", ""},               // bare 2-hex is not a case lookup
		{"router", ""},           // not hex
		{"5564d1a0-53d2-4f60-9a31-000000000000", "5564D1A053D24F609A31000000000000"},
		{"P-5564D1; DROP TABLE x", ""}, // injection-shaped input rejected
	}
	for _, c := range cases {
		if got := searchrank.CaseHex(c.in); got != c.want {
			t.Errorf("searchrank.CaseHex(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// searchTestServer builds a server with devices, cloud inventory (resources +
// attributed apps) and connector scopes for two tenants.
func searchTestServer(t *testing.T) *server {
	t.Helper()
	d := discovery.NewDiscoveryAggregator()
	d.Upsert(models.Device{ID: "acme-core", Name: "acme-core", Address: "10.1.0.1", Vendor: "cisco", TenantID: "acme"})
	d.Upsert(models.Device{ID: "acme-edge", Name: "acme-edge", Address: "10.1.0.2", TenantID: "acme"})
	d.Upsert(models.Device{ID: "globex-core", Name: "globex-core", Address: "10.2.0.1", TenantID: "globex"})
	roles, err := newRoleStore(t.TempDir() + "/roles.json")
	if err != nil {
		t.Fatalf("roleStore: %v", err)
	}
	s := &server{discovery: d, roles: roles}
	s.cloud = cloud.NewMemStore()
	if err := s.cloud.ReplaceInventory(context.Background(), "acme", []cloud.CloudResource{
		{Provider: cloud.AWS, AccountID: "111122223333", Region: "us-east-1", ResourceID: "i-0acme01", ResourceType: "ec2_instance",
			ResourceName: "checkout-web-1", PrivateIPs: []string{"10.50.1.10"}, AppID: "checkout", AppName: "Checkout", Confidence: cloud.Confirmed},
		{Provider: cloud.AWS, AccountID: "111122223333", Region: "us-east-1", ResourceID: "i-0acme02", ResourceType: "ec2_instance",
			ResourceName: "checkout-web-2", PrivateIPs: []string{"10.50.1.11"}, AppID: "checkout", AppName: "Checkout", Confidence: cloud.Confirmed},
	}, nil); err != nil {
		t.Fatalf("seed acme inventory: %v", err)
	}
	if err := s.cloud.ReplaceInventory(context.Background(), "globex", []cloud.CloudResource{
		{Provider: cloud.Azure, AccountID: "sub-globex", Region: "eastus", ResourceID: "vm-globex01", ResourceType: "vm",
			ResourceName: "checkout-globex", PrivateIPs: []string{"10.60.1.10"}, AppID: "gx-shop", AppName: "GX Shop", Confidence: cloud.Strong},
	}, nil); err != nil {
		t.Fatalf("seed globex inventory: %v", err)
	}
	s.cloudConn = cloudconn.NewMemStore()
	mustCreateConnector(t, s, "acme", "ccn-acme", "AWS prod", "111122223333", "Acme Prod")
	mustCreateConnector(t, s, "globex", "ccn-globex", "Azure prod", "sub-globex", "Globex Prod")
	return s
}

func mustCreateConnector(t *testing.T, s *server, tenant, id, name, scopeRef, scopeDisplay string) {
	t.Helper()
	scopeType, provider := cloudconn.ScopeAccount, cloudconn.Provider("aws")
	if strings.HasPrefix(scopeRef, "sub-") {
		scopeType, provider = cloudconn.ScopeSubscription, cloudconn.Provider("azure")
	}
	c := cloudconn.Connector{
		TenantID: tenant, ConnectorID: id, DisplayName: name, Provider: provider,
		Scopes: []cloudconn.Scope{{Type: scopeType, Ref: scopeRef, Display: scopeDisplay}},
	}
	if _, err := s.cloudConn.Create(context.Background(), c); err != nil {
		t.Fatalf("seed connector %s: %v", id, err)
	}
}

func searchGet(t *testing.T, s *server, q string, claims jwtClaims) []searchrank.Hit {
	t.Helper()
	w := httptest.NewRecorder()
	s.handleUnifiedSearch(w, req(http.MethodGet, "/api/search?q="+q, "", claims))
	if w.Code != http.StatusOK {
		t.Fatalf("GET /api/search?q=%s = %d (body %s)", q, w.Code, w.Body.String())
	}
	var resp struct {
		Results []searchrank.Hit `json:"results"`
	}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return resp.Results
}

func TestUnifiedSearchShortQueryReturnsEmpty(t *testing.T) {
	s := searchTestServer(t)
	if got := searchGet(t, s, "a", acme()); len(got) != 0 {
		t.Fatalf("1-char query must return no results, got %d", len(got))
	}
}

func TestUnifiedSearchExactBeatsPrefixBeatsSubstring(t *testing.T) {
	fakeCH(t)
	s := searchTestServer(t)
	s.discovery.Upsert(models.Device{ID: "core", Name: "core", Address: "10.1.9.9", TenantID: "acme"})
	got := searchGet(t, s, "core", acme())
	if len(got) < 2 {
		t.Fatalf("want ≥2 results, got %v", got)
	}
	if got[0].ID != "core" {
		t.Errorf("exact match must rank first, got %q", got[0].ID)
	}
	for _, h := range got[1:] {
		if h.ID == "core" {
			t.Errorf("exact match duplicated below first place")
		}
	}
}

func TestUnifiedSearchExactIPMatch(t *testing.T) {
	fakeCH(t)
	s := searchTestServer(t)
	got := searchGet(t, s, "10.50.1.10", acme())
	if len(got) == 0 || got[0].Kind != "resource" || got[0].ID != "i-0acme01" {
		t.Fatalf("exact private-IP lookup should top-rank the resource, got %v", got)
	}
}

func TestUnifiedSearchKindsAndHrefs(t *testing.T) {
	fakeCH(t)
	s := searchTestServer(t)
	got := searchGet(t, s, "checkout", acme())
	byKind := map[string]searchrank.Hit{}
	for _, h := range got {
		if _, ok := byKind[h.Kind]; !ok {
			byKind[h.Kind] = h
		}
	}
	r, ok := byKind["resource"]
	if !ok {
		t.Fatalf("no resource hit in %v", got)
	}
	if r.Href != "resource/cloud/i-0acme01" {
		t.Errorf("resource href = %q, want permanent resource URL", r.Href)
	}
	a, ok := byKind["app"]
	if !ok {
		t.Fatalf("no app hit in %v", got)
	}
	if a.ID != "checkout" || a.Href != "monitoring/appobs/services" {
		t.Errorf("app hit = %+v", a)
	}
	// Account search by id → the scope-bar deep link.
	acct := searchGet(t, s, "111122223333", acme())
	if len(acct) == 0 || acct[0].Kind != "account" || acct[0].Href != "monitoring/appobs/resources?account=111122223333" {
		t.Fatalf("account hit = %v", acct)
	}
}

func TestUnifiedSearchPerKindCap(t *testing.T) {
	fakeCH(t)
	s := searchTestServer(t)
	for i := 0; i < searchrank.PerKindCap*2; i++ {
		s.discovery.Upsert(models.Device{ID: fmt.Sprintf("edge-%02d", i), Name: fmt.Sprintf("edge-%02d", i), Address: fmt.Sprintf("10.1.7.%d", i), TenantID: "acme"})
	}
	got := searchGet(t, s, "edge", acme())
	devices := 0
	for _, h := range got {
		if h.Kind == "device" {
			devices++
		}
	}
	if devices != searchrank.PerKindCap {
		t.Fatalf("device hits = %d, want per-kind cap %d", devices, searchrank.PerKindCap)
	}
}

func TestUnifiedSearchCaseHandleQueriesClickHouse(t *testing.T) {
	queries := fakeCH(t)
	s := searchTestServer(t)
	_ = searchGet(t, s, "P-5564D1", acme())
	if len(*queries) != 1 {
		t.Fatalf("case-handle query should hit ClickHouse exactly once, got %d", len(*queries))
	}
	if !strings.Contains((*queries)[0], "'5564D1'") {
		t.Errorf("case SQL missing validated hex prefix:\n%s", (*queries)[0])
	}
	// A non-case query must NOT touch ClickHouse.
	_ = searchGet(t, s, "checkout", acme())
	if len(*queries) != 1 {
		t.Fatalf("non-case query must not reach ClickHouse (got %d queries)", len(*queries))
	}
}
