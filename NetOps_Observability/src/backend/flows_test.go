package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"netops/backend/models"
)

// intToString is the dependency-free integer formatter the flow SQL builders
// use; verify it matches strconv semantics for the cases that show up in
// queries (limits, interval seconds).
func TestIntToString(t *testing.T) {
	cases := []struct {
		in   int
		want string
	}{
		{0, "0"},
		{7, "7"},
		{20, "20"},
		{3600, "3600"},
		{-5, "-5"},
		{1000000, "1000000"},
	}
	for _, c := range cases {
		if got := intToString(c.in); got != c.want {
			t.Errorf("intToString(%d) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestParseIntStrict(t *testing.T) {
	if n, err := parseIntStrict("42"); err != nil || n != 42 {
		t.Errorf("parseIntStrict(42) = %d,%v", n, err)
	}
	if _, err := parseIntStrict("nope"); err == nil {
		t.Errorf("parseIntStrict(nope) expected error")
	}
}

// intQuery clamps to [min,max] and falls back to the default for missing/bad/
// out-of-range values.
func TestIntQuery(t *testing.T) {
	cases := []struct {
		raw  string
		want int
	}{
		{"", 20},       // missing -> default
		{"50", 50},     // in range
		{"0", 20},      // below min -> default
		{"999", 20},    // above max -> default
		{"abc", 20},    // unparseable -> default
		{"1", 1},       // min boundary
		{"500", 500},   // max boundary
	}
	for _, c := range cases {
		r := httptest.NewRequest(http.MethodGet, "/api/flows?limit="+c.raw, nil)
		if got := intQuery(r, "limit", 20, 1, 500); got != c.want {
			t.Errorf("intQuery(limit=%q) = %d, want %d", c.raw, got, c.want)
		}
	}
}

// durationQuery rejects non-positive, unparseable, and absurdly-large values,
// falling back to the default in each case.
func TestDurationQuery(t *testing.T) {
	def := time.Hour
	cases := []struct {
		raw  string
		want time.Duration
	}{
		{"", def},
		{"30m", 30 * time.Minute},
		{"2h", 2 * time.Hour},
		{"bogus", def},
		{"-5m", def},                 // non-positive
		{"0s", def},                  // non-positive
		{"9000h", def},               // exceeds 30-day cap
	}
	for _, c := range cases {
		r := httptest.NewRequest(http.MethodGet, "/api/flows?since="+c.raw, nil)
		if got := durationQuery(r, "since", def); got != c.want {
			t.Errorf("durationQuery(since=%q) = %v, want %v", c.raw, got, c.want)
		}
	}
}

// writeEmptyClickHouse emits the same envelope shape the ClickHouse JSON format
// uses so the SPA's .data access is safe.
func TestWriteEmptyClickHouse(t *testing.T) {
	w := httptest.NewRecorder()
	writeEmptyClickHouse(w)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		t.Fatalf("content-type = %q", ct)
	}
	if body := w.Body.String(); body != `{"meta":[],"data":[],"rows":0}` {
		t.Fatalf("body = %q", body)
	}
}

// flowsTestServer builds a server with a small multi-tenant inventory for
// flow-scoping tests (uniquely named to avoid clashing with tenantServer).
func flowsTestServer(t *testing.T) *server {
	t.Helper()
	d := NewDiscoveryAggregator()
	d.Upsert(models.Device{ID: "acme-core", Name: "acme-core", Address: "10.1.0.1", TenantID: "acme"})
	d.Upsert(models.Device{ID: "globex-core", Name: "globex-core", Address: "10.2.0.1", TenantID: "globex"})
	d.Upsert(models.Device{ID: "shared-dns", Name: "shared-dns", Address: "10.9.0.1"})
	return &server{discovery: d}
}

// flowTenantClause: cross-tenant principal gets no restriction.
func TestFlowTenantClauseCrossTenant(t *testing.T) {
	s := flowsTestServer(t)
	r := req(http.MethodGet, "/api/flows", "", superA())
	clause, empty := s.flowTenantClause(r)
	if empty {
		t.Fatal("super-admin must not be empty")
	}
	if clause != "" {
		t.Fatalf("super-admin clause = %q, want empty", clause)
	}
}

// flowTenantClause: scoped principal gets a src/dst IN(...) restriction limited
// to its own device addresses, never another tenant's nor global/untagged ones.
func TestFlowTenantClauseScoped(t *testing.T) {
	s := flowsTestServer(t)
	r := req(http.MethodGet, "/api/flows", "", acme())
	clause, empty := s.flowTenantClause(r)
	if empty {
		t.Fatal("acme has visible devices, must not be empty")
	}
	if !strings.Contains(clause, "src_addr IN") || !strings.Contains(clause, "dst_addr IN") {
		t.Fatalf("clause missing src/dst restriction: %q", clause)
	}
	if !strings.Contains(clause, "'10.1.0.1'") {
		t.Errorf("clause should include acme's own address: %q", clause)
	}
	if strings.Contains(clause, "'10.9.0.1'") {
		t.Errorf("strict isolation: shared/global address must NOT appear in a scoped clause: %q", clause)
	}
	if strings.Contains(clause, "'10.2.0.1'") {
		t.Errorf("TENANT LEAK: acme clause must not include globex address: %q", clause)
	}
}

// flowsServerNoShared has only tenant-owned devices (no global/shared device),
// so a scoped principal of an unknown tenant has zero visible addresses.
func flowsServerNoShared(t *testing.T) *server {
	t.Helper()
	d := NewDiscoveryAggregator()
	d.Upsert(models.Device{ID: "acme-core", Name: "acme-core", Address: "10.1.0.1", TenantID: "acme"})
	return &server{discovery: d}
}

// flowTenantClause: a scoped principal of a tenant with no visible devices
// yields empty=true so the handler short-circuits to an empty result.
func TestFlowTenantClauseEmptyForUnknownTenant(t *testing.T) {
	s := flowsServerNoShared(t)
	r := req(http.MethodGet, "/api/flows", "", jwtClaims{Sub: "x", Role: RoleOperator, Tenant: "nobody"})
	clause, empty := s.flowTenantClause(r)
	if !empty {
		t.Fatalf("tenant with no devices should be empty (got clause=%q)", clause)
	}
}

// handleFlowsByType (added yesterday): for a cross-tenant principal it builds
// the flow_type breakdown SQL and proxies it to ClickHouse. Stub ClickHouse via
// CLICKHOUSE_URL and assert the SQL groups by flow_type and counts exporters.
func TestHandleFlowsByTypeBuildsSQL(t *testing.T) {
	var gotSQL string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		gotSQL = string(b)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"meta":[],"data":[],"rows":0}`))
	}))
	defer srv.Close()
	t.Setenv("CLICKHOUSE_URL", srv.URL)
	t.Setenv("CLICKHOUSE_PASSWORD", "")

	s := flowsTestServer(t)
	r := req(http.MethodGet, "/api/flows/by-type?since=2h", "", superA())
	w := httptest.NewRecorder()
	s.handleFlowsByType(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	for _, want := range []string{
		"FROM netops.flows",
		"GROUP BY flow_type",
		"uniqExact(sampler_address) AS exporters",
		"INTERVAL 7200 SECOND", // since=2h -> 7200s
		"FORMAT JSON",
	} {
		if !strings.Contains(gotSQL, want) {
			t.Errorf("by-type SQL missing %q\nSQL:\n%s", want, gotSQL)
		}
	}
}

// A scoped principal with no visible devices short-circuits handleFlowsByType to
// the empty ClickHouse envelope WITHOUT issuing any backend query.
func TestHandleFlowsByTypeEmptyTenantShortCircuits(t *testing.T) {
	called := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()
	t.Setenv("CLICKHOUSE_URL", srv.URL)

	s := flowsServerNoShared(t)
	r := req(http.MethodGet, "/api/flows/by-type", "", jwtClaims{Sub: "x", Role: RoleOperator, Tenant: "nobody"})
	w := httptest.NewRecorder()
	s.handleFlowsByType(w, r)

	if called {
		t.Fatal("empty-tenant request must not reach ClickHouse")
	}
	if body := w.Body.String(); body != `{"meta":[],"data":[],"rows":0}` {
		t.Fatalf("body = %q, want empty envelope", body)
	}
}
