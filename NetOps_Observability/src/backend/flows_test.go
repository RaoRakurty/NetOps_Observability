package backend

import (
	"io"
	"net/http"
	"net/http/httptest"
	"netops/backend/internal/discovery"
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

// intQuery takes the default ONLY for an absent parameter, and FAILS CLOSED on
// anything malformed or out of range (F-71).
//
// This test previously asserted the opposite — that `limit=999` and `limit=abc`
// silently became 20 — and it passed for the entire life of the defect. An
// assertion that pins fail-open behaviour is worse than no test: it converts a
// silent data-truncation bug into a documented, protected feature. Note the two
// cases below that used to read `{"999", 20}` and `{"abc", 20}`.
func TestIntQuery(t *testing.T) {
	okCases := []struct {
		raw  string
		want int
	}{
		{"", 20},     // absent -> default (the documented contract)
		{"50", 50},   // in range
		{"1", 1},     // min boundary
		{"500", 500}, // max boundary
	}
	for _, c := range okCases {
		r := httptest.NewRequest(http.MethodGet, "/api/flows?limit="+c.raw, nil)
		got, err := intQuery(r, "limit", 20, 1, 500)
		if err != nil {
			t.Errorf("intQuery(limit=%q) unexpected error: %v", c.raw, err)
			continue
		}
		if got != c.want {
			t.Errorf("intQuery(limit=%q) = %d, want %d", c.raw, got, c.want)
		}
	}

	// The whole point: asking for something the endpoint cannot serve is an
	// ERROR, never a quiet downgrade to fewer rows than the caller requested.
	for _, raw := range []string{"0", "999", "501", "-1", "abc", "1e3", "100x", "%2050"} {
		r := httptest.NewRequest(http.MethodGet, "/api/flows?limit="+raw, nil)
		if got, err := intQuery(r, "limit", 20, 1, 500); err == nil {
			t.Errorf("intQuery(limit=%q) = (%d, nil) — must fail closed, not silently return the default", raw, got)
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
		{"-5m", def},   // non-positive
		{"0s", def},    // non-positive
		{"9000h", def}, // exceeds 30-day cap
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
	d := discovery.NewDiscoveryAggregator()
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
	d := discovery.NewDiscoveryAggregator()
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

// isIPish allowlists IPv4/IPv6-literal characters only; anything that could
// break out of a SQL string literal (quotes, backslash, spaces, letters g-z)
// must be rejected.
func TestIsIPish(t *testing.T) {
	ok := []string{"10.1.0.1", "255.255.255.255", "::1", "fe80::1", "2001:db8::abcd"}
	for _, s := range ok {
		if !isIPish(s) {
			t.Errorf("isIPish(%q) = false, want true", s)
		}
	}
	bad := []string{"", "10.1.0.1'; DROP", "1.2.3.4 OR 1=1", "host\\", "x'", "8.8.8.8;", strings.Repeat("1", 46)}
	for _, s := range bad {
		if isIPish(s) {
			t.Errorf("isIPish(%q) = true, want false", s)
		}
	}
}

// flowFilterClause builds an injection-safe AND-fragment from filter-bar params,
// validating addresses (isIPish) and interface ids (integers); malformed input
// is an error, never a silently-dropped or injected value.
func TestFlowFilterClause(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/api/flows/topn?src=10.1.0.1&dst=10.2.0.2&device=10.0.0.9&in_if=10&out_if=20", nil)
	clause, err := flowFilterClause(r)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, want := range []string{
		"src_addr = '10.1.0.1'", "dst_addr = '10.2.0.2'",
		"sampler_address = '10.0.0.9'", "in_if = 10", "out_if = 20",
	} {
		if !strings.Contains(clause, want) {
			t.Errorf("clause missing %q: %q", want, clause)
		}
	}
	// No filters -> empty fragment.
	if c, err := flowFilterClause(httptest.NewRequest(http.MethodGet, "/api/flows/topn", nil)); err != nil || c != "" {
		t.Errorf("no-filter clause = %q,%v want empty", c, err)
	}
	// Injection attempt in an address param is rejected.
	if _, err := flowFilterClause(httptest.NewRequest(http.MethodGet, "/api/flows/topn?src=1'+OR+'1'='1", nil)); err == nil {
		t.Error("expected error for malformed src filter")
	}
	// Non-numeric interface is rejected.
	if _, err := flowFilterClause(httptest.NewRequest(http.MethodGet, "/api/flows/topn?in_if=abc", nil)); err == nil {
		t.Error("expected error for non-numeric in_if")
	}
}

// handleFlowsTopN: a valid dimension builds GROUP BY <expr> AS k with the limit,
// applies the filter fragment, and drops zero rows for nonzero dims (ports).
func TestHandleFlowsTopNBuildsSQL(t *testing.T) {
	var gotSQL string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		gotSQL = string(b)
		_, _ = w.Write([]byte(`{"meta":[],"data":[],"rows":0}`))
	}))
	defer srv.Close()
	t.Setenv("CLICKHOUSE_URL", srv.URL)

	s := flowsTestServer(t)
	r := req(http.MethodGet, "/api/flows/topn?by=dst_port&limit=12&device=10.0.0.9", "", superA())
	w := httptest.NewRecorder()
	s.handleFlowsTopN(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	for _, want := range []string{
		"toString(dst_port) AS k",
		"GROUP BY k",
		"LIMIT 12",
		"sampler_address = '10.0.0.9'",
		"AND dst_port > 0", // nonzero noise filter
		"FORMAT JSON",
	} {
		if !strings.Contains(gotSQL, want) {
			t.Errorf("topn SQL missing %q\nSQL:\n%s", want, gotSQL)
		}
	}
}

// handleFlowsTopN rejects an unknown/forbidden dimension with 400 and never
// reaches ClickHouse (the client cannot pick an arbitrary GROUP BY column).
func TestHandleFlowsTopNRejectsBadDim(t *testing.T) {
	called := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()
	t.Setenv("CLICKHOUSE_URL", srv.URL)

	s := flowsTestServer(t)
	for _, by := range []string{"", "bogus", "bytes", "ts", "tenant_id"} {
		r := req(http.MethodGet, "/api/flows/topn?by="+by, "", superA())
		w := httptest.NewRecorder()
		s.handleFlowsTopN(w, r)
		if w.Code != http.StatusBadRequest {
			t.Errorf("by=%q status = %d, want 400", by, w.Code)
		}
	}
	if called {
		t.Fatal("bad dimension must not reach ClickHouse")
	}
}

// handleFlowsTopTalkers with direction=bi folds A↔B into one row by grouping on
// the ordered address pair (least/greatest).
func TestHandleFlowsTopTalkersBidirectional(t *testing.T) {
	var gotSQL string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		gotSQL = string(b)
		_, _ = w.Write([]byte(`{"meta":[],"data":[],"rows":0}`))
	}))
	defer srv.Close()
	t.Setenv("CLICKHOUSE_URL", srv.URL)

	s := flowsTestServer(t)
	r := req(http.MethodGet, "/api/flows/top?direction=bi", "", superA())
	w := httptest.NewRecorder()
	s.handleFlowsTopTalkers(w, r)

	if !strings.Contains(gotSQL, "least(src_addr, dst_addr) AS src") ||
		!strings.Contains(gotSQL, "greatest(src_addr, dst_addr) AS dst") {
		t.Errorf("bidirectional SQL missing least/greatest folding:\n%s", gotSQL)
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
