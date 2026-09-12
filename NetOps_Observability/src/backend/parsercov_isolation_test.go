// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// parsercov_isolation_test.go — the CLAUDE.md §3a rule-5 cross-org test for the
// parser-coverage routes (programme A6), exercised through the REAL
// parserCovAuthz gate mapping rather than a fake, because the gate CHOICE is
// half of what §3a rule 3 is about.
//
// The OpenSearch stand-in RECORDS the index pattern and the query body of every
// request, because those are the two halves of the isolation chokepoint: the
// pattern is the at-rest boundary (another tenant's indices are never NAMED, so
// its documents are unreachable even if a filter were dropped) and the body
// carries the per-doc tenant clause underneath it.
//
// Proven here:
//   - "/api/telemetry/unrecognized" mines ONLY the caller's own syslog indices
//     and carries the caller's per-doc tenant clause;
//   - a scoped caller can never reach another org's indices, and ?as_tenant into
//     another org is accepted-then-IGNORED (the scope is unchanged);
//   - the platform owner is the ONLY principal that reads cross-tenant;
//   - "/api/telemetry/unrecognized/" propose answers 404 for a template id that
//     does not resolve in the caller's own window — the same answer another
//     tenant's id gets, so the route is not an existence oracle;
//   - "/api/admin/parser/stats" is platform-GLOBAL: a tenant admin holding full
//     administration:admin is refused (a scope-blind requireAdmin would be a
//     privilege leak).

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"netops/backend/internal/discovery"
	"netops/backend/models"
	"netops/backend/parsercov"
)

// pcOSCall is one recorded OpenSearch request.
type pcOSCall struct {
	Index string // the index pattern the API named (the at-rest boundary)
	Body  string // the raw query DSL (the per-doc tenant clause lives here)
}

type pcFakeOS struct {
	mu    sync.Mutex
	calls []pcOSCall
}

func (f *pcFakeOS) all() []pcOSCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]pcOSCall, len(f.calls))
	copy(out, f.calls)
	return out
}

// pcStartFakeOS answers every search with an EMPTY window (total 0, no hits, no
// stamp buckets). That is enough: this test is about which indices are named
// and which clause is carried, not about what mining finds.
func pcStartFakeOS(t *testing.T) *pcFakeOS {
	t.Helper()
	fake := &pcFakeOS{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20)) // test double: a short read fails an assertion below
		index := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/"), "/_search")
		fake.mu.Lock()
		fake.calls = append(fake.calls, pcOSCall{Index: index, Body: string(body)})
		fake.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"took":1,"timed_out":false,` +
			`"hits":{"total":{"value":0,"relation":"eq"},"hits":[]},` +
			`"aggregations":{"versions":{"buckets":[]}}}`))
	}))
	t.Cleanup(srv.Close)
	t.Setenv("OPENSEARCH_URL", srv.URL)
	return fake
}

// pcTestServer builds the minimal server the parser-coverage handlers need.
func pcTestServer(t *testing.T) *server {
	t.Helper()
	roles, err := newRoleStore(t.TempDir() + "/roles.json")
	if err != nil {
		t.Fatalf("roleStore: %v", err)
	}
	d := discovery.NewDiscoveryAggregator()
	d.Upsert(models.Device{ID: "acme-core", Name: "acme-core", Address: "10.1.0.1", TenantID: "acme"})
	d.Upsert(models.Device{ID: "globex-core", Name: "globex-core", Address: "10.2.0.1", TenantID: "globex"})
	s := &server{roles: roles, discovery: d}
	s.parserCovMetrics = parsercov.NewMetrics()
	s.parserCov = parsercov.New(s.parserCovDeps())
	return s
}

// pcPatternFor is the syslog index pattern a scoped tenant must name — and the
// ONLY one it may name.
func pcPatternFor(tenant string) string {
	return "netops-syslog-" + tenant + "-*,netops-syslog-untagged-*"
}

func TestParserCovUnrecognizedIsOwnTenantOnly(t *testing.T) {
	fake := pcStartFakeOS(t)
	s := pcTestServer(t)

	w := httptest.NewRecorder()
	s.parserCov.HandleUnrecognized(w, req(http.MethodGet, "/api/telemetry/unrecognized", "", acme()))
	if w.Code != http.StatusOK {
		t.Fatalf("unrecognized = %d (%s)", w.Code, w.Body.String())
	}
	calls := fake.all()
	if len(calls) == 0 {
		t.Fatal("no OpenSearch query was issued — the guard would be vacuous")
	}
	for _, c := range calls {
		if c.Index != pcPatternFor("acme") {
			t.Fatalf("index pattern = %q, want %q", c.Index, pcPatternFor("acme"))
		}
		if strings.Contains(c.Index, "globex") {
			t.Fatal("TENANT LEAK: the query NAMED another tenant's index family")
		}
		if !strings.Contains(c.Body, `{"term":{"tenant_id":"acme"}}`) {
			t.Fatalf("the per-doc tenant clause is missing from the body: %s", c.Body)
		}
		if strings.Contains(c.Body, "globex") {
			t.Fatalf("TENANT LEAK: another tenant appears in the query body: %s", c.Body)
		}
	}
	if strings.Contains(w.Body.String(), "globex") {
		t.Fatalf("TENANT LEAK: acme's response carried globex data: %s", w.Body.String())
	}
}

func TestParserCovUnrecognizedRefusesAsTenant(t *testing.T) {
	fake := pcStartFakeOS(t)
	s := pcTestServer(t)

	w := httptest.NewRecorder()
	s.parserCov.HandleUnrecognized(w,
		req(http.MethodGet, "/api/telemetry/unrecognized?as_tenant=globex", "", acme()))
	// as_tenant is an always-allowed parameter (the tenancy middleware's
	// acting-tenant narrowing), so it is ACCEPTED and then IGNORED for a
	// non-owner: principalTenant keeps the caller in its own tenant. The scope
	// must be unchanged, not merely non-fatal.
	if w.Code != http.StatusOK {
		t.Fatalf("as_tenant = %d (%s)", w.Code, w.Body.String())
	}
	calls := fake.all()
	if len(calls) == 0 {
		t.Fatal("no OpenSearch query was issued — the guard would be vacuous")
	}
	for _, c := range calls {
		if c.Index != pcPatternFor("acme") {
			t.Fatalf("TENANT LEAK: ?as_tenant changed the scope to %q", c.Index)
		}
		if strings.Contains(c.Index, "globex") || strings.Contains(c.Body, "globex") {
			t.Fatalf("TENANT LEAK: ?as_tenant reached another org: %+v", c)
		}
	}
	if strings.Contains(w.Body.String(), "globex") {
		t.Fatalf("TENANT LEAK: the as_tenant response carried globex data: %s", w.Body.String())
	}
}

func TestParserCovUnrecognizedIsCrossTenantOnlyForThePlatformOwner(t *testing.T) {
	fake := pcStartFakeOS(t)
	s := pcTestServer(t)

	w := httptest.NewRecorder()
	s.parserCov.HandleUnrecognized(w, req(http.MethodGet, "/api/telemetry/unrecognized", "", platformOwner()))
	if w.Code != http.StatusOK {
		t.Fatalf("platform owner = %d (%s)", w.Code, w.Body.String())
	}
	calls := fake.all()
	if len(calls) == 0 {
		t.Fatal("no OpenSearch query was issued")
	}
	for _, c := range calls {
		if c.Index != "netops-syslog-*" {
			t.Fatalf("platform owner named %q, want the cross-tenant pattern", c.Index)
		}
		if strings.Contains(c.Body, `"term":{"tenant_id"`) {
			t.Fatalf("the cross-tenant read carried a per-doc tenant clause: %s", c.Body)
		}
	}
}

func TestParserCovUnrecognizedEachTenantSeesOnlyItsOwn(t *testing.T) {
	fake := pcStartFakeOS(t)
	s := pcTestServer(t)

	for _, tc := range []struct {
		claims jwtClaims
		tenant string
	}{{acme(), "acme"}, {globex(), "globex"}} {
		w := httptest.NewRecorder()
		s.parserCov.HandleUnrecognized(w, req(http.MethodGet, "/api/telemetry/unrecognized", "", tc.claims))
		if w.Code != http.StatusOK {
			t.Fatalf("%s = %d (%s)", tc.tenant, w.Code, w.Body.String())
		}
	}
	seen := map[string]bool{}
	for _, c := range fake.all() {
		seen[c.Index] = true
	}
	if !seen[pcPatternFor("acme")] || !seen[pcPatternFor("globex")] {
		t.Fatalf("each tenant must name its OWN pattern; saw %v", seen)
	}
	if seen["netops-syslog-*"] {
		t.Fatal("TENANT LEAK: a scoped caller issued the cross-tenant pattern")
	}
}

func TestParserCovProposeHidesTemplatesOutsideTheCallersWindow(t *testing.T) {
	pcStartFakeOS(t)
	s := pcTestServer(t)

	// A well-formed template id that does not resolve in acme's own window —
	// exactly the shape another tenant's mined id would have.
	w := httptest.NewRecorder()
	s.parserCov.HandlePropose(w,
		req(http.MethodPost, "/api/telemetry/unrecognized/t-0123456789/propose", "", tAdmin("acme")))
	if w.Code != http.StatusNotFound {
		t.Fatalf("propose for an id outside the caller's scope = %d, want 404 (never an "+
			"existence oracle for another tenant's shapes): %s", w.Code, w.Body.String())
	}
}

func TestParserCovProposeRequiresAlertsWrite(t *testing.T) {
	pcStartFakeOS(t)
	s := pcTestServer(t)

	w := httptest.NewRecorder()
	s.parserCov.HandlePropose(w,
		req(http.MethodPost, "/api/telemetry/unrecognized/t-0123456789/propose", "", tViewer("acme")))
	if w.Code != http.StatusForbidden {
		t.Fatalf("read-only principal got %d, want 403", w.Code)
	}
}

func TestParserCovStatsIsPlatformOwnerOnly(t *testing.T) {
	pcStartFakeOS(t)
	s := pcTestServer(t)

	// A TENANT admin holds full administration:admin. A scope-blind requireAdmin
	// would let it read the whole fleet's parser counters — the §3a rule 3
	// privilege leak this gate exists to prevent.
	w := httptest.NewRecorder()
	s.parserCov.HandleStats(w, req(http.MethodGet, "/api/admin/parser/stats", "", tAdmin("acme")))
	if w.Code != http.StatusForbidden {
		t.Fatalf("tenant admin got %d on /api/admin/parser/stats, want 403", w.Code)
	}

	w2 := httptest.NewRecorder()
	s.parserCov.HandleStats(w2, req(http.MethodGet, "/api/admin/parser/stats", "", platformOwner()))
	if w2.Code == http.StatusForbidden || w2.Code == http.StatusUnauthorized {
		t.Fatalf("the platform owner was refused its own platform surface: %d (%s)",
			w2.Code, w2.Body.String())
	}
}
