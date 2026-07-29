package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"netops/backend/cloud"
)

// ── Tenant isolation (CLAUDE.md §3a) ─────────────────────────────────────────
// The service-map read surface is scoped by the CALLER's principal: the scope
// literal is what the corr_signals FORCE row policy enforces on, a request
// without claims fails closed, and no query reaches ClickHouse unscoped or
// unbounded. Mirrors the cloud_signals_test.go isolation contract.
func TestServiceMapQueriesAreTenantScoped(t *testing.T) {
	scopeFor := func(c *jwtClaims) string {
		r := httptest.NewRequest(http.MethodGet, "/api/cloud/service-map", nil)
		if c != nil {
			r = r.WithContext(context.WithValue(r.Context(), userCtxKey, *c))
		}
		return cloud.SafeScopeLiteral(chTenantScope(r))
	}
	cases := []struct {
		name  string
		claim *jwtClaims
		want  string
	}{
		{"platform owner", &jwtClaims{Role: RoleSuperAdmin, Tenant: ""}, "__all__"},
		{"tenant admin", &jwtClaims{Role: "admin", Tenant: "acme"}, "acme"},
		{"tenant super-admin is NOT cross-tenant", &jwtClaims{Role: RoleSuperAdmin, Tenant: "acme"}, "acme"},
		{"no claims fails closed", nil, "__none__"},
		{"tenantless viewer fails closed", &jwtClaims{Role: "viewer", Tenant: ""}, "__none__"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			scope := scopeFor(tc.claim)
			if scope != tc.want {
				t.Fatalf("scope = %q, want %q", scope, tc.want)
			}
			for _, q := range []string{
				cloudPairSQL(24, serviceMapMaxPairRows, scope),
				cloudRejectPairSQL(24, serviceMapMaxRejectRows, scope),
			} {
				if !strings.Contains(q, "SETTINGS tenant_scope = '"+tc.want+"'") {
					t.Fatalf("query is not scoped to %q:\n%s", tc.want, q)
				}
				if tc.want == "acme" && strings.Contains(q, "globex") {
					t.Fatalf("query leaked another tenant:\n%s", q)
				}
				// bounded by construction (§9 / #100 read budgets)
				if !strings.Contains(q, "LIMIT") || !strings.Contains(q, "INTERVAL") {
					t.Fatalf("query is unbounded:\n%s", q)
				}
				if strings.Contains(q, "SELECT *") {
					t.Fatalf("query must name its columns (#100 contract):\n%s", q)
				}
			}
		})
	}
}

// The clamped window must parameterize both reads (echoed as meta.window_hours).
func TestServiceMapQueriesCarryWindow(t *testing.T) {
	for _, q := range []string{
		cloudPairSQL(168, 500, "acme"),
		cloudRejectPairSQL(168, 200, "acme"),
	} {
		if !strings.Contains(q, "INTERVAL 168 HOUR") {
			t.Fatalf("query does not honor the requested window:\n%s", q)
		}
	}
}

// The pair read aggregates ONLY the pair kind; the blocked layer ONLY REJECT
// flow-log evidence — the two lanes must never mix magnitudes.
func TestServiceMapQueriesReadTheRightKinds(t *testing.T) {
	pair := cloudPairSQL(24, 500, "acme")
	if !strings.Contains(pair, "kind = 'cloud_flow_pair'") {
		t.Fatalf("pair query must read cloud_flow_pair:\n%s", pair)
	}
	rej := cloudRejectPairSQL(24, 200, "acme")
	if !strings.Contains(rej, "kind = 'cloud_flow_log'") ||
		!strings.Contains(rej, "JSONExtractString(attrs,'action') = 'REJECT'") {
		t.Fatalf("reject query must read REJECT flow logs only:\n%s", rej)
	}
	if !strings.Contains(rej, "0                                  AS bytes") {
		t.Fatalf("reject query must never claim volume (provider-specific value semantics):\n%s", rej)
	}
}

// ── pure graph builder ────────────────────────────────────────────────────────

// a resolver over a fixed address book (the tenant's own identity map/inventory).
func mapResolver(book map[string]string) func(string) (string, bool) {
	return func(addr string) (string, bool) {
		svc, ok := book[addr]
		return svc, ok
	}
}

func TestBuildServiceMapResolvesAndWeightsEdges(t *testing.T) {
	book := map[string]string{
		"10.0.1.10": "web-frontend",
		"10.0.2.20": "billing-api",
		"10.0.3.30": "billing-api", // second address of the same service
	}
	pairs := []chPairRow{
		{Src: "10.0.1.10", Dst: "10.0.2.20", Bytes: 9000, Obs: 3, Providers: []string{"aws"}},
		{Src: "10.0.1.10", Dst: "10.0.3.30", Bytes: 1000, Obs: 1, Providers: []string{"azure"}},
	}
	g := buildServiceMap(pairs, nil, mapResolver(book), 10)

	if len(g.Nodes) != 2 {
		t.Fatalf("nodes = %+v, want web-frontend + billing-api", g.Nodes)
	}
	if g.Nodes[0].ID != "svc:web-frontend" && g.Nodes[1].ID != "svc:web-frontend" {
		t.Fatalf("missing service node: %+v", g.Nodes)
	}
	// two addresses of one service collapse to ONE node and ONE edge
	if len(g.Edges) != 1 {
		t.Fatalf("edges = %+v, want one collapsed talks_to edge", g.Edges)
	}
	e := g.Edges[0]
	if e.SourceService != "svc:web-frontend" || e.DestService != "svc:billing-api" {
		t.Fatalf("edge endpoints wrong: %+v", e)
	}
	if e.Relationship != "talks_to" {
		t.Fatalf("relationship = %q", e.Relationship)
	}
	if e.Bytes != 10000 || e.PairCount != 2 {
		t.Fatalf("edge must be volume-weighted over its address pairs: %+v", e)
	}
	if e.Blocked || e.BlockedCount != 0 {
		t.Fatalf("no REJECT evidence ⇒ not blocked: %+v", e)
	}
	if strings.Join(e.Providers, ",") != "aws,azure" {
		t.Fatalf("providers = %v", e.Providers)
	}
	if g.Meta.PairSignals != 4 || g.Meta.ResolvedEndpoints != 3 || g.Meta.UnresolvedEndpoints != 0 {
		t.Fatalf("meta = %+v", g.Meta)
	}
}

func TestBuildServiceMapUnattributedIsBoundedTopN(t *testing.T) {
	book := map[string]string{"10.0.1.10": "web-frontend"}
	pairs := []chPairRow{
		{Src: "10.0.1.10", Dst: "203.0.113.9", Bytes: 500, Obs: 1, Providers: []string{"aws"}},
		{Src: "10.0.1.10", Dst: "203.0.113.8", Bytes: 9000, Obs: 1, Providers: []string{"aws"}},
		{Src: "10.0.1.10", Dst: "203.0.113.7", Bytes: 100, Obs: 1, Providers: []string{"aws"}},
	}
	g := buildServiceMap(pairs, nil, mapResolver(book), 2)

	// only the two LOUDEST unresolved endpoints become nodes
	ids := map[string]bool{}
	for _, n := range g.Nodes {
		ids[n.ID] = true
	}
	if !ids["ip:203.0.113.8"] || !ids["ip:203.0.113.9"] || ids["ip:203.0.113.7"] {
		t.Fatalf("unattributed top-N wrong: %+v", g.Nodes)
	}
	if len(g.Edges) != 2 {
		t.Fatalf("dropped endpoint must drop its edge, not invent a peer: %+v", g.Edges)
	}
	// the drop is REPORTED, never silent
	if g.Meta.UnresolvedEndpoints != 3 || g.Meta.UnattributedShown != 2 || g.Meta.UnattributedDropped != 1 {
		t.Fatalf("meta must account for the bound: %+v", g.Meta)
	}
	// unattributed nodes say what they are
	for _, n := range g.Nodes {
		if strings.HasPrefix(n.ID, "ip:") && (n.Resolved || n.Kind != "endpoint") {
			t.Fatalf("unresolved endpoint mislabeled: %+v", n)
		}
	}
}

func TestBuildServiceMapBlockedEdgesFromRejects(t *testing.T) {
	book := map[string]string{"10.0.1.10": "web-frontend", "10.0.2.20": "billing-api"}
	pairs := []chPairRow{
		{Src: "10.0.1.10", Dst: "10.0.2.20", Bytes: 5000, Obs: 2, Providers: []string{"aws"}},
	}
	rejects := []chPairRow{
		{Src: "10.0.1.10", Dst: "10.0.2.20", Obs: 4, Providers: []string{"aws"}},
		// a blocked-ONLY conversation is still real evidence of attempted talks
		{Src: "10.0.2.20", Dst: "10.0.1.10", Obs: 1, Providers: []string{"aws"}},
	}
	g := buildServiceMap(pairs, rejects, mapResolver(book), 10)
	if len(g.Edges) != 2 {
		t.Fatalf("edges = %+v", g.Edges)
	}
	fwd := g.Edges[0]
	if !fwd.Blocked || fwd.BlockedCount != 4 || fwd.Bytes != 5000 {
		t.Fatalf("accepted+blocked edge wrong: %+v", fwd)
	}
	rev := g.Edges[1]
	if !rev.Blocked || rev.Bytes != 0 || rev.PairCount != 0 {
		t.Fatalf("blocked-only edge must carry no fabricated volume: %+v", rev)
	}
	// REJECT evidence never inflates node traffic
	for _, n := range g.Nodes {
		if n.Bytes != 5000 {
			t.Fatalf("node bytes must be accepted volume only: %+v", n)
		}
	}
}

func TestBuildServiceMapDropsNoiseAndSelfTalk(t *testing.T) {
	book := map[string]string{"10.0.1.10": "web-frontend", "10.0.1.11": "web-frontend"}
	pairs := []chPairRow{
		{Src: "10.0.1.10", Dst: "10.0.1.10", Bytes: 100, Obs: 1},     // self-talk
		{Src: "10.0.1.10", Dst: "224.0.0.5", Bytes: 100, Obs: 1},     // multicast (OSPF)
		{Src: "10.0.1.10", Dst: "255.255.255.255", Bytes: 9, Obs: 1}, // broadcast
		{Src: "10.0.1.10", Dst: "169.254.169.254", Bytes: 9, Obs: 1}, // link-local (IMDS)
		{Src: "", Dst: "10.0.1.10", Bytes: 9, Obs: 1},                // empty peer
		{Src: "10.0.1.10", Dst: "10.0.1.11", Bytes: 100, Obs: 1},     // intra-service
	}
	g := buildServiceMap(pairs, nil, mapResolver(book), 10)
	if len(g.Edges) != 0 {
		t.Fatalf("plumbing/self-talk must never become a dependency: %+v", g.Edges)
	}
}

func TestBuildServiceMapEmptyIsWellFormed(t *testing.T) {
	g := buildServiceMap(nil, nil, nil, 10)
	if g.Nodes == nil || g.Edges == nil {
		t.Fatal("empty graph must have non-nil slices (honest empty state)")
	}
	if len(g.Nodes) != 0 || len(g.Edges) != 0 || g.Meta.PairSignals != 0 {
		t.Fatalf("empty in, empty out: %+v", g)
	}
}

func TestBuildServiceMapDeterministicOrder(t *testing.T) {
	book := map[string]string{"10.0.1.10": "a", "10.0.2.20": "b", "10.0.3.30": "c"}
	pairs := []chPairRow{
		{Src: "10.0.1.10", Dst: "10.0.2.20", Bytes: 100, Obs: 1},
		{Src: "10.0.1.10", Dst: "10.0.3.30", Bytes: 100, Obs: 1},
	}
	first := buildServiceMap(pairs, nil, mapResolver(book), 10)
	for i := 0; i < 5; i++ {
		again := buildServiceMap(pairs, nil, mapResolver(book), 10)
		if len(again.Edges) != 2 || again.Edges[0].DestService != first.Edges[0].DestService ||
			again.Nodes[0].ID != first.Nodes[0].ID {
			t.Fatalf("graph order must be deterministic: %+v vs %+v", again, first)
		}
	}
}

func TestServiceMapNoise(t *testing.T) {
	cases := []struct {
		src, dst string
		want     bool
	}{
		{"10.0.0.1", "10.0.0.2", false},
		{"10.0.0.1", "10.0.0.1", true},        // self-talk
		{"", "10.0.0.2", true},                // empty peer
		{"10.0.0.1", "", true},                //
		{"10.0.0.1", "224.0.0.5", true},       // multicast
		{"10.0.0.1", "255.255.255.255", true}, // broadcast
		{"10.0.0.1", "169.254.0.7", true},     // link-local
		{"10.0.0.1", "0.0.0.0", true},         // unspecified
		{"10.0.0.1", "db.internal", false},    // hostname-shaped → resolver's job
	}
	for _, tc := range cases {
		if got := serviceMapNoise(tc.src, tc.dst); got != tc.want {
			t.Fatalf("serviceMapNoise(%q,%q) = %v, want %v", tc.src, tc.dst, got, tc.want)
		}
	}
}
