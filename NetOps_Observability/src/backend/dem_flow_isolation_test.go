package backend

// Cross-tenant isolation for the DEM passive-flow lane (§3a.5, tracker 252).
//
// This path adds NO route: it is a read the existing /api/dem/overview and
// /api/dem/data-health handlers make on the caller's behalf, so the ledger and
// the OpenAPI document are unchanged and the thing that needs pinning is the
// QUERY. It reads netops.flows, whose row policy is HYBRID — untagged rows are
// shared into every tenant scope — so the app-layer address clause is the only
// isolation untagged telemetry has, exactly as for /api/flows/apps.
//
// The contract these tests pin, in the order the code enforces it:
//
//	1. no principal on the context           → refused, no query at all
//	2. the caller's scope ≠ the tenant asked  → refused, no query at all
//	3. a scoped principal with no devices     → nothing, and no query
//	4. a scoped principal                     → its OWN device addresses only,
//	                                            plus its declared endpoints, at
//	                                            its own tenant_scope
//	5. attribution                            → a flow aggregate lands only on a
//	                                            subject that declared it

import (
	"context"
	"strings"
	"testing"
	"time"

	"netops/backend/internal/dem/experience"
	"netops/backend/internal/discovery"
	"netops/backend/models"
)

func demFlowSubjects() []experience.FlowSubject {
	return []experience.FlowSubject{{
		Subject: "checkout@dc1", App: "checkout", Site: "dc1",
		Endpoints: []experience.FlowEndpoint{{Addr: "10.1.0.1", Port: 443}},
	}}
}

func demFlowCtx(claims jwtClaims) context.Context {
	return context.WithValue(context.Background(), userCtxKey, claims)
}

func TestDEMFlowQuerierRefusesAReadWithNoPrincipal(t *testing.T) {
	queries := fakeCH(t)
	q := demFlowQuerier{s: flowsTestServer(t)}
	_, err := q.FlowStats(context.Background(), "acme", demFlowSubjects(),
		time.Unix(1000, 0), time.Unix(2000, 0))
	if err == nil {
		t.Fatal("a read with no principal was allowed; it cannot be scoped, so it must be refused")
	}
	if len(*queries) != 0 {
		t.Fatalf("an unscoped read still reached ClickHouse: %v", *queries)
	}
}

func TestDEMFlowQuerierRefusesATenantItWasNotScopedTo(t *testing.T) {
	queries := fakeCH(t)
	q := demFlowQuerier{s: flowsTestServer(t)}
	_, err := q.FlowStats(demFlowCtx(acme()), "globex", demFlowSubjects(),
		time.Unix(1000, 0), time.Unix(2000, 0))
	if err == nil {
		t.Fatal("acme's principal read globex's wire")
	}
	if len(*queries) != 0 {
		t.Fatalf("a mismatched read still reached ClickHouse: %v", *queries)
	}
}

func TestDEMFlowQuerierIsDefaultClosedWithoutDevices(t *testing.T) {
	queries := fakeCH(t)
	// A tenant that owns no device sees no untagged flow, and asks nothing.
	s := &server{discovery: discovery.NewDiscoveryAggregator()}
	s.discovery.Upsert(models.Device{ID: "globex-core", Name: "globex-core", Address: "10.2.0.1", TenantID: "globex"})
	q := demFlowQuerier{s: s}
	got, err := q.FlowStats(demFlowCtx(acme()), "acme", demFlowSubjects(),
		time.Unix(1000, 0), time.Unix(2000, 0))
	if err != nil {
		t.Fatalf("a deviceless tenant produced an error rather than an empty answer: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("a deviceless tenant saw flow aggregates: %+v", got)
	}
	if len(*queries) != 0 {
		t.Fatalf("a deviceless tenant still reached ClickHouse: %v", *queries)
	}
}

func TestDEMFlowQuerierScopesTheQueryToItsOwnAddresses(t *testing.T) {
	queries := fakeCH(t)
	q := demFlowQuerier{s: flowsTestServer(t)}
	if _, err := q.FlowStats(demFlowCtx(acme()), "acme", demFlowSubjects(),
		time.Unix(1000, 0), time.Unix(2000, 0)); err != nil {
		t.Fatalf("FlowStats: %v", err)
	}
	if len(*queries) != 1 {
		t.Fatalf("want exactly 1 ClickHouse query, got %d: %v", len(*queries), *queries)
	}
	sql := (*queries)[0]
	for _, want := range []string{
		"FROM netops.flows",
		"'10.1.0.1'", // the declared endpoint
		"AND (src_addr IN ('10.1.0.1') OR dst_addr IN ('10.1.0.1'))", // acme's own device
		"toDateTime(1000)", "toDateTime(2000)",
		"FORMAT JSON",
	} {
		if !strings.Contains(sql, want) {
			t.Errorf("the flow read is missing %q:\n%s", want, sql)
		}
	}
	// Never another tenant's address, and never the untagged device's.
	for _, forbidden := range []string{"10.2.0.1", "10.9.0.1"} {
		if strings.Contains(sql, forbidden) {
			t.Errorf("acme's flow read reached %s:\n%s", forbidden, sql)
		}
	}
	// Aggregate counters only — no raw conversation ever leaves ClickHouse.
	if strings.Contains(sql, "SELECT *") {
		t.Errorf("the flow read is not an aggregate:\n%s", sql)
	}
}

func TestDEMFlowQuerierAsksNothingWithNoSubjects(t *testing.T) {
	queries := fakeCH(t)
	q := demFlowQuerier{s: flowsTestServer(t)}
	got, err := q.FlowStats(demFlowCtx(acme()), "acme", nil, time.Unix(1000, 0), time.Unix(2000, 0))
	if err != nil || len(got) != 0 || len(*queries) != 0 {
		t.Fatalf("a subjectless read did something: err=%v rows=%+v queries=%v", err, got, *queries)
	}
}

// foldDEMFlowRows is the attribution step: a (server endpoint, exporter)
// aggregate belongs to the subject that DECLARED that endpoint, and to no other.
func TestFoldDEMFlowRowsAttributesOnlyDeclaredEndpoints(t *testing.T) {
	subjects := []experience.FlowSubject{
		{Subject: "checkout@dc1", App: "checkout", Site: "dc1",
			Endpoints: []experience.FlowEndpoint{{Addr: "10.1.0.1", Port: 443}}},
		{Subject: "dns@dc1", App: "dns", Site: "dc1",
			Endpoints: []experience.FlowEndpoint{{Addr: "10.1.0.9"}}}, // any port
	}
	rows := []map[string]any{
		{"ep": "10.1.0.1:443", "exporter": "10.0.0.7", "flows": float64(100), "tcp_flows": float64(90),
			"flag_flows": float64(80), "reset_flows": float64(8), "bytes": "5000", "packets": "60",
			"first_seen": float64(1000), "last_seen": float64(1900)},
		{"ep": "10.1.0.1:443", "exporter": "10.0.0.8", "flows": float64(20), "tcp_flows": float64(20),
			"flag_flows": float64(20), "reset_flows": float64(2), "bytes": "500", "packets": "6",
			"first_seen": float64(900), "last_seen": float64(1800)},
		// A different port on the same address: the checkout subject declared
		// 443 and must NOT absorb it.
		{"ep": "10.1.0.1:9200", "exporter": "10.0.0.7", "flows": float64(70), "tcp_flows": float64(70),
			"flag_flows": float64(70), "reset_flows": float64(70), "bytes": "1", "packets": "1",
			"first_seen": float64(1000), "last_seen": float64(1000)},
		// The port-agnostic subject takes any port on its address.
		{"ep": "10.1.0.9:53", "exporter": "10.0.0.7", "flows": float64(5), "tcp_flows": float64(0),
			"flag_flows": float64(0), "reset_flows": float64(0), "bytes": "9", "packets": "5",
			"first_seen": float64(1100), "last_seen": float64(1100)},
		// Nobody declared this.
		{"ep": "10.9.9.9:443", "exporter": "10.0.0.7", "flows": float64(999)},
		// Malformed keys are dropped, never guessed at.
		{"ep": "not-an-endpoint", "exporter": "10.0.0.7", "flows": float64(999)},
	}

	got := foldDEMFlowRows(subjects, rows)
	if len(got) != 2 {
		t.Fatalf("expected the two declared subjects, got %d: %+v", len(got), got)
	}
	checkout := got[0]
	if checkout.Subject != "checkout@dc1" {
		t.Fatalf("results are not sorted by subject: %+v", got)
	}
	if checkout.Flows != 120 || checkout.TCPFlows != 110 || checkout.FlagBearingFlows != 100 || checkout.ResetFlows != 10 {
		t.Fatalf("the declared (address, port) counters were not summed correctly: %+v", checkout)
	}
	if checkout.Bytes != 5500 || checkout.Packets != 66 {
		t.Fatalf("string-typed 64-bit counters were not read: %+v", checkout)
	}
	if len(checkout.Exporters) != 2 || checkout.Exporters[0] != "10.0.0.7" {
		t.Fatalf("the observers were not collected in order: %+v", checkout.Exporters)
	}
	if checkout.FirstSeen != time.Unix(900, 0).UTC() || checkout.LastSeen != time.Unix(1900, 0).UTC() {
		t.Fatalf("the observed span is wrong: %v .. %v", checkout.FirstSeen, checkout.LastSeen)
	}
	if got[1].Subject != "dns@dc1" || got[1].Flows != 5 {
		t.Fatalf("a port-agnostic subject did not take its address's traffic: %+v", got[1])
	}
	// And the whole point: an ungraded aggregate produces no evidence.
	if r := got[1].ResetRatio(); r.Measured {
		t.Fatalf("a subject with no TCP flows was graded: %+v", r)
	}
}

// The route ledger is unchanged by this slice, and this test says so out loud so
// a future reader does not go looking for a missing entry.
func TestDEMFlowLaneAddsNoRoute(t *testing.T) {
	for _, p := range []string{
		experience.OverviewPath, experience.DataHealthPath,
	} {
		if !strings.HasPrefix(p, "/api/dem/") {
			t.Fatalf("the flow lane is served under an unexpected path: %q", p)
		}
	}
	// A compile-time reminder: demFlowQuerier is reached only through the
	// experience surface's Deps, never registered on the mux itself.
	var _ experience.FlowQuerier = demFlowQuerier{}
}
