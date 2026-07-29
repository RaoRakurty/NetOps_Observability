package main

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"netops/backend/collectors"
	"netops/backend/pathgraph"
)

// path_graph_isolation_test.go — §9 of the frozen contract, the MANDATORY two-tenant
// test (CLAUDE.md §3a.5, org_isolation_test.go is the template).
//
// The fixture is deliberately the WORST case: Tenant A and Tenant B have
//
//	OVERLAPPING ADDRESSES  — byte-identical IPs on every hop (172.40.40.1,
//	                         10.70.245.122, 10.60.1.10, 10.60.10.10),
//	IDENTICAL APP NAMES    — both run "store-api",
//	IDENTICAL PATH SHAPES  — the same four-hop LAN→WAN→NVA→app spine,
//	IDENTICAL CONTEXT NAMES— even the network-context labels collide.
//
// Nothing but the tenant id distinguishes them. We then assert that NOTHING crosses:
// endpoint resolution, graph edge, path observation, store listing, cleanup, or API
// response. If tenancy were "organic" rather than structural, this test would light
// up like a christmas tree.

// ── test doubles for the two DI seams (§5: interfaces for external deps) ──────

// stubCorrPath models the correlation→path linkage the way ClickHouse's row policy
// does in production: an object is only visible inside its own tenant's scope.
type stubCorrPath struct {
	byID map[string]struct {
		tenant string
		dst    string
	}
}

func (s stubCorrPath) PathRefFor(_ context.Context, scope, id string) (pathQueryRef, bool, error) {
	rec, ok := s.byID[id]
	if !ok {
		return pathQueryRef{}, false, nil
	}
	if scope != "__all__" && scope != rec.tenant {
		return pathQueryRef{}, false, nil // another tenant's object simply does not exist here
	}
	return pathQueryRef{DstAddress: rec.dst, Tenant: rec.tenant}, true, nil
}

// stubFacts serves each tenant ONLY its own fact base — which is what the real
// serverPathFacts does (every inventory read is tenant-scoped).
type stubFacts struct {
	byTenant map[string]pathgraph.PathFacts
	nc       netContext
}

func (s stubFacts) Facts(_ context.Context, tenant string, _ time.Time) (pathgraph.PathFacts, netContext, error) {
	return s.byTenant[tenant], s.nc, nil
}

// tenantFacts builds one tenant's fact base over the SHARED (overlapping) addresses,
// resolving them to that tenant's OWN resources.
func tenantFacts(tenant, instanceID, nvaID, lanDev, wanDev string) pathgraph.PathFacts {
	open := pathgraph.Window{From: ingestNow.Add(-24 * time.Hour)}
	return pathgraph.PathFacts{
		NICBindings: []pathgraph.NICBinding{
			{TenantID: tenant, Address: "10.60.10.10", NetworkContext: "vpc-aws", ResourceID: instanceID,
				Kind: pathgraph.KindAppEndpoint, Window: open, EvidenceRef: "cloud_inventory:" + instanceID,
				DataClass: pathgraph.DataClassLive, ObservedAt: ingestNow},
			{TenantID: tenant, Address: "10.60.1.10", NetworkContext: "vpc-aws", ResourceID: nvaID,
				Kind: pathgraph.KindNVA, Window: open, EvidenceRef: "cloud_inventory:" + nvaID,
				DataClass: pathgraph.DataClassLive, ObservedAt: ingestNow},
		},
		InterfaceBindings: []pathgraph.InterfaceBinding{
			{TenantID: tenant, Address: "172.40.40.1", NetworkContext: "lab-lan", DeviceID: lanDev,
				Window: open, EvidenceRef: "if:" + lanDev, DataClass: pathgraph.DataClassLive, ObservedAt: ingestNow},
			{TenantID: tenant, Address: "10.70.245.122", NetworkContext: "lab-wan", DeviceID: wanDev,
				Window: open, EvidenceRef: "if:" + wanDev, DataClass: pathgraph.DataClassLive, ObservedAt: ingestNow},
		},
		AppBindings: []pathgraph.AppBinding{
			// IDENTICAL app name in both tenants — the name is not what binds it.
			{TenantID: tenant, Service: "store-api", Address: "10.60.10.10", NetworkContext: "vpc-aws",
				ResourceRef: instanceID, Window: open, EvidenceRef: "app_identity:store-api@10.60.10.10",
				DataClass: pathgraph.DataClassLive, ObservedAt: ingestNow},
		},
	}
}

// ingestFor writes one tenant's measurement run through the REAL ingest path.
func ingestFor(t *testing.T, s *server, tenant string, facts pathgraph.PathFacts, dataClass string, at time.Time, runID string, dstOverride string) pathRecords {
	t.Helper()
	cfg := pathgraph.IngestConfig{
		Tenant: tenant, DataClass: dataClass, Environment: "lab", RunID: runID,
		ProducerID: "prober-" + tenant, VantageID: "prober-" + tenant,
		VantageAddress: "172.40.40.92", Now: at,
	}
	p := labProbe()
	p.TS = at
	if dstOverride != "" {
		p.Dst = dstOverride
		p.Hops[3] = collectors.Hop{TTL: 4, IP: dstOverride, RTTms: 25}
	}
	recs, err := pathgraph.BuildRecords(cfg, facts, labSeams(), labNetContext(), p)
	if err != nil {
		t.Fatalf("build %s: %v", tenant, err)
	}
	if err := s.persistPathRecords(context.Background(), recs); err != nil {
		t.Fatalf("persist %s: %v", tenant, err)
	}
	return recs
}

func getPath(t *testing.T, srv *httptest.Server, token, corrID, query string) (int, []byte, pathSpineResponse) {
	t.Helper()
	st, body := do(t, srv, "GET", "/api/rca/"+corrID+"/path"+query, token, nil)
	var resp pathSpineResponse
	if st == 200 {
		if err := json.Unmarshal(body, &resp); err != nil {
			t.Fatalf("decode spine: %v (%s)", err, body)
		}
	}
	return st, body, resp
}

// TestPathGraphTwoTenantIsolation is the §9 fixture.
func TestPathGraphTwoTenantIsolation(t *testing.T) {
	srv, s := newTestServerState(t)
	s.pathGraph = pathgraph.NewMemStore()

	admin := login(t, srv, "admin", "Passw0rd!2345").Token

	// Two orgs, each with one tenant and one tenant-scoped operator.
	type fix struct{ org, tenant, user, token string }
	f := map[string]*fix{}
	for _, name := range []string{"A", "B"} {
		st, b := do(t, srv, "POST", "/api/orgs", admin, map[string]any{"name": "Org " + name})
		if st != 201 {
			t.Fatalf("create org %s: %d %s", name, st, b)
		}
		orgID := idOf(t, b)
		st, b = do(t, srv, "POST", "/api/tenants", admin, map[string]any{"name": "Tenant " + name, "org_id": orgID})
		if st != 201 {
			t.Fatalf("create tenant %s: %d %s", name, st, b)
		}
		tenantID := idOf(t, b)
		user := "user-" + name
		st, b = do(t, srv, "POST", "/api/users", admin, map[string]any{
			"username": user, "password": "Passw0rd!2345", "role": "operator", "tenant_id": tenantID,
		})
		if st != 201 {
			t.Fatalf("create user %s: %d %s", name, st, b)
		}
		f[name] = &fix{org: orgID, tenant: tenantID, user: user, token: login(t, srv, user, "Passw0rd!2345").Token}
	}
	a, b := f["A"], f["B"]

	// The two fact bases: SAME addresses, SAME app name, DIFFERENT resources.
	factsA := tenantFacts(a.tenant, "i-AAAAAAAA", "i-NVA-AAAA", "lan-sw-A", "wan-edge-A")
	factsB := tenantFacts(b.tenant, "i-BBBBBBBB", "i-NVA-BBBB", "lan-sw-B", "wan-edge-B")
	s.pathFacts = stubFacts{byTenant: map[string]pathgraph.PathFacts{a.tenant: factsA, b.tenant: factsB}, nc: labNetContext()}

	// Identical measurement runs in both tenants.
	recA := ingestFor(t, s, a.tenant, factsA, pathgraph.DataClassLive, ingestNow, "run-A", "")
	recB := ingestFor(t, s, b.tenant, factsB, pathgraph.DataClassLive, ingestNow, "run-B", "")

	corrA := "11111111-1111-4111-8111-111111111111"
	corrB := "22222222-2222-4222-8222-222222222222"
	s.corrPath = stubCorrPath{byID: map[string]struct {
		tenant string
		dst    string
	}{
		corrA: {tenant: a.tenant, dst: "10.60.10.10"},
		corrB: {tenant: b.tenant, dst: "10.60.10.10"}, // the SAME address
	}}

	// ── 1) each tenant's spine resolves to ITS OWN resources ────────────────────
	st, rawA, spineA := getPath(t, srv, a.token, corrA, "")
	if st != 200 || !spineA.SpineAvailable {
		t.Fatalf("A GET path: %d available=%v (%s)", st, spineA.SpineAvailable, rawA)
	}
	st, rawB, spineB := getPath(t, srv, b.token, corrB, "")
	if st != 200 || !spineB.SpineAvailable {
		t.Fatalf("B GET path: %d available=%v (%s)", st, spineB.SpineAvailable, rawB)
	}
	assertRefs(t, "A", spineA, []string{"i-AAAAAAAA", "i-NVA-AAAA", "lan-sw-A", "wan-edge-A"})
	assertRefs(t, "B", spineB, []string{"i-BBBBBBBB", "i-NVA-BBBB", "lan-sw-B", "wan-edge-B"})

	// ── 2) NO byte of the other tenant appears in the API response ──────────────
	for _, leak := range []string{"i-BBBBBBBB", "i-NVA-BBBB", "lan-sw-B", "wan-edge-B", recB.Observation.ObservationID, recB.Definition.PathID, "run-B"} {
		if strings.Contains(string(rawA), leak) {
			t.Fatalf("CROSS-TENANT LEAK: tenant A's response contains tenant B's %q\n%s", leak, rawA)
		}
	}
	for _, leak := range []string{"i-AAAAAAAA", "i-NVA-AAAA", "lan-sw-A", "wan-edge-A", recA.Observation.ObservationID, recA.Definition.PathID, "run-A"} {
		if strings.Contains(string(rawB), leak) {
			t.Fatalf("CROSS-TENANT LEAK: tenant B's response contains tenant A's %q\n%s", leak, rawB)
		}
	}

	// ── 3) tenant A cannot read tenant B's correlation object's path ────────────
	st, raw, spine := getPath(t, srv, a.token, corrB, "")
	if st != 200 {
		t.Fatalf("A GET B's path: %d %s", st, raw)
	}
	if spine.SpineAvailable {
		t.Fatalf("tenant A obtained a spine for tenant B's correlation object: %s", raw)
	}
	if strings.Contains(string(raw), "i-BBBBBBBB") {
		t.Fatalf("tenant A saw tenant B's resources: %s", raw)
	}

	// ── 4) ?as_tenant into another org is ignored ───────────────────────────────
	st, raw, spine = getPath(t, srv, a.token, corrA, "?as_tenant="+b.tenant)
	if st != 200 || !spine.SpineAvailable {
		t.Fatalf("A ?as_tenant=B: %d %s", st, raw)
	}
	assertRefs(t, "A(as_tenant=B)", spine, []string{"i-AAAAAAAA"})
	if strings.Contains(string(raw), "i-BBBBBBBB") {
		t.Fatalf("as_tenant override leaked tenant B's data: %s", raw)
	}

	// ── 5) the STORE itself never crosses (below the API, where the leak would be
	//        invisible to a handler-level test) ──────────────────────────────────
	ctx := context.Background()
	obsA, _, _, ok, err := s.pathGraph.LatestObservation(ctx, a.tenant, false, pathgraph.ObservationFilter{
		DstAddress: "10.60.10.10", DataClasses: pathgraph.LiveOnly(), Limit: 1})
	if err != nil || !ok || obsA.ObservationID != recA.Observation.ObservationID {
		t.Fatalf("store: tenant A got %v (%v), want its own observation", obsA.ObservationID, err)
	}
	eps, err := s.pathGraph.ListEndpoints(ctx, a.tenant, false)
	if err != nil {
		t.Fatal(err)
	}
	for _, ep := range eps {
		if ep.TenantID != normTenant(a.tenant) {
			t.Fatalf("store: tenant A's endpoint listing contains tenant %q", ep.TenantID)
		}
	}
	defs, err := s.pathGraph.ListPathDefinitions(ctx, b.tenant, false)
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range defs {
		if d.TenantID != normTenant(b.tenant) {
			t.Fatalf("store: tenant B's path definitions contain tenant %q", d.TenantID)
		}
	}
	// The two tenants' identical paths are DIFFERENT objects (the tenant is in the id).
	if recA.Definition.PathID == recB.Definition.PathID {
		t.Fatal("identical path shapes in two tenants collapsed onto ONE path_id")
	}

	// ── 6) CLEANUP is scoped: purging tenant A's run leaves tenant B intact ─────
	if err := s.pathGraph.PurgeRun(ctx, a.tenant, "", "run-A"); err != nil {
		t.Fatal(err)
	}
	if _, _, _, ok, _ := s.pathGraph.LatestObservation(ctx, a.tenant, false, pathgraph.ObservationFilter{
		DataClasses: pathgraph.LiveOnly(), Limit: 1}); ok {
		t.Fatal("purge did not remove tenant A's run")
	}
	obsB, _, _, ok, err := s.pathGraph.LatestObservation(ctx, b.tenant, false, pathgraph.ObservationFilter{
		DataClasses: pathgraph.LiveOnly(), Limit: 1})
	if err != nil || !ok || obsB.ObservationID != recB.Observation.ObservationID {
		t.Fatalf("purging tenant A's run destroyed tenant B's observation (%v, %v)", ok, err)
	}
	// …and tenant B's API answer still works.
	st, raw, spine = getPath(t, srv, b.token, corrB, "")
	if st != 200 || !spine.SpineAvailable {
		t.Fatalf("tenant B's path broke after tenant A's cleanup: %d %s", st, raw)
	}
}

// assertRefs checks the spine names ONLY the expected tenant's entities.
func assertRefs(t *testing.T, who string, sp pathSpineResponse, want []string) {
	t.Helper()
	if sp.Spine == nil {
		t.Fatalf("%s: no spine", who)
	}
	refs := map[string]bool{}
	for _, n := range sp.Spine.Spine {
		if n.EntityRef != "" {
			refs[n.EntityRef] = true
		}
	}
	for _, w := range want {
		if !refs[w] {
			t.Fatalf("%s: spine does not name %q (got %v)", who, w, refs)
		}
	}
}

// TestPathGraphDataClassExclusion — §1/§8: the customer API returns ONLY live
// records, even when a synthetic/lab run is NEWER; and a tenant principal may not
// widen its own data-class window.
func TestPathGraphDataClassExclusion(t *testing.T) {
	srv, s := newTestServerState(t)
	s.pathGraph = pathgraph.NewMemStore()
	admin := login(t, srv, "admin", "Passw0rd!2345").Token

	st, b := do(t, srv, "POST", "/api/orgs", admin, map[string]any{"name": "Org X"})
	if st != 201 {
		t.Fatalf("org: %d %s", st, b)
	}
	orgID := idOf(t, b)
	st, b = do(t, srv, "POST", "/api/tenants", admin, map[string]any{"name": "Tenant X", "org_id": orgID})
	if st != 201 {
		t.Fatalf("tenant: %d %s", st, b)
	}
	tenantID := idOf(t, b)
	if st, b := do(t, srv, "POST", "/api/users", admin, map[string]any{
		"username": "user-x", "password": "Passw0rd!2345", "role": "operator", "tenant_id": tenantID}); st != 201 {
		t.Fatalf("user: %d %s", st, b)
	}
	token := login(t, srv, "user-x", "Passw0rd!2345").Token

	facts := tenantFacts(tenantID, "i-LIVE", "i-NVA", "lan-sw", "wan-edge")
	s.pathFacts = stubFacts{byTenant: map[string]pathgraph.PathFacts{tenantID: facts}, nc: labNetContext()}

	// Fresh timestamps: this test also asserts anchors_live_verdict, which is a
	// function of the FRESHNESS window (§8), so the run must be recent.
	fresh := time.Now().UTC().Add(-time.Minute)
	live := ingestFor(t, s, tenantID, facts, pathgraph.DataClassLive, fresh, "run-live", "")
	// A LAB run of the same path, 30 seconds NEWER — it must not win a customer read.
	lab := ingestFor(t, s, tenantID, facts, pathgraph.DataClassLab, fresh.Add(30*time.Second), "run-lab", "")

	corr := "33333333-3333-4333-8333-333333333333"
	s.corrPath = stubCorrPath{byID: map[string]struct {
		tenant string
		dst    string
	}{corr: {tenant: tenantID, dst: "10.60.10.10"}}}

	st, raw, sp := getPath(t, srv, token, corr, "")
	if st != 200 || !sp.SpineAvailable {
		t.Fatalf("GET path: %d %s", st, raw)
	}
	if sp.ObservationID != live.Observation.ObservationID {
		t.Fatalf("the customer API returned observation %s, want the LIVE one %s (a NEWER lab run must be excluded)",
			sp.ObservationID, live.Observation.ObservationID)
	}
	if sp.DataClass != pathgraph.DataClassLive || !sp.AnchorsLive {
		t.Fatalf("data_class=%s anchors_live=%v", sp.DataClass, sp.AnchorsLive)
	}
	if strings.Contains(string(raw), lab.Observation.ObservationID) {
		t.Fatalf("the lab run leaked into the customer response: %s", raw)
	}

	// A tenant principal cannot ask for a non-live class.
	if st, _, _ := getPath(t, srv, token, corr, "?data_class=lab"); st != 403 {
		t.Fatalf("tenant asked for ?data_class=lab: %d, want 403", st)
	}
	// The platform owner can — that is what makes lab/replay data inspectable at all.
	st, raw, sp = getPath(t, srv, admin, corr, "?data_class=lab")
	if st != 200 || !sp.SpineAvailable || sp.ObservationID != lab.Observation.ObservationID {
		t.Fatalf("platform owner ?data_class=lab: %d %s", st, raw)
	}
	if sp.AnchorsLive {
		t.Fatal("a LAB observation claimed it could anchor a live verdict")
	}
}

// TestPathGraphStaleObservationDoesNotAnchor — §8, end to end through the API.
func TestPathGraphStaleObservationDoesNotAnchor(t *testing.T) {
	srv, s := newTestServerState(t)
	s.pathGraph = pathgraph.NewMemStore()
	admin := login(t, srv, "admin", "Passw0rd!2345").Token

	facts := tenantFacts("", "i-LIVE", "i-NVA", "lan-sw", "wan-edge") // platform-tenant fixture
	s.pathFacts = stubFacts{byTenant: map[string]pathgraph.PathFacts{"": facts}, nc: labNetContext()}
	old := time.Now().UTC().Add(-2 * time.Hour) // far outside the 15-minute freshness window
	ingestFor(t, s, "", facts, pathgraph.DataClassLive, old, "run-old", "")

	corr := "44444444-4444-4444-8444-444444444444"
	s.corrPath = stubCorrPath{byID: map[string]struct {
		tenant string
		dst    string
	}{corr: {tenant: "", dst: "10.60.10.10"}}}

	st, raw, sp := getPath(t, srv, admin, corr, "")
	if st != 200 || !sp.SpineAvailable {
		t.Fatalf("GET path: %d %s", st, raw)
	}
	if !sp.Stale || sp.AnchorsLive {
		t.Fatalf("stale=%v anchors_live_verdict=%v — a stale observation must not anchor a live verdict",
			sp.Stale, sp.AnchorsLive)
	}
}

// TestPathGraphNoObservationIsHonest — the UI must never invent a spine, so the API
// must be explicit when there is nothing to render.
func TestPathGraphNoObservationIsHonest(t *testing.T) {
	srv, s := newTestServerState(t)
	s.pathGraph = pathgraph.NewMemStore()
	s.pathFacts = stubFacts{byTenant: map[string]pathgraph.PathFacts{}, nc: labNetContext()}
	s.corrPath = stubCorrPath{byID: map[string]struct {
		tenant string
		dst    string
	}{}}
	admin := login(t, srv, "admin", "Passw0rd!2345").Token

	corr := "55555555-5555-4555-8555-555555555555"
	st, raw, sp := getPath(t, srv, admin, corr, "")
	if st != 200 {
		t.Fatalf("GET path: %d %s", st, raw)
	}
	if sp.SpineAvailable || sp.Reason == "" {
		t.Fatalf("an object with no measured path must return spine_available=false WITH a reason: %s", raw)
	}
}
