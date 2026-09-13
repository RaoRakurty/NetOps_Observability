// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// topology_links_unread_test.go — tracker 290, the CALLER half.
//
// Fixing the fold in collectors.FetchTopologyLinks changes nothing an operator
// can see, because every caller on the topology read path dropped the error it
// started returning: `links, _ := fetch(ctx)` under a comment calling it
// "best-effort". So these tests assert on WHAT THE OPERATOR RECEIVES — the
// rendered payload, the status code, the persisted graph — never on an internal
// error being returned.
//
// The disposition is per caller, and it is not the same everywhere:
//
//	/api/topology/view   → RENDERABLE WITH A BANNER. Nodes, alerts and health in
//	                       the same payload are real; the view carries `degraded`.
//	/api/topology/links  → REFUSAL (502). The link set IS the payload; there is
//	                       nowhere to put a caveat, and count:0 reads as a fact.
//	the reconciler       → REFUSAL for the EDGE HALF. It WRITES, and an
//	                       unobserved edge is aged out and eventually deleted.
//	/api/wan/interfaces  → RENDERABLE WITH A BANNER. Every interface silently
//	                       falls back to a reachability anchor without one.
//	the assistant        → A NOTE, through the mechanism the seam register uses.

import (
	"context"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"netops/backend/ai"
	"netops/backend/alerts"
	"netops/backend/collectors"
	"netops/backend/internal/discovery"
	"netops/backend/models"
	"netops/backend/pathgraph"
	"netops/backend/topology"
)

// errDeadChannel stands in for the transport failure collectors.FetchTopologyLinks
// now reports: the channel is configured, the collectors are publishing into it,
// and the api cannot read it.
var errDeadChannel = errors.New("topology links: the discovery channel failed while reading netops:topo:links:lldp (3 of 3 protocol keys were not read): redis: connection failed")

// deadTopoLinks is the injected seam: an adjacency read that fails the way a
// dead channel fails — no links, and an error that says so.
func deadTopoLinks(context.Context) ([]collectors.LLDPNeighbor, error) {
	return nil, errDeadChannel
}

// newTopoLinkTestServer builds the real router with two adjacent devices in one
// tenant, so a HEALTHY read draws exactly one link and a broken one draws none.
func newTopoLinkTestServer(t *testing.T) (*httptest.Server, *server, string) {
	t.Helper()
	ts, st := newTestServerState(t)
	st.alerts = alerts.NewEngine("", nil) // the minimal test server leaves it nil
	admin := login(t, ts, "admin", "Passw0rd!2345").Token
	for _, d := range []models.Device{
		{ID: "spine-1", Name: "spine-1", Address: "10.0.0.1", TenantID: TenantGlobal, Source: "test"},
		{ID: "leaf-1", Name: "leaf-1", Address: "10.0.0.2", TenantID: TenantGlobal, Source: "test"},
	} {
		if err := st.discovery.Upsert(d); err != nil {
			t.Fatalf("seed %s: %v", d.ID, err)
		}
	}
	st.topoLinks = func(context.Context) ([]collectors.LLDPNeighbor, error) {
		return []collectors.LLDPNeighbor{{
			LocalDevice: "spine-1", LocalName: "spine-1", LocalPort: "Ethernet1",
			RemSysName: "leaf-1", RemPort: "Ethernet2", Proto: "lldp",
		}}, nil
	}
	return ts, st, admin
}

// TestTopologyViewSaysWhenTheAdjacencyEvidenceNeverArrived is the canvas half.
//
// BEFORE THE FIX the broken-channel response was byte-for-byte the healthy
// response minus its one edge: 2 nodes, 0 edges, no degraded field, HTTP 200.
// An operator working an incident read "these two devices are not adjacent"
// off a map that had simply never been given the evidence.
func TestTopologyViewSaysWhenTheAdjacencyEvidenceNeverArrived(t *testing.T) {
	srv, s, token := newTopoLinkTestServer(t)

	view := func() topology.View {
		st, b := do(t, srv, "GET", "/api/topology/view?mode=explore", token, nil)
		if st != 200 {
			t.Fatalf("GET /api/topology/view: %d %s", st, b)
		}
		var v topology.View
		if err := json.Unmarshal(b, &v); err != nil {
			t.Fatalf("decode view: %v (%s)", err, b)
		}
		return v
	}

	healthy := view()
	if len(healthy.Edges) != 1 {
		t.Fatalf("the healthy view draws %d edges, want 1 — the comparison would prove nothing", len(healthy.Edges))
	}
	if len(healthy.Degraded) != 0 {
		t.Fatalf("a healthy read raised a degradation banner: %v", healthy.Degraded)
	}

	s.topoLinks = deadTopoLinks
	broken := view()
	// The canvas still renders: refusing it would take away the inventory and the
	// alert overlay, which arrived and are real.
	if len(broken.Nodes) != len(healthy.Nodes) {
		t.Fatalf("the broken-channel view draws %d nodes, want the %d the healthy one draws — the read failure must not cost the inventory",
			len(broken.Nodes), len(healthy.Nodes))
	}
	// …but it must not present the missing adjacency as a finding.
	if len(broken.Degraded) == 0 {
		t.Fatalf("the view drew %d nodes and %d edges with NOTHING saying the adjacency evidence never arrived — an operator reads that as 'these devices are not adjacent'",
			len(broken.Nodes), len(broken.Edges))
	}
	if !strings.Contains(broken.Degraded[0], "does NOT mean") {
		t.Errorf("the degradation note does not forbid the inference an operator will otherwise make: %q", broken.Degraded[0])
	}
}

// TestTopologyLinksRefusesWhenTheAdjacencyEvidenceNeverArrived is the refusal.
//
// BEFORE THE FIX this endpoint answered 200 with {"links":[],"count":0} — the
// silent failure in its purest form, because the link set is the whole payload
// and there is nothing else in it to carry a caveat.
func TestTopologyLinksRefusesWhenTheAdjacencyEvidenceNeverArrived(t *testing.T) {
	srv, s, token := newTopoLinkTestServer(t)

	st, b := do(t, srv, "GET", "/api/topology/links", token, nil)
	if st != 200 {
		t.Fatalf("healthy GET /api/topology/links: %d %s", st, b)
	}
	var healthy struct {
		Links []topoLink `json:"links"`
		Count int        `json:"count"`
	}
	if err := json.Unmarshal(b, &healthy); err != nil {
		t.Fatalf("decode: %v (%s)", err, b)
	}
	if healthy.Count != 1 {
		t.Fatalf("the healthy endpoint reports %d links, want 1", healthy.Count)
	}

	s.topoLinks = deadTopoLinks
	st, b = do(t, srv, "GET", "/api/topology/links", token, nil)
	if st == 200 {
		t.Fatalf("an unread discovery channel answered 200 %s — every consumer reads count:0 as 'this estate has no adjacencies'", b)
	}
	if st != 502 {
		t.Fatalf("status %d, want 502 (never a confident empty): %s", st, b)
	}
	if !strings.Contains(string(b), "does NOT mean") {
		t.Errorf("the refusal does not explain what the caller must not conclude: %s", b)
	}
}

// TestReconcilerDoesNotAgeOutEdgesItNeverObserved is the WRITE half, and the
// worst of the four: topology.Reconcile marks every persisted record it does not
// observe stale after topologyStaleAfter and DROPS it after topologyPruneAfter.
//
// BEFORE THE FIX an unread channel therefore did not merely draw an empty map
// for one request — it marked the whole persisted spine stale within 15 minutes
// and deleted it within 7 days, while the Persisted tab stamped the graph as
// freshly reconciled. This test observes the edge coming back STALE from a cycle
// that observed nothing because it could not read anything.
func TestReconcilerDoesNotAgeOutEdgesItNeverObserved(t *testing.T) {
	_, s, _ := newTopoLinkTestServer(t)
	s.topology = newTopologyStore()
	ctx := context.Background()

	s.reconcileTopologyOnce(ctx) // seed from the healthy seam
	seeded, err := s.topology.Snapshot(ctx, "", true)
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	if len(seeded.Edges) != 1 {
		t.Fatalf("the seeded graph holds %d edges, want 1 — the comparison would prove nothing", len(seeded.Edges))
	}

	// Age the persisted edge past the stale grace window, the way a real graph is
	// aged by the time between the last good cycle and the outage.
	aged := seeded
	for i := range aged.Edges {
		aged.Edges[i].LastSeen = time.Now().Add(-2 * topologyStaleAfter)
	}
	for i := range aged.Nodes {
		aged.Nodes[i].LastSeen = time.Now().Add(-2 * topologyStaleAfter)
	}
	if err := s.topology.ReplaceAll(ctx, aged); err != nil {
		t.Fatalf("replace: %v", err)
	}

	s.topoLinks = deadTopoLinks
	s.reconcileTopologyOnce(ctx)

	after, err := s.topology.Snapshot(ctx, "", true)
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	if len(after.Edges) != 1 {
		t.Fatalf("a cycle that could not READ the adjacency channel left %d edges, want the 1 it never observed to survive untouched", len(after.Edges))
	}
	if after.Edges[0].Stale {
		t.Fatal("the persisted edge was marked STALE by a cycle that observed nothing because it observed nothing it could read — an observation that never happened must not be able to age anything out")
	}
	// The node half still reconciles: nodes come from the device registry, which
	// was read successfully, and refusing the whole cycle would rot the inventory.
	if len(after.Nodes) != len(seeded.Nodes) {
		t.Fatalf("the node half stopped reconciling: %d nodes, want %d", len(after.Nodes), len(seeded.Nodes))
	}
	for _, n := range after.Nodes {
		if n.Stale {
			t.Fatalf("node %s reads stale after a cycle whose device read succeeded", n.ID)
		}
	}
}

// TestWanInterfacesSayWhenThePeersWereNeverLookedFor is the WAN half. The
// neighbour index is the second rung of the target-derivation ranking, so with
// no index every interface falls through to the reachability anchor.
//
// BEFORE THE FIX that fallback was invisible: the row said "Reachability anchor
// 1.1.1.1" and nothing said the peer across the link had never been looked for.
// The failure is SAFE — it fails closed and discloses nothing — and that is
// exactly what made it survive.
func TestWanInterfacesSayWhenThePeersWereNeverLookedFor(t *testing.T) {
	srv, s, token := newTopoLinkTestServer(t)
	for _, d := range []models.Device{
		{ID: "wan-a", Name: "wan-a", Address: "10.0.9.1", TenantID: TenantGlobal, Source: "test"},
	} {
		if err := s.discovery.Upsert(d); err != nil {
			t.Fatalf("seed %s: %v", d.ID, err)
		}
	}
	s.wanIfAddr = func(context.Context) (map[string]map[string]string, error) {
		return map[string]map[string]string{"wan-a": {"10.0.9.1": "Ethernet1"}}, nil
	}
	s.wanNeighbors = nil // fall through to the shared adjacency-evidence resolver

	read := func() (rows []map[string]any, degraded []string) {
		st, b := do(t, srv, "GET", "/api/wan/interfaces", token, nil)
		if st != 200 {
			t.Fatalf("GET /api/wan/interfaces: %d %s", st, b)
		}
		var body struct {
			Interfaces []map[string]any `json:"interfaces"`
			Degraded   []string         `json:"degraded"`
		}
		if err := json.Unmarshal(b, &body); err != nil {
			t.Fatalf("decode: %v (%s)", err, b)
		}
		return body.Interfaces, body.Degraded
	}

	healthyRows, healthyDeg := read()
	if len(healthyRows) == 0 {
		t.Fatal("the harness projects no WAN interface, so the comparison would prove nothing")
	}
	if len(healthyDeg) != 0 {
		t.Fatalf("a healthy read raised a degradation banner: %v", healthyDeg)
	}

	s.topoLinks = deadTopoLinks
	brokenRows, brokenDeg := read()
	if len(brokenRows) != len(healthyRows) {
		t.Fatalf("the broken-channel table has %d rows, want the %d the healthy one has — the interface, its load and its SLA all still arrived", len(brokenRows), len(healthyRows))
	}
	if len(brokenDeg) == 0 {
		t.Fatal("every interface fell back to its reachability anchor and the table said NOTHING — the operator cannot tell a measured internet path from a peer that was never looked for")
	}
	if !strings.Contains(brokenDeg[0], "reachability anchor") {
		t.Errorf("the note does not name the consequence the reader is looking at: %q", brokenDeg[0])
	}
}

// TestAITopologyContextSaysTheNeighboursAreUnknown is the assistant's half.
//
// BEFORE THE FIX the answer carried an EMPTY Neighbors list and no note, which
// the model reads as "this device is adjacent to nothing" and will then reason
// from with full confidence. §15's rule that model input is untrusted cuts both
// ways: we must not feed it a fact we do not have. The mechanism is the one the
// seam register already uses two blocks down in the same function.
func TestAITopologyContextSaysTheNeighboursAreUnknown(t *testing.T) {
	ts, err := newTenantStore(filepath.Join(t.TempDir(), "tenants.json"))
	if err != nil {
		t.Fatalf("newTenantStore: %v", err)
	}
	acme, err := ts.Create("Acme", "acme", "", "", "")
	if err != nil {
		t.Fatalf("create acme: %v", err)
	}
	d := discovery.NewDiscoveryAggregator()
	for _, dev := range []models.Device{
		{ID: "core1", Name: "core1", Address: "10.0.0.1", TenantID: acme.ID},
		{ID: "leaf1", Name: "leaf1", Address: "10.0.0.2", TenantID: acme.ID},
	} {
		if err := d.Upsert(dev); err != nil {
			t.Fatalf("seed %s: %v", dev.ID, err)
		}
	}
	s := &server{discovery: d, tenants: ts, pathGraph: pathgraph.NewMemStore()}
	claims := jwtClaims{Sub: "a@acme", Role: RoleOperator, Tenant: acme.ID}
	ctx := context.Background()

	s.topoLinks = func(context.Context) ([]collectors.LLDPNeighbor, error) {
		return []collectors.LLDPNeighbor{{
			LocalDevice: "core1", LocalName: "core1", LocalPort: "Ethernet1",
			RemSysName: "leaf1", RemPort: "Ethernet2", Proto: "lldp",
		}}, nil
	}
	healthy, err := s.aiTopologyContext(claims)(ctx, ai.Principal{}, "core1")
	if err != nil {
		t.Fatalf("TopologyContext: %v", err)
	}
	if len(healthy.Neighbors) != 1 {
		t.Fatalf("the healthy answer carries %d neighbours, want 1 — the comparison would prove nothing", len(healthy.Neighbors))
	}

	s.topoLinks = deadTopoLinks
	broken, err := s.aiTopologyContext(claims)(ctx, ai.Principal{}, "core1")
	if err != nil {
		t.Fatalf("TopologyContext: %v", err)
	}
	if len(broken.Neighbors) != 0 {
		t.Fatalf("got %d neighbours off a dead channel", len(broken.Neighbors))
	}
	var said bool
	for _, n := range broken.Notes {
		if strings.Contains(n, "UNKNOWN for this answer, not absent") {
			said = true
		}
	}
	if !said {
		t.Fatalf("the answer reports NO neighbours and says nothing about why. Notes: %v", broken.Notes)
	}
}
