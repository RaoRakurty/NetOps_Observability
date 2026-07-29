package main

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"netops/backend/collectors"
	"netops/backend/pathgraph"
)

// path_multivantage_test.go — §8 "multiple vantages: distinct vantage_id ⇒ distinct
// paths; they may agree or disagree".
//
// This is the regression guard for a REAL bug: every prober published its whole
// path registry to ONE shared key, so a LAN vantage and the co-located WAN prober
// silently CLOBBERED each other and no published path carried an attribution. The
// fix is vantage-scoped publication + a merged, attributed read; these tests hold
// both ends of it.

// TestPathsFromTwoVantagesAreDistinctObjects — the LAN vantage's client-anchored
// trace and the WAN prober's edge-anchored trace must produce DIFFERENT paths.
func TestPathsFromTwoVantagesAreDistinctObjects(t *testing.T) {
	// The LAN vantage sees the whole path, starting at the client segment.
	lan := collectors.PathResult{
		Dst: "10.60.10.10", Method: "icmp", Reached: true, TS: ingestNow, VantageID: "lan-vantage-1",
		Hops: []collectors.Hop{
			{TTL: 1, IP: "172.40.40.1", RTTms: 1.1},
			{TTL: 2, IP: "10.70.245.122", RTTms: 3.5},
			{TTL: 3, IP: "10.60.1.10", RTTms: 24},
			{TTL: 4, IP: "10.60.10.10", RTTms: 25},
		},
	}
	// The co-located prober starts at the WAN edge — it CANNOT see the client hop.
	wan := collectors.PathResult{
		Dst: "10.60.10.10", Method: "icmp", Reached: true, TS: ingestNow, VantageID: "prober",
		Hops: []collectors.Hop{
			{TTL: 1, IP: "10.60.1.10", RTTms: 22},
			{TTL: 2, IP: "10.60.10.10", RTTms: 23},
		},
	}

	cfg := labIngestCfg()
	cfg.VantageID = "prober" // the ingester's default; each path's own id must win
	t.Setenv("PATH_GRAPH_VANTAGE_ADDRESSES", "lan-vantage-1:172.40.40.200,prober:10.70.245.122")

	lanRec, err := pathgraph.BuildRecords(cfg, labFacts(), labSeams(), labNetContext(), lan)
	if err != nil {
		t.Fatal(err)
	}
	wanRec, err := pathgraph.BuildRecords(cfg, labFacts(), labSeams(), labNetContext(), wan)
	if err != nil {
		t.Fatal(err)
	}

	if lanRec.Observation.VantageID != "lan-vantage-1" || wanRec.Observation.VantageID != "prober" {
		t.Fatalf("vantage attribution lost: lan=%q wan=%q",
			lanRec.Observation.VantageID, wanRec.Observation.VantageID)
	}
	if lanRec.Definition.PathID == wanRec.Definition.PathID {
		t.Fatal("two vantages measuring the same destination collapsed onto ONE path_id — " +
			"they are distinct paths (§2.2) and must be allowed to disagree")
	}
	// The LAN vantage is what makes the spine legitimately start at the CLIENT.
	if lanRec.SrcEndpoint.Address != "172.40.40.200" {
		t.Fatalf("LAN vantage src = %q, want its declared client-segment address", lanRec.SrcEndpoint.Address)
	}
	if len(lanRec.Hops) != 4 || len(wanRec.Hops) != 2 {
		t.Fatalf("hop counts: lan=%d wan=%d — the two vantages see different amounts of the path",
			len(lanRec.Hops), len(wanRec.Hops))
	}
	// …and the WAN prober's shorter view is not "wrong", it is a different vantage.
	if wanRec.Hops[0].ObservedAddress != "10.60.1.10" {
		t.Fatalf("WAN prober's first hop = %q", wanRec.Hops[0].ObservedAddress)
	}
}

// TestVantageWithoutDeclaredAddressStaysUnresolved — we never borrow another
// prober's source address to fill a spine's client node.
func TestVantageWithoutDeclaredAddressStaysUnresolved(t *testing.T) {
	t.Setenv("PATH_GRAPH_VANTAGE_ADDRESSES", "") // nothing declared
	cfg := labIngestCfg()
	cfg.VantageID = "prober"
	p := labProbe()
	p.VantageID = "unknown-vantage-9"

	rec, err := pathgraph.BuildRecords(cfg, labFacts(), labSeams(), labNetContext(), p)
	if err != nil {
		t.Fatal(err)
	}
	if rec.SrcEndpoint.Address != "" {
		t.Fatalf("an undeclared vantage inherited the address %q — it must stay unresolved",
			rec.SrcEndpoint.Address)
	}
}

// TestRemoteVantagePushIsAuthenticatedAndAttributed — the LAN vantage's transport.
func TestRemoteVantagePushIsAuthenticatedAndAttributed(t *testing.T) {
	srv, s := newTestServerState(t)
	s.pathGraph = pathgraph.NewMemStore()
	s.remotePaths = newRemotePathStore()
	admin := login(t, srv, "admin", "Passw0rd!2345").Token

	body := []collectors.PathResult{{
		Dst: "10.60.10.10", Method: "icmp", Reached: true, TS: time.Now().UTC(), VantageID: "lan-vantage-1",
		Hops: []collectors.Hop{
			{TTL: 1, IP: "172.40.40.1"},
			{TTL: 2, IP: ""}, // a non-responding hop must survive the transport
			{TTL: 3, IP: "10.60.10.10"},
		},
	}}

	// 1) unauthenticated → refused (a forgeable path is not evidence).
	if st, _ := do(t, srv, "POST", "/api/probe/paths", "", body); st != 401 && st != 403 {
		t.Fatalf("unauthenticated push: %d, want 401/403", st)
	}

	// 2) authenticated → accepted and attributed.
	st, raw := do(t, srv, "POST", "/api/probe/paths", admin, body)
	if st != 202 {
		t.Fatalf("push: %d %s", st, raw)
	}
	var ack struct {
		VantageID string `json:"vantage_id"`
		Paths     int    `json:"paths"`
	}
	if err := json.Unmarshal(raw, &ack); err != nil || ack.VantageID != "lan-vantage-1" || ack.Paths != 1 {
		t.Fatalf("push ack = %s", raw)
	}

	// 3) the pushed path shows up in the merged read, attributed, hops intact.
	got, err := s.currentProbePaths(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, p := range got {
		if p.VantageID == "lan-vantage-1" {
			found = true
			if len(p.Hops) != 3 || p.Hops[1].IP != "" {
				t.Fatalf("the non-responding hop did not survive the push: %+v", p.Hops)
			}
		}
	}
	if !found {
		t.Fatalf("the pushed path is not in the merged read: %+v", got)
	}

	// 4) an unattributable push is refused — a path with no vantage cannot be a path.
	bad := []collectors.PathResult{{Dst: "10.60.10.10", Method: "icmp"}}
	if st, _ := do(t, srv, "POST", "/api/probe/paths", admin, bad); st != 400 {
		t.Fatalf("push without vantage_id: %d, want 400", st)
	}
	// 5) a push mixing vantages is refused (it could not be attributed).
	mixed := []collectors.PathResult{
		{Dst: "10.60.10.10", Method: "icmp", VantageID: "v1"},
		{Dst: "10.60.10.10", Method: "icmp", VantageID: "v2"},
	}
	if st, _ := do(t, srv, "POST", "/api/probe/paths", admin, mixed); st != 400 {
		t.Fatalf("mixed-vantage push: %d, want 400", st)
	}
}

// TestPathGraphEnrichmentExportShape — the file the correlation engine consumes.
// The field names + the resolution-method VOCABULARY are the wire contract with
// src/correlation/path_graph.py (PathGraphView.from_dict): an unknown method there
// silently becomes rank 7 (candidate), so a rename on either side is a real outage.
func TestPathGraphEnrichmentExportShape(t *testing.T) {
	_, s := newTestServerState(t)
	s.pathGraph = pathgraph.NewMemStore()
	facts := tenantFacts("t_x", "i-APP", "i-NVA", "lan-sw", "wan-edge")
	s.pathFacts = stubFacts{byTenant: map[string]pathgraph.PathFacts{"t_x": facts}, nc: labNetContext()}
	ingestFor(t, s, "t_x", facts, pathgraph.DataClassLive, time.Now().UTC().Add(-time.Minute), "run-x", "")

	exp, err := s.pathGraphView(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if exp.ContractVersion != pathgraph.ContractVersion {
		t.Fatalf("contract_version = %d", exp.ContractVersion)
	}
	if len(exp.Observations) != 1 || len(exp.Endpoints) == 0 {
		t.Fatalf("export = %d observations, %d endpoints", len(exp.Observations), len(exp.Endpoints))
	}
	o := exp.Observations[0]
	if o.TenantID != "t_x" || o.Definition.PathID == "" || len(o.Hops) != 4 {
		t.Fatalf("observation = %+v", o)
	}
	// Ordered hops, resolved with the SHARED vocabulary.
	for i, h := range o.Hops {
		if h.HopIndex != i+1 {
			t.Fatalf("hop %d out of order (index %d) — the engine relies on hop_index", i, h.HopIndex)
		}
		switch h.ResolutionMethod {
		case pathgraph.MethodEndpointBinding, pathgraph.MethodHopInventory,
			pathgraph.MethodAppBinding, pathgraph.MethodResourceIdentity,
			pathgraph.MethodSessionStitch, pathgraph.MethodUnresolved, pathgraph.MethodTokenSimilarity:
		default:
			t.Fatalf("hop %d carries method %q, which is NOT in the engine's RANK vocabulary "+
				"(it would silently demote to rank 7)", h.HopIndex, h.ResolutionMethod)
		}
	}
	// The wire names the engine's RANK{} keys on.
	if pathgraph.MethodSessionStitch != "flow_nat_stitch" || pathgraph.MethodTokenSimilarity != "shared_token" {
		t.Fatalf("resolution-method vocabulary drifted from src/correlation/path_graph.py: %q / %q",
			pathgraph.MethodSessionStitch, pathgraph.MethodTokenSimilarity)
	}
	// The app↔endpoint edge travels as a SERVICE BINDING (rank 2/4), not a token.
	if len(exp.ServiceBindings) == 0 {
		t.Fatal("no service_bindings exported — the engine then has no app→endpoint relation " +
			"and the cloud node stays orphaned (the exact bug the contract exists to fix)")
	}
	sb := exp.ServiceBindings[0]
	if sb.ServiceRef != "store-api" || sb.EndpointRef == "" || sb.TenantID != "t_x" {
		t.Fatalf("service binding = %+v", sb)
	}
	// Timestamps must be Z-suffixed UTC: python's _dt() cannot parse a +00:00 offset.
	if o.ObservedAt == "" || o.ObservedAt[len(o.ObservedAt)-1] != 'Z' {
		t.Fatalf("observed_at = %q, want a Z-suffixed UTC stamp", o.ObservedAt)
	}
	// It must round-trip as JSON (the file is the contract).
	if _, err := json.Marshal(exp); err != nil {
		t.Fatal(err)
	}
}

// TestPathGraphExportExcludesNonLive — §1 across the process boundary: the engine
// must not be ABLE to confirm a live verdict from lab evidence, so we don't ship it.
func TestPathGraphExportExcludesNonLive(t *testing.T) {
	_, s := newTestServerState(t)
	s.pathGraph = pathgraph.NewMemStore()
	facts := tenantFacts("t_x", "i-APP", "i-NVA", "lan-sw", "wan-edge")
	s.pathFacts = stubFacts{byTenant: map[string]pathgraph.PathFacts{"t_x": facts}, nc: labNetContext()}
	ingestFor(t, s, "t_x", facts, pathgraph.DataClassLab, time.Now().UTC(), "run-lab", "")

	exp, err := s.pathGraphView(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(exp.Observations) != 0 {
		t.Fatalf("a LAB observation was exported to the correlation engine: %+v", exp.Observations)
	}
}
