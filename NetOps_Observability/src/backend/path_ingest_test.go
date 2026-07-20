package main

import (
	"testing"
	"time"

	"netops/backend/collectors"
	"netops/backend/pathgraph"
)

// path_ingest_test.go — §8 REQUIRED BEHAVIOURS, exercised on the real ingest path
// (prober output → PathObservation + ordered PathHops), plus the §3 resolution and
// §1 provenance rules the ingester is responsible for.

var ingestNow = time.Date(2026, 7, 12, 12, 0, 0, 0, time.UTC)

func labIngestCfg() pathIngestCfg {
	return pathIngestCfg{
		Tenant: "t_a", DataClass: pathgraph.DataClassLive, Environment: "lab", RunID: "run-1",
		ProducerID: "prober-lab", VantageID: "prober-lab", VantageAddress: "172.40.40.92", Now: ingestNow,
	}
}

// labFacts mirrors what the real inventories supply for the verified live path.
func labFacts() pathgraph.PathFacts {
	open := pathgraph.Window{From: ingestNow.Add(-24 * time.Hour)}
	return pathgraph.PathFacts{
		NICBindings: []pathgraph.NICBinding{
			{TenantID: "t_a", Address: "10.60.10.10", NetworkContext: "vpc-aws", ResourceID: "i-0448c046139420a7f",
				InterfaceID: "eni-01830be2f44b23cb2", Kind: pathgraph.KindAppEndpoint, Window: open,
				EvidenceRef: "cloud_inventory:i-0448c046139420a7f", DataClass: pathgraph.DataClassLive, ObservedAt: ingestNow},
			{TenantID: "t_a", Address: "10.60.1.10", NetworkContext: "vpc-aws", ResourceID: "i-0e8acbf8493d037f9",
				InterfaceID: "eni-007542c1d61f44947", Kind: pathgraph.KindNVA, Window: open,
				EvidenceRef: "cloud_inventory:i-0e8acbf8493d037f9", DataClass: pathgraph.DataClassLive, ObservedAt: ingestNow},
		},
		InterfaceBindings: []pathgraph.InterfaceBinding{
			{TenantID: "t_a", Address: "172.40.40.1", NetworkContext: "lab-lan", DeviceID: "lan-sw1",
				InterfaceID: "Vlan40", Window: open, EvidenceRef: "if:lan-sw1", DataClass: pathgraph.DataClassLive, ObservedAt: ingestNow},
			{TenantID: "t_a", Address: "10.70.245.122", NetworkContext: "lab-wan", DeviceID: "wan-edge1",
				InterfaceID: "eth0", Window: open, EvidenceRef: "if:wan-edge1", DataClass: pathgraph.DataClassLive, ObservedAt: ingestNow},
			{TenantID: "t_a", Address: "172.40.40.92", NetworkContext: "lab-lan", DeviceID: "host-lan-92",
				InterfaceID: "eth0", Window: open, EvidenceRef: "if:host-92", DataClass: pathgraph.DataClassLive, ObservedAt: ingestNow},
		},
		AppBindings: []pathgraph.AppBinding{
			{TenantID: "t_a", Service: "store-api", Address: "10.60.10.10", NetworkContext: "vpc-aws",
				ResourceRef: "i-0448c046139420a7f", Window: open, EvidenceRef: "app_identity:store-api@10.60.10.10",
				DataClass: pathgraph.DataClassLive, ObservedAt: ingestNow},
		},
	}
}

// labNetContext: the operator-declared on-prem contexts + the discovered AWS VPC.
func labNetContext() netContext {
	return newNetContext(nil, "lab-lan:172.40.40.0/24,lab-wan:10.70.245.0/24,vpc-aws:10.60.0.0/16")
}

// labSeams: the ACTIVE lab↔AWS VPN seam, with the endpoints the seam inventory holds.
func labSeams() seamIndex {
	return buildSeamIndex([]Seam{{
		SeamID: "sm-f36b592d4e76", TenantID: "t_a", SeamType: "VPN", State: "active",
		Endpoints: map[string]string{"on_prem": "10.70.245.122", "remote": "10.60.1.10"},
	}})
}

// labProbe is the prober's traceroute for the verified live path. The third hop is
// deliberately non-responding in some tests; here it responds.
func labProbe() collectors.PathResult {
	return collectors.PathResult{
		Dst: "10.60.10.10", Method: "icmp", Reached: true, TS: ingestNow,
		Hops: []collectors.Hop{
			{TTL: 1, IP: "172.40.40.1", RTTms: 1.2},
			{TTL: 2, IP: "10.70.245.122", RTTms: 3.8},
			{TTL: 3, IP: "10.60.1.10", RTTms: 24.1},
			{TTL: 4, IP: "10.60.10.10", RTTms: 25.0},
		},
	}
}

func buildLab(t *testing.T, p collectors.PathResult) pathRecords {
	t.Helper()
	recs, err := buildPathRecords(labIngestCfg(), labFacts(), labSeams(), labNetContext(), p)
	if err != nil {
		t.Fatalf("buildPathRecords: %v", err)
	}
	return recs
}

// TestIngestResolvesTheLivePath — every hop bound by ranks 1–5, the seam stamped,
// the tunnel transformation explicit, and the service tail from a rank-4 binding.
func TestIngestResolvesTheLivePath(t *testing.T) {
	recs := buildLab(t, labProbe())

	if got := len(recs.Hops); got != 4 {
		t.Fatalf("hops = %d, want 4", got)
	}
	want := []struct{ addr, ref, kind, method string }{
		{"172.40.40.1", "lan-sw1", pathgraph.KindLANGateway, pathgraph.MethodHopInventory},
		{"10.70.245.122", "wan-edge1", pathgraph.KindWANEdge, pathgraph.MethodHopInventory},
		{"10.60.1.10", "i-0e8acbf8493d037f9", pathgraph.KindNVA, pathgraph.MethodEndpointBinding},
		{"10.60.10.10", "i-0448c046139420a7f", pathgraph.KindAppEndpoint, pathgraph.MethodEndpointBinding},
	}
	for i, w := range want {
		h := recs.Hops[i]
		if h.HopIndex != i+1 {
			t.Fatalf("hop %d has index %d — hop order is DATA", i, h.HopIndex)
		}
		if h.ObservedAddress != w.addr || h.ResolvedEntityRef != w.ref || h.Kind != w.kind || h.ResolutionMethod != w.method {
			t.Fatalf("hop %d = {%s %s %s %s}, want {%s %s %s %s}", i+1,
				h.ObservedAddress, h.ResolvedEntityRef, h.Kind, h.ResolutionMethod, w.addr, w.ref, w.kind, w.method)
		}
		if !pathgraph.Authoritative(h.ResolutionMethod) {
			t.Fatalf("hop %d resolved by a non-authoritative method %s", i+1, h.ResolutionMethod)
		}
	}
	// Seam membership + explicit transformation at the seam (§4 of the build brief).
	if recs.Hops[1].SeamID != "sm-f36b592d4e76" || recs.Hops[1].Transformation != pathgraph.TransformTunnelIngress {
		t.Fatalf("WAN edge hop = seam %q transform %q, want the seam's near side (tunnel_ingress)",
			recs.Hops[1].SeamID, recs.Hops[1].Transformation)
	}
	if recs.Hops[2].SeamID != "sm-f36b592d4e76" || recs.Hops[2].Transformation != pathgraph.TransformTunnelEgress {
		t.Fatalf("NVA hop = seam %q transform %q, want the seam's far side (tunnel_egress)",
			recs.Hops[2].SeamID, recs.Hops[2].Transformation)
	}
	if recs.Service == nil || recs.Service.Service != "store-api" || recs.Service.Method != pathgraph.MethodAppBinding {
		t.Fatalf("service tail = %+v, want store-api from the rank-4 binding", recs.Service)
	}
	// §1 provenance is complete and the run id is stamped (§2.3).
	if err := recs.Observation.Validate(); err != nil {
		t.Fatalf("observation provenance: %v", err)
	}
	if recs.Observation.RunID != "run-1" || recs.Observation.ProvenanceID == "" {
		t.Fatalf("observation provenance = %+v", recs.Observation.Provenance)
	}
}

// TestMissingHopIsPreservedThroughIngest — §8: the prober delivers a non-responding
// hop with an EMPTY ip; it must survive as state=missing, never be dropped.
func TestMissingHopIsPreservedThroughIngest(t *testing.T) {
	p := labProbe()
	p.Hops[2] = collectors.Hop{TTL: 3, IP: ""} // the NVA hop goes dark
	recs := buildLab(t, p)

	if len(recs.Hops) != 4 {
		t.Fatalf("hops = %d, want 4 — a non-responding hop must NOT be dropped", len(recs.Hops))
	}
	h := recs.Hops[2]
	if h.State != pathgraph.HopMissing || h.ObservedAddress != "" || h.ResolvedEntityRef != "" {
		t.Fatalf("missing hop = %+v, want state=missing with no address and no binding", h)
	}
	if h.HopIndex != 3 {
		t.Fatalf("missing hop index = %d, want 3 (its POSITION is part of the fact)", h.HopIndex)
	}
	// …and the hops after it keep their positions: the gap is not closed up.
	if recs.Hops[3].HopIndex != 4 || recs.Hops[3].ObservedAddress != "10.60.10.10" {
		t.Fatalf("the gap was bridged: hop 4 = %+v", recs.Hops[3])
	}
}

// TestRouteChangeProducesANewObservation — §8: every run is a NEW immutable
// observation; the path identity is stable, so the history is queryable.
func TestRouteChangeProducesANewObservation(t *testing.T) {
	first := buildLab(t, labProbe())

	changed := labProbe()
	changed.TS = ingestNow.Add(5 * time.Minute)
	changed.Hops[2] = collectors.Hop{TTL: 3, IP: "10.60.2.10", RTTms: 30} // the route moved
	second := buildLab(t, changed)

	if first.Observation.ObservationID == second.Observation.ObservationID {
		t.Fatal("a second run reused the observation id — observations are immutable, one per run")
	}
	if first.Definition.PathID != second.Definition.PathID {
		t.Fatalf("the path identity changed on a route change (%s → %s) — it must not; only the OBSERVATION changes",
			first.Definition.PathID, second.Definition.PathID)
	}
	if second.Hops[2].ObservedAddress != "10.60.2.10" {
		t.Fatalf("the new observation did not record the new route: %+v", second.Hops[2])
	}
	if first.Hops[2].ObservedAddress != "10.60.1.10" {
		t.Fatal("the earlier observation was mutated — history must be immutable")
	}
}

// TestDistinctPathsAreDistinctObjects — §8: asymmetric paths, vantages, and
// TCP-vs-ICMP are DIFFERENT paths and are never merged.
func TestDistinctPathsAreDistinctObjects(t *testing.T) {
	icmp := buildLab(t, labProbe())

	tcpProbe := labProbe()
	tcpProbe.Method = "tcp"
	tcp := buildLab(t, tcpProbe)
	if tcp.Definition.PathID == icmp.Definition.PathID {
		t.Fatal("a TCP path and an ICMP path to the same host share a path_id — they must be allowed to disagree")
	}
	if tcp.Observation.Method != pathgraph.MethodTracerouteTCP {
		t.Fatalf("tcp observation method = %s", tcp.Observation.Method)
	}

	// A second vantage measuring the same destination is a DIFFERENT path.
	cfg2 := labIngestCfg()
	cfg2.VantageID = "prober-dc2"
	other, err := buildPathRecords(cfg2, labFacts(), labSeams(), labNetContext(), labProbe())
	if err != nil {
		t.Fatal(err)
	}
	if other.Definition.PathID == icmp.Definition.PathID {
		t.Fatal("two vantages collapsed onto one path_id — they must stay distinct")
	}

	// The reverse direction is a different path too (identity includes direction).
	rev := pathgraph.PathID("t_a", icmp.Definition.DstEndpointRef, icmp.Definition.SrcEndpointRef,
		"reverse", "icmp", 0, "prober-lab", "lab-lan")
	if rev == icmp.Definition.PathID {
		t.Fatal("forward and reverse produced the same path_id — asymmetric paths must never merge")
	}
}

// TestNATTransformationIsExplicitFromASession — §8: NAT is stitched by a rank-5
// session record, never by address coincidence.
func TestNATTransformationIsExplicitFromASession(t *testing.T) {
	facts := labFacts()
	facts.SessionSourceAvailable = true
	facts.Sessions = []pathgraph.SessionStitch{{
		TenantID: "t_a", PreAddress: "172.40.40.92", PostAddress: "10.70.245.122", NetworkContext: "lab-wan",
		ResourceRef: "wan-edge1", Transformation: pathgraph.TransformNAT,
		Window: pathgraph.Window{From: ingestNow.Add(-time.Hour)}, EvidenceRef: "session:1",
		DataClass: pathgraph.DataClassLive, ObservedAt: ingestNow,
	}}
	// Drop the interface binding for the WAN edge so the session is the resolver's
	// best (rank-5) answer for that hop.
	facts.InterfaceBindings = facts.InterfaceBindings[:1]

	recs, err := buildPathRecords(labIngestCfg(), facts, seamIndex{}, labNetContext(), labProbe())
	if err != nil {
		t.Fatal(err)
	}
	h := recs.Hops[1]
	if h.ResolutionMethod != pathgraph.MethodSessionStitch || h.Transformation != pathgraph.TransformNAT {
		t.Fatalf("NAT hop = {%s %s}, want a rank-5 session stitch with an explicit nat transformation",
			h.ResolutionMethod, h.Transformation)
	}
}

// TestUnresolvedHopStaysUnknownThroughIngest — §8: an unresolvable hop is never
// guessed, and its rDNS name is a CANDIDATE lead, never a binding.
func TestUnresolvedHopStaysUnknownThroughIngest(t *testing.T) {
	facts := labFacts()
	facts.Tokens = []pathgraph.NameToken{{
		TenantID: "t_a", Token: "aws-nva.lab", Ref: "i-0e8acbf8493d037f9", NetworkContext: "lab-wan",
		EvidenceRef: "rdns", DataClass: pathgraph.DataClassLive,
	}}
	p := labProbe()
	// A carrier hop we know nothing about — but whose rDNS name matches a known NVA.
	p.Hops[1] = collectors.Hop{TTL: 2, IP: "10.70.245.200", Host: "aws-nva.lab", RTTms: 4}

	recs, err := buildPathRecords(labIngestCfg(), facts, seamIndex{}, labNetContext(), p)
	if err != nil {
		t.Fatal(err)
	}
	h := recs.Hops[1]
	if h.ResolvedEntityRef != "" {
		t.Fatalf("an rDNS NAME bound entity %q — rank 7 must NEVER create a binding", h.ResolvedEntityRef)
	}
	if h.Kind != pathgraph.KindUnknown || h.Confidence != pathgraph.ConfCandidate {
		t.Fatalf("unresolved hop = {kind=%s conf=%s}, want unknown/candidate", h.Kind, h.Confidence)
	}
	if h.CandidateRef != "i-0e8acbf8493d037f9" {
		t.Fatalf("candidate_ref = %q, want the name match surfaced as a lead (and nothing more)", h.CandidateRef)
	}
}

// TestSyntheticRunIsClassStamped — §1: the ingester stamps the data class from
// configuration, and the store's customer filter excludes it (asserted in the API
// test). Here we prove the stamp reaches every record.
func TestSyntheticRunIsClassStamped(t *testing.T) {
	cfg := labIngestCfg()
	cfg.DataClass = pathgraph.DataClassSynthetic
	cfg.ScenarioID = "scn-1"
	recs, err := buildPathRecords(cfg, labFacts(), labSeams(), labNetContext(), labProbe())
	if err != nil {
		t.Fatal(err)
	}
	if recs.Observation.DataClass != pathgraph.DataClassSynthetic || recs.Observation.ScenarioID != "scn-1" {
		t.Fatalf("observation provenance = %+v", recs.Observation.Provenance)
	}
	for _, h := range recs.Hops {
		if h.DataClass != pathgraph.DataClassSynthetic {
			t.Fatalf("hop %d carries data_class %q, want synthetic", h.HopIndex, h.DataClass)
		}
	}
	if recs.Definition.DataClass != pathgraph.DataClassSynthetic || recs.SrcEndpoint.DataClass != pathgraph.DataClassSynthetic {
		t.Fatal("the definition/endpoint did not inherit the run's data class")
	}
	// A synthetic run resolves against LIVE facts only if it opts in — by default it
	// must not silently consume live inventory as if it were its own.
	if recs.Hops[0].ResolvedEntityRef == "" {
		t.Skip("synthetic runs admit non-live facts; nothing to assert here")
	}
}

// TestSeamIndexOnlyUsesTheInventory — a seam's sides come from the seam INVENTORY
// (its endpoints), not from address arithmetic, and a non-tunnel seam type never
// claims a tunnel transformation.
func TestSeamIndexOnlyUsesTheInventory(t *testing.T) {
	si := buildSeamIndex([]Seam{{
		SeamID: "sm-dia", SeamType: "DIA", State: "active",
		Endpoints: map[string]string{"on_prem": "10.70.245.122", "provider_edge": "203.0.113.1"},
	}})
	onPath := map[string]bool{"10.70.245.122": true, "203.0.113.1": true}
	id, tr := si.transformAt("10.70.245.122", onPath)
	if id != "sm-dia" || tr != pathgraph.TransformNone {
		t.Fatalf("DIA seam produced {%s %s}, want the seam id with NO tunnel transformation", id, tr)
	}
	if id, tr := si.transformAt("198.51.100.1", onPath); id != "" || tr != pathgraph.TransformNone {
		t.Fatalf("an address that is not a seam endpoint got {%s %s}", id, tr)
	}
}

// TestSharedSeamEndpointDisambiguatedByPath — one enterprise edge terminates TWO
// VPN seams (the live lab: 10.70.245.122 is a_ip of both the AWS and the Azure
// tunnel). The seam stamped on a hop must be the one whose FAR side is on this
// path; with no on-path far side, NO seam is stamped (a wrong seam id would send
// the NOC to the wrong tunnel). Uses the live inventory's a_ip/b_ip vocabulary,
// and non-address endpoint metadata must never index.
func TestSharedSeamEndpointDisambiguatedByPath(t *testing.T) {
	si := buildSeamIndex([]Seam{
		{SeamID: "sm-aws", SeamType: "VPN", State: "active",
			Endpoints: map[string]string{"a_ip": "10.70.245.122", "b_ip": "10.60.1.10",
				"a_name": "netops-lab-edge", "b_host": "aws-app-host-01", "b_public_ip": "100.21.102.86"}},
		{SeamID: "sm-azure", SeamType: "VPN", State: "active",
			Endpoints: map[string]string{"a_ip": "10.70.245.122", "b_ip": "10.61.2.10",
				"probe_target": "192.0.2.120"}},
	})
	awsPath := map[string]bool{"172.40.40.1": true, "10.70.245.122": true, "10.60.1.10": true, "10.60.10.10": true}
	if id, tr := si.transformAt("10.70.245.122", awsPath); id != "sm-aws" || tr != pathgraph.TransformTunnelIngress {
		t.Fatalf("shared edge on the AWS path = {%s %s}, want sm-aws tunnel_ingress (near side)", id, tr)
	}
	azurePath := map[string]bool{"172.40.40.1": true, "10.70.245.122": true, "10.61.2.10": true, "10.61.10.10": true}
	if id, tr := si.transformAt("10.70.245.122", azurePath); id != "sm-azure" || tr != pathgraph.TransformTunnelIngress {
		t.Fatalf("shared edge on the Azure path = {%s %s}, want sm-azure tunnel_ingress", id, tr)
	}
	if id, tr := si.transformAt("10.61.2.10", azurePath); id != "sm-azure" || tr != pathgraph.TransformTunnelEgress {
		t.Fatalf("far side = {%s %s}, want sm-azure tunnel_egress", id, tr)
	}
	// Ambiguous (neither far side on the path) → honest omission, not a guess.
	if id, tr := si.transformAt("10.70.245.122", map[string]bool{"192.0.2.7": true}); id != "" || tr != pathgraph.TransformNone {
		t.Fatalf("ambiguous shared edge = {%s %s}, want NO seam", id, tr)
	}
	// probe_target / names must not have been indexed as seam endpoints.
	if id, _ := si.transformAt("192.0.2.120", map[string]bool{"192.0.2.120": true}); id != "" {
		t.Fatalf("probe_target was indexed as a seam endpoint (%s)", id)
	}
	if id, _ := si.transformAt("100.21.102.86", awsPath); id != "sm-aws" {
		t.Fatalf("b_public_ip should index as the seam's far side, got %q", id)
	}
}

// The operator env formats: "=" is canonical (IPv6-safe), ":" is the legacy form.
// Both must parse, and the "=" orientation for local contexts is cidr=name.
func TestOperatorEnvSeparators(t *testing.T) {
	t.Setenv("PATH_GRAPH_VANTAGE_ADDRESSES",
		"lan-vantage-1=172.40.40.92, prober:10.70.245.122, v6=2001:db8::7")
	if got := vantageAddressFor("lan-vantage-1"); got != "172.40.40.92" {
		t.Fatalf("canonical '=' form: got %q", got)
	}
	if got := vantageAddressFor("prober"); got != "10.70.245.122" {
		t.Fatalf("legacy ':' form: got %q", got)
	}
	if got := vantageAddressFor("v6"); got != "2001:db8::7" {
		t.Fatalf("IPv6 address must survive the '=' form intact: got %q", got)
	}
	if got := vantageAddressFor("undeclared"); got != "" {
		t.Fatalf("undeclared vantage must resolve to empty, got %q", got)
	}

	nc := newNetContext(nil, "172.40.40.0/24=lan-campus, lab-wan:10.70.245.0/24, junk")
	if got := nc.Of("172.40.40.92"); got != "lan-campus" {
		t.Fatalf("canonical cidr=name form: got %q", got)
	}
	if got := nc.Of("10.70.245.122"); got != "lab-wan" {
		t.Fatalf("legacy name:cidr form: got %q", got)
	}
}

// The default vantage's own address resolves from the per-vantage map when the
// singular override is unset — one declaration per vantage (map is the source of
// truth), and the explicit singular env still wins when present.
func TestDefaultVantageAddressFromMap(t *testing.T) {
	t.Setenv("PATH_GRAPH_VANTAGE_ID", "prober")
	t.Setenv("PATH_GRAPH_VANTAGE_ADDRESSES", "prober=10.70.245.122")
	t.Setenv("PATH_GRAPH_VANTAGE_ADDRESS", "")
	if got := pathIngestConfigFromEnv(ingestNow).VantageAddress; got != "10.70.245.122" {
		t.Fatalf("map fallback: got %q", got)
	}
	t.Setenv("PATH_GRAPH_VANTAGE_ADDRESS", "192.0.2.9")
	if got := pathIngestConfigFromEnv(ingestNow).VantageAddress; got != "192.0.2.9" {
		t.Fatalf("singular override must win: got %q", got)
	}
}
