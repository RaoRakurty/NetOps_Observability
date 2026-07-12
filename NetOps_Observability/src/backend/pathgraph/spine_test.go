package pathgraph

import (
	"testing"
	"time"
)

// spine_test.go — §7/§10. The acceptance case: the live lab path must come back as
// EXACTLY the ordered spine below, with the app↔endpoint edge sourced from a rank-2/4
// binding, every edge stating its evidence, and the boundaries computed server-side.

func labObservation(dataClass string, at time.Time) PathObservation {
	return PathObservation{
		ObservationID: "ob-1", PathID: "pd-1", ObservedAt: at, Method: MethodTracerouteICMP,
		VantageID: "prober-lab", Status: StatusComplete, HopCount: 4, ContractVersion: ContractVersion,
		Provenance: Provenance{TenantID: "t_a", DataClass: dataClass, Environment: "lab",
			RunID: "run-1", ProducerID: "prober-lab", ProvenanceID: "pv-obs"},
	}
}

// labHops is the VERIFIED live path: LAN gw → WAN edge (seam near side) → AWS NVA
// (seam far side) → app endpoint.
func labHops(at time.Time) []PathHop {
	return []PathHop{
		{ObservationID: "ob-1", HopIndex: 1, State: HopResponding, ObservedAddress: "172.40.40.1",
			ResolvedEntityRef: "lan-sw1", ResolutionMethod: MethodHopInventory, Confidence: ConfAuthoritative,
			Kind: KindLANGateway, NetworkContext: "lab-lan", Transformation: TransformNone,
			EvidenceRef: "pv-h1", ObservedAt: at, TenantID: "t_a", DataClass: DataClassLive, RTTms: 1.2},
		{ObservationID: "ob-1", HopIndex: 2, State: HopResponding, ObservedAddress: "10.70.245.122",
			ResolvedEntityRef: "wan-edge1", ResolutionMethod: MethodHopInventory, Confidence: ConfAuthoritative,
			Kind: KindWANEdge, NetworkContext: "lab-wan", SeamID: "sm-f36b592d4e76",
			Transformation: TransformTunnelIngress, EvidenceRef: "pv-h2", ObservedAt: at,
			TenantID: "t_a", DataClass: DataClassLive, RTTms: 3.8},
		{ObservationID: "ob-1", HopIndex: 3, State: HopResponding, ObservedAddress: "10.60.1.10",
			ResolvedEntityRef: "i-0e8acbf8493d037f9", ResolutionMethod: MethodEndpointBinding,
			Confidence: ConfAuthoritative, Kind: KindNVA, NetworkContext: "vpc-04bea9c06ff23abd9",
			SeamID: "sm-f36b592d4e76", Transformation: TransformTunnelEgress, EvidenceRef: "pv-h3",
			ObservedAt: at, TenantID: "t_a", DataClass: DataClassLive, RTTms: 24.1},
		{ObservationID: "ob-1", HopIndex: 4, State: HopResponding, ObservedAddress: "10.60.10.10",
			ResolvedEntityRef: "i-0448c046139420a7f", ResolutionMethod: MethodEndpointBinding,
			Confidence: ConfAuthoritative, Kind: KindAppEndpoint, NetworkContext: "vpc-04bea9c06ff23abd9",
			Transformation: TransformNone, EvidenceRef: "pv-h4", ObservedAt: at,
			TenantID: "t_a", DataClass: DataClassLive, RTTms: 25.0},
	}
}

func labSpineInput(now time.Time) SpineInput {
	at := now.Add(-time.Minute)
	return SpineInput{
		CorrelationID: "c-1",
		Observation:   labObservation(DataClassLive, at),
		Hops:          labHops(at),
		Client: Endpoint{
			EndpointID: "ep-client", Address: "172.40.40.92", NetworkContext: "lab-lan", Kind: KindClient,
			ResolvedEntityRef: "host-lan-92", ResolutionMethod: MethodEndpointBinding, Confidence: ConfAuthoritative,
			EvidenceRef: "pv-client",
		},
		Service: &ServiceTail{
			Service: "store-api", EntityRef: "i-0448c046139420a7f", Method: MethodAppBinding,
			Confidence: ConfStrong, EvidenceRef: "app_identity:store-api@10.60.10.10",
			ObservedAt: at, DataClass: DataClassLive,
		},
		Supporting: map[int][]SupportingRel{
			3: {{Method: MethodCloudRoute, Class: ClassInferred, Ref: "10.60.1.10", ToKind: "nva",
				Destination: "172.40.40.0/24", RouteTable: "correlix-rt-app", EvidenceRef: "cloud_route:1",
				DataClass: DataClassLive, Confidence: ConfStrong}},
		},
		SessionSourceAvailable: false,
		Now:                    now,
		Freshness:              15 * time.Minute,
	}
}

// TestAcceptanceSpine — §10, the primary acceptance case.
func TestAcceptanceSpine(t *testing.T) {
	now := time.Date(2026, 7, 12, 12, 0, 0, 0, time.UTC)
	sp := BuildSpine(labSpineInput(now))

	want := []struct{ kind, addr, boundary string }{
		{KindClient, "172.40.40.92", "LAN"},
		{KindLANGateway, "172.40.40.1", "LAN"},
		{KindWANEdge, "10.70.245.122", "SD-WAN"},
		{KindNVA, "10.60.1.10", "CLOUD"},
		{KindAppEndpoint, "10.60.10.10", "CLOUD"},
		{KindApplication, "", "CLOUD"},
	}
	if len(sp.Spine) != len(want) {
		t.Fatalf("spine has %d nodes, want %d: %+v", len(sp.Spine), len(want), sp.Spine)
	}
	for i, w := range want {
		got := sp.Spine[i]
		if got.Index != i {
			t.Fatalf("node %d has index %d — the ORDER is data, not layout", i, got.Index)
		}
		if got.Kind != w.kind || got.Address != w.addr || got.Boundary != w.boundary {
			t.Fatalf("node %d = {%s %s %s}, want {%s %s %s}", i, got.Kind, got.Address, got.Boundary, w.kind, w.addr, w.boundary)
		}
		if got.Evidence.Ref == "" || got.Evidence.Method == "" || got.Evidence.DataClass == "" {
			t.Fatalf("node %d cannot state its evidence: %+v", i, got.Evidence)
		}
	}

	// The application tail must be reachable ONLY through the rank-2/4 binding.
	app := sp.Spine[5]
	if app.Label != "store-api" || app.Evidence.Method != MethodAppBinding {
		t.Fatalf("application node %+v — the app↔endpoint edge must come from rank 2/4", app)
	}
	if !Authoritative(app.Evidence.Method) {
		t.Fatalf("application node evidence method %s is not authoritative", app.Evidence.Method)
	}

	// Boundaries — computed SERVER-SIDE, exactly the §7 shape.
	wantB := []Boundary{
		{Name: "LAN", From: 0, To: 1},
		{Name: "SD-WAN", From: 2, To: 2},
		{Name: "CARRIER", From: 2, To: 3},
		{Name: "CLOUD", From: 3, To: 5},
	}
	if len(sp.Boundaries) != len(wantB) {
		t.Fatalf("boundaries = %+v, want %+v", sp.Boundaries, wantB)
	}
	for i, b := range wantB {
		if sp.Boundaries[i] != b {
			t.Fatalf("boundary %d = %+v, want %+v", i, sp.Boundaries[i], b)
		}
	}

	// Edges: 5 consecutive, the seam crossing typed and transformed, the app edge
	// typed as SERVICE_EXPOSED_BY_ENDPOINT, and EVERY edge stating its evidence.
	if len(sp.Edges) != 5 {
		t.Fatalf("edges = %d, want 5: %+v", len(sp.Edges), sp.Edges)
	}
	seam := sp.Edges[2]
	if seam.From != 2 || seam.To != 3 || seam.Type != EdgeCrossesSeam ||
		seam.SeamID != "sm-f36b592d4e76" || seam.Transformation != TransformTunnelIngress {
		t.Fatalf("seam edge = %+v, want 2→3 CROSSES_SEAM sm-f36b592d4e76 tunnel_ingress", seam)
	}
	// EXACTLY ONE crossing: the LAN-gateway→WAN-edge edge changes boundary LABEL
	// (LAN → SD-WAN) but crosses no ownership seam — both ends are ours. Typing it as
	// a seam crossing would claim a tunnel that does not exist.
	crossings := 0
	for _, e := range sp.Edges {
		if e.Type == EdgeCrossesSeam {
			crossings++
		}
	}
	if crossings != 1 {
		t.Fatalf("%d CROSSES_SEAM edges, want exactly 1 (only the WAN-edge→NVA hop crosses the VPN seam): %+v",
			crossings, sp.Edges)
	}
	if sp.Edges[1].Type != EdgePathHasHop {
		t.Fatalf("edge 1→2 = %s, want PATH_HAS_HOP (adjacent to a seam member is not a crossing)", sp.Edges[1].Type)
	}
	appEdge := sp.Edges[4]
	if appEdge.Type != EdgeServiceExposedBy || appEdge.Evidence.Method != MethodAppBinding {
		t.Fatalf("app edge = %+v, want SERVICE_EXPOSED_BY_ENDPOINT with a rank-4 evidence method", appEdge)
	}
	for i, e := range sp.Edges {
		if e.Evidence.Ref == "" || e.Evidence.Confidence == "" || e.Evidence.ObservedAt == "" || e.Evidence.DataClass == "" {
			t.Fatalf("edge %d cannot state its evidence: %+v", i, e)
		}
	}

	// A fresh, live observation anchors a live verdict.
	if !sp.AnchorsLive || sp.Stale {
		t.Fatalf("fresh live observation: stale=%v anchors=%v", sp.Stale, sp.AnchorsLive)
	}
	// The inferred cloud route rides as SUPPORT, off the spine, never as an edge.
	sup := 0
	for _, b := range sp.EvidenceBranches {
		if b.Type == EdgeEvidenceSupports && b.Class == ClassInferred {
			sup++
		}
	}
	if sup != 1 {
		t.Fatalf("inferred cloud-route support branches = %d, want 1", sup)
	}
	for _, e := range sp.Edges {
		if e.Evidence.Method == MethodCloudRoute || e.Evidence.Method == MethodTokenSimilarity {
			t.Fatalf("an INFERRED/CANDIDATE method produced a spine edge: %+v", e)
		}
	}
}

// TestMissingHopPreserved — §8: a non-responding hop is an explicit unknown segment,
// never dropped and never bridged.
func TestMissingHopPreserved(t *testing.T) {
	now := time.Date(2026, 7, 12, 12, 0, 0, 0, time.UTC)
	in := labSpineInput(now)
	at := in.Observation.ObservedAt
	// The carrier hop goes dark.
	in.Hops = []PathHop{
		in.Hops[0],
		{ObservationID: "ob-1", HopIndex: 2, State: HopMissing, ResolutionMethod: MethodUnresolved,
			Confidence: ConfUnknown, Kind: KindUnknown, Transformation: TransformNone,
			EvidenceRef: "pv-h2", ObservedAt: at, TenantID: "t_a", DataClass: DataClassLive},
		in.Hops[3],
	}
	in.Service = nil
	sp := BuildSpine(in)

	if len(sp.Spine) != 4 {
		t.Fatalf("spine dropped a hop: %d nodes, want 4 (client + 3 hops)", len(sp.Spine))
	}
	gap := sp.Spine[2]
	if gap.State != HopMissing || gap.Address != "" || gap.Kind != KindUnknown || gap.EntityRef != "" {
		t.Fatalf("missing hop rendered as %+v — must be an addressless, unresolved, explicit unknown", gap)
	}
	found := false
	for _, b := range sp.EvidenceBranches {
		if b.Type == EdgeEvidenceMissing && b.Index == 2 {
			found = true
		}
	}
	if !found {
		t.Fatal("a missing hop produced no EVIDENCE_MISSING branch — an honest absence IS an edge (§5)")
	}
}

// TestStaleObservationCannotAnchorLiveVerdict — §8.
func TestStaleObservationCannotAnchorLiveVerdict(t *testing.T) {
	now := time.Date(2026, 7, 12, 12, 0, 0, 0, time.UTC)
	in := labSpineInput(now)
	in.Observation.ObservedAt = now.Add(-2 * time.Hour) // well outside the freshness window
	sp := BuildSpine(in)
	if !sp.Stale || sp.AnchorsLive {
		t.Fatalf("stale=%v anchors_live_verdict=%v — a stale observation must not anchor a live verdict", sp.Stale, sp.AnchorsLive)
	}
}

// TestNonLiveObservationCannotAnchorLiveVerdict — §1: synthetic/replay/lab evidence
// may support or illustrate, never confirm.
func TestNonLiveObservationCannotAnchorLiveVerdict(t *testing.T) {
	now := time.Date(2026, 7, 12, 12, 0, 0, 0, time.UTC)
	for _, dc := range []string{DataClassSynthetic, DataClassReplay, DataClassLab} {
		in := labSpineInput(now)
		in.Observation.DataClass = dc
		sp := BuildSpine(in)
		if sp.AnchorsLive {
			t.Fatalf("data_class=%s anchored a live verdict", dc)
		}
	}
}

// TestUnresolvedHopStaysUnknown — §8: never guessed.
func TestUnresolvedHopStaysUnknown(t *testing.T) {
	now := time.Date(2026, 7, 12, 12, 0, 0, 0, time.UTC)
	in := labSpineInput(now)
	at := in.Observation.ObservedAt
	in.Hops = []PathHop{{
		ObservationID: "ob-1", HopIndex: 1, State: HopResponding, ObservedAddress: "203.0.113.7",
		ResolutionMethod: MethodTokenSimilarity, Confidence: ConfCandidate, CandidateRef: "seam:sm-f36b592d4e76",
		Kind: KindUnknown, Transformation: TransformNone, EvidenceRef: "pv-x", ObservedAt: at,
		TenantID: "t_a", DataClass: DataClassLive,
	}}
	in.Service = nil
	sp := BuildSpine(in)
	n := sp.Spine[1]
	if n.EntityRef != "" || n.Kind != KindUnknown {
		t.Fatalf("a rank-7 candidate hop resolved to %+v — it must stay unknown", n)
	}
	if n.CandidateRef == "" {
		t.Fatal("the candidate lead was hidden; it should be shown, labelled, and unusable as an edge")
	}
	for _, e := range sp.Edges {
		if e.Evidence.Method == MethodTokenSimilarity {
			t.Fatalf("a candidate produced an edge: %+v", e)
		}
	}
}
