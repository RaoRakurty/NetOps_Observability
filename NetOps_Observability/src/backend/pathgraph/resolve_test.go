// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package pathgraph

import (
	"testing"
	"time"
)

// resolve_test.go — §3 ranked resolution. The load-bearing assertion is
// TestRank7TokenNeverAuthoritative: token/rDNS/name overlap must NEVER produce an
// entity binding or an authoritative edge, no matter how "obviously" the names match.
// That is the bug the whole contract exists to kill.

var t0 = time.Date(2026, 7, 12, 12, 0, 0, 0, time.UTC)

// liveLabFacts is the verified live path's fact base, tenant "t_a":
// 172.40.40.92 (client) → 172.40.40.1 (LAN gw) → 10.70.245.122 (WAN edge)
// → 10.60.1.10 (AWS NVA) → 10.60.10.10 (app endpoint) → store-api.
func liveLabFacts() PathFacts {
	open := Window{From: t0.Add(-24 * time.Hour)}
	return PathFacts{
		NICBindings: []NICBinding{
			{TenantID: "t_a", Address: "10.60.10.10", NetworkContext: "vpc-04bea9c06ff23abd9",
				ResourceID: "i-0448c046139420a7f", InterfaceID: "eni-01830be2f44b23cb2", Kind: KindAppEndpoint,
				Window: open, EvidenceRef: "cloud_inventory:i-0448c046139420a7f", DataClass: DataClassLive, ObservedAt: t0},
			{TenantID: "t_a", Address: "10.60.1.10", NetworkContext: "vpc-04bea9c06ff23abd9",
				ResourceID: "i-0e8acbf8493d037f9", InterfaceID: "eni-007542c1d61f44947", Kind: KindNVA,
				Window: open, EvidenceRef: "cloud_inventory:i-0e8acbf8493d037f9", DataClass: DataClassLive, ObservedAt: t0},
		},
		InterfaceBindings: []InterfaceBinding{
			{TenantID: "t_a", Address: "172.40.40.1", NetworkContext: "lab-lan", DeviceID: "lan-sw1",
				InterfaceID: "Vlan40", Window: open, EvidenceRef: "if_inventory:lan-sw1:Vlan40", DataClass: DataClassLive, ObservedAt: t0},
			{TenantID: "t_a", Address: "10.70.245.122", NetworkContext: "lab-wan", DeviceID: "wan-edge1",
				InterfaceID: "eth0", Window: open, EvidenceRef: "if_inventory:wan-edge1:eth0", DataClass: DataClassLive, ObservedAt: t0},
		},
		AppBindings: []AppBinding{
			{TenantID: "t_a", Service: "store-api", Address: "10.60.10.10", NetworkContext: "vpc-04bea9c06ff23abd9",
				ResourceRef: "i-0448c046139420a7f", Window: open, EvidenceRef: "app_identity:store-api@10.60.10.10",
				DataClass: DataClassLive, ObservedAt: t0},
		},
		Routes: []RouteRelation{
			{TenantID: "t_a", NetworkContext: "vpc-04bea9c06ff23abd9", FromSubnet: "subnet-01f8d07890ee79e9c",
				Destination: "172.40.40.0/24", ToRef: "10.60.1.10", ToKind: "nva", RouteTable: "correlix-rt-app",
				Window: open, EvidenceRef: "cloud_route:rtb-01f9ab54f8c0360f5:172.40.40.0/24",
				DataClass: DataClassLive, ObservedAt: t0},
		},
		Tokens: []NameToken{
			// The coincidence the old engine would have joined on: the seam's rDNS name
			// and the application both carry "store-api"-ish tokens. It must stay inert.
			{TenantID: "t_a", Token: "store-api", Ref: "seam:sm-f36b592d4e76", NetworkContext: "lab-wan",
				EvidenceRef: "rdns", DataClass: DataClassLive},
		},
	}
}

func TestRankOrderAndAuthority(t *testing.T) {
	f := liveLabFacts()

	// rank 2 — the ENI/NIC inventory binds the app address to the AWS instance.
	got := f.Resolve(Query{TenantID: "t_a", Address: "10.60.10.10", NetworkContext: "vpc-04bea9c06ff23abd9", At: t0})
	if got.Rank != 2 || got.Method != MethodEndpointBinding {
		t.Fatalf("app endpoint: rank=%d method=%s, want rank 2 endpoint_binding", got.Rank, got.Method)
	}
	if got.EntityRef != "i-0448c046139420a7f" || !got.Authoritative || got.Class != ClassObserved {
		t.Fatalf("app endpoint: %+v — want authoritative observed binding to the instance", got)
	}

	// rank 3 — a device interface resolves the LAN gateway hop.
	got = f.Resolve(Query{TenantID: "t_a", Address: "172.40.40.1", NetworkContext: "lab-lan", At: t0})
	if got.Rank != 3 || got.EntityRef != "lan-sw1" || !got.Authoritative {
		t.Fatalf("lan gw: %+v — want rank 3 authoritative lan-sw1", got)
	}

	// rank 1 beats everything when the measurement itself names the resource.
	f.ResourceIdentities = []ResourceIdentity{{
		TenantID: "t_a", ResourceID: "i-0448c046139420a7f", NetworkContext: "vpc-04bea9c06ff23abd9",
		Kind: KindAppEndpoint, Window: Window{From: t0.Add(-time.Hour)}, EvidenceRef: "agent", DataClass: DataClassLive,
	}}
	got = f.Resolve(Query{TenantID: "t_a", Address: "10.60.10.10", NetworkContext: "vpc-04bea9c06ff23abd9",
		DeclaredResourceID: "i-0448c046139420a7f", At: t0})
	if got.Rank != 1 || got.Method != MethodResourceIdentity {
		t.Fatalf("declared resource: rank=%d method=%s, want rank 1", got.Rank, got.Method)
	}
}

// TestRank7TokenNeverAuthoritative is THE regression guard for §10: a shared token
// (or rDNS name) may never bind an entity or create an authoritative edge.
func TestRank7TokenNeverAuthoritative(t *testing.T) {
	f := liveLabFacts()
	// An address nothing observed knows about, whose rDNS name collides with the
	// application's token. The old (token-overlap) model would have joined these.
	got := f.Resolve(Query{
		TenantID: "t_a", Address: "203.0.113.7", NetworkContext: "lab-wan", At: t0,
		Tokens: []string{"store-api"}, Hostname: "store-api",
	})
	if got.Authoritative {
		t.Fatalf("token overlap produced an AUTHORITATIVE resolution: %+v", got)
	}
	if got.EntityRef != "" {
		t.Fatalf("token overlap bound an entity_ref %q — rank 7 must never name an entity", got.EntityRef)
	}
	if got.CandidateRef != "seam:sm-f36b592d4e76" {
		t.Fatalf("candidate_ref = %q, want the token match surfaced as a CANDIDATE lead", got.CandidateRef)
	}
	if got.Rank != 7 || got.Class != ClassCandidate || got.Confidence != ConfCandidate {
		t.Fatalf("token match: rank=%d class=%s conf=%s, want 7/candidate/candidate", got.Rank, got.Class, got.Confidence)
	}
	// The gate itself must agree.
	if Authoritative(MethodTokenSimilarity) || Authoritative(MethodCloudRoute) {
		t.Fatal("Authoritative() admitted rank 6 or 7 — ranks 1–5 only")
	}
	for _, m := range []string{MethodResourceIdentity, MethodEndpointBinding, MethodHopInventory, MethodAppBinding, MethodSessionStitch} {
		if !Authoritative(m) {
			t.Fatalf("Authoritative(%s) = false, want true (ranks 1–5)", m)
		}
	}
}

// TestRank6InferredIsSupportingOnly — a cloud route table explains a hop, it never
// asserts one (§4).
func TestRank6InferredIsSupportingOnly(t *testing.T) {
	f := PathFacts{Routes: liveLabFacts().Routes}
	got := f.Resolve(Query{TenantID: "t_a", Address: "10.60.1.10", NetworkContext: "vpc-04bea9c06ff23abd9", At: t0})
	if got.Authoritative || got.EntityRef != "" {
		t.Fatalf("a route table alone bound an entity: %+v", got)
	}
	if got.Method != MethodUnresolved {
		t.Fatalf("method = %s, want unresolved (route tables cannot resolve an endpoint)", got.Method)
	}
	if len(got.Supporting) != 1 || got.Supporting[0].Class != ClassInferred {
		t.Fatalf("supporting = %+v, want exactly one INFERRED relation", got.Supporting)
	}

	// With the observed rank-2 fact present, the route becomes supporting evidence
	// ON an authoritative resolution — it explains, it does not decide.
	full := liveLabFacts()
	got = full.Resolve(Query{TenantID: "t_a", Address: "10.60.1.10", NetworkContext: "vpc-04bea9c06ff23abd9", At: t0})
	if got.Rank != 2 || got.EntityRef != "i-0e8acbf8493d037f9" {
		t.Fatalf("NVA: %+v — want the observed rank-2 binding to win", got)
	}
	if len(got.Supporting) != 1 {
		t.Fatalf("supporting = %+v, want the route table attached as inferred support", got.Supporting)
	}
}

// TestOverlappingTenantsNeverResolve — §9: the SAME address in two tenants is two
// endpoints and they never join, even with an identical network context name.
func TestOverlappingTenantsNeverResolve(t *testing.T) {
	f := liveLabFacts()
	got := f.Resolve(Query{TenantID: "t_b", Address: "10.60.10.10", NetworkContext: "vpc-04bea9c06ff23abd9", At: t0})
	if got.EntityRef != "" || got.Authoritative {
		t.Fatalf("tenant t_b resolved tenant t_a's address: %+v — CROSS-TENANT LEAK", got)
	}
	// Not even a candidate crosses.
	got = f.Resolve(Query{TenantID: "t_b", Address: "203.0.113.7", NetworkContext: "lab-wan", At: t0,
		Tokens: []string{"store-api"}})
	if got.CandidateRef != "" {
		t.Fatalf("tenant t_b got tenant t_a's token candidate %q", got.CandidateRef)
	}
	// And the service tail does not cross either.
	if tail := f.ServiceOf(Query{TenantID: "t_b", Address: "10.60.10.10", NetworkContext: "vpc-04bea9c06ff23abd9", At: t0}); tail != nil {
		t.Fatalf("tenant t_b resolved tenant t_a's service: %+v", tail)
	}
}

// TestNetworkContextIsRequired — an address without its context is meaningless
// (§2.1/§6.4): the same IP in a different context must not resolve.
func TestNetworkContextMismatchDoesNotResolve(t *testing.T) {
	f := liveLabFacts()
	got := f.Resolve(Query{TenantID: "t_a", Address: "10.60.10.10", NetworkContext: "vpc-OTHER", At: t0})
	if got.EntityRef != "" {
		t.Fatalf("resolved across network contexts: %+v", got)
	}
}

// TestValidityWindow — bindings MOVE. A binding that had closed before the
// observation must not resolve it (§6.2).
func TestValidityWindowBoundsResolution(t *testing.T) {
	closed := t0.Add(-time.Hour)
	f := PathFacts{NICBindings: []NICBinding{{
		TenantID: "t_a", Address: "10.60.10.10", NetworkContext: "vpc-1", ResourceID: "i-old",
		Window: Window{From: t0.Add(-48 * time.Hour), To: &closed}, DataClass: DataClassLive,
	}}}
	if got := f.Resolve(Query{TenantID: "t_a", Address: "10.60.10.10", NetworkContext: "vpc-1", At: t0}); got.EntityRef != "" {
		t.Fatalf("an EXPIRED binding resolved a later observation: %+v", got)
	}
	// …and it still resolves an observation from when it WAS valid.
	if got := f.Resolve(Query{TenantID: "t_a", Address: "10.60.10.10", NetworkContext: "vpc-1", At: t0.Add(-2 * time.Hour)}); got.EntityRef != "i-old" {
		t.Fatalf("a valid-at-the-time binding failed to resolve: %+v", got)
	}
}

// TestNonLiveFactsExcludedByDefault — §1: synthetic/replay/lab never enter a
// customer resolution unless explicitly admitted.
func TestNonLiveFactsExcludedByDefault(t *testing.T) {
	f := PathFacts{NICBindings: []NICBinding{{
		TenantID: "t_a", Address: "10.60.10.10", NetworkContext: "vpc-1", ResourceID: "i-lab",
		Window: Window{From: t0.Add(-time.Hour)}, DataClass: DataClassLab,
	}}}
	if got := f.Resolve(Query{TenantID: "t_a", Address: "10.60.10.10", NetworkContext: "vpc-1", At: t0}); got.EntityRef != "" {
		t.Fatalf("a LAB fact resolved a customer query: %+v", got)
	}
	got := f.Resolve(Query{TenantID: "t_a", Address: "10.60.10.10", NetworkContext: "vpc-1", At: t0, IncludeNonLive: true})
	if got.EntityRef != "i-lab" {
		t.Fatalf("explicit non-live query did not resolve: %+v", got)
	}
}

// TestServiceTailComesFromRank2Or4Only — the app↔endpoint edge is a BINDING, never
// a name match (§10 acceptance).
func TestServiceTailComesFromRank2Or4Only(t *testing.T) {
	f := liveLabFacts()
	tail := f.ServiceOf(Query{TenantID: "t_a", Address: "10.60.10.10", NetworkContext: "vpc-04bea9c06ff23abd9", At: t0})
	if tail == nil {
		t.Fatal("no service tail for the app endpoint")
	}
	if tail.Service != "store-api" || tail.Method != MethodAppBinding || !Authoritative(tail.Method) {
		t.Fatalf("service tail %+v — want store-api via the rank-4 app binding", tail)
	}
	// Remove the rank-4 app binding AND the rank-2 service attribution: the tail must
	// disappear entirely rather than fall back to the name token.
	f.AppBindings = nil
	for i := range f.NICBindings {
		f.NICBindings[i].Service = ""
	}
	if tail := f.ServiceOf(Query{TenantID: "t_a", Address: "10.60.10.10", NetworkContext: "vpc-04bea9c06ff23abd9", At: t0}); tail != nil {
		t.Fatalf("service tail %+v survived without ANY binding — it must come only from rank 2/4", tail)
	}
}

// TestSessionStitchIsRank5 — NAT is explicit, from a session record, never from an
// address coincidence.
func TestSessionStitchIsRank5(t *testing.T) {
	f := PathFacts{
		SessionSourceAvailable: true,
		Sessions: []SessionStitch{{
			TenantID: "t_a", PreAddress: "192.168.5.9", PostAddress: "203.0.113.9", NetworkContext: "lab-wan",
			ResourceRef: "fw-1", Transformation: TransformNAT, Window: Window{From: t0.Add(-time.Hour)},
			EvidenceRef: "session:1", DataClass: DataClassLive, ObservedAt: t0,
		}},
	}
	got := f.Resolve(Query{TenantID: "t_a", Address: "203.0.113.9", NetworkContext: "lab-wan", At: t0})
	if got.Rank != 5 || got.Transformation != TransformNAT || !got.Authoritative {
		t.Fatalf("session stitch: %+v — want an authoritative rank-5 NAT transformation", got)
	}
}
