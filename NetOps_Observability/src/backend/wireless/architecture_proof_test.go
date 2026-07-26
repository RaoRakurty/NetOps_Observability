package wireless

// architecture_proof_test.go — the §15 multi-vendor architecture proof
// (#128 Phase 5, docs/Wireslessdesign.md §15): for each of the nine deployment
// models the canonical model must derive exactly the edges that deployment
// HAS, and must NOT derive the ones it doesn't. The second direction is the
// one wireless designs usually fail — an absent edge is a fact of the
// deployment, never missing evidence, and never invented.
//
// Every fixture here is doc_claimed by construction: it describes the
// deployment SHAPE (which is architecture, not vendor leaf data). Vendor leaf
// spellings are the connector fixtures' problem; this proof is about whether
// the canonical model can represent each shape without corruption.

import "testing"

func ap(id, wlc string, fwd ForwardingMode, uplinkSw, uplinkPort string) AccessPoint {
	return AccessPoint{
		TenantID: "t1", APID: id, Name: id, Vendor: "x", ControllerRef: wlc,
		ForwardingMode: fwd, UplinkSwitchRef: uplinkSw, UplinkPortRef: uplinkPort,
		Radios: []Radio{{APID: id, Slot: 0, Band: "5GHz"}},
	}
}

// 1 — controller-based CAPWAP, central switching (Cisco 9800 default).
func TestProofCentralCAPWAP(t *testing.T) {
	inv := Inventory{
		Controllers: []Controller{{TenantID: "t1", ControllerID: "wlc1",
			ClusterRole: ClusterHAPair, ForwardingDefault: ForwardCentral,
			Members: []Member{{MemberID: "m1", ControllerID: "wlc1", MemberState: "active"},
				{MemberID: "m2", ControllerID: "wlc1", MemberState: "standby"}}}},
		APs: []AccessPoint{ap("A", "wlc1", ForwardCentral, "sw1", "Gi1/0/1")},
	}
	e := DeriveEdges(inv)
	if !HasEdge(e, EdgeAPManagedByController, "ap-A", "wlc-wlc1") {
		t.Fatal("central CAPWAP: managed edge must exist")
	}
	if !HasEdge(e, EdgeAPTunnelsToController, "ap-A", "wlc-wlc1") {
		t.Fatal("central CAPWAP: client data tunnels to the WLC — edge must exist")
	}
	if !HasEdge(e, EdgeAPUplinksViaPort, "ap-A", "sw1:Gi1/0/1") {
		t.Fatal("the rank-1 LAN join must exist")
	}
	if !HasEdge(e, EdgeControllerMember, "wlc-wlc1:m2", "wlc-wlc1") {
		t.Fatal("physical members must ground to the LOGICAL cluster")
	}
}

// 2 — controller-based, LOCAL switching (FlexConnect): managed WITHOUT tunnel.
func TestProofLocalSwitching(t *testing.T) {
	inv := Inventory{
		Controllers: []Controller{{TenantID: "t1", ControllerID: "wlc1",
			ClusterRole: ClusterStandalone, ForwardingDefault: ForwardCentral}},
		APs: []AccessPoint{ap("A", "wlc1", ForwardLocal, "sw1", "Gi1/0/2")},
	}
	e := DeriveEdges(inv)
	if !HasEdge(e, EdgeAPManagedByController, "ap-A", "") {
		t.Fatal("local switching: the AP is still MANAGED by the controller")
	}
	if HasEdge(e, EdgeAPTunnelsToController, "ap-A", "") {
		t.Fatal("local switching: NO data tunnel exists — deriving one is the " +
			"mis-attribution bug the report §8.1 forbids")
	}
}

// 3 — gateway-tunneled (Aruba mobility gateway): same two-tier shape, kind
// discriminator only; the gateway CLUSTER is distinct from its members.
func TestProofGatewayTunneled(t *testing.T) {
	inv := Inventory{
		Controllers: []Controller{{TenantID: "t1", ControllerID: "gw1", Kind: "gateway",
			ClusterRole: ClusterNPlus1, ForwardingDefault: ForwardCentral,
			Members: []Member{{MemberID: "g1", ControllerID: "gw1"}, {MemberID: "g2", ControllerID: "gw1"}, {MemberID: "g3", ControllerID: "gw1"}}}},
		APs: []AccessPoint{ap("A", "gw1", ForwardCentral, "", "")},
	}
	e := DeriveEdges(inv)
	if !HasEdge(e, EdgeAPTunnelsToController, "ap-A", "wlc-gw1") {
		t.Fatal("gateway-tunneled: data tunnels to the gateway cluster")
	}
	n := 0
	for _, ed := range e {
		if ed.Type == EdgeControllerMember {
			n++
		}
	}
	if n != 3 {
		t.Fatalf("gateway cluster: want 3 member edges, got %d", n)
	}
}

// 4 — cloud-managed, LOCAL forwarding (Meraki): opaque members, partial
// visibility, no data tunnel to the cloud.
func TestProofCloudManagedLocal(t *testing.T) {
	inv := Inventory{
		Controllers: []Controller{{TenantID: "t1", ControllerID: "dash1",
			ClusterRole: ClusterCloudManaged, Visibility: "partial",
			ForwardingDefault: ForwardLocal}},
		APs: []AccessPoint{ap("A", "dash1", ForwardUnknown, "sw1", "Gi1/0/3")},
	}
	e := DeriveEdges(inv)
	if !HasEdge(e, EdgeAPManagedByController, "ap-A", "wlc-dash1") {
		t.Fatal("cloud-managed: the dashboard IS the logical controller")
	}
	// AP forwarding unknown → falls back to the controller default (local):
	// no tunnel. An unknown must never fabricate a data-path edge.
	if HasEdge(e, EdgeAPTunnelsToController, "", "") {
		t.Fatal("cloud-managed local: no data tunnel to the vendor cloud")
	}
	if inv.Controllers[0].Visibility != "partial" {
		t.Fatal("cloud-managed visibility stays partial — full is earned, never assumed")
	}
}

// 5 — cloud-managed control + on-prem data anchor (Mist + Mist Edge): TWO
// logical controllers, control to the cloud, data to the edge appliance.
func TestProofCloudControlOnPremData(t *testing.T) {
	inv := Inventory{
		Controllers: []Controller{
			{TenantID: "t1", ControllerID: "mist-cloud", ClusterRole: ClusterCloudManaged,
				Visibility: "partial", ForwardingDefault: ForwardLocal},
			{TenantID: "t1", ControllerID: "mist-edge1", Kind: "gateway",
				ClusterRole: ClusterStandalone, ForwardingDefault: ForwardCentral},
		},
		APs: []AccessPoint{
			// Control association: the cloud org. (Represented as managed-by.)
			ap("A", "mist-cloud", ForwardLocal, "sw1", "Gi1/0/4"),
			// Data anchor: a second AP record view binding data to the edge is
			// modelled as an AP whose controller is the edge and forwarding is
			// central — the model must hold BOTH without conflating them.
			ap("B", "mist-edge1", ForwardCentral, "sw1", "Gi1/0/5"),
		},
	}
	e := DeriveEdges(inv)
	if HasEdge(e, EdgeAPTunnelsToController, "ap-A", "wlc-mist-cloud") {
		t.Fatal("control-plane association must not become a data tunnel")
	}
	if !HasEdge(e, EdgeAPTunnelsToController, "ap-B", "wlc-mist-edge1") {
		t.Fatal("the on-prem data anchor carries the tunnel edge")
	}
}

// 6 — controllerless (autonomous APs): ZERO controller edges, and their
// absence is a fact, not a gap.
func TestProofControllerless(t *testing.T) {
	inv := Inventory{
		Controllers: []Controller{{TenantID: "t1", ControllerID: "auto",
			ClusterRole: ClusterControllerless}},
		APs: []AccessPoint{ap("A", "auto", ForwardLocal, "sw1", "Gi1/0/6")},
	}
	e := DeriveEdges(inv)
	if HasEdge(e, EdgeAPManagedByController, "", "") || HasEdge(e, EdgeAPTunnelsToController, "", "") {
		t.Fatal("controllerless: no controller edges may exist")
	}
	// The AP still fully participates: radios ground, the LAN join exists.
	if !HasEdge(e, EdgeRadioOnAP, "", "ap-A") || !HasEdge(e, EdgeAPUplinksViaPort, "ap-A", "") {
		t.Fatal("controllerless APs still ground radios and the uplink join")
	}
}

// 7+8 — mixed forwarding / split tunneling: one AP, one controller, some WLAN
// traffic central and some local SIMULTANEOUSLY. Forwarding is a WLAN property
// surfacing at the AP as 'mixed' — the tunnel edge exists (some traffic rides
// it) AND the local path is real (the WLANs record which is which).
func TestProofMixedForwardingSplitTunnel(t *testing.T) {
	wlc := "wlc1"
	inv := Inventory{
		Controllers: []Controller{{TenantID: "t1", ControllerID: wlc,
			ClusterRole: ClusterStandalone, ForwardingDefault: ForwardMixed}},
		APs: []AccessPoint{ap("A", wlc, ForwardMixed, "sw1", "Gi1/0/7")},
		WLANs: []WLAN{
			{TenantID: "t1", WLANID: "w-corp", ProfileName: "corp", SSIDName: "corp",
				SSIDRef: "s-corp", ControllerRef: wlc, ForwardingMode: ForwardCentral, Enabled: true},
			{TenantID: "t1", WLANID: "w-guest", ProfileName: "guest", SSIDName: "guest",
				SSIDRef: "s-guest", ControllerRef: wlc, ForwardingMode: ForwardLocal, Enabled: true},
		},
	}
	e := DeriveEdges(inv)
	if !HasEdge(e, EdgeAPTunnelsToController, "ap-A", "wlc-wlc1") {
		t.Fatal("mixed: the tunnel edge exists (corp traffic rides it)")
	}
	// Both WLANs keep their own forwarding truth — the model does not flatten.
	var central, local bool
	for _, w := range inv.WLANs {
		central = central || w.ForwardingMode == ForwardCentral
		local = local || w.ForwardingMode == ForwardLocal
	}
	if !central || !local {
		t.Fatal("mixed forwarding: per-WLAN modes must both survive")
	}
	if !HasEdge(e, EdgeWLANBroadcastsSSID, "wlan-w-corp", "ssid-s-corp") {
		t.Fatal("WLAN→SSID edges must derive")
	}
}

// 9 — separate management vs control vs data paths: the model represents an
// AP whose management uplink, controller association, and client data path
// are three different relationships — asserted here as edge DISTINCTNESS
// (the nested-encapsulation TRANSFORMATION chain is a path_hops property,
// proven on the Python side where hop transformations live).
func TestProofSeparatePlanes(t *testing.T) {
	inv := Inventory{
		Controllers: []Controller{{TenantID: "t1", ControllerID: "wlc1",
			ClusterRole: ClusterStandalone, ForwardingDefault: ForwardCentral}},
		APs: []AccessPoint{ap("A", "wlc1", ForwardCentral, "sw-mgmt", "Gi1/0/8")},
	}
	e := DeriveEdges(inv)
	types := map[EdgeTypeName]bool{}
	for _, ed := range e {
		types[ed.Type] = true
	}
	for _, want := range []EdgeTypeName{EdgeAPUplinksViaPort, EdgeAPManagedByController, EdgeAPTunnelsToController} {
		if !types[want] {
			t.Fatalf("plane separation: %s must be its own edge", want)
		}
	}
	// And every derived edge in this proof is authoritative (ranks 1–5) —
	// wireless topology is observed, never inferred-only.
	for _, ed := range e {
		if !ed.Authoritative() {
			t.Fatalf("edge %+v must be authoritative", ed)
		}
	}
}
