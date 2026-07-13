package cloud

import "testing"

// Truthfulness/cloud-correlation: a route's next-hop role beats the generic
// "instance" node label — an NVA must never render as an app endpoint.
func TestNodeKindOfRouteRoleBeatsGenericInstance(t *testing.T) {
	topo := Topology{
		Nodes: []TopoNode{{ID: "i-nva", Kind: "instance", PrivateIP: "10.60.1.10"}},
		Edges: []TopoEdge{{To: "i-nva", ToKind: "nva"}},
	}
	if k := topo.NodeKindOf("i-nva"); k != "nva" {
		t.Fatalf("kind = %q, want nva (route role wins over generic instance)", k)
	}
	if k := topo.NodeKindOf("10.60.1.10"); k != "nva" {
		t.Fatalf("by-ip kind = %q, want nva", k)
	}
	// a SPECIFIC node kind still wins outright
	topo.Nodes[0].Kind = "nat_gateway"
	if k := topo.NodeKindOf("i-nva"); k != "nat_gateway" {
		t.Fatalf("specific node kind must win, got %q", k)
	}
}
