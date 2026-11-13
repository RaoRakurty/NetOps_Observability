// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package topology

import (
	"fmt"
	"strings"
	"testing"

	"netops/backend/collectors"
)

func pairsOf(ps ...string) [][2]string {
	var out [][2]string
	for _, p := range ps {
		ab := strings.SplitN(p, "-", 2)
		out = append(out, [2]string{ab[0], ab[1]})
	}
	return out
}

func TestOverlayShape(t *testing.T) {
	// Full mesh of 4 sites, 2 of them dual-edge: every cross-site pair holds
	// tunnels; the same-site pairs (a1-a2, b1-b2) do not and are not counted.
	members := []string{"a1", "a2", "b1", "b2", "c", "d"}
	site := map[string]string{"a1": "A", "a2": "A", "b1": "B", "b2": "B", "c": "C", "d": "D"}
	var all [][2]string
	for i := range members {
		for j := i + 1; j < len(members); j++ {
			if site[members[i]] != site[members[j]] {
				all = append(all, [2]string{members[i], members[j]})
			}
		}
	}
	if s, possible, _ := OverlayShape(members, all, site); s != ShapeFullMesh || possible != 13 {
		t.Errorf("full mesh: shape=%s possible=%d", s, possible)
	}

	// Hub and spoke: two hubs, every spoke to both hubs, no spoke-spoke.
	hm := []string{"h1", "h2", "s1", "s2", "s3", "s4", "s5"}
	hp := pairsOf("h1-h2", "h1-s1", "h1-s2", "h1-s3", "h1-s4", "h1-s5", "h2-s1", "h2-s2", "h2-s3", "h2-s4", "h2-s5")
	s, _, hubs := OverlayShape(hm, hp, nil)
	if s != ShapeHubAndSpoke || strings.Join(hubs, ",") != "h1,h2" {
		t.Errorf("hub and spoke: shape=%s hubs=%v", s, hubs)
	}

	// Partial mesh: a chain.
	if s, _, _ := OverlayShape([]string{"a", "b", "c", "d", "e"}, pairsOf("a-b", "b-c", "c-d", "d-e"), nil); s != ShapePartialMesh {
		t.Errorf("chain: shape=%s", s)
	}
	// Too few members, or only same-site members: unknown, never a guess.
	if s, _, _ := OverlayShape([]string{"a"}, nil, nil); s != ShapeUnknown {
		t.Errorf("one member: %s", s)
	}
	if s, _, _ := OverlayShape([]string{"a", "b"}, nil, map[string]string{"a": "X", "b": "X"}); s != ShapeUnknown {
		t.Errorf("one site: %s", s)
	}
}

// OverlayPairs folds both ends' reports into one pair and never pairs a device
// with one outside the caller's set (another tenant's, or one it cannot see).
func TestOverlayPairsAreTheCallersOwn(t *testing.T) {
	cp := func(l, r string, n, up int) collectors.OverlayColorPairs {
		return collectors.OverlayColorPairs{LocalColor: l, RemoteColor: r, Sessions: n, Up: up}
	}
	facts := map[string]collectors.OverlayDeviceFacts{
		"e1": {Peers: []collectors.OverlayPeer{
			{SystemIP: "1.1.1.2", ColorPairs: []collectors.OverlayColorPairs{cp("mpls", "mpls", 1, 1), cp("biz-internet", "biz-internet", 1, 0)}},
			{SystemIP: "9.9.9.9", ColorPairs: []collectors.OverlayColorPairs{cp("mpls", "mpls", 1, 1)}}, // another tenant's edge
		}},
		"e2": {Peers: []collectors.OverlayPeer{{SystemIP: "1.1.1.1", ColorPairs: []collectors.OverlayColorPairs{cp("mpls", "mpls", 1, 1)}}}},
		"x1": {Peers: []collectors.OverlayPeer{{SystemIP: "1.1.1.1", ColorPairs: []collectors.OverlayColorPairs{cp("mpls", "mpls", 1, 1)}}}},
	}
	sys := map[string]map[string]string{
		"t-a": {"1.1.1.1": "e1", "1.1.1.2": "e2"},
		"t-b": {"9.9.9.9": "x1"},
	}
	got := OverlayPairs(facts, sys, map[string]string{"e1": "t-a", "e2": "t-a"})
	if len(got) != 1 {
		t.Fatalf("want exactly the one t-a pair, got %+v", got)
	}
	p := got[0]
	if p.A != "e1" || p.B != "e2" || p.Sessions != 3 || p.Up != 2 || strings.Join(p.Colors, ",") != "biz-internet,mpls" {
		t.Fatalf("pair fold: %+v", p)
	}
	// A device the caller cannot see is not paired even when it is in the facts.
	if got := OverlayPairs(facts, sys, map[string]string{"e1": "t-a"}); len(got) != 0 {
		t.Fatalf("a pair with an invisible end must not appear: %+v", got)
	}
}

func labView() (View, []OverlayPair) {
	v := View{Nodes: []Node{
		{ID: "ve51", Label: "vEdge-51", Kind: KindRouter, DeviceRole: DevRoleWANEdge, RoleConfidence: "strong", Vendor: "cisco", Model: "vedge-cloud", Site: "SD-WAN site 50", Health: HealthOK, MgmtIP: "192.168.222.102"},
		{ID: "ve52", Label: "vEdge-52", Kind: KindRouter, DeviceRole: DevRoleWANEdge, Site: "SD-WAN site 50", MgmtIP: "192.168.222.103"},
		{ID: "ce80", Label: "cEdge-80", Kind: KindRouter, DeviceRole: DevRoleWANEdge, Site: "SD-WAN site 80"},
		{ID: "ce20", Label: "10.9.9.9", Kind: KindRouter, DeviceRole: DevRoleWANEdge, Site: "SD-WAN site 20"}, // unnamed: label is its address
		{ID: TransportNodeID("t-a", "mpls"), Label: "WAN transport · mpls", Kind: KindWAN, Health: HealthOK,
			Metrics: map[string]float64{"members": 4, "sessions": 10, "sessions_up": 10}, Tags: map[string]string{"color": "mpls"}},
		{ID: "ext:isp-pe", Label: "isp-pe", Kind: KindUnresolved},
	}, Edges: []Edge{
		{Source: "ce80", Target: "ext:isp-pe", SourcePort: "Gi1", TargetPort: "10.0.0.1", Relationship: RelConnectedTo, Protocol: "lldp", Status: StatusUp},
		{Source: "ve51", Target: TransportNodeID("t-a", "mpls"), Relationship: RelInferred},
	}, Degraded: []string{"SD-WAN overlay 7 min old"}}
	pairs := []OverlayPair{
		{A: "ce20", B: "ce80", Colors: []string{"mpls"}, Sessions: 2, Up: 2},
		{A: "ce20", B: "ve51", Colors: []string{"mpls"}, Sessions: 2, Up: 2},
		{A: "ce20", B: "ve52", Colors: []string{"mpls"}, Sessions: 2, Up: 1},
		{A: "ce80", B: "ve51", Colors: []string{"mpls"}, Sessions: 2, Up: 2},
		{A: "ce80", B: "ve52", Colors: []string{"mpls"}, Sessions: 2, Up: 2},
		{A: "ve51", B: "zz-invisible", Sessions: 2, Up: 2}, // an end outside the view
	}
	return v, pairs
}

func TestSummarizeReadsTheLabInNetworkTerms(t *testing.T) {
	v, pairs := labView()
	sm := Summarize(SummaryInput{View: v, Pairs: pairs, OverlayRead: true})
	if !sm.Collected || sm.DevicesTotal != 4 {
		t.Fatalf("devices: collected=%v total=%d", sm.Collected, sm.DevicesTotal)
	}
	ov := sm.Overlay
	if ov == nil || ov.Shape != ShapeFullMesh || ov.Members != 4 || ov.Pairs != 5 || ov.PossiblePairs != 5 {
		t.Fatalf("overlay: %+v", ov)
	}
	if len(ov.Missing) != 0 || len(ov.SameSiteNoTunnel) != 1 || ov.SameSiteNoTunnel[0].A != "vEdge-51" || ov.SameSiteNoTunnel[0].Site != "SD-WAN site 50" {
		t.Fatalf("the same-site pair is expected, not a gap: missing=%+v same=%+v", ov.Missing, ov.SameSiteNoTunnel)
	}
	if ov.NotUpTotal != 1 || ov.NotUp[0].Status != StatusDegraded {
		t.Fatalf("not-up pairs: %+v", ov.NotUp)
	}
	if len(ov.Transports) != 1 || ov.Transports[0].Name != "mpls" || ov.Transports[0].Up != 10 {
		t.Fatalf("transports: %+v", ov.Transports)
	}
	if sm.LinksTotal != 1 || sm.External != 1 || !sm.Links[0].External || sm.Links[0].BPort != "" || sm.Links[0].B != "isp-pe" {
		t.Fatalf("links (the address-valued port must be dropped): %+v", sm.Links)
	}
	if len(sm.RoleNotes) != 1 || !strings.Contains(sm.RoleNotes[0].Likely, "SD-WAN edge") {
		t.Fatalf("role notes: %+v", sm.RoleNotes)
	}
	if len(sm.Notes) != 1 {
		t.Fatalf("the view's degradations must travel: %v", sm.Notes)
	}
	dump := fmt.Sprintf("%+v", sm)
	for _, addr := range []string{"192.168.222.102", "192.168.222.103", "10.9.9.9", "10.0.0.1"} {
		if strings.Contains(dump, addr) {
			t.Fatalf("a management/interface address reached the summary: %s", addr)
		}
	}
	if !strings.Contains(dump, "unnamed device 1") {
		t.Fatalf("an address-labelled device must be renamed: %s", dump)
	}
}

func TestSummarizeEmptyIsNotCollected(t *testing.T) {
	sm := Summarize(SummaryInput{})
	if sm.Collected || sm.Overlay != nil || sm.DevicesTotal != 0 {
		t.Fatalf("an empty view is not collected: %+v", sm)
	}
}

// Multi-vendor: a leaf-spine fabric from LLDP, no SD-WAN — no vendor keyed
// anywhere, and no overlay invented.
func TestSummarizeLeafSpineFabric(t *testing.T) {
	v := View{Nodes: []Node{
		{ID: "s1", Label: "spine-1", Kind: KindSwitch, DeviceRole: DevRoleDCSpine, Vendor: "arista"},
		{ID: "l1", Label: "leaf-1", Kind: KindSwitch, DeviceRole: DevRoleDCLeaf, Vendor: "juniper"},
		{ID: "l2", Label: "leaf-2", Kind: KindSwitch, DeviceRole: DevRoleDCLeaf, Vendor: "nokia"},
	}, Edges: []Edge{
		{Source: "l1", Target: "s1", Relationship: RelConnectedTo, Protocol: "lldp", Status: StatusUp},
		{Source: "l2", Target: "s1", Relationship: RelRoutedAdjacency, Protocol: "bgp_ls", Status: StatusUp},
	}}
	sm := Summarize(SummaryInput{View: v, OverlayRead: true})
	if sm.Overlay != nil {
		t.Fatalf("no overlay pairs → no overlay: %+v", sm.Overlay)
	}
	if sm.LinksTotal != 2 || len(sm.LinkProtocols) != 2 || sm.External != 0 {
		t.Fatalf("links: %+v protos=%+v", sm.Links, sm.LinkProtocols)
	}
	if sm.Devices[0].Name != "spine-1" || sm.Devices[0].Adjacencies != 2 {
		t.Fatalf("spine first with both adjacencies: %+v", sm.Devices)
	}
	if len(sm.RoleNotes) != 2 || !strings.Contains(sm.RoleNotes[0].Likely, "spine") || !strings.Contains(sm.RoleNotes[1].Likely, "lea") {
		t.Fatalf("role notes: %+v", sm.RoleNotes)
	}
	if len(sm.Vendors) != 3 {
		t.Fatalf("vendors: %+v", sm.Vendors)
	}
}

func TestLikelyFunctionCoversEveryRole(t *testing.T) {
	for _, r := range []string{DevRoleAccessSwitch, DevRoleDistributionSwitch, DevRoleCoreRouter, DevRoleFirewall,
		DevRoleLoadBalancer, DevRoleWANEdge, DevRoleCarrierHop, DevRoleDCWANEdge, DevRoleDCLeaf, DevRoleDCSpine, DevRoleCloudEdge} {
		if LikelyFunction(r, false) == "" {
			t.Errorf("role %s has no likely function", r)
		}
		for _, vendor := range []string{"cisco", "juniper", "arista", "nokia", "viptela"} {
			if strings.Contains(strings.ToLower(LikelyFunction(r, true)), vendor) {
				t.Errorf("role %s names a vendor", r)
			}
		}
	}
	if LikelyFunction(DevRoleUnknown, true) != "" {
		t.Error("an unknown role has no likely function")
	}
}

func TestSummaryBounds(t *testing.T) {
	var v View
	var pairs []OverlayPair
	for i := 0; i < 80; i++ {
		v.Nodes = append(v.Nodes, Node{ID: fmt.Sprintf("d%02d", i), Label: fmt.Sprintf("edge-%02d", i), DeviceRole: DevRoleWANEdge, Site: fmt.Sprintf("s%02d", i)})
		v.Edges = append(v.Edges, Edge{Source: fmt.Sprintf("d%02d", i), Target: "ext:pe", Relationship: RelConnectedTo, Protocol: "lldp"})
	}
	// A star around d00: everything else misses its spoke-spoke pairs.
	for i := 1; i < 80; i++ {
		pairs = append(pairs, OverlayPair{A: "d00", B: fmt.Sprintf("d%02d", i), Sessions: 1})
	}
	sm := Summarize(SummaryInput{View: v, Pairs: pairs, OverlayRead: true})
	if len(sm.Devices) != SummaryMaxDevices || sm.DevicesTotal != 80 || len(sm.Links) != SummaryMaxLinks || sm.LinksTotal != 80 {
		t.Fatalf("bounds: devices %d/%d links %d/%d", len(sm.Devices), sm.DevicesTotal, len(sm.Links), sm.LinksTotal)
	}
	ov := sm.Overlay
	if ov.Shape != ShapeHubAndSpoke || len(ov.Missing) != SummaryMaxMissing || ov.MissingTotal == SummaryMaxMissing ||
		len(ov.NotUp) != SummaryMaxNotUp || ov.NotUpTotal != 79 {
		t.Fatalf("overlay bounds: shape=%s missing %d/%d notup %d/%d", ov.Shape, len(ov.Missing), ov.MissingTotal, len(ov.NotUp), ov.NotUpTotal)
	}
}
