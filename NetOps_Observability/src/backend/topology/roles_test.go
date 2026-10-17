// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package topology

import (
	"strings"
	"testing"
)

// roles_test.go — the discovery-driven device-role classifier, per-signal and
// combined, with realistic discovery fact fixtures. The invariants under test:
// every assignment names its evidence, confidence is a word tier, and unknown
// stays unknown (default-closed — no facts, no role).

func evidenceMentions(t *testing.T, r RoleResult, signal string) {
	t.Helper()
	for _, e := range r.Evidence {
		if e.Signal == signal {
			return
		}
	}
	t.Fatalf("expected evidence signal %q, got %+v", signal, r.Evidence)
}

func TestOperatorDeclaredRoleIsAuthoritative(t *testing.T) {
	r := ClassifyDeviceRole(DeviceFact{Name: "whatever", Role: "dc_wan_edge"})
	if r.Role != DevRoleDCWANEdge || r.Confidence != RoleConfStrong {
		t.Fatalf("declared role: got %+v", r)
	}
	evidenceMentions(t, r, "operator_declared")

	// Free-text notes are NOT a role declaration.
	r = ClassifyDeviceRole(DeviceFact{Name: "sw-9", Role: "the closet one, third floor"})
	if r.Role != DevRoleUnknown {
		t.Fatalf("free-text role hint must not classify: got %+v", r)
	}
}

func TestSDWANVendorStringsMeanWANEdge(t *testing.T) {
	fixtures := []DeviceFact{
		{Name: "br1-cpe", Vendor: "Cisco", SysDescr: "Cisco IOS XE, vEdge cloud router"},
		{Name: "site-edge", Vendor: "VMware", Model: "VeloCloud Edge 620"},
		{Name: "b2", Vendor: "Versa Networks", Model: "FlexVNF"},
		{Name: "mx1", Vendor: "Cisco Meraki", Model: "Meraki MX68"},
		{Name: "sp1", SysDescr: "Silver Peak Systems EC-XS"},
	}
	for _, f := range fixtures {
		r := ClassifyDeviceRole(f)
		if r.Role != DevRoleWANEdge || r.Confidence != RoleConfStrong {
			t.Fatalf("%s: want wan_edge/strong, got %+v", f.Name, r)
		}
		evidenceMentions(t, r, "sdwan_identity")
	}
}

func TestModelIdentityRoles(t *testing.T) {
	cases := []struct {
		fact DeviceFact
		want string
	}{
		{DeviceFact{Name: "fw-1", Type: "firewall", Vendor: "Palo Alto"}, DevRoleFirewall},
		{DeviceFact{Name: "lb-1", Type: "load-balancer", Vendor: "F5"}, DevRoleLoadBalancer},
		{DeviceFact{Name: "vgw-1", Type: "cloud-gw", Model: "CSR1000v"}, DevRoleCloudEdge},
	}
	for _, c := range cases {
		r := ClassifyDeviceRole(c.fact)
		if r.Role != c.want || r.Confidence != RoleConfStrong {
			t.Fatalf("%s: want %s/strong, got %+v", c.fact.Name, c.want, r)
		}
		evidenceMentions(t, r, "model_identity")
	}
}

func TestFirewallBeatsGenericRouterSignals(t *testing.T) {
	// A firewall that also participates in the IGP must never be mislabelled a
	// core router — specific identity precedes adjacency shape.
	r := ClassifyDeviceRole(DeviceFact{
		Name: "edge-fw", Type: "firewall", HasIGPAdjacency: true, RouterNeighborCount: 3,
	})
	if r.Role != DevRoleFirewall {
		t.Fatalf("want firewall, got %+v", r)
	}
}

func TestTunnelFacts(t *testing.T) {
	// Tunnel terminating in published cloud space ⇒ the cloud attachment point.
	r := ClassifyDeviceRole(DeviceFact{Name: "hub-r1", Type: "router", TunnelCount: 2, HasCloudTunnel: true})
	if r.Role != DevRoleCloudEdge || r.Confidence != RoleConfStrong {
		t.Fatalf("cloud tunnel: got %+v", r)
	}
	evidenceMentions(t, r, "cloud_tunnel")

	// Site-to-site tunnels ⇒ WAN edge, corroborated inference (medium).
	r = ClassifyDeviceRole(DeviceFact{Name: "br2-r1", Type: "router", TunnelCount: 1})
	if r.Role != DevRoleWANEdge || r.Confidence != RoleConfMedium {
		t.Fatalf("site tunnel: got %+v", r)
	}
	evidenceMentions(t, r, "tunnel_endpoint")
}

func TestLeafSpineNamingWithFabricCorroboration(t *testing.T) {
	r := ClassifyDeviceRole(DeviceFact{
		Name: "dc1-leaf03", Type: "switch", Vendor: "Arista",
		SysDescr: "Arista DCS-7050X3, EOS, VXLAN EVPN fabric",
	})
	if r.Role != DevRoleDCLeaf || r.Confidence != RoleConfMedium {
		t.Fatalf("leaf: got %+v", r)
	}
	evidenceMentions(t, r, "naming_convention")
	evidenceMentions(t, r, "fabric_identity")

	r = ClassifyDeviceRole(DeviceFact{Name: "dc1-spine1", Type: "switch", Model: "Nexus 9336C"})
	if r.Role != DevRoleDCSpine {
		t.Fatalf("spine: got %+v", r)
	}

	// "leafield" must not token-match "leaf".
	r = ClassifyDeviceRole(DeviceFact{Name: "leafield-sw", Type: "switch"})
	if r.Role == DevRoleDCLeaf {
		t.Fatalf("substring must not match a token: got %+v", r)
	}
}

func TestAdjacencyShapeForSwitches(t *testing.T) {
	// IGP participation + switch fan-out ⇒ distribution tier (medium).
	r := ClassifyDeviceRole(DeviceFact{
		Name: "b1-dist1", Type: "switch", HasIGPAdjacency: true,
		NeighborCount: 6, SwitchNeighborCount: 4,
	})
	if r.Role != DevRoleDistributionSwitch || r.Confidence != RoleConfMedium {
		t.Fatalf("distribution: got %+v", r)
	}
	evidenceMentions(t, r, "igp_participation")
	evidenceMentions(t, r, "adjacency_shape")

	// Wide switch fan-out without IGP corroboration is only weak.
	r = ClassifyDeviceRole(DeviceFact{
		Name: "b2-agg", Type: "switch", NeighborCount: 5, SwitchNeighborCount: 4,
	})
	if r.Role != DevRoleDistributionSwitch || r.Confidence != RoleConfWeak {
		t.Fatalf("distribution weak: got %+v", r)
	}

	// Few upstream network neighbours, outside the IGP ⇒ access tier, WEAK on
	// purpose (the strong signal — MAC/endpoint density — is not collected yet).
	r = ClassifyDeviceRole(DeviceFact{
		Name: "flr3-sw2", Type: "switch", NeighborCount: 2, SwitchNeighborCount: 1,
	})
	if r.Role != DevRoleAccessSwitch || r.Confidence != RoleConfWeak {
		t.Fatalf("access: got %+v", r)
	}
}

func TestCoreRouterFromIGP(t *testing.T) {
	r := ClassifyDeviceRole(DeviceFact{
		Name: "core-r1", Type: "router", HasIGPAdjacency: true,
		RouterNeighborCount: 3, SwitchNeighborCount: 2,
	})
	if r.Role != DevRoleCoreRouter || r.Confidence != RoleConfStrong {
		t.Fatalf("core strong: got %+v", r)
	}
	// IGP alone (no fan-out visibility) stays medium.
	r = ClassifyDeviceRole(DeviceFact{Name: "core-r2", Type: "router", HasIGPAdjacency: true})
	if r.Role != DevRoleCoreRouter || r.Confidence != RoleConfMedium {
		t.Fatalf("core medium: got %+v", r)
	}
}

func TestUnknownStaysUnknown(t *testing.T) {
	fixtures := []DeviceFact{
		{},                                   // no facts at all
		{Name: "mystery-9", Type: "generic"}, // bare inventory row
		{Name: "r-77", Type: "router"},       // router with no IGP/tunnel/identity signal
		{Name: "sw-0", Type: "switch"},       // switch with zero observed neighbours
		{Name: "printer-3", Type: "ap"},      // a type with no role mapping
	}
	for _, f := range fixtures {
		r := ClassifyDeviceRole(f)
		if r.Role != DevRoleUnknown {
			t.Fatalf("%s: want unknown, got %+v", f.Name, r)
		}
		if r.Confidence != "" {
			t.Fatalf("%s: unknown must carry no confidence, got %q", f.Name, r.Confidence)
		}
	}
}

func TestConfidenceIsAlwaysAWordNeverAPercentage(t *testing.T) {
	facts := []DeviceFact{
		{Role: "wan_edge"},
		{Type: "firewall"},
		{Type: "switch", HasIGPAdjacency: true, SwitchNeighborCount: 2},
		{Type: "switch", NeighborCount: 1},
	}
	for _, f := range facts {
		r := ClassifyDeviceRole(f)
		switch r.Confidence {
		case RoleConfStrong, RoleConfMedium, RoleConfWeak, "":
		default:
			t.Fatalf("non-word confidence %q", r.Confidence)
		}
		for _, e := range r.Evidence {
			if strings.Contains(e.Detail, "%") {
				t.Fatalf("evidence must not carry percentages: %q", e.Detail)
			}
		}
	}
}

func TestProjectStampsDeviceRoles(t *testing.T) {
	// Example usage end-to-end: the projection carries the classifier output on
	// the node payload, and omits it for unknowns.
	in := Input{
		Mode:     ModeExplore,
		TenantID: "t1",
		Devices: []DeviceFact{
			{ID: "fw1", Name: "edge-fw", Type: "firewall"},
			{ID: "d9", Name: "mystery", Type: "generic"},
		},
	}
	v := Project(in)
	var fwRole, mysteryRole string
	for _, n := range v.Nodes {
		switch n.ID {
		case "fw1":
			fwRole = n.DeviceRole
			if n.RoleConfidence != RoleConfStrong || len(n.RoleEvidence) == 0 {
				t.Fatalf("fw node missing confidence/evidence: %+v", n)
			}
		case "d9":
			mysteryRole = n.DeviceRole
		}
	}
	if fwRole != DevRoleFirewall {
		t.Fatalf("want firewall on node payload, got %q", fwRole)
	}
	if mysteryRole != "" {
		t.Fatalf("unknown must be omitted from the payload, got %q", mysteryRole)
	}
}

// ── WAN-edge flavor (tracker 349): SD-WAN vs data center vs plain routed ─────

func TestWANEdgeFlavorClassification(t *testing.T) {
	cases := []struct {
		name                       string
		d                          DeviceFact
		role, conf, flavor, signal string
	}{
		{"vEdge personality", DeviceFact{Name: "site-a", SDWANPersonality: "vedge"},
			DevRoleWANEdge, RoleConfStrong, WANFlavorSDWAN, "sdwan_personality"},
		{"overlay system-ip answered", DeviceFact{Name: "site-b", SDWANSystemIP: "10.255.0.7"},
			DevRoleWANEdge, RoleConfStrong, WANFlavorSDWAN, "sdwan_system_ip"},
		{"Viptela enterprise sysObjectID", DeviceFact{Name: "site-c", SysObjectID: "1.3.6.1.4.1.41916.3.2.6"},
			DevRoleWANEdge, RoleConfStrong, WANFlavorSDWAN, "sysobjectid"},
		{"cEdge interface marker only", DeviceFact{Name: "br-12", Type: "router", IfNames: []string{"Gi1", "Gi2", "Sdwan-intf", "Tu1"}},
			DevRoleWANEdge, RoleConfMedium, WANFlavorSDWAN, "sdwan_interfaces"},
		{"vEdge interface markers", DeviceFact{Name: "br-13", IfNames: []string{"ge0/0", "system", "loopback65528"}},
			DevRoleWANEdge, RoleConfMedium, WANFlavorSDWAN, "sdwan_interfaces"},
		{"SD-WAN edge at a declared DC", DeviceFact{Name: "dc-hub", SDWANPersonality: "vedge", SiteKind: "DC"},
			DevRoleDCWANEdge, RoleConfStrong, WANFlavorSDWAN, "site_kind"},
		{"SD-WAN edge next to the fabric", DeviceFact{Name: "hub-2", IfNames: []string{"Sdwan-intf"}, FabricNeighborCount: 2},
			DevRoleDCWANEdge, RoleConfMedium, WANFlavorSDWAN, "fabric_adjacency"},
		{"plain CE with an ISP peer", DeviceFact{Name: "branch-7", Type: "router", ExternalBGPPeers: 1},
			DevRoleWANEdge, RoleConfMedium, WANFlavorRouted, "external_bgp"},
		{"router with external peer AND IGP is only weakly an edge", DeviceFact{Name: "rtr-9", Type: "router", ExternalBGPPeers: 2, HasIGPAdjacency: true},
			DevRoleWANEdge, RoleConfWeak, WANFlavorRouted, "external_bgp"},
		{"routed DC border", DeviceFact{Name: "dc-border-1", Type: "router", ExternalBGPPeers: 2, FabricNeighborCount: 4},
			DevRoleDCWANEdge, RoleConfMedium, WANFlavorRouted, "fabric_adjacency"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := ClassifyDeviceRole(c.d)
			if r.Role != c.role || r.Confidence != c.conf || r.WANFlavor != c.flavor {
				t.Fatalf("got role=%s conf=%s flavor=%s, want %s/%s/%s (%+v)", r.Role, r.Confidence, r.WANFlavor, c.role, c.conf, c.flavor, r.Evidence)
			}
			evidenceMentions(t, r, c.signal)
		})
	}
}

// A controller is SD-WAN but never an edge: it has no transport and no site.
func TestSDWANControllerIsNotAnEdge(t *testing.T) {
	for _, p := range []string{"vsmart", "vbond", "vmanage", "vSmart"} {
		r := ClassifyDeviceRole(DeviceFact{Name: "ctrl", SDWANPersonality: p, SysObjectID: "1.3.6.1.4.1.41916.3.2.1"})
		if r.Role != DevRoleUnknown || r.WANFlavor != WANFlavorSDWAN || r.Confidence != "" {
			t.Fatalf("%s: got %+v, want unknown role with the sdwan flavor", p, r)
		}
		evidenceMentions(t, r, "sdwan_controller")
	}
}

// Generic names alone are not SD-WAN: `system` without the reserved loopbacks,
// and NV0 (an IOS XE NAT interface) are on plenty of non-SD-WAN routers.
func TestGenericInterfaceNamesAreNotSDWANEvidence(t *testing.T) {
	for _, names := range [][]string{{"system"}, {"loopback65528"}, {"NV0", "Gi1"}, {"Tunnel1"}} {
		if r := ClassifyDeviceRole(DeviceFact{Name: "x", IfNames: names}); r.WANFlavor != "" || r.Role != DevRoleUnknown {
			t.Fatalf("%v classified as %+v", names, r)
		}
	}
}

// The operator names the role; the flavor is still measured, never declared.
func TestDeclaredWANRoleStillCarriesAMeasuredFlavor(t *testing.T) {
	if r := ClassifyDeviceRole(DeviceFact{Role: "wan_edge", IfNames: []string{"Sdwan-intf"}}); r.WANFlavor != WANFlavorSDWAN {
		t.Fatalf("declared + SD-WAN marker: %+v", r)
	}
	if r := ClassifyDeviceRole(DeviceFact{Role: "dc_wan_edge", ExternalBGPPeers: 3}); r.Role != DevRoleDCWANEdge || r.WANFlavor != WANFlavorRouted {
		t.Fatalf("declared DC edge + external BGP: %+v", r)
	}
	if r := ClassifyDeviceRole(DeviceFact{Role: "wan_edge"}); r.WANFlavor != "" {
		t.Fatalf("declared with no evidence must not invent a flavor: %+v", r)
	}
	if r := ClassifyDeviceRole(DeviceFact{Role: "core_router", ExternalBGPPeers: 3}); r.WANFlavor != "" {
		t.Fatalf("a non-WAN role carries no flavor: %+v", r)
	}
}

func TestNoFactsNoFlavor(t *testing.T) {
	if r := ClassifyDeviceRole(DeviceFact{}); r.Role != DevRoleUnknown || r.WANFlavor != "" || r.SDWANPersonality != "" {
		t.Fatalf("empty facts: %+v", r)
	}
}

// Node kind falls back to the classified role only when the type inference left
// the device generic — an evidenced WAN edge renders as a router, not a switch.
func TestNodeKindUsesTheClassifiedRoleForGenericDevices(t *testing.T) {
	if k := KindOf(DeviceFact{Name: "vEdge-x", Type: "generic", SDWANSystemIP: "10.255.0.9"}); k != KindRouter {
		t.Fatalf("evidenced SD-WAN edge: kind %q, want router", k)
	}
	if k := KindOf(DeviceFact{Name: "box-1", Type: "generic"}); k != KindSwitch {
		t.Fatalf("no evidence must keep the neutral default: kind %q", k)
	}
	if k := KindOf(DeviceFact{Name: "fw-x", Type: "firewall", SDWANSystemIP: "10.255.0.9"}); k != KindFirewall {
		t.Fatalf("the inferred type still wins over the role fallback: kind %q", k)
	}
}
