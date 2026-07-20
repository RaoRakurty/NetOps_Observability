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
