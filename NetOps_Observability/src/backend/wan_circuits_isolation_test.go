package main

import (
	"context"
	"path/filepath"
	"testing"

	"netops/backend/models"
)

// newWanTestServer builds a minimal server with just the stores the WAN circuit
// projector touches, plus the wanIfAddr DI seam so the interface registry can be
// injected without Redis.
func newWanTestServer(t *testing.T, ifaddr map[string]map[string]string) *server {
	t.Helper()
	dir := t.TempDir()
	wp, err := newWanPolicyStore(filepath.Join(dir, "wan_policy.json"))
	if err != nil {
		t.Fatalf("wan policy store: %v", err)
	}
	sites, err := newSitesStore(filepath.Join(dir, "sites.json"))
	if err != nil {
		t.Fatalf("sites store: %v", err)
	}
	ds, err := newDeviceSiteStore(filepath.Join(dir, "device_sites.json"))
	if err != nil {
		t.Fatalf("device sites store: %v", err)
	}
	return &server{
		discovery:   NewDiscoveryAggregator(),
		wanPolicy:   wp,
		sites:       sites,
		deviceSites: ds,
		wanIfAddr: func(context.Context) (map[string]map[string]string, error) {
			return ifaddr, nil
		},
	}
}

// TestWanProjectTenantIsolation is the §3a guarantee: the derived endpoint/circuit
// projection must never surface another tenant's device interfaces.
func TestWanProjectTenantIsolation(t *testing.T) {
	ifaddr := map[string]map[string]string{
		"wan-hub":   {"10.0.0.1": "Ethernet1"},
		"wan-spoke": {"10.0.1.1": "Ethernet1"},
		"wan-other": {"10.9.0.1": "Ethernet1"}, // belongs to globex
	}
	s := newWanTestServer(t, ifaddr)
	s.discovery.Upsert(models.Device{ID: "wan-hub", Name: "wan-hub", Address: "10.0.0.254", TenantID: "acme"})
	s.discovery.Upsert(models.Device{ID: "wan-spoke", Name: "wan-spoke", Address: "10.0.1.254", TenantID: "acme"})
	s.discovery.Upsert(models.Device{ID: "wan-other", Name: "wan-other", Address: "10.9.0.254", TenantID: "globex"})

	ctx := context.Background()

	// acme principal sees ONLY its own two devices' interfaces.
	eps, _ := s.wanProject(ctx, "acme", false)
	if len(eps) == 0 {
		t.Fatal("acme should see its own WAN endpoints")
	}
	for _, e := range eps {
		if e.Device == "wan-other" {
			t.Fatalf("TENANT LEAK: acme saw globex device %q", e.Device)
		}
		if e.TenantID != "acme" {
			t.Errorf("endpoint stamped with wrong tenant %q", e.TenantID)
		}
	}

	// globex sees ONLY wan-other.
	gEps, _ := s.wanProject(ctx, "globex", false)
	for _, e := range gEps {
		if e.Device != "wan-other" {
			t.Fatalf("TENANT LEAK: globex saw %q", e.Device)
		}
	}

	// Cross-tenant platform principal sees all three.
	allEps, _ := s.wanProject(ctx, TenantGlobal, true)
	devs := map[string]bool{}
	for _, e := range allEps {
		devs[e.Device] = true
	}
	for _, want := range []string{"wan-hub", "wan-spoke", "wan-other"} {
		if !devs[want] {
			t.Errorf("cross-tenant principal should see %q", want)
		}
	}

	// Circuits never cross the tenant boundary either.
	_, ckts := s.wanProject(ctx, "acme", false)
	for _, c := range ckts {
		if c.Local.Device == "wan-other" || c.Remote.Device == "wan-other" {
			t.Fatalf("TENANT LEAK in circuit %s: touches globex device", c.ID)
		}
	}
}

// TestWanResolveRolePrecedence locks the documented precedence:
// override → hub list → site role → name hint → default spoke.
func TestWanResolveRolePrecedence(t *testing.T) {
	s := newWanTestServer(t, nil)
	// Site "acme-dc" is a hub; bind wan-edge1 to it.
	if _, err := s.sites.Upsert(Site{TenantID: "acme", Slug: "acme-dc", Name: "DC", Role: "hub"}); err != nil {
		t.Fatalf("site upsert: %v", err)
	}
	if err := s.deviceSites.Set(DeviceSiteBinding{TenantID: "acme", DeviceID: "wan-edge1", Site: "acme-dc"}); err != nil {
		t.Fatalf("binding: %v", err)
	}

	dev := func(id, name string) models.Device {
		return models.Device{ID: id, Name: name, TenantID: "acme"}
	}

	// 1. Explicit override wins over everything (even the hub site).
	pol := WanTopologyPolicy{RoleOverrides: map[string]WanRole{"wan-edge1": WanRoleSpoke}}.withDefaults()
	if r, src, _ := s.wanResolveRole("acme", false, dev("wan-edge1", "wan-edge1"), pol); r != WanRoleSpoke || src != RoleDeclared {
		t.Errorf("override: got %v/%v, want spoke/declared", r, src)
	}

	// 2. Site role applies when no override.
	pol = WanTopologyPolicy{}.withDefaults()
	if r, src, _ := s.wanResolveRole("acme", false, dev("wan-edge1", "wan-edge1"), pol); r != WanRoleHub || src != RoleFromSite {
		t.Errorf("site role: got %v/%v, want hub/site", r, src)
	}

	// 3. Name hint when no override / site role.
	if r, src, _ := s.wanResolveRole("acme", false, dev("br-1", "branch-1"), pol); r != WanRoleSpoke || src != RoleSuggested {
		t.Errorf("name hint: got %v/%v, want spoke/suggested", r, src)
	}

	// 4. Default-closed → spoke when nothing is known.
	if r, src, _ := s.wanResolveRole("acme", false, dev("x9", "x9"), pol); r != WanRoleSpoke || src != RoleDefault {
		t.Errorf("default: got %v/%v, want spoke/default", r, src)
	}
}

// TestWanMeshHubSpoke verifies hub-spoke generates spoke⇄hub circuits (both
// directions when bidirectional) and never spoke↔spoke.
func TestWanMeshHubSpoke(t *testing.T) {
	hubEp := WanEndpoint{Device: "hub1", Interface: "Eth1", Address: "10.0.0.1", Measurable: "10.0.0.1", Role: WanRoleHub}
	sp1 := WanEndpoint{Device: "spoke1", Interface: "Eth1", Address: "10.1.0.1", Measurable: "10.1.0.1", Role: WanRoleSpoke}
	sp2 := WanEndpoint{Device: "spoke2", Interface: "Eth1", Address: "10.2.0.1", Measurable: "10.2.0.1", Role: WanRoleSpoke}
	byDevice := map[string][]WanEndpoint{
		"hub1":   {hubEp},
		"spoke1": {sp1},
		"spoke2": {sp2},
	}
	s := newWanTestServer(t, nil)
	pol := WanTopologyPolicy{Mode: "hub-spoke", Bidirectional: true}
	ckts := s.wanMesh(byDevice, nil, pol)

	if len(ckts) == 0 {
		t.Fatal("hub-spoke should generate circuits")
	}
	for _, c := range ckts {
		// No spoke→spoke.
		if c.Local.Role == WanRoleSpoke && c.Remote.Role == WanRoleSpoke {
			t.Errorf("spoke↔spoke circuit must not exist: %s→%s", c.Local.Device, c.Remote.Device)
		}
		if c.Topology != "hub-spoke" {
			t.Errorf("topology tag = %q, want hub-spoke", c.Topology)
		}
	}

	// Unidirectional: only spoke→hub.
	uni := s.wanMesh(byDevice, nil, WanTopologyPolicy{Mode: "hub-spoke", Bidirectional: false})
	for _, c := range uni {
		if c.Local.Role != WanRoleSpoke || c.Remote.Role != WanRoleHub {
			t.Errorf("unidirectional should be spoke→hub only, got %v→%v", c.Local.Role, c.Remote.Role)
		}
	}
}

// TestWanPolicyStoreIsolation: a tenant's policy is private; a non-cross caller
// never reads another tenant's policy.
func TestWanPolicyStoreIsolation(t *testing.T) {
	s := newWanTestServer(t, nil)
	if err := s.wanPolicy.Put(WanTopologyPolicy{TenantID: "acme", Mode: "full-mesh", Bidirectional: true}); err != nil {
		t.Fatalf("acme put: %v", err)
	}
	if err := s.wanPolicy.Put(WanTopologyPolicy{TenantID: "globex", Mode: "hub-spoke", Bidirectional: false}); err != nil {
		t.Fatalf("globex put: %v", err)
	}
	if got := s.wanPolicy.Get("acme", false); got.Mode != "full-mesh" {
		t.Errorf("acme policy = %q, want full-mesh", got.Mode)
	}
	if got := s.wanPolicy.Get("globex", false); got.Mode != "hub-spoke" {
		t.Errorf("globex policy = %q, want hub-spoke", got.Mode)
	}
	// A tenant with no policy gets the safe default, NOT another tenant's.
	if got := s.wanPolicy.Get("initech", false); got.Mode != "hub-spoke" || got.TenantID != "initech" {
		t.Errorf("unconfigured tenant should get default hub-spoke baseline, got %q/%q", got.Mode, got.TenantID)
	}
}
