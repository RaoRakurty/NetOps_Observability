package backend

import (
	"context"
	"netops/backend/internal/discovery"
	"path/filepath"
	"testing"

	"netops/backend/collectors"
	"netops/backend/models"
	"netops/backend/wan"
)

// newWanTestServer builds a minimal server with just the stores the WAN projector
// touches, plus the wanIfAddr + wanNeighbors DI seams so the interface registry
// and directly-connected neighbours can be injected without Redis.
func newWanTestServer(t *testing.T, ifaddr map[string]map[string]string, neighbors []collectors.LLDPNeighbor) *server {
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
		discovery:   discovery.NewDiscoveryAggregator(),
		wanPolicy:   wp,
		sites:       sites,
		deviceSites: ds,
		wanIfAddr: func(context.Context) (map[string]map[string]string, error) {
			return ifaddr, nil
		},
		wanNeighbors: func(context.Context) ([]collectors.LLDPNeighbor, error) {
			return neighbors, nil
		},
	}
}

// TestWanProjectTenantIsolation is the §3a guarantee: the derived endpoint/target
// projection must never surface another tenant's device interfaces.
func TestWanProjectTenantIsolation(t *testing.T) {
	ifaddr := map[string]map[string]string{
		"wan-a":     {"10.0.0.1": "Ethernet1"},
		"wan-a2":    {"10.0.1.1": "Ethernet1"},
		"wan-other": {"10.9.0.1": "Ethernet1"}, // belongs to globex
	}
	s := newWanTestServer(t, ifaddr, nil)
	s.discovery.Upsert(models.Device{ID: "wan-a", Name: "wan-a", Address: "10.0.0.254", TenantID: "acme"})
	s.discovery.Upsert(models.Device{ID: "wan-a2", Name: "wan-a2", Address: "10.0.1.254", TenantID: "acme"})
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
	for _, want := range []string{"wan-a", "wan-a2", "wan-other"} {
		if !devs[want] {
			t.Errorf("cross-tenant principal should see %q", want)
		}
	}

	// Interface→target links never cross the tenant boundary either.
	_, links := s.wanProject(ctx, "acme", false)
	for _, c := range links {
		if c.Local.Device == "wan-other" {
			t.Fatalf("TENANT LEAK in link %s: touches globex device", c.ID)
		}
	}
}

// TestWanDeriveTarget locks the target-derivation precedence:
// operator next-hop → directly-connected peer → reachability anchor.
func TestWanDeriveTarget(t *testing.T) {
	neighbors := map[string]wan.Peer{
		wan.IfKey("wan-r2", "Eth1"): {Device: "spine1", Iface: "Eth3", Addr: "10.0.0.2"},
	}

	// 1. Operator next-hop override wins over everything.
	pol := WanMeasurementPolicy{NextHops: map[string]string{"wan-r2/Eth1": "203.0.113.1"}}.WithDefaults()
	if tgt, kind, _ := wan.DeriveTarget("wan-r2", "Eth1", neighbors, pol); tgt != "203.0.113.1" || kind != WanTargetNextHop {
		t.Errorf("next-hop override: got %q/%v, want 203.0.113.1/next_hop", tgt, kind)
	}

	// 2. Directly-connected peer when no override.
	pol = WanMeasurementPolicy{}.WithDefaults()
	if tgt, kind, _ := wan.DeriveTarget("wan-r2", "Eth1", neighbors, pol); tgt != "10.0.0.2" || kind != WanTargetDirectPeer {
		t.Errorf("direct peer: got %q/%v, want 10.0.0.2/direct_peer", tgt, kind)
	}

	// 3. Reachability anchor when no peer and no override (prod internet-facing).
	if tgt, kind, _ := wan.DeriveTarget("wan-r2", "Eth9", neighbors, pol); tgt != "1.1.1.1" || kind != WanTargetAnchor {
		t.Errorf("anchor default: got %q/%v, want 1.1.1.1/anchor", tgt, kind)
	}

	// Custom anchor is honoured.
	pol2 := WanMeasurementPolicy{Anchors: []string{"9.9.9.9"}}.WithDefaults()
	if tgt, kind, _ := wan.DeriveTarget("wan-r2", "Eth9", neighbors, pol2); tgt != "9.9.9.9" || kind != WanTargetAnchor {
		t.Errorf("custom anchor: got %q/%v, want 9.9.9.9/anchor", tgt, kind)
	}
}

// TestWanConnectedInterfaceIncluded is the LAB guarantee: the WAN router's
// interface AND the Spine's interface toward it are BOTH in scope and measure to
// each other (directly-connected peer) — no hub/spoke needed.
func TestWanConnectedInterfaceIncluded(t *testing.T) {
	ifaddr := map[string]map[string]string{
		"wan-r2": {"10.0.0.1": "Eth1"},
		"spine1": {"10.0.0.2": "Eth3", "10.1.0.1": "Eth1"}, // Eth1 is NOT connected to WAN
	}
	neighbors := []collectors.LLDPNeighbor{
		{LocalDevice: "wan-r2", LocalPort: "Eth1", RemSysName: "spine1", RemPort: "Eth3", Proto: "lldp"},
		{LocalDevice: "spine1", LocalPort: "Eth3", RemSysName: "wan-r2", RemPort: "Eth1", Proto: "lldp"},
	}
	s := newWanTestServer(t, ifaddr, neighbors)
	s.discovery.Upsert(models.Device{ID: "wan-r2", Name: "wan-r2", TenantID: "acme"})
	s.discovery.Upsert(models.Device{ID: "spine1", Name: "spine1", TenantID: "acme"})

	eps, _ := s.wanProject(context.Background(), "acme", false)
	byKey := map[string]WanEndpoint{}
	for _, e := range eps {
		byKey[e.Device+"/"+e.Interface] = e
	}

	// WAN router interface → measures to the spine peer.
	wr := byKey["wan-r2/Eth1"]
	if wr.Target != "10.0.0.2" || wr.TargetKind != WanTargetDirectPeer {
		t.Errorf("wan-r2/Eth1 should target the spine peer, got %q/%v", wr.Target, wr.TargetKind)
	}
	// Spine's interface toward the WAN router is pulled in and measures back.
	sp := byKey["spine1/Eth3"]
	if sp.Target != "10.0.0.1" || sp.TargetKind != WanTargetDirectPeer || !sp.ConnectedToWAN {
		t.Errorf("spine1/Eth3 should be included (connected_to_wan) and target the WAN router, got %+v", sp)
	}
	// The spine's OTHER interface (not connected to a WAN device) is NOT in scope.
	if _, ok := byKey["spine1/Eth1"]; ok {
		t.Error("spine1/Eth1 is not connected to a WAN device and must not be measured")
	}
}

// TestWanMgmtInterfacesExcluded: management ports are never WAN transport, even
// when a shared mgmt segment makes them LLDP neighbours of a WAN device. This is
// the lab bug — the WAN router's mgmt0 must not pull the whole fabric in.
func TestWanMgmtInterfacesExcluded(t *testing.T) {
	if !wan.IsMgmtInterface("mgmt0") || !wan.IsMgmtInterface("Management0") || !wan.IsMgmtInterface("ma1") {
		t.Fatal("mgmt interface matcher must catch mgmt0/Management0/ma1")
	}
	if wan.IsMgmtInterface("Ethernet1") || wan.IsMgmtInterface("Eth3") {
		t.Fatal("data interfaces must NOT be treated as management")
	}
	ifaddr := map[string]map[string]string{
		"wan-r2": {"172.40.40.10": "Management0", "10.0.0.1": "Eth1"},
		"leaf1":  {"172.40.40.11": "Management0"}, // only a mgmt port, shared segment
	}
	neighbors := []collectors.LLDPNeighbor{
		// shared mgmt segment: every device neighbours the WAN router's mgmt0
		{LocalDevice: "leaf1", LocalPort: "Management0", RemSysName: "wan-r2", RemPort: "Management0", Proto: "lldp"},
	}
	s := newWanTestServer(t, ifaddr, neighbors)
	s.discovery.Upsert(models.Device{ID: "wan-r2", Name: "wan-r2", TenantID: "acme"})
	s.discovery.Upsert(models.Device{ID: "leaf1", Name: "leaf1", TenantID: "acme"})
	eps, _ := s.wanProject(context.Background(), "acme", false)
	for _, e := range eps {
		if wan.IsMgmtInterface(e.Interface) {
			t.Fatalf("management interface leaked into WAN scope: %s/%s", e.Device, e.Interface)
		}
		if e.Device == "leaf1" {
			t.Fatalf("leaf1 has only a mgmt port and must not be pulled in via the shared mgmt segment: %+v", e)
		}
	}
	// wan-r2's DATA interface is still measured (as an anchor — no data-plane peer).
	var sawData bool
	for _, e := range eps {
		if e.Device == "wan-r2" && e.Interface == "Eth1" {
			sawData = true
		}
	}
	if !sawData {
		t.Fatal("wan-r2's data interface Eth1 should still be in scope")
	}
}

// TestWanConnectedDisabled: include_connected=false drops the Spine interface.
func TestWanConnectedDisabled(t *testing.T) {
	ifaddr := map[string]map[string]string{
		"wan-r2": {"10.0.0.1": "Eth1"},
		"spine1": {"10.0.0.2": "Eth3"},
	}
	neighbors := []collectors.LLDPNeighbor{
		{LocalDevice: "spine1", LocalPort: "Eth3", RemSysName: "wan-r2", RemPort: "Eth1", Proto: "lldp"},
	}
	s := newWanTestServer(t, ifaddr, neighbors)
	s.discovery.Upsert(models.Device{ID: "wan-r2", Name: "wan-r2", TenantID: "acme"})
	s.discovery.Upsert(models.Device{ID: "spine1", Name: "spine1", TenantID: "acme"})
	no := false
	if err := s.wanPolicy.Put(WanMeasurementPolicy{TenantID: "acme", IncludeConnected: &no}); err != nil {
		t.Fatalf("policy put: %v", err)
	}
	eps, _ := s.wanProject(context.Background(), "acme", false)
	for _, e := range eps {
		if e.Device == "spine1" {
			t.Fatalf("include_connected=false must drop the spine interface, got %+v", e)
		}
	}
}

// TestWanSparkSeries: the live-throughput sparkline series is fetched via the
// range seam and keyed by device+ifName.
func TestWanSparkSeries(t *testing.T) {
	s := newWanTestServer(t, nil, nil)
	s.vmRangeRaw = func(_ context.Context, _ string, _, _, _ int64) (map[string][]float64, error) {
		return map[string][]float64{
			wan.IfKey("wan-r2", "Ethernet4"): {1e6, 2e6, 3.6e7},
		}, nil
	}
	got := s.wanSparkSeries(context.Background(), 1000, 600, 30)
	sp := got[wan.IfKey("wan-r2", "Ethernet4")]
	if len(sp) != 3 || sp[2] != 3.6e7 {
		t.Fatalf("expected the injected throughput series, got %v", sp)
	}
}

// TestWanPolicyStoreIsolation: a tenant's policy is private; a non-cross caller
// never reads another tenant's policy.
func TestWanPolicyStoreIsolation(t *testing.T) {
	s := newWanTestServer(t, nil, nil)
	if err := s.wanPolicy.Put(WanMeasurementPolicy{TenantID: "acme", WanPattern: "acme-wan"}); err != nil {
		t.Fatalf("acme put: %v", err)
	}
	if err := s.wanPolicy.Put(WanMeasurementPolicy{TenantID: "globex", Anchors: []string{"9.9.9.9"}}); err != nil {
		t.Fatalf("globex put: %v", err)
	}
	if got := s.wanPolicy.Get("acme", false); got.WanPattern != "acme-wan" {
		t.Errorf("acme policy = %q, want acme-wan", got.WanPattern)
	}
	if got := s.wanPolicy.Get("globex", false); len(got.Anchors) == 0 || got.Anchors[0] != "9.9.9.9" {
		t.Errorf("globex anchors = %v, want [9.9.9.9]", got.Anchors)
	}
	// A tenant with no policy gets the safe default, NOT another tenant's.
	got := s.wanPolicy.Get("initech", false)
	if got.TenantID != "initech" || got.WanPattern != wan.DefaultPattern || len(got.Anchors) == 0 {
		t.Errorf("unconfigured tenant should get the default baseline, got %+v", got)
	}
}
