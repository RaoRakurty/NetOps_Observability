package main

import (
	"context"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"netops/backend/models"

	"netops/backend/internal/discovery"
)

// --- range validation (the zero-trust gate on what the prober may touch) ---

func TestValidateDiscoveryRangesRefusesBadInput(t *testing.T) {
	cases := []struct {
		name   string
		ranges []string
		errHas string
	}{
		{"not cidr", []string{"10.20.0.5"}, "not valid CIDR"},
		{"garbage", []string{"bananas/24"}, "not valid CIDR"},
		{"public space", []string{"8.8.8.0/24"}, "not private"},
		{"ipv6", []string{"fd00::/64"}, "IPv4"},
		{"oversized single", []string{"10.0.0.0/8"}, "narrow"},
		{"oversized sum", []string{"10.1.0.0/20", "10.2.0.0/20"}, "narrow"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, _, err := discovery.ValidateScanRanges(c.ranges, false); err == nil || !strings.Contains(err.Error(), c.errHas) {
				t.Fatalf("want error containing %q, got %v", c.errHas, err)
			}
		})
	}
}

func TestValidateDiscoveryRangesNonPrivateAcknowledgment(t *testing.T) {
	// Squatted-public space (enterprises do this; the lab's 172.40.40.0/24 is
	// one) needs the explicit acknowledgment — refused without, accepted with.
	if _, _, err := discovery.ValidateScanRanges([]string{"172.40.40.0/24"}, false); err == nil || !strings.Contains(err.Error(), "not private") {
		t.Fatalf("non-private without acknowledgment must be refused, got %v", err)
	}
	clean, total, err := discovery.ValidateScanRanges([]string{"172.40.40.0/24"}, true)
	if err != nil || len(clean) != 1 || total != 256 {
		t.Fatalf("acknowledged non-private should pass: %v %v %d", err, clean, total)
	}
	// Never-scannable space stays refused even WITH the acknowledgment.
	for _, r := range []string{"127.0.0.0/24", "169.254.1.0/24", "224.0.0.0/24", "0.0.0.0/24"} {
		if _, _, err := discovery.ValidateScanRanges([]string{r}, true); err == nil {
			t.Fatalf("%s must be refused even with allow_non_private", r)
		}
	}
}

func TestValidateDiscoveryRangesAcceptsAndNormalizes(t *testing.T) {
	clean, total, err := discovery.ValidateScanRanges([]string{" 10.20.0.1/24 ", "", "192.168.5.0/26"}, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(clean) != 2 || clean[0] != "10.20.0.0/24" || clean[1] != "192.168.5.0/26" {
		t.Fatalf("normalized ranges wrong: %v", clean)
	}
	if total != 256+64 {
		t.Fatalf("host count = %d, want 320", total)
	}
}

func TestExpandCIDRSkipsNetworkAndBroadcast(t *testing.T) {
	hosts := discovery.ExpandCIDRForTest("10.20.0.0/30")
	if len(hosts) != 2 || hosts[0] != "10.20.0.1" || hosts[1] != "10.20.0.2" {
		t.Fatalf("/30 expansion wrong: %v", hosts)
	}
	if got := discovery.ExpandCIDRForTest("10.20.0.0/31"); len(got) != 2 {
		t.Fatalf("/31 should probe both addresses, got %v", got)
	}
	if got := discovery.ExpandCIDRForTest("10.20.0.9/32"); len(got) != 1 || got[0] != "10.20.0.9" {
		t.Fatalf("/32 should probe the single host, got %v", got)
	}
}

// --- the scan engine, with a fake prober (no network IO in tests) ---

func fakeProbe(alive map[string]string) discovery.Probe {
	return func(_ context.Context, addr, _ string) (string, string, string, bool) {
		name, ok := alive[addr]
		if !ok {
			return "", "", "", false
		}
		return name, "arista", "Arista vEOS 4.30", true
	}
}

func TestSNMPSourceDiscoversOnlyUnknownHosts(t *testing.T) {
	cfg := discovery.ScanSettings{Enabled: true, Ranges: []string{"10.20.0.0/29"}}
	known := []models.Device{{ID: "existing", Address: "10.20.0.2"}}
	src := discovery.NewSNMPSource(
		func() discovery.ScanSettings { return cfg },
		func() []models.Device { return known },
	)
	src.SetProbeForTest(fakeProbe(map[string]string{
		"10.20.0.2": "already-known", // must be skipped: address exists in inventory
		"10.20.0.3": "leaf-1",
	}))

	devs, err := src.Poll(context.Background())
	if err != nil {
		t.Fatalf("poll: %v", err)
	}
	if len(devs) != 1 {
		t.Fatalf("want exactly 1 discovered device, got %d: %+v", len(devs), devs)
	}
	d := devs[0]
	if d.ID != "leaf-1" || d.Address != "10.20.0.3" || d.Vendor != "arista" || d.Source != "snmp" {
		t.Fatalf("device shape wrong: %+v", d)
	}
	if d.TenantID != "" {
		t.Fatalf("discovered device must be platform-scoped (empty tenant), got %q", d.TenantID)
	}
}

func TestSNMPSourceDisabledAndOversizedAreSafe(t *testing.T) {
	// Disabled → no probes, no devices.
	var probed bool
	src := discovery.NewSNMPSource(
		func() discovery.ScanSettings {
			return discovery.ScanSettings{Enabled: false, Ranges: []string{"10.20.0.0/29"}}
		},
		nil,
	)
	src.SetProbeForTest(func(context.Context, string, string) (string, string, string, bool) {
		probed = true
		return "", "", "", false
	})
	if devs, err := src.Poll(context.Background()); err != nil || len(devs) != 0 || probed {
		t.Fatalf("disabled source must be inert: devs=%v err=%v probed=%v", devs, err, probed)
	}

	// The shipped env default (10.0.0.0/8) must be refused, not swept.
	src2 := discovery.NewSNMPSource(
		func() discovery.ScanSettings {
			return discovery.ScanSettings{Enabled: true, Ranges: []string{"10.0.0.0/8"}}
		},
		nil,
	)
	src2.SetProbeForTest(func(context.Context, string, string) (string, string, string, bool) {
		t.Fatal("oversized range must never be probed")
		return "", "", "", false
	})
	if _, err := src2.Poll(context.Background()); err == nil || !strings.Contains(err.Error(), "refused") {
		t.Fatalf("want refusal error, got %v", err)
	}
}

func TestSNMPSourceCooldownServesCache(t *testing.T) {
	cfg := discovery.ScanSettings{Enabled: true, Ranges: []string{"10.20.0.0/30"}}
	var probeCount atomic.Int64 // probes run concurrently — unsynced counter races
	src := discovery.NewSNMPSource(func() discovery.ScanSettings { return cfg }, nil)
	src.SetProbeForTest(func(_ context.Context, addr, _ string) (string, string, string, bool) {
		probeCount.Add(1)
		return "sw-" + addr, "", "", true
	})
	if _, err := src.Poll(context.Background()); err != nil {
		t.Fatalf("first poll: %v", err)
	}
	first := probeCount.Load()
	if first == 0 {
		t.Fatal("first poll should probe")
	}
	// Immediate re-poll (e.g. tenant-triggered /api/discovery/refresh) must be
	// absorbed by the cooldown: cached results, zero new probes.
	devs, err := src.Poll(context.Background())
	if err != nil {
		t.Fatalf("second poll: %v", err)
	}
	if got := probeCount.Load(); got != first {
		t.Fatalf("cooldown violated: probes went %d → %d", first, got)
	}
	if len(devs) != 2 {
		t.Fatalf("cached snapshot wrong: %v", devs)
	}
}

// --- config store semantics ---

func TestDiscoveryConfigStoreValidatesAndPreservesSecret(t *testing.T) {
	dir := t.TempDir()
	st := newDiscoveryConfigStore(dir+"/disc.json", nil)

	if _, err := st.set(discoveryScanConfig{Enabled: true}); err == nil {
		t.Fatal("enabling with no ranges must be refused")
	}
	if _, err := st.set(discoveryScanConfig{Enabled: true, Ranges: []string{"8.8.8.0/24"}}); err == nil {
		t.Fatal("public range must be refused")
	}

	out, err := st.set(discoveryScanConfig{Enabled: true, Ranges: []string{"10.20.0.0/24"}, Community: "s3cret", IntervalSec: 10})
	if err != nil {
		t.Fatalf("valid set: %v", err)
	}
	if out.IntervalSec != 60 {
		t.Fatalf("interval floor not applied: %d", out.IntervalSec)
	}
	// Blank community on re-save preserves the stored secret.
	out, err = st.set(discoveryScanConfig{Enabled: true, Ranges: []string{"10.20.0.0/24"}})
	if err != nil {
		t.Fatalf("re-save: %v", err)
	}
	if out.Community != "s3cret" {
		t.Fatalf("blank save must preserve community, got %q", out.Community)
	}
	// The public (GET) shape never leaks the secret.
	pub := out.public()
	if !pub.CommunitySet {
		t.Fatal("community_set should be true")
	}

	// A fresh store on the same path round-trips from disk.
	st2 := newDiscoveryConfigStore(dir+"/disc.json", nil)
	if got := st2.effective(); !got.Enabled || got.Community != "s3cret" || len(got.Ranges) != 1 {
		t.Fatalf("persistence round-trip wrong: %+v", got)
	}
}

func TestDiscoveryConfigEnvBootstrapFallback(t *testing.T) {
	t.Setenv("ENABLE_SNMP_DISCOVERY", "true")
	t.Setenv("SNMP_CIDR_RANGES", "10.9.0.0/24, 10.9.1.0/24")
	t.Setenv("SNMP_COMMUNITY", "lab")
	st := newDiscoveryConfigStore(t.TempDir()+"/none.json", nil)
	got := st.effective()
	if !got.Enabled || len(got.Ranges) != 2 || got.Community != "lab" {
		t.Fatalf("env fallback wrong: %+v", got)
	}
	// A console-saved config wins over env.
	if _, err := st.set(discoveryScanConfig{Enabled: false, Ranges: []string{"10.9.0.0/24"}}); err != nil {
		t.Fatalf("set: %v", err)
	}
	if got := st.effective(); got.Enabled {
		t.Fatal("stored config must override env bootstrap")
	}
}

// --- authz: the scan scope is platform-global plumbing (§3a) ---

func TestDiscoveryConfigHandlerRefusesTenantAdmin(t *testing.T) {
	srv, s := newTestServerState(t)
	s.discoveryCfg = newDiscoveryConfigStore(t.TempDir()+"/disc.json", nil)

	admin := login(t, srv, "admin", "Passw0rd!2345").Token

	// A tenant-scoped ADMIN holds full administration rights INSIDE its tenant —
	// exactly the §3a privilege-leak case: it must still never reach the
	// platform-global scan scope.
	st, b := do(t, srv, "POST", "/api/tenants", admin, map[string]any{"name": "Acme"})
	if st != 201 {
		t.Fatalf("create tenant: %d %s", st, b)
	}
	tenantID := idOf(t, b)
	if st, b = do(t, srv, "POST", "/api/users", admin, map[string]any{
		"username": "acme-admin", "password": "Passw0rd!2345", "role": "admin", "tenant_id": tenantID,
	}); st != 201 {
		t.Fatalf("create tenant admin: %d %s", st, b)
	}
	tenantTok := login(t, srv, "acme-admin", "Passw0rd!2345").Token

	cfg := map[string]any{"enabled": true, "ranges": []string{"10.20.0.0/24"}}
	if st, b = do(t, srv, "PUT", "/api/discovery/config", tenantTok, cfg); st != 403 && st != 404 {
		t.Fatalf("tenant admin must be refused (403/404), got %d: %s", st, b)
	}
	if st, b = do(t, srv, "GET", "/api/discovery/config", tenantTok, nil); st != 403 && st != 404 {
		t.Fatalf("tenant admin must not read the scan scope, got %d: %s", st, b)
	}
	if st, b = do(t, srv, "PUT", "/api/discovery/config", admin, cfg); st != 200 {
		t.Fatalf("platform admin should succeed, got %d: %s", st, b)
	}
	// The GET shape must not leak the community secret.
	st, b = do(t, srv, "GET", "/api/discovery/config", admin, nil)
	if st != 200 || strings.Contains(string(b), "s3cret") || strings.Contains(string(b), `"community"`) {
		t.Fatalf("GET must be redacted: %d %s", st, b)
	}
}

func TestSNMPSourceTriesCommunityList(t *testing.T) {
	// Mixed fleets use per-vendor communities; the sweep tries each in priority
	// order per host until one answers.
	cfg := discovery.ScanSettings{Enabled: true, Ranges: []string{"10.20.0.0/31"}, Community: "arista-public, srl-public"}
	src := discovery.NewSNMPSource(func() discovery.ScanSettings { return cfg }, nil)
	src.SetProbeForTest(func(_ context.Context, addr, community string) (string, string, string, bool) {
		if addr == "10.20.0.0" && community == "arista-public" {
			return "leaf-1", "arista", "", true
		}
		if addr == "10.20.0.1" && community == "srl-public" {
			return "spine-1", "nokia", "", true
		}
		return "", "", "", false
	})
	devs, err := src.Poll(context.Background())
	if err != nil {
		t.Fatalf("poll: %v", err)
	}
	if len(devs) != 2 || devs[0].Vendor != "arista" || devs[1].Vendor != "nokia" {
		t.Fatalf("community list not tried per host: %+v", devs)
	}
}

// Guard against a regression that reintroduces unbounded sweeps: the constants
// themselves are part of the security contract.
func TestDiscoveryBoundsContract(t *testing.T) {
	if discovery.MaxScanHosts > 4096 {
		t.Fatalf("discovery.MaxScanHosts raised to %d — review the scan-abuse implications before widening", discovery.MaxScanHosts)
	}
	if discovery.ScanCooldown < 30*time.Second {
		t.Fatalf("discovery.ScanCooldown lowered to %v — refresh endpoint becomes a scan-amplification lever", discovery.ScanCooldown)
	}
}
