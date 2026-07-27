package main

// seam_bootstrap_test.go — unit tests for the seam bootstrap rules (#67 build
// ⑤). The rules are pure functions over fetched telemetry rows, so every
// inference is pinned without infrastructure: boundary detection, DX-vs-DIA
// split, iBGP exclusion, thresholds, group inference, rejection semantics,
// and the determinism the suggestion_key idempotency contract relies on.

import (
	"net"
	"netops/backend/internal/seam"
	"os"
	"strings"
	"testing"
	"time"

	"netops/backend/collectors"
	"netops/backend/models"
)

func TestSeamPrivateIP(t *testing.T) {
	cases := []struct {
		ip   string
		want bool
	}{
		{"10.1.2.3", true},
		{"172.16.0.1", true},
		{"172.32.0.1", false}, // outside 172.16/12
		{"192.168.255.1", true},
		{"100.64.0.1", true},   // CGNAT
		{"100.128.0.1", false}, // outside 100.64/10
		{"127.0.0.1", true},
		{"169.254.10.10", true}, // link-local
		{"8.8.8.8", false},
		{"203.0.113.7", false},
		{"fd00::1", true}, // ULA
		{"2001:db8::1", false},
	}
	for _, c := range cases {
		if got := seamPrivateIP(net.ParseIP(c.ip)); got != c.want {
			t.Errorf("seamPrivateIP(%s) = %v, want %v", c.ip, got, c.want)
		}
	}
	if seamPrivateIP(nil) {
		t.Error("nil IP must not classify as private")
	}
}

func pathOf(dst string, reached, changed bool, hops ...string) collectors.PathResult {
	p := collectors.PathResult{Dst: dst, Reached: reached, Changed: changed, TS: time.Now().UTC()}
	for _, h := range hops {
		p.Hops = append(p.Hops, collectors.Hop{IP: h})
	}
	return p
}

func TestRuleTracerouteBoundaryDIA(t *testing.T) {
	out := ruleTracerouteBoundary([]collectors.PathResult{
		pathOf("8.8.8.8", true, false, "10.0.0.1", "10.0.1.1", "203.0.113.1", "8.8.8.8"),
	})
	if len(out) != 1 {
		t.Fatalf("want 1 suggestion, got %d", len(out))
	}
	s := out[0]
	if s.SeamType != "DIA" {
		t.Errorf("public dst should suggest DIA, got %s", s.SeamType)
	}
	if s.SuggestionKey != "r1:8.8.8.8" {
		t.Errorf("unexpected key %q", s.SuggestionKey)
	}
	if s.Endpoints["on_prem"] != "10.0.1.1" || s.Endpoints["provider_edge"] != "203.0.113.1" {
		t.Errorf("boundary endpoints wrong: %v", s.Endpoints)
	}
	if s.Confidence <= 0.5 {
		t.Errorf("reached+stable path should raise confidence, got %v", s.Confidence)
	}
	if s.SuggestedBy != "traceroute_boundary" || s.Evidence["rule"] != "traceroute_boundary" {
		t.Error("provenance missing")
	}
}

func TestRuleTracerouteBoundaryDXPrivateFarSide(t *testing.T) {
	// Private dst reached across public space = provider underlay (DX candidate).
	out := ruleTracerouteBoundary([]collectors.PathResult{
		pathOf("10.200.0.5", true, false, "10.0.0.1", "198.51.100.1", "198.51.100.9", "10.200.0.5"),
	})
	if len(out) != 1 || out[0].SeamType != "DX" {
		t.Fatalf("private far side should suggest DX, got %+v", out)
	}
}

func TestRuleTracerouteBoundarySkipsAndSilentHops(t *testing.T) {
	out := ruleTracerouteBoundary([]collectors.PathResult{
		pathOf("10.0.9.9", true, false, "10.0.0.1", "10.0.1.1"), // never leaves private
		pathOf("", false, false),                                // empty
		// Silent hop ("") between private and public must not hide the boundary.
		pathOf("1.1.1.1", false, true, "10.0.0.1", "", "203.0.113.5"),
	})
	if len(out) != 1 {
		t.Fatalf("want only the crossing path, got %d", len(out))
	}
	if out[0].Endpoints["on_prem"] != "10.0.0.1" || out[0].Endpoints["provider_edge"] != "203.0.113.5" {
		t.Errorf("silent hop broke boundary detection: %v", out[0].Endpoints)
	}
	// Unreached + changed path: confidence dropped but clamped above zero.
	if c := out[0].Confidence; c <= 0 || c >= 0.5 {
		t.Errorf("unstable path confidence out of range: %v", c)
	}
}

func TestRuleBGPPeers(t *testing.T) {
	devices := []models.Device{
		{ID: "edge1", Name: "edge1", Address: "10.0.0.1", TenantID: "acme"},
		{ID: "core1", Name: "core1", Address: "10.0.0.2"},
	}
	out := ruleBGPPeers([]seamBGPPeer{
		{Device: "edge1", PeerIP: "10.0.0.2", State: 6},      // iBGP to inventory device → skip
		{Device: "edge1", PeerIP: "169.254.255.1", State: 6}, // provider peering, established
		{Device: "edge1", PeerIP: "203.0.113.33", State: 1},  // provider peering, down
		{Device: "edge1", PeerIP: "not-an-ip", State: 6},     // garbage label → skip
	}, devices)
	if len(out) != 2 {
		t.Fatalf("want 2 suggestions, got %d: %+v", len(out), out)
	}
	if out[0].SeamType != "DX" || out[0].TenantID != "acme" {
		t.Errorf("expected DX seam stamped with device tenant, got %+v", out[0])
	}
	if out[0].Confidence <= out[1].Confidence {
		t.Error("established peer must score higher than a down peer")
	}
	if out[0].SuggestionKey != "r2:edge1:169.254.255.1" {
		t.Errorf("unexpected key %q", out[0].SuggestionKey)
	}
}

func TestRuleFlowBoundary(t *testing.T) {
	out := ruleFlowBoundary([]seamFlowBoundary{
		{Sampler: "10.0.0.1", WanIf: 3, TenantID: "acme", Crossing: 5000},
		{Sampler: "10.0.0.2", WanIf: 7, Crossing: 60},
		{Sampler: "10.0.0.3", WanIf: 1, Crossing: 10}, // under threshold
		{Sampler: "", WanIf: 1, Crossing: 9999},       // no exporter identity
	})
	if len(out) != 2 {
		t.Fatalf("want 2 suggestions, got %d", len(out))
	}
	if out[0].Confidence <= out[1].Confidence {
		t.Error("confidence must scale with crossing volume")
	}
	if out[0].SeamType != "DIA" || out[0].SuggestionKey != "r3:10.0.0.1:3" {
		t.Errorf("unexpected suggestion %+v", out[0])
	}
	if out[0].TenantID != "acme" {
		t.Error("flow tenant must carry into the suggestion")
	}
}

func TestRuleTunnels(t *testing.T) {
	devices := []models.Device{{ID: "branch1", Name: "branch1", TenantID: "acme"}}
	seams, groups := ruleTunnels([]seamTunnel{
		{ID: "branch1/Tunnel1", Type: "ipsec", LocalDevice: "branch1", LocalAddr: "10.1.0.1", RemoteAddr: "198.51.100.1", Status: "up"},
		{ID: "branch1/Tunnel2", Type: "gre", LocalDevice: "branch1", RemoteAddr: "203.0.113.1", Status: "up"},
		{ID: "site2/Tunnel1", Type: "ipsec", LocalDevice: "site2", RemoteAddr: "198.51.100.9", Status: "down"},
		{ID: "", LocalDevice: "ghost"}, // no identity → skip
	}, devices)
	if len(seams) != 3 {
		t.Fatalf("want 3 tunnel seams, got %d", len(seams))
	}
	if seams[0].SeamType != "VPN" || seams[0].TenantID != "acme" {
		t.Errorf("tunnel seam wrong: %+v", seams[0])
	}
	if seams[0].Confidence <= seams[1].Confidence {
		t.Error("ipsec must score higher than gre")
	}
	// branch1 has 2 tunnels → one SDWAN overlay group; site2 has 1 → none.
	if len(groups) != 1 {
		t.Fatalf("want 1 group, got %d", len(groups))
	}
	g := groups[0]
	if g.SeamType != "SDWAN" || g.RedundancyModel != "active_active" || len(g.Members) != 2 {
		t.Errorf("unexpected group %+v", g)
	}
	if g.SuggestionKey != "r4g:branch1" {
		t.Errorf("unexpected group key %q", g.SuggestionKey)
	}
	// Member ids must reference the deterministic per-tunnel seam ids.
	if g.Members[0].MemberID != seam.IDForKey("", "r4:branch1/Tunnel1") {
		t.Errorf("group member does not reference tunnel seam id: %+v", g.Members[0])
	}
}

func TestRuleRedundancyGroups(t *testing.T) {
	inv := []seam.Seam{
		{SeamID: "sm-a", TenantID: "acme", SeamType: "DX", State: "active", Endpoints: map[string]string{"on_prem": "dallas-edge"}},
		{SeamID: "sm-b", TenantID: "acme", SeamType: "DX", State: "suggested", Endpoints: map[string]string{"on_prem": "dallas-edge"}},
		{SeamID: "sm-c", TenantID: "acme", SeamType: "VPN", State: "confirmed", Endpoints: map[string]string{"on_prem": "dallas-edge"}},
		{SeamID: "sm-d", TenantID: "acme", SeamType: "DX", State: "rejected", Endpoints: map[string]string{"on_prem": "austin-edge"}},
		{SeamID: "sm-e", TenantID: "acme", SeamType: "DIA", State: "active", Endpoints: map[string]string{"on_prem": "austin-edge"}},
		{SeamID: "sm-f", TenantID: "", SeamType: "DX", State: "active"}, // no on_prem → ungroupable
	}
	groups := ruleRedundancyGroups(inv)
	if len(groups) != 2 {
		t.Fatalf("want dx-redundancy + hybrid at dallas-edge only, got %d: %+v", len(groups), groups)
	}
	var dx, hybrid *seam.SeamGroup
	for i := range groups {
		switch groups[i].RedundancyModel {
		case "active_active":
			dx = &groups[i]
		case "hybrid_fallback":
			hybrid = &groups[i]
		}
	}
	if dx == nil || len(dx.Members) != 2 {
		t.Fatalf("dx group wrong: %+v", dx)
	}
	if hybrid == nil || len(hybrid.Members) != 3 {
		t.Fatalf("hybrid group wrong: %+v", hybrid)
	}
	// DX members lead as primary, the VPN shadows as fallback (#68 §4).
	rolesSeen := map[string]int{}
	for _, m := range hybrid.Members {
		rolesSeen[m.Role]++
	}
	if rolesSeen["primary"] != 2 || rolesSeen["fallback"] != 1 {
		t.Errorf("hybrid roles wrong: %v", rolesSeen)
	}
}

func TestRuleRedundancyGroupsDeterministic(t *testing.T) {
	inv := []seam.Seam{
		{SeamID: "s1", SeamType: "DX", State: "active", Endpoints: map[string]string{"on_prem": "b"}},
		{SeamID: "s2", SeamType: "DX", State: "active", Endpoints: map[string]string{"on_prem": "b"}},
		{SeamID: "s3", SeamType: "DX", State: "active", Endpoints: map[string]string{"on_prem": "a"}},
		{SeamID: "s4", SeamType: "DX", State: "active", Endpoints: map[string]string{"on_prem": "a"}},
	}
	first := ruleRedundancyGroups(inv)
	for i := 0; i < 5; i++ {
		again := ruleRedundancyGroups(inv)
		if len(again) != len(first) {
			t.Fatal("non-deterministic group count")
		}
		for j := range again {
			if again[j].SuggestionKey != first[j].SuggestionKey {
				t.Fatal("non-deterministic group order")
			}
		}
	}
}

// ── lifecycle / normalization ─────────────────────────────────────────────────

func TestSeamMigrationContract(t *testing.T) {
	sql, err := os.ReadFile("migrations/0010_seam_inventory.sql")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"CREATE UNIQUE INDEX IF NOT EXISTS seams_suggestion_key_idx",
		"WHERE suggestion_key <> ''",
		"ALTER TABLE seams FORCE ROW LEVEL SECURITY",
		"ALTER TABLE seam_groups FORCE ROW LEVEL SECURITY",
		"'DX','VPN','SDWAN','DIA','CLOUD_BACKBONE'",
		"'single','active_active','active_standby','hybrid_fallback'",
		"'suggested','confirmed','active','rejected','retired'",
	} {
		if !strings.Contains(string(sql), want) {
			t.Errorf("migration missing contract clause: %s", want)
		}
	}
}
