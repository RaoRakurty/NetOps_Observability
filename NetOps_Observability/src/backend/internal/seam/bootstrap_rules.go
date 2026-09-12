// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package seam

// bootstrap_rules.go — the seam SUGGESTION rules R1–R5 (Phase-2 W2.4,
// extracted from package main's seam_bootstrap.go): traceroute boundary
// detection, BGP peering seams, flow-boundary seams, tunnel seams with their
// redundancy groups, and the private-IP predicate + its SQL twin. Pure over
// collectors.PathResult / models.Device / the row types the fetchers decode
// into — the fetchers, the bootstrap loop and the enrichment exporter stay in
// main (they hold the CH transport and srv).

import (
	"fmt"
	"net"
	"sort"
	"strings"
	"time"

	"netops/backend/collectors"
	"netops/backend/models"
)

// PrivateIP reports whether ip is enterprise-internal address space:
// RFC 1918 / ULA (ip.IsPrivate), CGNAT 100.64/10, loopback, link-local.
func PrivateIP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	if ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
		return true
	}
	if v4 := ip.To4(); v4 != nil {
		if v4[0] == 100 && v4[1] >= 64 && v4[1] <= 127 { // CGNAT 100.64.0.0/10
			return true
		}
	}
	return false
}

// RuleTracerouteBoundary suggests one provider seam per traced destination
// whose path crosses from internal to external address space. Destination
// kind decides the candidate type: a public destination is a direct internet
// breakout (DIA); a private destination reached across public space means a
// provider underlay carries us back into private territory (DX candidate —
// colo/leased-line/cloud-interconnect semantics).
func RuleTracerouteBoundary(paths []collectors.PathResult) []Seam {
	var out []Seam
	for _, p := range paths {
		if len(p.Hops) == 0 {
			continue
		}
		// First private→public transition along the hop list, skipping
		// silent hops (IP == "" when a TTL got no reply).
		lastPrivate, firstPublic := "", ""
		boundaryTTL := 0
		var prev net.IP
		prevIPStr := ""
		for i, h := range p.Hops {
			ip := net.ParseIP(h.IP)
			if ip == nil {
				continue
			}
			if prev != nil && PrivateIP(prev) && !PrivateIP(ip) {
				lastPrivate, firstPublic = prevIPStr, h.IP
				boundaryTTL = i + 1
				break
			}
			prev, prevIPStr = ip, h.IP
		}
		if firstPublic == "" {
			continue // never left internal space (or path was all-silent)
		}
		dstIP := net.ParseIP(p.Dst)
		seamType := "DIA"
		if dstIP != nil && PrivateIP(dstIP) {
			seamType = "DX"
		}
		conf := 0.5
		if p.Reached {
			conf += 0.15
		}
		if p.Changed {
			conf -= 0.15 // unstable path: weaker DX evidence, still a seam hint
		}
		owner := "isp"
		name := fmt.Sprintf("Internet breakout toward %s", p.Dst)
		if seamType == "DX" {
			owner = "enterprise" // deterministic backbone is enterprise-contracted; owner edits if carrier-managed
			name = fmt.Sprintf("Provider underlay toward %s", p.Dst)
		}
		out = append(out, Seam{
			TenantID:          "", // probe paths are platform vantage measurements
			SeamType:          seamType,
			DisplayName:       name,
			Endpoints:         map[string]string{"on_prem": lastPrivate, "provider_edge": firstPublic, "dst": p.Dst},
			ControlPlaneOwner: owner,
			SuggestedBy:       "traceroute_boundary",
			Evidence: map[string]any{
				"rule":         "traceroute_boundary",
				"dst":          p.Dst,
				"boundary_ttl": boundaryTTL,
				"last_private": lastPrivate,
				"first_public": firstPublic,
				"path_reached": p.Reached,
				"path_changed": p.Changed,
				"hop_count":    len(p.Hops),
				"observed_at":  p.TS.UTC().Format(time.RFC3339),
			},
			Confidence:    ClampConf(conf),
			SuggestionKey: "r1:" + p.Dst,
		})
	}
	return out
}

func ClampConf(c float64) float64 {
	if c < 0.05 {
		return 0.05
	}
	if c > 0.95 {
		return 0.95
	}
	return c
}

// ── R2: BGP neighbor metadata ─────────────────────────────────────────────────

// BGPPeer is one device_bgp_peer_state series: the SNMP BGP4-MIB table walk
// emits {device, index=<peer ip>} with the FSM state as the value (6 = established).
type BGPPeer struct {
	Device string
	PeerIP string
	State  float64
}

// RuleBGPPeers suggests a carrier/cloud seam (DX/ER semantics) per eBGP-looking
// neighbor: a peer address that is not itself an inventory device. iBGP
// neighbors between our own devices are internal topology, not seams.
func RuleBGPPeers(peers []BGPPeer, devices []models.Device) []Seam {
	known := make(map[string]models.Device, len(devices))
	byName := make(map[string]models.Device, len(devices))
	for _, d := range devices {
		if d.Address != "" {
			known[d.Address] = d
		}
		byName[d.Name] = d
		byName[d.ID] = d
	}
	var out []Seam
	for _, p := range peers {
		if p.PeerIP == "" || net.ParseIP(p.PeerIP) == nil {
			continue
		}
		if _, internal := known[p.PeerIP]; internal {
			continue // iBGP between inventory devices
		}
		established := p.State == 6
		conf := 0.5
		if established {
			conf += 0.15
		}
		tenant := ""
		if d, ok := byName[p.Device]; ok {
			tenant = d.TenantID
		}
		out = append(out, Seam{
			TenantID:          tenant,
			SeamType:          "DX",
			DisplayName:       fmt.Sprintf("BGP provider seam %s ↔ %s", p.Device, p.PeerIP),
			Endpoints:         map[string]string{"on_prem": p.Device, "provider_edge": p.PeerIP},
			ControlPlaneOwner: "enterprise",
			SuggestedBy:       "bgp_peer",
			Evidence: map[string]any{
				"rule":        "bgp_peer",
				"device":      p.Device,
				"peer":        p.PeerIP,
				"established": established,
				"fsm_state":   p.State,
			},
			Confidence:    ClampConf(conf),
			SuggestionKey: "r2:" + p.Device + ":" + p.PeerIP,
		})
	}
	return out
}

// ── R3: flow ingress/egress boundary ──────────────────────────────────────────

// FlowBoundary is one (exporter, WAN-side interface) aggregate of
// private↔public crossings from netops.flows.
type FlowBoundary struct {
	Sampler  string `json:"sampler"`
	WanIf    uint32 `json:"wan_if"`
	TenantID string `json:"tenant_id"`
	Crossing uint32 `json:"crossing"`
}

// RuleFlowBoundary suggests a breakout seam per exporter interface where
// private↔public crossings concentrate — the LAN/WAN ownership transition at
// that edge. Typed DIA: a sustained private↔public flow boundary is internet
// breakout semantics (a DX boundary shows up as private↔private and is R1/R2's
// job). Confidence scales with crossing volume.
func RuleFlowBoundary(rows []FlowBoundary) []Seam {
	var out []Seam
	for _, r := range rows {
		if r.Sampler == "" || r.Crossing < 50 {
			continue
		}
		conf := 0.45
		if r.Crossing >= 1000 {
			conf = 0.65
		} else if r.Crossing >= 250 {
			conf = 0.55
		}
		ifs := fmt.Sprintf("%d", r.WanIf)
		out = append(out, Seam{
			TenantID:          r.TenantID,
			SeamType:          "DIA",
			DisplayName:       fmt.Sprintf("WAN boundary %s if%s", r.Sampler, ifs),
			Endpoints:         map[string]string{"on_prem": r.Sampler, "interface": ifs},
			ControlPlaneOwner: "isp",
			SuggestedBy:       "flow_boundary",
			Evidence: map[string]any{
				"rule":           "flow_boundary",
				"sampler":        r.Sampler,
				"interface":      r.WanIf,
				"crossing_flows": r.Crossing,
				"window":         "24h",
			},
			Confidence:    ClampConf(conf),
			SuggestionKey: "r3:" + r.Sampler + ":" + ifs,
		})
	}
	return out
}

// ── R4: tunnel discovery ──────────────────────────────────────────────────────

// Tunnel is the latest netops.tunnels row per tunnel id.
type Tunnel struct {
	ID          string `json:"id"`
	Type        string `json:"type"`
	LocalDevice string `json:"local_device"`
	LocalAddr   string `json:"local_addr"`
	RemoteAddr  string `json:"remote_addr"`
	Status      string `json:"status"`
	TenantID    string `json:"tenant_id"`
}

// RuleTunnels suggests a VPN seam per discovered overlay tunnel (the tunnel IS
// an ownership transition: the underlay between its endpoints belongs to
// somebody else). A device terminating ≥2 tunnels additionally suggests an
// SDWAN overlay seam plus a redundancy group over the per-tunnel members —
// multiple simultaneous overlays from one edge is the SD-WAN shape (#68 §4.1
// "overlay + each underlay it rides"; per-underlay members are what we can see
// without a controller integration).
func RuleTunnels(tunnels []Tunnel, devices []models.Device) ([]Seam, []SeamGroup) {
	byName := make(map[string]models.Device, len(devices))
	for _, d := range devices {
		byName[d.Name] = d
		byName[d.ID] = d
	}
	var out []Seam
	perDevice := map[string][]Tunnel{}
	for _, t := range tunnels {
		if t.ID == "" || t.LocalDevice == "" {
			continue
		}
		perDevice[t.LocalDevice] = append(perDevice[t.LocalDevice], t)
		conf := 0.55
		if strings.EqualFold(t.Type, "ipsec") {
			conf = 0.7
		}
		tenant := t.TenantID
		if tenant == "" {
			if d, ok := byName[t.LocalDevice]; ok {
				tenant = d.TenantID
			}
		}
		remote := t.RemoteAddr
		if remote == "" {
			remote = "unknown"
		}
		out = append(out, Seam{
			TenantID:          tenant,
			SeamType:          "VPN",
			DisplayName:       fmt.Sprintf("Tunnel %s → %s", t.ID, remote),
			Endpoints:         map[string]string{"on_prem": t.LocalDevice, "local": t.LocalAddr, "remote": t.RemoteAddr},
			ControlPlaneOwner: "enterprise",
			SuggestedBy:       "tunnel_discovery",
			Evidence: map[string]any{
				"rule":      "tunnel_discovery",
				"tunnel_id": t.ID,
				"type":      t.Type,
				"status":    t.Status,
			},
			Confidence:    ClampConf(conf),
			SuggestionKey: "r4:" + t.ID,
		})
	}

	var groups []SeamGroup
	devNames := make([]string, 0, len(perDevice))
	for name := range perDevice {
		devNames = append(devNames, name)
	}
	sort.Strings(devNames) // deterministic output order for tests/replay
	for _, dev := range devNames {
		ts := perDevice[dev]
		if len(ts) < 2 {
			continue
		}
		tenant := ts[0].TenantID
		members := make([]SeamMember, 0, len(ts))
		ids := make([]string, 0, len(ts))
		for _, t := range ts {
			// Roles are owner-assigned at confirm; bootstrap cannot honestly
			// rank primaries, so members enter unranked.
			members = append(members, SeamMember{MemberID: IDForKey(tenant, "r4:"+t.ID), Role: "member", SeamType: "VPN"})
			ids = append(ids, t.ID)
		}
		groups = append(groups, SeamGroup{
			TenantID:        tenant,
			SeamType:        "SDWAN",
			RedundancyModel: "active_active",
			DisplayName:     fmt.Sprintf("SD-WAN overlay at %s (%d tunnels)", dev, len(ts)),
			Members:         members,
			SuggestedBy:     "tunnel_discovery",
			Evidence: map[string]any{
				"rule":    "tunnel_discovery",
				"device":  dev,
				"tunnels": ids,
			},
			Confidence:    0.45,
			SuggestionKey: "r4g:" + dev,
		})
	}
	return out, groups
}

// ── R5: redundancy-group inference over the inventory ─────────────────────────

// RuleRedundancyGroups proposes groups from the seam inventory itself (#68 §4):
// ≥2 DX seams sharing an on-prem endpoint → redundant circuits of one group;
// a VPN sharing an on-prem endpoint with a DX → hybrid fallback shadowing it.
// Rejected/retired seams never join a group.
func RuleRedundancyGroups(inventory []Seam) []SeamGroup {
	type bucket struct {
		dx, vpn []Seam
		tenant  string
	}
	buckets := map[string]*bucket{}
	for _, s := range inventory {
		if s.State == "rejected" || s.State == "retired" {
			continue
		}
		site := s.Endpoints["on_prem"]
		if site == "" {
			continue
		}
		key := s.TenantID + "|" + site
		b := buckets[key]
		if b == nil {
			b = &bucket{tenant: s.TenantID}
			buckets[key] = b
		}
		switch s.SeamType {
		case "DX":
			b.dx = append(b.dx, s)
		case "VPN":
			b.vpn = append(b.vpn, s)
		}
	}
	keys := make([]string, 0, len(buckets))
	for k := range buckets {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var out []SeamGroup
	for _, k := range keys {
		b := buckets[k]
		site := strings.SplitN(k, "|", 2)[1]
		if len(b.dx) >= 2 {
			members := make([]SeamMember, 0, len(b.dx))
			for _, s := range b.dx {
				members = append(members, SeamMember{MemberID: s.SeamID, Role: "member", SeamType: "DX"})
			}
			out = append(out, SeamGroup{
				TenantID:        b.tenant,
				SeamType:        "DX",
				RedundancyModel: "active_active",
				DisplayName:     fmt.Sprintf("Redundant DX at %s (%d circuits)", site, len(b.dx)),
				Members:         members,
				SuggestedBy:     "redundancy_group",
				Evidence:        map[string]any{"rule": "redundancy_group", "site": site, "dx_count": len(b.dx)},
				Confidence:      0.4,
				SuggestionKey:   "r5:" + site + ":dx",
			})
		}
		if len(b.dx) >= 1 && len(b.vpn) >= 1 {
			members := make([]SeamMember, 0, len(b.dx)+len(b.vpn))
			for _, s := range b.dx {
				members = append(members, SeamMember{MemberID: s.SeamID, Role: "primary", SeamType: "DX"})
			}
			for _, s := range b.vpn {
				// Cross-type fallback member: while carrying traffic it
				// inherits the WORSE visibility class (#68 §4) — the engine
				// enforces that; here we just record the shape.
				members = append(members, SeamMember{MemberID: s.SeamID, Role: "fallback", SeamType: "VPN"})
			}
			out = append(out, SeamGroup{
				TenantID:        b.tenant,
				SeamType:        "DX",
				RedundancyModel: "hybrid_fallback",
				DisplayName:     fmt.Sprintf("DX + VPN fallback at %s", site),
				Members:         members,
				SuggestedBy:     "redundancy_group",
				Evidence:        map[string]any{"rule": "redundancy_group", "site": site, "dx_count": len(b.dx), "vpn_count": len(b.vpn)},
				Confidence:      0.5,
				SuggestionKey:   "r5:" + site + ":hybrid",
			})
		}
	}
	return out
}

// ── fetchers (IO; thin, each with explicit timeout) ───────────────────────────

// seamFetchProbePaths reads the traceroute path store the same way
// handleProbePaths serves it: Redis (sidecar prober) → shared file → in-process.
func PrivateIPSQL(col string) string {
	return `((isIPv4String(` + col + `) AND (isIPAddressInRange(` + col + `,'10.0.0.0/8') OR isIPAddressInRange(` + col + `,'172.16.0.0/12') OR isIPAddressInRange(` + col + `,'192.168.0.0/16') OR isIPAddressInRange(` + col + `,'100.64.0.0/10'))) OR (isIPv6String(` + col + `) AND isIPAddressInRange(` + col + `,'fc00::/7')))`
}

// seamFetchFlowBoundaries aggregates private↔public crossings per (exporter,
// WAN-side interface) over the last 24 h. The WAN side is out_if for egress
// crossings and in_if for ingress ones, so both directions attribute to the
// same physical boundary interface.
