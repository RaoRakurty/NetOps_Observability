package main

// seam_bootstrap.go — the seam bootstrap engine (#67 build ⑤, design
// cloud-ingestion.md §4.1, P1-required). An empty seam inventory makes the
// correlation engine's grounding gate ground against nothing (research C5), so
// this engine auto-suggests seam instances from telemetry the platform already
// collects. Owner reviews: suggest → confirm/edit → active.
//
// Four rules over today's sources, each a PURE function over fetched rows so
// the inference is unit-testable without infrastructure:
//   R1 traceroute ownership boundary  (probe paths: private→public transition)
//   R2 BGP neighbor metadata          (VictoriaMetrics device_bgp_peer_state)
//   R3 flow ingress/egress boundary   (ClickHouse netops.flows)
//   R4 tunnel discovery               (ClickHouse netops.tunnels)
// plus R5, redundancy-group inference over the resulting inventory (#68 §4:
// groups are instance-level topology — two DX at one site, a VPN shadowing a
// DX → "members of one group?").
//
// §4.1 names R1 an "ASN transition" rule: per-hop ASN data needs an external
// ASN database we deliberately do not bundle, so v0 detects the private→public
// ownership transition (which IS an ASN transition: ours → somebody else's)
// and splits DX vs DIA by destination + path stability. An ASN enrichment
// source upgrades the split later without changing the rule's contract.
//
// Suggestions are idempotent and rejections permanent — both enforced by the
// (tenant_id, suggestion_key) unique index (see seams.go Suggest). Every
// suggestion carries provenance: which rule, what evidence, what confidence.

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"netops/backend/collectors"
	"netops/backend/models"

	"netops/backend/chhttp"
)

// startSeamBootstrap launches the periodic suggestion loop. Postgres-only
// (the inventory is lifecycle state); on by default because the inventory is a
// P1-required input to grounding — disable with ENABLE_SEAM_BOOTSTRAP=false.
func (s *server) startSeamBootstrap(ctx context.Context) {
	if s.seams == nil {
		log.Printf("seam-bootstrap: disabled (requires Postgres backend)")
		return
	}
	if os.Getenv("ENABLE_SEAM_BOOTSTRAP") == "false" {
		log.Printf("seam-bootstrap: disabled by ENABLE_SEAM_BOOTSTRAP=false")
		return
	}
	interval := 10 * time.Minute
	if v := os.Getenv("SEAM_BOOTSTRAP_INTERVAL"); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d >= time.Minute {
			interval = d
		} else {
			log.Printf("seam-bootstrap: ignoring invalid SEAM_BOOTSTRAP_INTERVAL=%q (want ≥1m)", v)
		}
	}
	go func() {
		// Let collectors take their first samples before the first pass; jitter
		// the tick so restarts don't synchronize the fleet's CH/VM queries.
		timer := time.NewTimer(2 * time.Minute)
		defer timer.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-timer.C:
			}
			s.runSeamBootstrapOnce(ctx)
			timer.Reset(interval + time.Duration(rand.Int63n(int64(interval/10)+1))) // #nosec G404 -- jitter, not crypto
		}
	}()
}

// runSeamBootstrapOnce executes all rules over current telemetry. Each source
// is best-effort but never silent: a fetch failure is logged and the other
// rules still run (a dead VictoriaMetrics must not stop flow-based seams).
func (s *server) runSeamBootstrapOnce(ctx context.Context) {
	devices := s.discovery.Devices()
	var suggestions []Seam

	paths, err := seamFetchProbePaths(ctx)
	if err != nil {
		log.Printf("seam-bootstrap: traceroute source unavailable: %v", err)
	} else {
		suggestions = append(suggestions, ruleTracerouteBoundary(paths)...)
	}

	peers, err := seamFetchBGPPeers(ctx)
	if err != nil {
		log.Printf("seam-bootstrap: bgp source unavailable: %v", err)
	} else {
		suggestions = append(suggestions, ruleBGPPeers(peers, devices)...)
	}

	flowRows, err := seamFetchFlowBoundaries(ctx)
	if err != nil {
		log.Printf("seam-bootstrap: flow source unavailable: %v", err)
	} else {
		suggestions = append(suggestions, ruleFlowBoundary(flowRows)...)
	}

	tunnels, err := seamFetchTunnels(ctx)
	if err != nil {
		log.Printf("seam-bootstrap: tunnel source unavailable: %v", err)
	} else {
		tunnelSeams, tunnelGroups := ruleTunnels(tunnels, devices)
		suggestions = append(suggestions, tunnelSeams...)
		for _, g := range tunnelGroups {
			if _, err := s.seams.SuggestGroup(ctx, g); err != nil {
				log.Printf("seam-bootstrap: group suggest %s: %v", g.SuggestionKey, err)
			}
		}
	}

	inserted := 0
	for _, sg := range suggestions {
		ok, err := s.seams.Suggest(ctx, sg)
		if err != nil {
			log.Printf("seam-bootstrap: suggest %s: %v", sg.SuggestionKey, err)
			continue
		}
		if ok {
			inserted++
		}
	}

	// R5 runs over the inventory AFTER this cycle's seams land, so a first run
	// can already propose groups. Rejected/retired seams never join a group.
	groupsInserted := 0
	inv, err := s.seams.List(ctx, "", true, "", "")
	if err != nil {
		log.Printf("seam-bootstrap: inventory read for grouping: %v", err)
	} else {
		for _, g := range ruleRedundancyGroups(inv) {
			ok, err := s.seams.SuggestGroup(ctx, g)
			if err != nil {
				log.Printf("seam-bootstrap: group suggest %s: %v", g.SuggestionKey, err)
				continue
			}
			if ok {
				groupsInserted++
			}
		}
	}
	log.Printf("seam-bootstrap: cycle done candidates=%d new_seams=%d new_groups=%d", len(suggestions), inserted, groupsInserted)
}

// ── seam export (engine grounding context) ────────────────────────────────────

// startSeamEnrichment exports the ACTIVE seam inventory to the shared
// enrichment dir (the device_tenant.csv plane) so the correlation engine's
// grounding gate has its context without a new auth surface. Suggested/
// rejected/retired rows never export — only owner-activated seams ground.
func (s *server) startSeamEnrichment(ctx context.Context) {
	dir := os.Getenv("TENANT_ENRICHMENT_DIR")
	if dir == "" || s.seams == nil {
		return
	}
	write := func() {
		active, err := s.seams.List(ctx, "", true, "active", "")
		if err != nil {
			log.Printf("seam-enrichment: list: %v", err)
			return
		}
		type seamExport struct {
			SeamID            string            `json:"seam_id"`
			TenantID          string            `json:"tenant_id"`
			SeamType          string            `json:"seam_type"`
			Endpoints         map[string]string `json:"endpoints"`
			Visibility        string            `json:"visibility"`
			ControlPlaneOwner string            `json:"control_plane_owner"`
		}
		out := make([]seamExport, 0, len(active))
		for _, sm := range active {
			out = append(out, seamExport{
				SeamID: sm.SeamID, TenantID: sm.TenantID, SeamType: sm.SeamType,
				Endpoints: sm.Endpoints, Visibility: sm.Visibility,
				ControlPlaneOwner: sm.ControlPlaneOwner,
			})
		}
		data, err := json.Marshal(out)
		if err != nil {
			log.Printf("seam-enrichment: marshal: %v", err)
			return
		}
		if err := writeFileAtomic(filepath.Join(dir, "seams.json"), data, 0o644); err != nil {
			log.Printf("seam-enrichment: write: %v", err)
			return
		}
		log.Printf("seam-enrichment: exported %d active seam(s)", len(out))
	}
	go func() {
		write()
		t := time.NewTicker(60 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				write()
			}
		}
	}()
}

// ── R1: traceroute ownership boundary ─────────────────────────────────────────

// seamPrivateIP reports whether ip is enterprise-internal address space:
// RFC 1918 / ULA (ip.IsPrivate), CGNAT 100.64/10, loopback, link-local.
func seamPrivateIP(ip net.IP) bool {
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

// ruleTracerouteBoundary suggests one provider seam per traced destination
// whose path crosses from internal to external address space. Destination
// kind decides the candidate type: a public destination is a direct internet
// breakout (DIA); a private destination reached across public space means a
// provider underlay carries us back into private territory (DX candidate —
// colo/leased-line/cloud-interconnect semantics).
func ruleTracerouteBoundary(paths []collectors.PathResult) []Seam {
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
			if prev != nil && seamPrivateIP(prev) && !seamPrivateIP(ip) {
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
		if dstIP != nil && seamPrivateIP(dstIP) {
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
			Confidence:    clampConf(conf),
			SuggestionKey: "r1:" + p.Dst,
		})
	}
	return out
}

func clampConf(c float64) float64 {
	if c < 0.05 {
		return 0.05
	}
	if c > 0.95 {
		return 0.95
	}
	return c
}

// ── R2: BGP neighbor metadata ─────────────────────────────────────────────────

// seamBGPPeer is one device_bgp_peer_state series: the SNMP BGP4-MIB table walk
// emits {device, index=<peer ip>} with the FSM state as the value (6 = established).
type seamBGPPeer struct {
	Device string
	PeerIP string
	State  float64
}

// ruleBGPPeers suggests a carrier/cloud seam (DX/ER semantics) per eBGP-looking
// neighbor: a peer address that is not itself an inventory device. iBGP
// neighbors between our own devices are internal topology, not seams.
func ruleBGPPeers(peers []seamBGPPeer, devices []models.Device) []Seam {
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
			Confidence:    clampConf(conf),
			SuggestionKey: "r2:" + p.Device + ":" + p.PeerIP,
		})
	}
	return out
}

// ── R3: flow ingress/egress boundary ──────────────────────────────────────────

// seamFlowBoundary is one (exporter, WAN-side interface) aggregate of
// private↔public crossings from netops.flows.
type seamFlowBoundary struct {
	Sampler  string `json:"sampler"`
	WanIf    uint32 `json:"wan_if"`
	TenantID string `json:"tenant_id"`
	Crossing uint32 `json:"crossing"`
}

// ruleFlowBoundary suggests a breakout seam per exporter interface where
// private↔public crossings concentrate — the LAN/WAN ownership transition at
// that edge. Typed DIA: a sustained private↔public flow boundary is internet
// breakout semantics (a DX boundary shows up as private↔private and is R1/R2's
// job). Confidence scales with crossing volume.
func ruleFlowBoundary(rows []seamFlowBoundary) []Seam {
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
			Confidence:    clampConf(conf),
			SuggestionKey: "r3:" + r.Sampler + ":" + ifs,
		})
	}
	return out
}

// ── R4: tunnel discovery ──────────────────────────────────────────────────────

// seamTunnel is the latest netops.tunnels row per tunnel id.
type seamTunnel struct {
	ID          string `json:"id"`
	Type        string `json:"type"`
	LocalDevice string `json:"local_device"`
	LocalAddr   string `json:"local_addr"`
	RemoteAddr  string `json:"remote_addr"`
	Status      string `json:"status"`
	TenantID    string `json:"tenant_id"`
}

// ruleTunnels suggests a VPN seam per discovered overlay tunnel (the tunnel IS
// an ownership transition: the underlay between its endpoints belongs to
// somebody else). A device terminating ≥2 tunnels additionally suggests an
// SDWAN overlay seam plus a redundancy group over the per-tunnel members —
// multiple simultaneous overlays from one edge is the SD-WAN shape (#68 §4.1
// "overlay + each underlay it rides"; per-underlay members are what we can see
// without a controller integration).
func ruleTunnels(tunnels []seamTunnel, devices []models.Device) ([]Seam, []SeamGroup) {
	byName := make(map[string]models.Device, len(devices))
	for _, d := range devices {
		byName[d.Name] = d
		byName[d.ID] = d
	}
	var out []Seam
	perDevice := map[string][]seamTunnel{}
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
			Confidence:    clampConf(conf),
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
			members = append(members, SeamMember{MemberID: seamIDForKey(tenant, "r4:"+t.ID), Role: "member", SeamType: "VPN"})
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

// ruleRedundancyGroups proposes groups from the seam inventory itself (#68 §4):
// ≥2 DX seams sharing an on-prem endpoint → redundant circuits of one group;
// a VPN sharing an on-prem endpoint with a DX → hybrid fallback shadowing it.
// Rejected/retired seams never join a group.
func ruleRedundancyGroups(inventory []Seam) []SeamGroup {
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
func seamFetchProbePaths(ctx context.Context) ([]collectors.PathResult, error) {
	if collectors.RedisAddr() != "" {
		if raw, err := collectors.FetchProbePaths(ctx); err == nil && raw != "" {
			var out []collectors.PathResult
			if err := json.Unmarshal([]byte(raw), &out); err != nil {
				return nil, fmt.Errorf("redis paths decode: %w", err)
			}
			return out, nil
		}
	}
	if path := os.Getenv("PROBE_PATHS_FILE"); path != "" {
		// #nosec G304 -- operator-configured shared-volume path, not user input
		if data, err := os.ReadFile(path); err == nil {
			var out []collectors.PathResult
			if err := json.Unmarshal(data, &out); err != nil {
				return nil, fmt.Errorf("paths file decode: %w", err)
			}
			return out, nil
		}
	}
	return collectors.Paths.All(), nil
}

// seamFetchBGPPeers reads the current BGP peer table from VictoriaMetrics
// (SNMP BGP4-MIB walk: device_bgp_peer_state{device, index=<peer ip>}).
func seamFetchBGPPeers(ctx context.Context) ([]seamBGPPeer, error) {
	base := envOr("VICTORIA_URL", envOr("METRICS_URL", "http://victoria:8428"))
	endpoint := strings.TrimRight(base, "/") + "/api/v1/query?query=" + url.QueryEscape("device_bgp_peer_state")
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	resp, err := backendHTTPClient(10 * time.Second).Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("victoriametrics status %d", resp.StatusCode)
	}
	var out struct {
		Data struct {
			Result []struct {
				Metric map[string]string `json:"metric"`
				Value  [2]any            `json:"value"`
			} `json:"result"`
		} `json:"data"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 8<<20)).Decode(&out); err != nil {
		return nil, err
	}
	peers := make([]seamBGPPeer, 0, len(out.Data.Result))
	for _, r := range out.Data.Result {
		state := 0.0
		if s, ok := r.Value[1].(string); ok {
			_, _ = fmtSscanf(s, "%f", &state)
		}
		peers = append(peers, seamBGPPeer{
			Device: r.Metric["device"],
			PeerIP: r.Metric["index"],
			State:  state,
		})
	}
	return peers, nil
}

// seamCHQueryJSON runs a read-only ClickHouse query (FORMAT JSON) and decodes
// the data rows into dst. The bootstrap is a trusted internal reader, so it
// passes tenant_scope=__all__ like the report scheduler; per-row tenancy is
// preserved by carrying tenant_id through the rules into the suggestions.
func seamCHQueryJSON(ctx context.Context, sql string, dst any) error {
	body, err := chClientFor(envOr("CLICKHOUSE_URL", "http://clickhouse:8123")).Exec(ctx, chhttp.Request{
		SQL:        sql,
		Op:         "seam bootstrap query",
		Scope:      "__all__",
		LogComment: "worker:seam-bootstrap",
		Budget:     chWorkerBudget,
		MaxBytes:   chMaxResponseBytes,
	})
	if err != nil {
		return err
	}
	var wrapper struct {
		Data json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(body, &wrapper); err != nil {
		return err
	}
	return json.Unmarshal(wrapper.Data, dst)
}

// seamPrivateIPSQL classifies an address column as enterprise-internal in CH
// SQL, mirroring seamPrivateIP (IPv4 RFC 1918 + CGNAT; IPv6 ULA).
func seamPrivateIPSQL(col string) string {
	return `((isIPv4String(` + col + `) AND (isIPAddressInRange(` + col + `,'10.0.0.0/8') OR isIPAddressInRange(` + col + `,'172.16.0.0/12') OR isIPAddressInRange(` + col + `,'192.168.0.0/16') OR isIPAddressInRange(` + col + `,'100.64.0.0/10'))) OR (isIPv6String(` + col + `) AND isIPAddressInRange(` + col + `,'fc00::/7')))`
}

// seamFetchFlowBoundaries aggregates private↔public crossings per (exporter,
// WAN-side interface) over the last 24 h. The WAN side is out_if for egress
// crossings and in_if for ingress ones, so both directions attribute to the
// same physical boundary interface.
func seamFetchFlowBoundaries(ctx context.Context) ([]seamFlowBoundary, error) {
	srcPriv := seamPrivateIPSQL("src_addr")
	dstPriv := seamPrivateIPSQL("dst_addr")
	sql := `
SELECT sampler_address AS sampler,
       if(` + srcPriv + ` AND NOT ` + dstPriv + `, out_if, in_if) AS wan_if,
       tenant_id,
       toUInt32(count()) AS crossing
  FROM netops.flows
 WHERE ts > now() - INTERVAL 24 HOUR
   AND ` + srcPriv + ` != ` + dstPriv + `
 GROUP BY sampler, wan_if, tenant_id
HAVING crossing >= 50
 ORDER BY crossing DESC
 LIMIT 200
FORMAT JSON`
	ctx, cancel := context.WithTimeout(ctx, 25*time.Second)
	defer cancel()
	var rows []seamFlowBoundary
	if err := seamCHQueryJSON(ctx, sql, &rows); err != nil {
		return nil, err
	}
	return rows, nil
}

// seamFetchTunnels returns the latest netops.tunnels row per tunnel id.
func seamFetchTunnels(ctx context.Context) ([]seamTunnel, error) {
	sql := `
SELECT id, type, local_device, local_addr, remote_addr, status, tenant_id
  FROM netops.tunnels
 ORDER BY ts DESC
 LIMIT 1 BY id
 LIMIT 500
FORMAT JSON`
	ctx, cancel := context.WithTimeout(ctx, 25*time.Second)
	defer cancel()
	var rows []seamTunnel
	if err := seamCHQueryJSON(ctx, sql, &rows); err != nil {
		return nil, err
	}
	return rows, nil
}
