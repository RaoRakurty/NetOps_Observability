// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package topology

// summary.go — the WHOLE-NETWORK reading of a projected view (Iris
// get_network_topology). Pure: no I/O.
//
// The canvas draws a view; an operator asking "explain the network topology"
// needs the same view READ in network terms: which roles and sites there are,
// what is physically adjacent to what (LLDP / CDP / BGP-LS / IGP links), and —
// when an SD-WAN overlay is present — its shape (full mesh, hub and spoke,
// partial mesh), the transports it rides on, and which pairs hold no tunnel.
//
// HONESTY RULES this fold keeps:
//
//   - Every count and adjacency is something the view OBSERVED. The overlay
//     SHAPE and each role's "likely function" are INFERENCES, and the summary
//     carries them in separate fields so the caller can mark them DERIVED.
//   - An empty input is not "an isolated network": Collected=false says the
//     inventory has nothing yet, and a view without adjacency evidence keeps
//     its Degraded lines as notes.
//   - No management address leaves here: Node.MgmtIP is never read, and a
//     label that IS an IP address (an unnamed device, an unresolved neighbour
//     known only by its chassis address) is replaced by a neutral name.
//
// Multi-vendor: nothing below keys on a vendor. Roles come from the
// discovery-driven classifier (roles.go), adjacencies from whichever protocol
// confirmed them, and the overlay from the BFD pairs the collector and the
// SD-WAN manager integrations publish.
//
// §3a: the caller hands in a view already scoped to the principal and pairs
// already restricted to that principal's devices (OverlayPairs); this fold adds
// nothing it was not given.

import (
	"fmt"
	"math"
	"net"
	"sort"
	"strings"

	"netops/backend/collectors"
)

// Overlay shape hints. They describe the observed pair graph; they are a
// reading, not a configuration fact.
const (
	ShapeFullMesh    = "full_mesh"
	ShapeHubAndSpoke = "hub_and_spoke"
	ShapePartialMesh = "partial_mesh"
	ShapeUnknown     = "unknown"
)

// Summary bounds: what one answer carries. The totals always carry the true
// count, so a cut is visible.
const (
	SummaryMaxDevices     = 40
	SummaryMaxLinks       = 30
	SummaryMaxMissing     = 12
	SummaryMaxNotUp       = 10
	SummaryMaxRoleMembers = 8
	SummaryMaxTransports  = 8
	summaryFullMeshMin    = 0.9
)

// OverlayPair is one pair of overlay members that hold sessions, folded across
// both reporting ends and every colour pair.
type OverlayPair struct {
	A, B     string // device ids, A < B
	Colors   []string
	Sessions int
	Up       int
}

// OverlayPairs reconstructs every observed overlay pair among the CALLER'S
// devices from the published per-device facts and the inference's resolved
// system-ip owners (OverlayResult.SystemIPs). devTenant must hold only the
// devices the principal can see: a peer whose owner is not in it (another
// tenant's device, or one this caller may not see) contributes nothing.
func OverlayPairs(facts map[string]collectors.OverlayDeviceFacts, systemIPs map[string]map[string]string, devTenant map[string]string) []OverlayPair {
	type agg struct {
		colors    map[string]bool
		sessions  int
		up        int
		reporters int
	}
	byKey := map[[2]string]*agg{}
	for dev, f := range facts {
		t, ok := devTenant[dev]
		if !ok {
			continue
		}
		owners := systemIPs[t]
		for _, p := range f.Peers {
			other := owners[p.SystemIP]
			if other == "" || other == dev {
				continue
			}
			if ot, ok := devTenant[other]; !ok || ot != t {
				continue
			}
			k := [2]string{dev, other}
			if k[1] < k[0] {
				k[0], k[1] = k[1], k[0]
			}
			a := byKey[k]
			if a == nil {
				a = &agg{colors: map[string]bool{}}
				byKey[k] = a
			}
			a.reporters++
			for _, cp := range p.ColorPairs {
				if cp.LocalColor != "" {
					a.colors[cp.LocalColor] = true
				}
				if cp.RemoteColor != "" {
					a.colors[cp.RemoteColor] = true
				}
				a.sessions += cp.Sessions
				a.up += cp.Up
			}
		}
	}
	out := make([]OverlayPair, 0, len(byKey))
	for k, a := range byKey {
		cs := make([]string, 0, len(a.colors))
		for c := range a.colors {
			cs = append(cs, c)
		}
		sort.Strings(cs)
		out = append(out, OverlayPair{A: k[0], B: k[1], Colors: cs, Sessions: a.sessions, Up: a.up})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].A != out[j].A {
			return out[i].A < out[j].A
		}
		return out[i].B < out[j].B
	})
	return out
}

// SummaryInput is one principal's projected view plus its overlay pairs.
type SummaryInput struct {
	View View
	// Pairs are the caller's observed overlay pairs (OverlayPairs). nil with
	// OverlayRead=false means the overlay has not been read since the process
	// started; nil with OverlayRead=true means it was read and holds no pair.
	Pairs       []OverlayPair
	OverlayRead bool
}

// SummaryCount is one name with its count.
type SummaryCount struct {
	Name  string
	Count int
}

// SummaryDevice is one device as the summary reports it.
type SummaryDevice struct {
	ID             string
	Name           string
	Role           string // canonical device role, "" when the classifier could not tell
	RoleConfidence string
	Vendor         string
	Model          string
	Site           string
	Health         string
	Adjacencies    int // physical / routed adjacencies in the view
	OverlayPeers   int // overlay members it holds sessions with
	// Protocols are the protocols the device is SEEN to run, from adjacency
	// evidence (lldp, cdp, isis, ospf from a BGP-LS link's origin, overlay,
	// bfd) — never inferred from its role (summary_design.go).
	Protocols []string
}

// SummaryLink is one physical or routed adjacency.
type SummaryLink struct {
	A, APort string
	B, BPort string
	Protocol string
	Status   string
	External bool // B is a neighbour outside the managed inventory
}

// TransportSummary is one overlay transport (an SD-WAN colour).
type TransportSummary struct {
	Name     string
	Members  int
	Sessions int
	Up       int
	Health   string
}

// PairName names an overlay pair without a tunnel.
type PairName struct {
	A, B     string
	SameSite bool
	Site     string
}

// PairStatus is an overlay pair whose sessions are not all up.
type PairStatus struct {
	A, B     string
	Status   string // down | degraded
	Sessions int
	Up       int
	Colors   []string
}

// OverlaySummary is the overlay read in network terms.
type OverlaySummary struct {
	Members          int
	Pairs            int // observed pairs between members
	PossiblePairs    int // pairs that could hold tunnels (same-site pairs excluded when both sites are known)
	SameSitePairs    int // member pairs inside one site (normally no tunnel between them)
	Shape            string
	Hubs             []string
	Transports       []TransportSummary
	Missing          []PairName // cross-site pairs with no observed tunnel
	MissingTotal     int
	SameSiteNoTunnel []PairName // same-site pairs with no tunnel (expected)
	NotUp            []PairStatus
	NotUpTotal       int
	// SitesOnOneTransport are the sites whose edges ride a single transport.
	SitesOnOneTransport []string
}

// RoleNote is a role's members and its likely network function. Likely is an
// INFERENCE from the role classification, never read from configuration.
type RoleNote struct {
	Role         string
	Members      []string
	MembersTotal int
	Likely       string
}

// NetworkSummary is the whole-network reading of one principal's view.
type NetworkSummary struct {
	Collected     bool // the view holds at least one managed device
	Devices       []SummaryDevice
	DevicesTotal  int
	Roles         []SummaryCount
	Sites         []SummaryCount
	Vendors       []SummaryCount
	Links         []SummaryLink
	LinksTotal    int
	LinkProtocols []SummaryCount
	External      int // distinct neighbours outside the managed inventory
	Overlay       *OverlaySummary
	RoleNotes     []RoleNote
	Notes         []string

	// ── design reading (summary_design.go) ──
	SiteDetails      []SiteSummary
	SitesTotal       int
	RedundancyGroups []RedundancyGroup
	RedundancyTotal  int
	RedundancyNote   string
	SPOF             []SPOFItem // DERIVED: over discovered adjacencies only
	SPOFTotal        int
	SPOFState        string // present | none | unknown
	Coverage         SummaryCoverage
	CoverageState    string // full | partial
}

// Summarize reads a projected view (and the overlay pairs) in network terms.
func Summarize(in SummaryInput) NetworkSummary {
	out := NetworkSummary{}
	v := in.View

	names := map[string]string{}
	managed := map[string]bool{}
	var devNodes []Node
	unnamed := 0
	for _, n := range v.Nodes {
		switch n.Kind {
		case KindWAN, KindSite, KindCloud:
			continue
		case KindUnresolved:
			continue
		}
		if strings.HasPrefix(n.ID, "ext:") {
			continue
		}
		managed[n.ID] = true
		devNodes = append(devNodes, n)
	}
	sort.Slice(devNodes, func(i, j int) bool { return devNodes[i].ID < devNodes[j].ID })
	for _, n := range devNodes {
		names[n.ID] = safeName(n.Label, n.ID, &unnamed)
	}
	extName := func(id, label string) string {
		if nm, ok := names[id]; ok {
			return nm
		}
		nm := safeName(strings.TrimPrefix(firstNonEmptyStr(label, id), "ext:"), "", &unnamed)
		names[id] = nm
		return nm
	}
	nodeLabel := map[string]string{}
	for _, n := range v.Nodes {
		nodeLabel[n.ID] = n.Label
	}

	out.Collected = len(devNodes) > 0
	out.DevicesTotal = len(devNodes)

	// ── physical / routed adjacencies ───────────────────────────────────────
	adj := map[string]int{}
	protos := map[string]int{}
	ext := map[string]bool{}
	var links []SummaryLink
	var designEdges []Edge
	for _, e := range v.Edges {
		if e.Relationship != RelConnectedTo && e.Relationship != RelRoutedAdjacency {
			continue
		}
		if !managed[e.Source] && !managed[e.Target] {
			continue
		}
		a, b, ap, bp := e.Source, e.Target, e.SourcePort, e.TargetPort
		if !managed[a] {
			a, b, ap, bp = b, a, bp, ap
		}
		external := !managed[b]
		if external {
			ext[b] = true
		}
		adj[a]++
		if !external {
			adj[b]++
		}
		designEdges = append(designEdges, e)
		proto := firstNonEmptyStr(e.Protocol, "observed")
		protos[proto]++
		links = append(links, SummaryLink{
			A: names[a], APort: safePort(ap), B: extName(b, nodeLabel[b]), BPort: safePort(bp),
			Protocol: proto, Status: firstNonEmptyStr(e.Status, StatusUnknown), External: external,
		})
	}
	sort.SliceStable(links, func(i, j int) bool {
		if links[i].External != links[j].External {
			return !links[i].External // managed↔managed first
		}
		if links[i].A != links[j].A {
			return links[i].A < links[j].A
		}
		return links[i].B < links[j].B
	})
	out.LinksTotal = len(links)
	if len(links) > SummaryMaxLinks {
		links = links[:SummaryMaxLinks]
	}
	out.Links = links
	out.LinkProtocols = sortedCounts(protos)
	out.External = len(ext)

	// ── overlay ─────────────────────────────────────────────────────────────
	site := map[string]string{}
	for _, n := range devNodes {
		site[n.ID] = n.Site
	}
	peers := map[string]int{}
	var visPairs []OverlayPair
	if in.OverlayRead || len(in.Pairs) > 0 {
		for _, p := range in.Pairs {
			if managed[p.A] && managed[p.B] {
				visPairs = append(visPairs, p)
				peers[p.A]++
				peers[p.B]++
			}
		}
		if len(visPairs) > 0 {
			out.Overlay = summarizeOverlay(visPairs, site, names, v)
		}
	}

	// ── devices, roles, sites, vendors ──────────────────────────────────────
	roles, sites, vendors := map[string]int{}, map[string]int{}, map[string]int{}
	roleMembers := map[string][]string{}
	for _, n := range devNodes {
		role := n.DeviceRole
		if role == DevRoleUnknown {
			role = ""
		}
		d := SummaryDevice{
			ID: n.ID, Name: names[n.ID], Role: role, RoleConfidence: n.RoleConfidence,
			Vendor: n.Vendor, Model: n.Model, Site: n.Site, Health: n.Health,
			Adjacencies: adj[n.ID], OverlayPeers: peers[n.ID],
		}
		out.Devices = append(out.Devices, d)
		roles[firstNonEmptyStr(role, "unclassified")]++
		if n.Site != "" {
			sites[n.Site]++
		}
		if n.Vendor != "" {
			vendors[n.Vendor]++
		}
		if role != "" {
			roleMembers[role] = append(roleMembers[role], d.Name)
		}
	}
	sort.SliceStable(out.Devices, func(i, j int) bool {
		ri, rj := roleRank(out.Devices[i].Role), roleRank(out.Devices[j].Role)
		if ri != rj {
			return ri < rj
		}
		if out.Devices[i].Site != out.Devices[j].Site {
			return out.Devices[i].Site < out.Devices[j].Site
		}
		return out.Devices[i].Name < out.Devices[j].Name
	})
	if len(out.Devices) > SummaryMaxDevices {
		out.Devices = out.Devices[:SummaryMaxDevices]
	}
	out.Roles = sortedCounts(roles)
	out.Sites = sortedCounts(sites)
	out.Vendors = sortedCounts(vendors)

	inOverlay := func(members []string) bool {
		if out.Overlay == nil {
			return false
		}
		for _, d := range out.Devices {
			for _, m := range members {
				if d.Name == m && d.OverlayPeers > 0 {
					return true
				}
			}
		}
		return false
	}
	roleKeys := make([]string, 0, len(roleMembers))
	for r := range roleMembers {
		roleKeys = append(roleKeys, r)
	}
	sort.Slice(roleKeys, func(i, j int) bool { return roleRank(roleKeys[i]) < roleRank(roleKeys[j]) })
	for _, r := range roleKeys {
		ms := roleMembers[r]
		sort.Strings(ms)
		rn := RoleNote{Role: r, MembersTotal: len(ms), Likely: LikelyFunction(r, inOverlay(ms))}
		if len(ms) > SummaryMaxRoleMembers {
			ms = ms[:SummaryMaxRoleMembers]
		}
		rn.Members = ms
		if rn.Likely != "" {
			out.RoleNotes = append(out.RoleNotes, rn)
		}
	}

	out.Notes = append(out.Notes, v.Degraded...)
	if out.Collected {
		summarizeDesign(designInput{
			devNodes: devNodes, names: names, managed: managed, site: site,
			edges: designEdges, pairs: visPairs, overlay: in.OverlayRead,
		}, &out)
	}
	return out
}

func summarizeOverlay(pairs []OverlayPair, site, names map[string]string, v View) *OverlaySummary {
	ov := &OverlaySummary{}
	memberSet := map[string]bool{}
	has := map[[2]string]bool{}
	for _, p := range pairs {
		memberSet[p.A], memberSet[p.B] = true, true
		has[[2]string{p.A, p.B}] = true
		if p.Sessions > 0 && p.Up == p.Sessions {
			continue
		}
		st := StatusDown
		if p.Up > 0 {
			st = StatusDegraded
		}
		ov.NotUp = append(ov.NotUp, PairStatus{A: names[p.A], B: names[p.B], Status: st, Sessions: p.Sessions, Up: p.Up, Colors: p.Colors})
	}
	ov.NotUpTotal = len(ov.NotUp)
	if len(ov.NotUp) > SummaryMaxNotUp {
		ov.NotUp = ov.NotUp[:SummaryMaxNotUp]
	}
	members := make([]string, 0, len(memberSet))
	for m := range memberSet {
		members = append(members, m)
	}
	sort.Strings(members)
	ov.Members = len(members)
	ov.Pairs = len(pairs)

	var obs [][2]string
	for k := range has {
		obs = append(obs, k)
	}
	shape, possible, hubs := OverlayShape(members, obs, site)
	ov.Shape, ov.PossiblePairs = shape, possible
	for _, h := range hubs {
		ov.Hubs = append(ov.Hubs, names[h])
	}
	for i := 0; i < len(members); i++ {
		for j := i + 1; j < len(members); j++ {
			a, b := members[i], members[j]
			same := sameSite(site, a, b)
			if same {
				ov.SameSitePairs++
			}
			if has[[2]string{a, b}] {
				continue
			}
			pn := PairName{A: names[a], B: names[b], SameSite: same}
			if same {
				pn.Site = site[a]
				ov.SameSiteNoTunnel = append(ov.SameSiteNoTunnel, pn)
				continue
			}
			ov.Missing = append(ov.Missing, pn)
		}
	}
	ov.MissingTotal = len(ov.Missing)
	if len(ov.Missing) > SummaryMaxMissing {
		ov.Missing = ov.Missing[:SummaryMaxMissing]
	}
	if len(ov.SameSiteNoTunnel) > SummaryMaxMissing {
		ov.SameSiteNoTunnel = ov.SameSiteNoTunnel[:SummaryMaxMissing]
	}

	// Transports: the view's inferred WAN nodes (members already recomputed to
	// the caller's visible devices by the server).
	for _, n := range v.Nodes {
		if n.Kind != KindWAN {
			continue
		}
		name := n.Tags["color"]
		if name == "" {
			name = strings.TrimPrefix(n.Label, "WAN transport · ")
		}
		ov.Transports = append(ov.Transports, TransportSummary{
			Name: name, Members: int(n.Metrics["members"]),
			Sessions: int(n.Metrics["sessions"]), Up: int(n.Metrics["sessions_up"]), Health: n.Health,
		})
	}
	sort.Slice(ov.Transports, func(i, j int) bool { return ov.Transports[i].Name < ov.Transports[j].Name })
	if len(ov.Transports) > SummaryMaxTransports {
		ov.Transports = ov.Transports[:SummaryMaxTransports]
	}
	return ov
}

// OverlayShape reads the shape of an overlay pair graph. members are device
// ids, pairs the observed member pairs, site the device → site map (a pair of
// members in the same known site is not counted as a possible tunnel: SD-WAN
// edges in one site do not normally build tunnels to each other). It returns
// the shape hint, the number of possible pairs, and the hubs of a
// hub-and-spoke overlay.
func OverlayShape(members []string, pairs [][2]string, site map[string]string) (shape string, possible int, hubs []string) {
	n := len(members)
	if n < 2 {
		return ShapeUnknown, 0, nil
	}
	idx := make(map[string]bool, n)
	for _, m := range members {
		idx[m] = true
	}
	degree := map[string]int{}
	observed := 0
	for _, p := range pairs {
		if !idx[p[0]] || !idx[p[1]] || p[0] == p[1] {
			continue
		}
		degree[p[0]]++
		degree[p[1]]++
		if !sameSite(site, p[0], p[1]) {
			observed++
		}
	}
	reach := map[string]int{}
	for i := 0; i < n; i++ {
		for j := i + 1; j < n; j++ {
			if sameSite(site, members[i], members[j]) {
				continue
			}
			possible++
			reach[members[i]]++
			reach[members[j]]++
		}
	}
	if possible == 0 {
		return ShapeUnknown, 0, nil
	}
	if float64(observed) >= summaryFullMeshMin*float64(possible) {
		return ShapeFullMesh, possible, nil
	}
	if n >= 3 {
		for _, m := range members {
			if r := reach[m]; r > 0 && float64(degree[m]) >= math.Ceil(0.8*float64(r)) && degree[m] >= 2 {
				hubs = append(hubs, m)
			}
		}
		if len(hubs) >= 1 && len(hubs)*2 <= n {
			spokesOnlyToHubs := true
			for _, m := range members {
				if contains(hubs, m) {
					continue
				}
				if degree[m] > len(hubs) {
					spokesOnlyToHubs = false
					break
				}
			}
			if spokesOnlyToHubs {
				return ShapeHubAndSpoke, possible, hubs
			}
		}
	}
	if observed > 0 {
		return ShapePartialMesh, possible, nil
	}
	return ShapeUnknown, possible, nil
}

// LikelyFunction is the likely network function of a device role, in network
// terms. It is an INFERENCE from the role classifier, worded as such, and it
// names no vendor. overlay says the role's devices are members of an
// observed SD-WAN overlay.
func LikelyFunction(role string, overlay bool) string {
	switch role {
	case DevRoleWANEdge, DevRoleDCWANEdge:
		if overlay {
			return "SD-WAN edge routers: likely terminate encrypted overlay tunnels (IPsec, monitored by BFD) over each transport and exchange routes with the SD-WAN controllers (OMP or the vendor's equivalent); usually also run local routing (static, OSPF or BGP) toward the site LAN"
		}
		return "WAN edge routers: likely run eBGP or static routing toward providers or an MPLS PE, with NAT and edge security policy"
	case DevRoleCoreRouter:
		return "core routers: likely run an IGP (OSPF or IS-IS) with iBGP and possibly MPLS, carrying transit between sites and the edge"
	case DevRoleDCSpine:
		return "data-centre spines: likely run the underlay routing (eBGP or OSPF/IS-IS) and often EVPN route reflection for a leaf-spine fabric"
	case DevRoleDCLeaf:
		return "data-centre leaves: likely attach servers and run VXLAN/EVPN or routed access toward the spines"
	case DevRoleDistributionSwitch:
		return "distribution switches: likely do inter-VLAN routing and first-hop redundancy (HSRP/VRRP) for the access layer"
	case DevRoleAccessSwitch:
		return "access switches: likely carry user and device VLANs with spanning tree on the edge ports"
	case DevRoleFirewall:
		return "firewalls: likely enforce security policy and NAT between zones"
	case DevRoleLoadBalancer:
		return "load balancers: likely front application servers with virtual IPs and health checks"
	case DevRoleCarrierHop:
		return "provider hops: seen on measured paths, not managed here"
	case DevRoleCloudEdge:
		return "cloud edges: likely the gateways between this network and a cloud provider (VPN or direct connect)"
	}
	return ""
}

// ── helpers ─────────────────────────────────────────────────────────────────

func sameSite(site map[string]string, a, b string) bool {
	sa, sb := site[a], site[b]
	return sa != "" && sa == sb
}

func roleRank(role string) int {
	order := []string{DevRoleDCWANEdge, DevRoleWANEdge, DevRoleCoreRouter, DevRoleDCSpine, DevRoleDCLeaf,
		DevRoleDistributionSwitch, DevRoleAccessSwitch, DevRoleFirewall, DevRoleLoadBalancer, DevRoleCloudEdge, DevRoleCarrierHop}
	for i, r := range order {
		if r == role {
			return i
		}
	}
	return len(order)
}

func sortedCounts(m map[string]int) []SummaryCount {
	out := make([]SummaryCount, 0, len(m))
	for k, c := range m {
		out = append(out, SummaryCount{Name: k, Count: c})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Name < out[j].Name
	})
	return out
}

// safeName is a device's display name, never an address: a label that parses
// as an IP (or is an IP with a port or prefix) is replaced by "unnamed device N".
func safeName(label, id string, unnamed *int) string {
	l := strings.TrimSpace(label)
	if l == "" {
		l = strings.TrimSpace(id)
	}
	if l == "" || looksLikeAddress(l) {
		*unnamed++
		return fmt.Sprintf("unnamed device %d", *unnamed)
	}
	return l
}

// safePort drops a port name that is an address (BGP-LS links can carry the
// raw interface IP where a port name belongs).
func safePort(p string) string {
	p = strings.TrimSpace(p)
	if p == "" || looksLikeAddress(p) {
		return ""
	}
	return p
}

func looksLikeAddress(s string) bool {
	s = strings.TrimSpace(s)
	if net.ParseIP(s) != nil {
		return true
	}
	if _, _, err := net.ParseCIDR(s); err == nil {
		return true
	}
	if host, _, err := net.SplitHostPort(s); err == nil && net.ParseIP(host) != nil {
		return true
	}
	return false
}

func contains(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}

func firstNonEmptyStr(vs ...string) string {
	for _, v := range vs {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}
