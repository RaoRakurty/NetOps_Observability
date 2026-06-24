package topology

import (
	"sort"
	"strings"
	"time"
)

// project.go — Project turns a tenant-scoped Input (devices, deduped links, active
// alerts, measured paths) into the canonical, renderer-agnostic View the frontend
// consumes. PURE: no I/O, no clocks of its own (time comes in via Input.Now), no
// third-party imports. Every rule below is intentionally conservative and HONEST —
// we never invent an edge without evidence, never claim "ok" for a device we
// haven't heard from, and distinguish "0%" from "unmeasured".

const defaultStaleAfter = 24 * time.Hour

// Project builds the View. Safe on empty/degenerate input (returns a well-formed
// empty view with non-nil slices so the JSON is always [] not null).
func Project(in Input) View {
	now := in.Now
	if now.IsZero() {
		// Deterministic fallback only matters for change_state/stale; callers
		// always pass a real Now. Avoid time.Now() to keep the package pure.
		now = time.Time{}
	}
	staleAfter := in.StaleAfter
	if staleAfter <= 0 {
		staleAfter = defaultStaleAfter
	}

	mode := in.Mode
	if mode == "" {
		mode = ModeExplore
	}

	// Index alerts by device so health/alert_count are O(1) per node.
	alertsByDev := map[string][]AlertFact{}
	for _, a := range in.Alerts {
		if a.DeviceID == "" {
			continue
		}
		alertsByDev[a.DeviceID] = append(alertsByDev[a.DeviceID], a)
	}

	// Managed device set (id present) — used to decide resolved vs unresolved.
	managed := make(map[string]bool, len(in.Devices))
	for _, d := range in.Devices {
		if d.ID != "" {
			managed[d.ID] = true
		}
	}

	// ── edges first: they tell us which unresolved neighbours to materialize and
	//    feed each node's link_count. Drop any link without evidence (the rule). ──
	edges := make([]Edge, 0, len(in.Links))
	linkCount := map[string]int{}
	unresolvedSeen := map[string]LinkFact{} // id → the link that introduced it
	graph := NewGraph()
	for _, d := range in.Devices {
		graph.AddNode(d.ID)
	}

	for _, l := range in.Links {
		if l.Source == "" || l.Target == "" || l.Source == l.Target {
			continue
		}
		ev := edgeEvidence(l, now)
		if len(ev) == 0 {
			continue // zero-trust: no evidence → not a real edge
		}
		conf := edgeConfidence(l)
		for i := range ev {
			ev[i].Confidence = conf
		}
		e := Edge{
			ID:           edgeID(l.Source, l.Target),
			Source:       l.Source,
			Target:       l.Target,
			SourcePort:   l.LocalPort,
			TargetPort:   l.RemotePort,
			Relationship: relationship(l),
			Protocol:     primaryProtocol(l.Protocol),
			Status:       linkStatus(l.Status),
			Confidence:   conf,
			LastSeen:     rfc3339(l.LastSeen),
			ChangeState:  changeState(l.LastSeen, now, staleAfter),
			Evidence:     ev,
		}
		if l.HasUtil {
			e.Utilization = l.Utilization
		}
		edges = append(edges, e)

		linkCount[l.Source]++
		linkCount[l.Target]++
		graph.AddEdge(l.Source, l.Target, l.Metric)

		// A target that isn't a managed device becomes an unresolved node.
		if !managed[l.Target] {
			if _, ok := unresolvedSeen[l.Target]; !ok {
				unresolvedSeen[l.Target] = l
			}
		}
	}

	// Deterministic edge order (stable rendering / diffing).
	sort.Slice(edges, func(i, j int) bool { return edges[i].ID < edges[j].ID })

	// ── nodes from managed devices ──
	nodes := make([]Node, 0, len(in.Devices)+len(unresolvedSeen))
	for _, d := range in.Devices {
		if d.ID == "" {
			continue
		}
		health, change := deviceHealth(d, alertsByDev[d.ID], now, staleAfter)
		n := Node{
			ID:          d.ID,
			Label:       displayName(d),
			Kind:        nodeKind(d),
			Role:        d.Role,
			Vendor:      d.Vendor,
			Model:       d.Model,
			Site:        d.Site,
			Rack:        d.Rack,
			MgmtIP:      d.MgmtIP,
			Health:      health,
			Owner:       d.Owner,
			Confidence:  1.0, // it's in our own inventory
			LastSeen:    rfc3339(d.LastSeen),
			ChangeState: change,
			Metrics:     deviceMetrics(d, linkCount[d.ID], len(alertsByDev[d.ID])),
			Evidence:    deviceEvidence(d),
			Issues:      nodeIssues(alertsByDev[d.ID]),
			Resolved:    true,
			GroupID:     groupID(d.Site),
		}
		nodes = append(nodes, n)
	}

	// ── unresolved neighbour nodes (muted; learned only from a neighbour's view) ──
	for id, l := range unresolvedSeen {
		name := l.TargetName
		if name == "" {
			name = strings.TrimPrefix(id, "ext:")
		}
		nodes = append(nodes, Node{
			ID:         id,
			Label:      name,
			Kind:       KindUnresolved,
			Health:     HealthUnknown,
			Confidence: 0.5,
			Metrics:    map[string]float64{"link_count": float64(linkCount[id])},
			Evidence: []EvidenceRef{{
				Source:     primaryProtocol(l.Protocol),
				Confidence: 0.5,
				Detail:     "Advertised by a managed neighbour; not in inventory",
				ObservedAt: rfc3339(l.LastSeen),
			}},
			Resolved: false,
		})
	}

	sort.Slice(nodes, func(i, j int) bool { return nodes[i].ID < nodes[j].ID })

	// ── groups by site (only when sites are present) ──
	groups := buildGroups(nodes)

	// ── path (path_trace): prefer a measured path; else compute IGP-weighted SPF ──
	var path []string
	var pathSource string
	if mode == ModePathTrace {
		path, pathSource = resolvePath(in, graph, managed, unresolvedSeen)
	}

	return View{
		ViewID:      viewID(mode, in.TenantID),
		Mode:        mode,
		Scope:       Scope{TenantID: in.TenantID},
		LayoutType:  layoutType(mode),
		GeneratedAt: rfc3339(now),
		Nodes:       nodes,
		Edges:       edges,
		Groups:      groups,
		Overlays:    overlays(mode, edges),
		Path:        path,
		PathSource:  pathSource,
	}
}

// ── node helpers ─────────────────────────────────────────────────────────────

func displayName(d DeviceFact) string {
	if d.Name != "" {
		return d.Name
	}
	if d.MgmtIP != "" {
		return d.MgmtIP
	}
	return d.ID
}

// nodeKind maps a device to a contract NodeKind. It trusts an explicit operator
// role first, then the SNMP-inferred type, then falls back to vendor/name hints
// — because type inference often yields "generic" for firewall/SP gear, which
// would otherwise mis-render a Fortinet firewall as a plain switch. Only when no
// signal resolves does it default to "switch" (a neutral box, never a guess).
func nodeKind(d DeviceFact) string {
	if k := kindFromKeyword(d.Role); k != "" {
		return k
	}
	if k := kindFromKeyword(d.Type); k != "" {
		return k
	}
	// Vendor hint: dedicated firewall/SD-WAN-security vendors → firewall.
	switch strings.ToLower(strings.TrimSpace(d.Vendor)) {
	case "fortinet", "fortigate", "palo alto", "paloalto", "palo-alto", "panw", "checkpoint", "check point":
		return KindFirewall
	}
	// Name hint: explicit role tokens in the hostname.
	name := strings.ToLower(d.Name)
	switch {
	case strings.Contains(name, "firewall") || hasToken(name, "fw"):
		return KindFirewall
	case hasToken(name, "lb") || hasToken(name, "slb"):
		return KindLoadBalancer
	case hasToken(name, "rtr") || hasToken(name, "router") || routerSuffix(name):
		return KindRouter
	}
	return KindSwitch
}

// kindFromKeyword resolves a role/type string to a NodeKind, or "" if unknown.
// "wan"/"edge" roles map to router: a WAN/edge node is a routed boundary device,
// not an access switch (this is what makes wan-r2's role=wan render as a router).
func kindFromKeyword(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "router", "wan", "edge", "wan-edge", "border-router":
		return KindRouter
	case "switch":
		return KindSwitch
	case "firewall":
		return KindFirewall
	case "load-balancer", "load_balancer", "lb":
		return KindLoadBalancer
	case "server", "host":
		return KindServer
	case "cloud-gw", "cloud", "cloud-gateway":
		return KindCloud
	default:
		return ""
	}
}

// routerSuffix matches a hostname whose last token is r<digits> (e.g. "wan-r2",
// "core-r1") — a common router naming convention.
func routerSuffix(name string) bool {
	parts := strings.FieldsFunc(name, func(r rune) bool {
		return r == '-' || r == '_' || r == '.' || r == ' '
	})
	if len(parts) == 0 {
		return false
	}
	last := parts[len(parts)-1]
	if len(last) < 2 || last[0] != 'r' {
		return false
	}
	for _, c := range last[1:] {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// hasToken reports whether tok appears as a hyphen/dot/underscore-delimited token
// in name (so "dmz-fw" matches "fw" but "software" does not).
func hasToken(name, tok string) bool {
	for _, part := range strings.FieldsFunc(name, func(r rune) bool {
		return r == '-' || r == '_' || r == '.' || r == ' '
	}) {
		if part == tok {
			return true
		}
	}
	return false
}

// deviceHealth derives health + change_state HONESTLY:
//   - any critical/major alert → critical; any warning/minor → warning
//   - an alert always wins over staleness (a firing alert is fresher signal)
//   - never seen / stale with no alert → unknown (we won't claim "ok" blind)
func deviceHealth(d DeviceFact, alerts []AlertFact, now time.Time, staleAfter time.Duration) (health, change string) {
	change = changeState(d.LastSeen, now, staleAfter)
	if worst := AlertSeverityHealth(alerts); worst != "" {
		return worst, change
	}
	if d.LastSeen.IsZero() || change == ChangeStale {
		return HealthUnknown, change
	}
	return HealthOK, change
}

// AlertSeverityHealth returns the worst node-health implied by a device's active
// alerts — HealthCritical for any critical/major, else HealthWarning for any
// warning/minor, else "" (no alert raises health). Shared by the live projection
// (deviceHealth) and the persisted-graph live enrichment (EnrichLive) so the rule
// can't drift between the two surfaces.
func AlertSeverityHealth(alerts []AlertFact) string {
	worst := ""
	for _, a := range alerts {
		switch strings.ToLower(a.Severity) {
		case "critical", "major", "crit", "emergency":
			return HealthCritical
		case "warning", "minor", "warn":
			worst = HealthWarning
		}
	}
	return worst
}

// alertSeverityRank orders alerts for the inspector's issue list (higher = worse).
func alertSeverityRank(s string) int {
	switch strings.ToLower(s) {
	case "critical", "major", "crit", "emergency":
		return 4
	case "warning", "minor", "warn":
		return 3
	case "info", "notice":
		return 2
	default:
		return 1
	}
}

// nodeIssues turns the alerts driving a device's health into inspector-ready issues —
// worst-severity first, then most-recent, capped so a flapping device can't flood the
// panel. This is what answers "why is this device critical?" on click. Empty = healthy.
func nodeIssues(alerts []AlertFact) []NodeIssue {
	if len(alerts) == 0 {
		return nil
	}
	sorted := append([]AlertFact(nil), alerts...)
	sort.SliceStable(sorted, func(i, j int) bool {
		ri, rj := alertSeverityRank(sorted[i].Severity), alertSeverityRank(sorted[j].Severity)
		if ri != rj {
			return ri > rj
		}
		return sorted[i].FiredAt.After(sorted[j].FiredAt)
	})
	const maxIssues = 6
	if len(sorted) > maxIssues {
		sorted = sorted[:maxIssues]
	}
	out := make([]NodeIssue, 0, len(sorted))
	for _, a := range sorted {
		out = append(out, NodeIssue{Severity: a.Severity, Summary: a.Summary, Since: rfc3339(a.FiredAt)})
	}
	return out
}

func deviceMetrics(d DeviceFact, links, alerts int) map[string]float64 {
	m := map[string]float64{
		"link_count":  float64(links),
		"alert_count": float64(alerts),
	}
	if d.HasCPU {
		m["cpu_pct"] = d.CPUPct
	}
	if d.HasMem {
		m["mem_pct"] = d.MemPct
	}
	return m
}

func deviceEvidence(d DeviceFact) []EvidenceRef {
	return []EvidenceRef{{
		Source:     "snmp",
		Confidence: 1.0,
		Detail:     "Managed device in inventory",
		ObservedAt: rfc3339(d.LastSeen),
	}}
}

// ── edge helpers ─────────────────────────────────────────────────────────────

// edgeEvidence turns the "+"-joined protocol string into one EvidenceRef per
// confirming source. An empty protocol yields no evidence → the edge is dropped.
func edgeEvidence(l LinkFact, now time.Time) []EvidenceRef {
	protos := splitProtocols(l.Protocol)
	if len(protos) == 0 {
		return nil
	}
	ev := make([]EvidenceRef, 0, len(protos))
	for _, p := range protos {
		detail := portDetail(l)
		if p == "bgp_ls" && l.IGP != "" {
			detail = strings.TrimSpace(l.IGP + " " + l.Area + " " + detail)
		}
		ev = append(ev, EvidenceRef{Source: p, Detail: detail, ObservedAt: rfc3339(l.LastSeen)})
	}
	return ev
}

func portDetail(l LinkFact) string {
	switch {
	case l.LocalPort != "" && l.RemotePort != "":
		return l.LocalPort + " ↔ " + l.RemotePort
	case l.LocalPort != "":
		return l.LocalPort
	case l.RemotePort != "":
		return l.RemotePort
	default:
		return ""
	}
}

// edgeConfidence rewards corroboration: bidirectional observation, multiple
// protocols, and both ends being managed all raise it. Range [0.3, 1.0].
func edgeConfidence(l LinkFact) float64 {
	c := 0.5
	if l.Bidirectional {
		c += 0.2
	}
	if extra := len(splitProtocols(l.Protocol)) - 1; extra > 0 {
		c += 0.15 * float64(extra)
	}
	if l.Resolved {
		c += 0.1
	}
	if c < 0.3 {
		c = 0.3
	}
	if c > 1.0 {
		c = 1.0
	}
	return c
}

func relationship(l LinkFact) string {
	for _, p := range splitProtocols(l.Protocol) {
		if p == "bgp_ls" || p == "isis_lsdb" || p == "ospf_lsdb" {
			return RelRoutedAdjacency
		}
	}
	return RelConnectedTo
}

func linkStatus(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	switch s {
	case "up", "down", "degraded", "warning", "maintenance":
		return s
	default:
		return "unknown"
	}
}

func splitProtocols(p string) []string {
	out := []string{}
	for _, tok := range strings.Split(p, "+") {
		tok = strings.ToLower(strings.TrimSpace(tok))
		if tok != "" {
			out = append(out, tok)
		}
	}
	return out
}

func primaryProtocol(p string) string {
	ps := splitProtocols(p)
	if len(ps) == 0 {
		return ""
	}
	return ps[0]
}

// edgeID is order-independent so A→B and B→A collapse to one stable id.
func edgeID(a, b string) string {
	if a > b {
		a, b = b, a
	}
	return "lnk:" + a + "--" + b
}

// ── group helpers ────────────────────────────────────────────────────────────

func groupID(site string) string {
	if site == "" {
		return ""
	}
	return "site:" + site
}

// buildGroups rolls site-tagged nodes into site groups, with a worst-child health
// rollup. Nodes without a site are left ungrouped (no synthetic "unknown" bucket).
func buildGroups(nodes []Node) []Group {
	bySite := map[string][]Node{}
	order := []string{}
	for _, n := range nodes {
		if n.Site == "" {
			continue
		}
		if _, ok := bySite[n.Site]; !ok {
			order = append(order, n.Site)
		}
		bySite[n.Site] = append(bySite[n.Site], n)
	}
	sort.Strings(order)
	groups := make([]Group, 0, len(order))
	for _, site := range order {
		members := bySite[site]
		children := make([]string, 0, len(members))
		health := HealthOK
		for _, m := range members {
			children = append(children, m.ID)
			health = worseHealth(health, m.Health)
		}
		sort.Strings(children)
		groups = append(groups, Group{
			ID:        groupID(site),
			Label:     site,
			GroupType: "site",
			Children:  children,
			Health:    health,
			Collapsed: false,
		})
	}
	return groups
}

// worseHealth returns the more severe of two health states.
func worseHealth(a, b string) string {
	rank := map[string]int{HealthOK: 0, HealthMaintenance: 1, HealthUnknown: 2, HealthWarning: 3, HealthCritical: 4}
	if rank[b] > rank[a] {
		return b
	}
	return a
}

// ── path helpers ─────────────────────────────────────────────────────────────

// resolvePath picks the highlighted path for path_trace mode AND reports its
// provenance (HONESTY — the UI must not present an inference as a measurement):
//   - a measured traceroute (Input.Paths[0]) wins — it's ground truth → PathMeasured;
//   - else, if explicit Src/Dst endpoints are given, the IGP-weighted SPF is an
//     INFERENCE → PathComputed.
//
// Returns (nil, "") when neither is available (the UI simply shows no path).
func resolvePath(in Input, g *Graph, managed map[string]bool, unresolved map[string]LinkFact) ([]string, string) {
	if len(in.Paths) > 0 {
		hops := sanitizeHops(in.Paths[0].Hops, managed, unresolved)
		if len(hops) >= 2 {
			return hops, PathMeasured
		}
	}
	if in.SrcID != "" && in.DstID != "" {
		if p, _, ok := g.Dijkstra(in.SrcID, in.DstID); ok {
			return p, PathComputed
		}
	}
	return nil, ""
}

// sanitizeHops drops empty/unknown hop ids and collapses consecutive duplicates,
// keeping only nodes that exist in the view (managed or materialized unresolved).
func sanitizeHops(hops []string, managed map[string]bool, unresolved map[string]LinkFact) []string {
	out := make([]string, 0, len(hops))
	for _, h := range hops {
		h = strings.TrimSpace(h)
		if h == "" {
			continue
		}
		_, isUnresolved := unresolved[h]
		if !managed[h] && !isUnresolved {
			continue
		}
		if len(out) > 0 && out[len(out)-1] == h {
			continue
		}
		out = append(out, h)
	}
	return out
}

// ── view helpers ─────────────────────────────────────────────────────────────

func layoutType(mode string) string {
	switch mode {
	case ModeInvestigate:
		return "incident"
	case ModePathTrace:
		return "path_first"
	case ModeDependency:
		return "dependency"
	default:
		return "spine_leaf"
	}
}

// overlays advertises only overlays we can actually populate from this view, so
// the UI never offers a toggle that would render nothing.
func overlays(mode string, edges []Edge) []string {
	ov := []string{"health"}
	hasUtil := false
	for _, e := range edges {
		if e.Utilization > 0 {
			hasUtil = true
			break
		}
	}
	if hasUtil {
		ov = append(ov, "utilization")
	}
	if mode == ModeInvestigate {
		ov = append(ov, "rca_evidence")
	}
	return ov
}

func viewID(mode, tenant string) string {
	if tenant == "" {
		return "topo:" + mode
	}
	return "topo:" + tenant + ":" + mode
}

// changeState flags a device/link we haven't heard from recently.
func changeState(lastSeen, now time.Time, staleAfter time.Duration) string {
	if lastSeen.IsZero() || now.IsZero() {
		return ChangeUnknown
	}
	if now.Sub(lastSeen) > staleAfter {
		return ChangeStale
	}
	return ChangeUnchanged
}

func rfc3339(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}
