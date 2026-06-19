package topology

import (
	"sort"
	"strings"
	"time"
)

// geo.go — ProjectGeo builds the executive_geo / WAN View: a SITE-level graph
// (one node per geographic site) with WAN circuits aggregated from the underlying
// device-to-device links. PURE (no I/O, time via Input): the handler gathers the
// SoT site facts + device→site assignments + deduped links and calls in here.
//
// Honesty rules, identical in spirit to Project():
//   - a site node carries its real coordinate from the SoT (intent data); a site
//     without coordinates is still emitted (so it surfaces as "not placed") but
//     gets no Coordinates,
//   - a WAN circuit is drawn ONLY between two distinct known sites and ONLY from
//     evidence-bearing device links — never invented; its status is worst-wins and
//     its utilization the busiest underlying link (HasUtil distinguishes 0% from
//     unmeasured, so we omit utilization entirely when nothing was measured),
//   - health is rolled up from the site's device up/down counts; a site we can't
//     speak to (no devices) is "unknown", never a blind "ok".

// GeoSiteFact is one geographic site, already tenant-scoped and joined with the
// live inventory health by the caller (mirrors the /api/geomap row).
type GeoSiteFact struct {
	Slug      string
	Name      string
	Lat       float64
	Lng       float64
	HasCoords bool
	Devices   int
	Up        int
	Down      int
	Status    string // SoT site status (e.g. "active") — informational
	Source    string // evidence source for placement: "netbox" | "manual"
}

// GeoInput is everything ProjectGeo needs. DeviceSite maps a managed device id to
// its site slug (SoT placement precedence resolved by the caller). Links is the
// SAME deduped, evidence-bearing LinkFact slice the other modes use.
type GeoInput struct {
	TenantID   string
	Now        time.Time
	Sites      []GeoSiteFact
	Links      []LinkFact
	DeviceSite map[string]string
}

// siteHealth rolls a site's device up/down counts into a health band.
func siteHealth(up, down, devices int) string {
	switch {
	case devices == 0:
		return HealthUnknown
	case down > 0 && up == 0:
		return HealthCritical
	case down > 0:
		return HealthWarning
	default:
		return HealthOK
	}
}

// statusRank ranks link statuses so a circuit takes the WORST of its members.
func statusRank(s string) int {
	switch s {
	case StatusDown:
		return 5
	case StatusDegraded:
		return 4
	case StatusWarning:
		return 3
	case StatusMaintenance:
		return 2
	case StatusUp:
		return 1
	default:
		return 0 // unknown / ""
	}
}

func worseStatus(a, b string) string {
	if statusRank(b) > statusRank(a) {
		return b
	}
	return a
}

// circuitAgg accumulates the device links between one ordered site pair.
type circuitAgg struct {
	src, dst  string
	count     int
	protocols map[string]bool
	util      float64
	hasUtil   bool
	status    string
	lastSeen  time.Time
}

// ProjectGeo builds the site-level geo View. Safe on empty input (well-formed
// empty view, non-nil slices).
func ProjectGeo(in GeoInput) View {
	now := in.Now

	siteBySlug := make(map[string]GeoSiteFact, len(in.Sites))
	nodes := make([]Node, 0, len(in.Sites))
	for _, s := range in.Sites {
		if s.Slug == "" {
			continue
		}
		if _, dup := siteBySlug[s.Slug]; dup {
			continue
		}
		siteBySlug[s.Slug] = s
		// Skip a site that is neither placeable nor has any device — pure noise.
		if !s.HasCoords && s.Devices == 0 {
			continue
		}
		n := Node{
			ID:          s.Slug,
			Label:       firstNonEmptyGeo(s.Name, s.Slug),
			Kind:        KindSite,
			Health:      siteHealth(s.Up, s.Down, s.Devices),
			Confidence:  0.95,
			Resolved:    true,
			ChangeState: ChangeUnchanged,
			Metrics: map[string]float64{
				"devices":     float64(s.Devices),
				"link_count":  0, // filled below once circuits are known
				"alert_count": float64(s.Down),
			},
			Evidence: []EvidenceRef{{
				Source:     placementSource(s.Source),
				Confidence: 0.95,
				Detail:     placementDetail(s),
				ObservedAt: rfc3339(now),
			}},
		}
		if s.HasCoords {
			n.Coordinates = &Coord{X: s.Lng, Y: s.Lat}
		}
		nodes = append(nodes, n)
	}

	// ── aggregate device links into inter-site circuits ──────────────────────────
	byPair := map[string]*circuitAgg{}
	order := []string{}
	for _, l := range in.Links {
		a := in.DeviceSite[l.Source]
		b := in.DeviceSite[l.Target]
		if a == "" || b == "" || a == b {
			continue // an endpoint isn't placed, or both ends are the same site
		}
		if _, ok := siteBySlug[a]; !ok {
			continue
		}
		if _, ok := siteBySlug[b]; !ok {
			continue
		}
		s1, s2 := a, b
		if s1 > s2 {
			s1, s2 = s2, s1
		}
		key := s1 + "\x00" + s2
		ag := byPair[key]
		if ag == nil {
			ag = &circuitAgg{src: s1, dst: s2, protocols: map[string]bool{}}
			byPair[key] = ag
			order = append(order, key)
		}
		ag.count++
		for _, p := range strings.Split(l.Protocol, "+") {
			if p = strings.TrimSpace(p); p != "" {
				ag.protocols[p] = true
			}
		}
		if l.HasUtil && l.Utilization > ag.util {
			ag.util, ag.hasUtil = l.Utilization, true
		}
		ag.status = worseStatus(ag.status, l.Status)
		if l.LastSeen.After(ag.lastSeen) {
			ag.lastSeen = l.LastSeen
		}
	}

	edges := make([]Edge, 0, len(order))
	linkCount := map[string]int{}
	for _, key := range order {
		ag := byPair[key]
		ev := circuitEvidence(ag, now)
		if len(ev) == 0 {
			continue // no evidence → never draw the circuit (contract rule)
		}
		status := ag.status
		if status == "" {
			status = StatusUnknown
		}
		e := Edge{
			ID:           "wan:" + ag.src + "|" + ag.dst,
			Source:       ag.src,
			Target:       ag.dst,
			Relationship: RelRoutedAdjacency,
			Protocol:     joinProtocols(ag.protocols),
			Status:       status,
			Confidence:   circuitConfidence(ag),
			ChangeState:  ChangeUnchanged,
			Evidence:     ev,
		}
		if ag.hasUtil {
			e.Utilization = ag.util
		}
		if !ag.lastSeen.IsZero() {
			e.LastSeen = rfc3339(ag.lastSeen)
		}
		edges = append(edges, e)
		linkCount[ag.src]++
		linkCount[ag.dst]++
	}

	// Backfill each site's link_count metric now that circuits are known.
	for i := range nodes {
		if c, ok := linkCount[nodes[i].ID]; ok {
			nodes[i].Metrics["link_count"] = float64(c)
		}
	}

	return View{
		ViewID:      "geo-" + in.TenantID,
		Mode:        ModeExecutiveGeo,
		Scope:       Scope{TenantID: in.TenantID},
		LayoutType:  "wan_geo",
		GeneratedAt: rfc3339(now),
		Nodes:       nodes,
		Edges:       edges,
		Groups:      []Group{},
		Overlays:    []string{"health", "utilization"},
	}
}

// circuitEvidence synthesizes one evidence ref per distinct underlying protocol.
func circuitEvidence(ag *circuitAgg, now time.Time) []EvidenceRef {
	protos := sortedKeys(ag.protocols)
	out := make([]EvidenceRef, 0, len(protos))
	for _, p := range protos {
		out = append(out, EvidenceRef{
			Source:     p,
			Confidence: circuitConfidence(ag),
			Detail:     pluralLinks(ag.count) + " between sites",
			ObservedAt: rfc3339(ag.lastSeen),
		})
	}
	return out
}

// circuitConfidence rises with corroboration: more distinct sources + more
// underlying links → higher confidence, capped at 0.95.
func circuitConfidence(ag *circuitAgg) float64 {
	c := 0.7 + 0.07*float64(len(ag.protocols)-1) + 0.03*float64(ag.count-1)
	if c > 0.95 {
		c = 0.95
	}
	if c < 0.5 {
		c = 0.5
	}
	return c
}

func placementSource(s string) string {
	if s == "manual" {
		return "manual"
	}
	return "netbox"
}

func placementDetail(s GeoSiteFact) string {
	where := "Source of Truth"
	if s.Source == "manual" {
		where = "operator location annotation"
	}
	if s.HasCoords {
		return "Site placement from " + where + " (decimal WGS-84)"
	}
	return "Site from " + where + " — no coordinates set"
}

func joinProtocols(set map[string]bool) string {
	return strings.Join(sortedKeys(set), "+")
}

func sortedKeys(set map[string]bool) []string {
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func pluralLinks(n int) string {
	if n == 1 {
		return "1 link"
	}
	return itoa(n) + " links"
}

func firstNonEmptyGeo(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

// itoa avoids pulling strconv just for small positive counts.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}
