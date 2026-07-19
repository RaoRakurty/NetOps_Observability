package cloud

// rollup.go — the Cloud Network Overview roll-up engine (design
// docs/design/cloud-network-overview.md, §6 P1).
//
// Pure + stdlib-only: takes the tenant's component inventory (P0 rows) plus the
// tenant's open investigations, returns the hierarchical model the overview
// surface renders:
//
//	providers[] → regions[] → vpcs[] → { components-by-family, subnets }
//	seams[]     — LATERAL links (§4a), top-level, never a VPC attribute
//
// Honesty rules encoded here (design §3, binding):
//   - Every level is a worst-of roll-up with a NAMED reason from the worst
//     contributor — never a bare count of signals.
//   - Unknown ≠ green: a level with ZERO measured children is not_measured; a
//     level with some measured-healthy + some unmeasured reads healthy but
//     carries measured_ratio so the render can say "8 of 11 measured".
//   - Performance carries only what was really measured; an absent metric is
//     absent, never a zero.
//   - Issues are LOCALIZED to a node (VPC / region / seam), not listed; a
//     seam-lane incident belongs to the SEAM, never to either VPC (§4a).
//   - Truncation is disclosed: every capped list carries a truncated marker and
//     the TRUE totals stay on the counts. Lists sort worst-first, so a cap can
//     never hide the red VPC behind fifty green ones.

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// ── input contract ────────────────────────────────────────────────────────────

// OverviewIssue is ONE open investigation as the caller read it from the
// correlation store: an opaque id, a customer-facing title, the raw resource
// handles its grounded evidence named (resource ids, ENIs, IPs — whatever the
// signals carried), and the signal kinds (seam-lane kinds route the issue to a
// seam). The engine resolves handles against the tenant inventory itself.
type OverviewIssue struct {
	ID      string
	Title   string
	Handles []string
	Kinds   []string
}

// OverviewLimits bounds every list in the response (§3 anti-overwhelm + §9
// bounded output). Zero values are replaced by DefaultOverviewLimits.
type OverviewLimits struct {
	MaxRegionsPerProvider int
	MaxVPCsPerRegion      int
	MaxSubnetsPerVPC      int
	MaxSeams              int
	MaxSeamDevices        int
	MaxSeamEndpoints      int
	MaxPerfMetrics        int
}

// DefaultOverviewLimits — generous enough for real estates, hard-bounded for
// hostile ones.
func DefaultOverviewLimits() OverviewLimits {
	return OverviewLimits{
		MaxRegionsPerProvider: 20,
		MaxVPCsPerRegion:      25,
		MaxSubnetsPerVPC:      20,
		MaxSeams:              50,
		MaxSeamDevices:        10,
		MaxSeamEndpoints:      8,
		MaxPerfMetrics:        8,
	}
}

func (l OverviewLimits) withDefaults() OverviewLimits {
	d := DefaultOverviewLimits()
	if l.MaxRegionsPerProvider <= 0 {
		l.MaxRegionsPerProvider = d.MaxRegionsPerProvider
	}
	if l.MaxVPCsPerRegion <= 0 {
		l.MaxVPCsPerRegion = d.MaxVPCsPerRegion
	}
	if l.MaxSubnetsPerVPC <= 0 {
		l.MaxSubnetsPerVPC = d.MaxSubnetsPerVPC
	}
	if l.MaxSeams <= 0 {
		l.MaxSeams = d.MaxSeams
	}
	if l.MaxSeamDevices <= 0 {
		l.MaxSeamDevices = d.MaxSeamDevices
	}
	if l.MaxSeamEndpoints <= 0 {
		l.MaxSeamEndpoints = d.MaxSeamEndpoints
	}
	if l.MaxPerfMetrics <= 0 {
		l.MaxPerfMetrics = d.MaxPerfMetrics
	}
	return l
}

// ── wire model (what /api/cloud/network/overview returns) ─────────────────────

// MeasuredRatio is the coverage caveat every roll-up carries: how many of the
// node's components have a REAL measured status. 8/11 renders "8 of 11 measured".
type MeasuredRatio struct {
	Measured int `json:"measured"`
	Total    int `json:"total"`
}

// IssueSummary localizes open investigations at a node: the count plus the top
// (most recent) issue's title — never the full list (design §3.5).
type IssueSummary struct {
	Count    int    `json:"count"`
	TopIssue string `json:"top_issue,omitempty"`
}

// FamilyRollup is the per-family "health dot" inside a VPC / region: how many
// components of this family exist and the worst-of status with its named reason.
type FamilyRollup struct {
	Family        string        `json:"family"`
	Count         int           `json:"count"`
	Status        string        `json:"status"`
	StatusReason  string        `json:"status_reason"`
	MeasuredRatio MeasuredRatio `json:"measured_ratio"`
}

// PerformanceMetric is one really-measured headline number rolled up per
// (family, metric). Aggregation is disclosed: "" = a single component's value,
// "sum" = count-like values summed, "max" = the worst rate among components.
// Absent metrics simply do not appear — never a zero.
type PerformanceMetric struct {
	Family      string  `json:"family"`
	Metric      string  `json:"metric"`
	Value       float64 `json:"value"`
	Unit        string  `json:"unit,omitempty"`
	Aggregation string  `json:"aggregation,omitempty"`
	Components  int     `json:"components"`
}

// SubnetRollup localizes a fault WITHIN a VPC (design §4: a grouping, not its
// own top-level surface).
type SubnetRollup struct {
	SubnetID       string        `json:"subnet_id"`
	ComponentCount int           `json:"component_count"`
	Status         string        `json:"status"`
	StatusReason   string        `json:"status_reason"`
	MeasuredRatio  MeasuredRatio `json:"measured_ratio"`
}

// VPCOverview is the PRIMARY unit (design §2): one VPC/VNet with its worst-of
// status, named reason, localized issues, family dots, measured performance and
// subnet grouping.
type VPCOverview struct {
	VpcID            string              `json:"vpc_id"`
	Name             string              `json:"name,omitempty"`
	CIDR             string              `json:"cidr,omitempty"`
	Status           string              `json:"status"`
	StatusReason     string              `json:"status_reason"`
	MeasuredRatio    MeasuredRatio       `json:"measured_ratio"`
	OpenIssues       IssueSummary        `json:"open_issues"`
	ComponentCount   int                 `json:"component_count"`
	Families         []FamilyRollup      `json:"families"`
	Performance      []PerformanceMetric `json:"performance"`
	Subnets          []SubnetRollup      `json:"subnets"`
	SubnetsTruncated bool                `json:"subnets_truncated"`
	LastMeasured     string              `json:"last_measured,omitempty"`
}

// RegionOverview is one provider region: worst-of across every component in it
// (in-VPC and regional/global alike), its VPCs, and the components that live
// outside any VPC (DNS zones, edge profiles) as a regional family roll-up.
type RegionOverview struct {
	Region             string         `json:"region"`
	Status             string         `json:"status"`
	StatusReason       string         `json:"status_reason"`
	MeasuredRatio      MeasuredRatio  `json:"measured_ratio"`
	OpenIssues         IssueSummary   `json:"open_issues"`
	VPCCount           int            `json:"vpc_count"`
	ComponentCount     int            `json:"component_count"`
	VPCs               []VPCOverview  `json:"vpcs"`
	VPCsTruncated      bool           `json:"vpcs_truncated"`
	RegionalComponents []FamilyRollup `json:"regional_components"`
	LastMeasured       string         `json:"last_measured,omitempty"`
}

// ProviderOverview is one cloud (aws | azure | gcp).
type ProviderOverview struct {
	Provider         string           `json:"provider"`
	Status           string           `json:"status"`
	StatusReason     string           `json:"status_reason"`
	MeasuredRatio    MeasuredRatio    `json:"measured_ratio"`
	OpenIssues       IssueSummary     `json:"open_issues"`
	RegionCount      int              `json:"region_count"`
	ComponentCount   int              `json:"component_count"`
	Regions          []RegionOverview `json:"regions"`
	RegionsTruncated bool             `json:"regions_truncated"`
	LastMeasured     string           `json:"last_measured,omitempty"`
}

// SeamEndpoint is one side of a lateral link: a region and/or VPC (design §4a).
type SeamEndpoint struct {
	Region string `json:"region,omitempty"`
	VpcID  string `json:"vpc_id,omitempty"`
}

// SeamDevice is one traversed device on a seam (VPN GW / DX / TGW / peering /
// NVA) with its OWN status — "via firewalls or any other devices".
type SeamDevice struct {
	ResourceID   string `json:"resource_id"`
	Name         string `json:"name,omitempty"`
	Type         string `json:"type"`
	Status       string `json:"status"`
	StatusReason string `json:"status_reason,omitempty"`
}

// SeamOverview is one first-class lateral link. A seam incident renders HERE,
// never inside either VPC's roll-up.
type SeamOverview struct {
	ID                 string         `json:"id"`
	Provider           string         `json:"provider"`
	Endpoints          []SeamEndpoint `json:"endpoints"`
	EndpointsTruncated bool           `json:"endpoints_truncated"`
	Devices            []SeamDevice   `json:"devices"`
	DevicesTruncated   bool           `json:"devices_truncated"`
	Status             string         `json:"status"`
	StatusReason       string         `json:"status_reason"`
	MeasuredRatio      MeasuredRatio  `json:"measured_ratio"`
	OpenIssues         IssueSummary   `json:"open_issues"`
	LastMeasured       string         `json:"last_measured,omitempty"`
}

// NetworkOverview is the whole response model.
type NetworkOverview struct {
	Providers []ProviderOverview `json:"providers"`
	Seams     []SeamOverview     `json:"seams"`
	// SeamsTruncated discloses that MaxSeams cut the list (worst-first, so only
	// the healthiest seams can fall off).
	SeamsTruncated bool `json:"seams_truncated"`
	// OpenIssuesLocalized / OpenIssuesUnlocalized: of the issues the caller
	// passed, how many the inventory could pin to a node vs not. An issue we
	// cannot localize is COUNTED here, never silently dropped.
	OpenIssuesLocalized   int    `json:"open_issues_localized"`
	OpenIssuesUnlocalized int    `json:"open_issues_unlocalized"`
	GeneratedAt           string `json:"generated_at"`
}

// ── worst-of precedence (the honesty core) ────────────────────────────────────

// statusRank orders MEASURED severities for the worst-of fold. not_measured is
// deliberately rank 0 here: it never wins the fold — it is surfaced through
// measured_ratio and through the "zero measured children" rule instead.
func statusRank(s string) int {
	switch s {
	case StatusDown:
		return 3
	case StatusDegraded:
		return 2
	case StatusHealthy:
		return 1
	default:
		return 0
	}
}

// displaySeverity orders NODES for worst-first sorting/truncation. Unknown ≠
// green: a fully-unmeasured node outranks a healthy one so a cap never hides it.
func displaySeverity(s string) int {
	switch s {
	case StatusDown:
		return 3
	case StatusDegraded:
		return 2
	case StatusNotMeasured:
		return 1
	default:
		return 0
	}
}

// statusAcc folds leaf component statuses into one level's roll-up. Every level
// (subnet, family, VPC, region, provider, seam) accumulates over its LEAF
// components, so the named reason always points at the actual broken component,
// not at an intermediate container.
type statusAcc struct {
	total, measured int
	worst           string // worst MEASURED status ("" until one arrives)
	worstReason     string
	worstName       string
	last            time.Time // max LastSeenAt among children
}

func (a *statusAcc) add(r CloudResource) {
	a.total++
	st := NormalizeComponentStatus(r.Status)
	if r.LastSeenAt.After(a.last) {
		a.last = r.LastSeenAt
	}
	if st == StatusNotMeasured {
		return
	}
	a.measured++
	if statusRank(st) > statusRank(a.worst) {
		a.worst = st
		a.worstReason = strings.TrimSpace(r.StatusReason)
		a.worstName = componentDisplayName(r)
	}
}

// ratio is the coverage caveat the level carries alongside its status.
func (a *statusAcc) ratio() MeasuredRatio {
	return MeasuredRatio{Measured: a.measured, Total: a.total}
}

// rollup resolves the accumulated children into (status, named reason). noun is
// the child noun for the wording ("component", "device").
//
// Precedence, explicit and honest:
//  1. any child down      → down     (reason names the worst contributor)
//  2. else any degraded   → degraded (reason names the worst contributor)
//  3. else ≥1 measured    → healthy  — with the coverage caveat spelled out when
//     some children are unmeasured (measured_ratio carries the numbers)
//  4. zero measured       → not_measured, NEVER healthy
//  5. zero children       → not_measured ("nothing discovered")
func (a *statusAcc) rollup(noun string) (status, reason string) {
	plural := noun + "s"
	switch {
	case a.total == 0:
		return StatusNotMeasured, "no " + plural + " discovered"
	case a.measured == 0:
		return StatusNotMeasured, fmt.Sprintf("none of the %d %s are measured yet", a.total, plural)
	case a.worst == StatusDown || a.worst == StatusDegraded:
		detail := a.worstReason
		if detail == "" {
			detail = a.worstName + " reported " + a.worst
		} else {
			detail += " (" + a.worstName + ")"
		}
		return a.worst, a.worst + " — " + detail
	case a.measured == a.total:
		if a.total == 1 {
			return StatusHealthy, "the 1 measured " + noun + " is healthy"
		}
		return StatusHealthy, fmt.Sprintf("all %d %s measured healthy", a.total, plural)
	default:
		return StatusHealthy, fmt.Sprintf("measured %s healthy — %d of %d measured", plural, a.measured, a.total)
	}
}

// lastMeasuredString renders the freshest child observation, "" when none.
func (a *statusAcc) lastMeasuredString() string {
	if a.last.IsZero() {
		return ""
	}
	return a.last.UTC().Format(time.RFC3339)
}

// componentDisplayName names a component for a human reason string: the operator
// name when declared, else the last path segment of the resource id (an ARM path
// or GCP resource path reads as its final name).
func componentDisplayName(r CloudResource) string {
	if r.ResourceName != "" {
		return r.ResourceName
	}
	id := r.ResourceID
	if i := strings.LastIndex(id, "/"); i >= 0 && i < len(id)-1 {
		return id[i+1:]
	}
	return id
}

// ── performance roll-up ───────────────────────────────────────────────────────

// countLikeUnits are the key-metric units that are meaningful when SUMMED across
// components (2 LBs × healthy targets → total healthy targets). Everything else
// (rates, percents) rolls up as the WORST (max) value — summing two error rates
// would fabricate a number nobody measured.
var countLikeUnits = map[string]bool{
	"":          true,
	"count":     true,
	"targets":   true,
	"tunnels":   true,
	"rules":     true,
	"records":   true,
	"zones":     true,
	"instances": true,
	"routes":    true,
	"sessions":  true,
}

// rollupPerformance groups the really-measured key metrics by (family, metric,
// unit). A component without a key metric contributes nothing — absence stays
// absence.
func rollupPerformance(components []CloudResource, limit int) []PerformanceMetric {
	type key struct{ family, metric, unit string }
	type agg struct {
		sum, max float64
		n        int
	}
	byKey := map[key]*agg{}
	for _, r := range components {
		if r.KeyMetricValue == nil || strings.TrimSpace(r.KeyMetricName) == "" {
			continue
		}
		k := key{family: ComponentFamily(r.ResourceType), metric: r.KeyMetricName, unit: r.KeyMetricUnit}
		a := byKey[k]
		if a == nil {
			a = &agg{max: *r.KeyMetricValue}
			byKey[k] = a
		}
		v := *r.KeyMetricValue
		a.sum += v
		if v > a.max {
			a.max = v
		}
		a.n++
	}
	out := make([]PerformanceMetric, 0, len(byKey))
	for k, a := range byKey {
		m := PerformanceMetric{Family: k.family, Metric: k.metric, Unit: k.unit, Components: a.n}
		switch {
		case a.n == 1:
			m.Value = a.sum
		case countLikeUnits[strings.ToLower(strings.TrimSpace(k.unit))]:
			m.Value, m.Aggregation = a.sum, "sum"
		default:
			m.Value, m.Aggregation = a.max, "max"
		}
		out = append(out, m)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Family != out[j].Family {
			return out[i].Family < out[j].Family
		}
		return out[i].Metric < out[j].Metric
	})
	if len(out) > limit {
		out = out[:limit]
	}
	return out
}

// ── family / subnet roll-ups ──────────────────────────────────────────────────

// familyOrder is the render order of the component families (entry points first,
// workloads last) — stable, not alphabetical, so the UI dots don't reshuffle.
var familyOrder = []string{FamilyLB, FamilyWAF, FamilyFirewall, FamilyDNS, FamilyGateway, FamilyK8s, FamilyServerless, FamilyDatabase, FamilyInstance, FamilyOther}

func rollupFamilies(components []CloudResource) []FamilyRollup {
	accs := map[string]*statusAcc{}
	for _, r := range components {
		f := ComponentFamily(r.ResourceType)
		a := accs[f]
		if a == nil {
			a = &statusAcc{}
			accs[f] = a
		}
		a.add(r)
	}
	out := make([]FamilyRollup, 0, len(accs))
	for _, f := range familyOrder {
		a, ok := accs[f]
		if !ok {
			continue
		}
		status, reason := a.rollup("component")
		out = append(out, FamilyRollup{Family: f, Count: a.total, Status: status, StatusReason: reason, MeasuredRatio: a.ratio()})
	}
	return out
}

func rollupSubnets(components []CloudResource, limit int) ([]SubnetRollup, bool) {
	accs := map[string]*statusAcc{}
	for _, r := range components {
		for _, sn := range r.SubnetIDs {
			sn = strings.TrimSpace(sn)
			if sn == "" {
				continue
			}
			a := accs[sn]
			if a == nil {
				a = &statusAcc{}
				accs[sn] = a
			}
			a.add(r)
		}
	}
	out := make([]SubnetRollup, 0, len(accs))
	for id, a := range accs {
		status, reason := a.rollup("component")
		out = append(out, SubnetRollup{SubnetID: id, ComponentCount: a.total, Status: status, StatusReason: reason, MeasuredRatio: a.ratio()})
	}
	sort.Slice(out, func(i, j int) bool {
		si, sj := displaySeverity(out[i].Status), displaySeverity(out[j].Status)
		if si != sj {
			return si > sj
		}
		return out[i].SubnetID < out[j].SubnetID
	})
	truncated := len(out) > limit
	if truncated {
		out = out[:limit]
	}
	return out, truncated
}

// ── issue localization ────────────────────────────────────────────────────────

// seamLaneKinds are signal kinds that belong to the LATERAL dimension by
// definition (§4a): an issue carrying one may only attach to a seam — attaching
// it to a VPC would misattribute a link fault to a node.
var seamLaneKinds = map[string]bool{
	"ipsec_tunnel_status":   true,
	"ipsec_underlay_status": true,
}

// handleIndex keys the tenant inventory by every handle a signal can carry
// (resource id, ARN/ARM URI incl. case-folded, ENIs, private/public IPs) —
// the same resolution the evidence surfaces use.
func handleIndex(res []CloudResource) map[string]*CloudResource {
	idx := make(map[string]*CloudResource, len(res)*2)
	put := func(key string, r *CloudResource) {
		if key == "" {
			return
		}
		if _, ok := idx[key]; !ok {
			idx[key] = r
		}
	}
	for i := range res {
		r := &res[i]
		put(r.ResourceID, r)
		put(r.ResourceURI, r)
		put(strings.ToLower(r.ResourceURI), r)
		for _, eni := range r.NetworkInterfaceIDs {
			put(eni, r)
		}
		for _, ip := range r.PrivateIPs {
			put(ip, r)
		}
		for _, ip := range r.PublicIPs {
			put(ip, r)
		}
	}
	return idx
}

// issueLedger accumulates localized issues per node key; each issue counts at a
// node ONCE, and the first (newest — callers pass newest-first) issue's title
// becomes the node's top issue.
type issueLedger struct {
	byNode map[string]*IssueSummary
}

func (l *issueLedger) attach(nodeKey, title string) {
	s := l.byNode[nodeKey]
	if s == nil {
		s = &IssueSummary{}
		l.byNode[nodeKey] = s
	}
	s.Count++
	if s.TopIssue == "" {
		s.TopIssue = title
	}
}

func (l *issueLedger) at(nodeKey string) IssueSummary {
	if s := l.byNode[nodeKey]; s != nil {
		return *s
	}
	return IssueSummary{}
}

// node key builders — one namespace per level.
func providerKey(p string) string       { return "p:" + p }
func regionKey(p, region string) string { return "r:" + p + "/" + region }
func vpcKey(p, vpcID string) string     { return "v:" + p + "/" + vpcID }
func seamNodeKey(seamID string) string  { return "s:" + seamID }

// localizeIssues resolves each issue's handles against the inventory and pins
// the issue to its nodes. Rules (design §3.5 + §4a):
//   - an issue whose evidence touches a seam device, or that carries a
//     seam-lane kind, is a SEAM issue: it attaches to the matching seam(s) and
//     to NOTHING inside the tree (never to either VPC);
//   - otherwise it attaches once to every distinct VPC its evidence resolves
//     into, and rolls up to those VPCs' regions and providers;
//   - evidence on a non-VPC resource attaches at that resource's region;
//   - an issue resolving to nothing is counted as unlocalized — visible, never
//     silently dropped.
func localizeIssues(issues []OverviewIssue, res []CloudResource, seamOf map[string]string) (ledger issueLedger, localized, unlocalized int) {
	ledger = issueLedger{byNode: map[string]*IssueSummary{}}
	idx := handleIndex(res)
	for _, is := range issues {
		title := strings.TrimSpace(is.Title)
		if title == "" {
			title = "Open investigation"
		}
		seamLane := false
		for _, k := range is.Kinds {
			if seamLaneKinds[strings.ToLower(strings.TrimSpace(k))] {
				seamLane = true
				break
			}
		}
		seamIDs := map[string]bool{}
		nodeKeys := map[string]bool{}
		for _, h := range is.Handles {
			h = strings.TrimSpace(h)
			if h == "" {
				continue
			}
			r, ok := idx[h]
			if !ok {
				r, ok = idx[strings.ToLower(h)]
			}
			if !ok {
				continue
			}
			if sid := seamOf[r.ResourceID]; sid != "" {
				seamIDs[sid] = true
				continue
			}
			p := string(r.Provider)
			region := overviewRegion(r.Region)
			if r.VpcID != "" {
				nodeKeys[vpcKey(p, r.VpcID)] = true
			}
			nodeKeys[regionKey(p, region)] = true
			nodeKeys[providerKey(p)] = true
		}
		switch {
		case len(seamIDs) > 0:
			// Seam issue: the seam ONLY — even if other handles touched a VPC,
			// the lateral fault renders on the link (§4a).
			for sid := range seamIDs {
				ledger.attach(seamNodeKey(sid), title)
			}
			localized++
		case seamLane:
			// Seam-lane kind but no seam device resolved: attaching it inside a
			// VPC would misattribute a link fault — count it unlocalized instead.
			unlocalized++
		case len(nodeKeys) > 0:
			for k := range nodeKeys {
				ledger.attach(k, title)
			}
			localized++
		default:
			unlocalized++
		}
	}
	return ledger, localized, unlocalized
}

// ── seams (§4a — the lateral dimension) ───────────────────────────────────────

// overviewRegion normalizes an empty region to the customer-facing "global"
// bucket (Route53 zones, Front Door profiles and friends are genuinely global).
func overviewRegion(region string) string {
	if strings.TrimSpace(region) == "" {
		return "global"
	}
	return region
}

// seamGroupID derives the seam a seam-endpoint resource belongs to. Resources
// declaring the SAME attachment set (the VPCs/regions the link joins) are one
// seam with several traversed devices; a resource declaring no attachments is
// its own seam (we never merge two undeclared links by guesswork).
func seamGroupID(r CloudResource) string {
	tokens := make([]string, 0, len(r.AttachedVpcIDs)+len(r.AttachedRegions))
	for _, v := range r.AttachedVpcIDs {
		if v = strings.TrimSpace(v); v != "" {
			tokens = append(tokens, "vpc="+v)
		}
	}
	for _, rg := range r.AttachedRegions {
		if rg = strings.TrimSpace(rg); rg != "" {
			tokens = append(tokens, "region="+rg)
		}
	}
	if len(tokens) == 0 {
		return string(r.Provider) + "|" + r.ResourceID
	}
	sort.Strings(tokens)
	return string(r.Provider) + "|" + strings.Join(tokens, ",")
}

// buildSeams groups the seam-family resources into first-class lateral links and
// returns (seams sorted worst-first, resourceID→seamID). Status is the worst-of
// the seam's own device rows — tunnel state / BGP state as P0 measured them.
func buildSeams(seamRes []CloudResource, lim OverviewLimits) ([]SeamOverview, map[string]string) {
	type seamAcc struct {
		provider  string
		devices   []SeamDevice
		endpoints map[string]SeamEndpoint
		acc       statusAcc
	}
	groups := map[string]*seamAcc{}
	seamOf := make(map[string]string, len(seamRes))
	for _, r := range seamRes {
		id := seamGroupID(r)
		seamOf[r.ResourceID] = id
		g := groups[id]
		if g == nil {
			g = &seamAcc{provider: string(r.Provider), endpoints: map[string]SeamEndpoint{}}
			groups[id] = g
		}
		g.acc.add(r)
		st := NormalizeComponentStatus(r.Status)
		g.devices = append(g.devices, SeamDevice{
			ResourceID:   r.ResourceID,
			Name:         componentDisplayName(r),
			Type:         r.ResourceType,
			Status:       st,
			StatusReason: strings.TrimSpace(r.StatusReason),
		})
		// Endpoint A: where the device itself sits. Endpoint B(+): what it
		// declares itself attached to. Both discovered, never assumed (§4a).
		own := SeamEndpoint{Region: overviewRegion(r.Region), VpcID: r.VpcID}
		g.endpoints[own.Region+"|"+own.VpcID] = own
		for _, v := range r.AttachedVpcIDs {
			if v = strings.TrimSpace(v); v != "" && v != r.VpcID {
				g.endpoints["|"+v] = SeamEndpoint{VpcID: v}
			}
		}
		for _, rg := range r.AttachedRegions {
			if rg = strings.TrimSpace(rg); rg != "" {
				g.endpoints[rg+"|"] = SeamEndpoint{Region: rg}
			}
		}
	}

	ids := make([]string, 0, len(groups))
	for id := range groups {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	out := make([]SeamOverview, 0, len(groups))
	for _, id := range ids {
		g := groups[id]
		status, reason := g.acc.rollup("device")
		eps := make([]SeamEndpoint, 0, len(g.endpoints))
		for _, e := range g.endpoints {
			eps = append(eps, e)
		}
		sort.Slice(eps, func(i, j int) bool {
			if eps[i].Region != eps[j].Region {
				return eps[i].Region < eps[j].Region
			}
			return eps[i].VpcID < eps[j].VpcID
		})
		epTrunc := len(eps) > lim.MaxSeamEndpoints
		if epTrunc {
			eps = eps[:lim.MaxSeamEndpoints]
		}
		devs := g.devices
		sort.Slice(devs, func(i, j int) bool {
			si, sj := displaySeverity(devs[i].Status), displaySeverity(devs[j].Status)
			if si != sj {
				return si > sj
			}
			return devs[i].ResourceID < devs[j].ResourceID
		})
		devTrunc := len(devs) > lim.MaxSeamDevices
		if devTrunc {
			devs = devs[:lim.MaxSeamDevices]
		}
		out = append(out, SeamOverview{
			ID:                 id,
			Provider:           g.provider,
			Endpoints:          eps,
			EndpointsTruncated: epTrunc,
			Devices:            devs,
			DevicesTruncated:   devTrunc,
			Status:             status,
			StatusReason:       reason,
			MeasuredRatio:      g.acc.ratio(),
			LastMeasured:       g.acc.lastMeasuredString(),
		})
	}
	sort.SliceStable(out, func(i, j int) bool {
		si, sj := displaySeverity(out[i].Status), displaySeverity(out[j].Status)
		if si != sj {
			return si > sj
		}
		return out[i].ID < out[j].ID
	})
	return out, seamOf
}

// ── the engine ────────────────────────────────────────────────────────────────

// BuildNetworkOverview rolls the tenant's component inventory (P0 rows) and its
// open investigations up into the provider → region → VPC hierarchy plus the
// top-level seams. Pure and deterministic; the caller has already scoped both
// inputs to the principal's tenant.
//
// Seam-family resources live ONLY in seams[] — they are excluded from every
// VPC / region / provider component roll-up so a lateral link is never
// double-reported as a node attribute (§4a).
func BuildNetworkOverview(res []CloudResource, issues []OverviewIssue, lim OverviewLimits, now time.Time) NetworkOverview {
	lim = lim.withDefaults()

	// Partition: seam endpoints out of the tree; everything else by
	// provider → region → VPC ("" VPC → the region's non-VPC bucket).
	var seamRes []CloudResource
	type vpcBucket struct{ components []CloudResource }
	type regionBucket struct {
		vpcs   map[string]*vpcBucket
		nonVPC []CloudResource
	}
	type providerBucket struct{ regions map[string]*regionBucket }
	providers := map[string]*providerBucket{}
	for _, r := range res {
		if !ValidProvider(r.Provider) {
			continue // a row without a valid provider has no place in the hierarchy
		}
		if ComponentFamily(r.ResourceType) == FamilySeam {
			seamRes = append(seamRes, r)
			continue
		}
		p := string(r.Provider)
		pb := providers[p]
		if pb == nil {
			pb = &providerBucket{regions: map[string]*regionBucket{}}
			providers[p] = pb
		}
		region := overviewRegion(r.Region)
		rb := pb.regions[region]
		if rb == nil {
			rb = &regionBucket{vpcs: map[string]*vpcBucket{}}
			pb.regions[region] = rb
		}
		if r.VpcID == "" {
			rb.nonVPC = append(rb.nonVPC, r)
			continue
		}
		vb := rb.vpcs[r.VpcID]
		if vb == nil {
			vb = &vpcBucket{}
			rb.vpcs[r.VpcID] = vb
		}
		vb.components = append(vb.components, r)
	}

	seams, seamOf := buildSeams(seamRes, lim)
	ledger, localized, unlocalized := localizeIssues(issues, res, seamOf)
	for i := range seams {
		seams[i].OpenIssues = ledger.at(seamNodeKey(seams[i].ID))
	}
	seamsTruncated := len(seams) > lim.MaxSeams
	if seamsTruncated {
		seams = seams[:lim.MaxSeams]
	}

	provNames := make([]string, 0, len(providers))
	for p := range providers {
		provNames = append(provNames, p)
	}
	sort.Strings(provNames)

	outProviders := make([]ProviderOverview, 0, len(provNames))
	for _, p := range provNames {
		pb := providers[p]
		regionNames := make([]string, 0, len(pb.regions))
		for rg := range pb.regions {
			regionNames = append(regionNames, rg)
		}
		sort.Strings(regionNames)

		var provAcc statusAcc
		provComponents := 0
		outRegions := make([]RegionOverview, 0, len(regionNames))
		for _, rg := range regionNames {
			rb := pb.regions[rg]
			var regAcc statusAcc
			regComponents := 0

			vpcIDs := make([]string, 0, len(rb.vpcs))
			for id := range rb.vpcs {
				vpcIDs = append(vpcIDs, id)
			}
			sort.Strings(vpcIDs)
			outVPCs := make([]VPCOverview, 0, len(vpcIDs))
			for _, vid := range vpcIDs {
				vb := rb.vpcs[vid]
				var acc statusAcc
				name, cidr := "", ""
				for _, c := range vb.components {
					acc.add(c)
					regAcc.add(c)
					provAcc.add(c)
					if name == "" {
						name = c.Attrs["vpc_name"]
					}
					if cidr == "" {
						cidr = c.Attrs["vpc_cidr"]
					}
				}
				regComponents += len(vb.components)
				status, reason := acc.rollup("component")
				subnets, subTrunc := rollupSubnets(vb.components, lim.MaxSubnetsPerVPC)
				outVPCs = append(outVPCs, VPCOverview{
					VpcID:            vid,
					Name:             name,
					CIDR:             cidr,
					Status:           status,
					StatusReason:     reason,
					MeasuredRatio:    acc.ratio(),
					OpenIssues:       ledger.at(vpcKey(p, vid)),
					ComponentCount:   len(vb.components),
					Families:         rollupFamilies(vb.components),
					Performance:      rollupPerformance(vb.components, lim.MaxPerfMetrics),
					Subnets:          subnets,
					SubnetsTruncated: subTrunc,
					LastMeasured:     acc.lastMeasuredString(),
				})
			}
			for _, c := range rb.nonVPC {
				regAcc.add(c)
				provAcc.add(c)
			}
			regComponents += len(rb.nonVPC)
			provComponents += regComponents

			// Worst-first so truncation can only drop the healthiest VPCs.
			sort.SliceStable(outVPCs, func(i, j int) bool {
				si, sj := displaySeverity(outVPCs[i].Status), displaySeverity(outVPCs[j].Status)
				if si != sj {
					return si > sj
				}
				return outVPCs[i].VpcID < outVPCs[j].VpcID
			})
			vpcCount := len(outVPCs)
			vpcsTruncated := vpcCount > lim.MaxVPCsPerRegion
			if vpcsTruncated {
				outVPCs = outVPCs[:lim.MaxVPCsPerRegion]
			}

			status, reason := regAcc.rollup("component")
			outRegions = append(outRegions, RegionOverview{
				Region:             rg,
				Status:             status,
				StatusReason:       reason,
				MeasuredRatio:      regAcc.ratio(),
				OpenIssues:         ledger.at(regionKey(p, rg)),
				VPCCount:           vpcCount,
				ComponentCount:     regComponents,
				VPCs:               outVPCs,
				VPCsTruncated:      vpcsTruncated,
				RegionalComponents: rollupFamilies(rb.nonVPC),
				LastMeasured:       regAcc.lastMeasuredString(),
			})
		}

		sort.SliceStable(outRegions, func(i, j int) bool {
			si, sj := displaySeverity(outRegions[i].Status), displaySeverity(outRegions[j].Status)
			if si != sj {
				return si > sj
			}
			return outRegions[i].Region < outRegions[j].Region
		})
		regionCount := len(outRegions)
		regionsTruncated := regionCount > lim.MaxRegionsPerProvider
		if regionsTruncated {
			outRegions = outRegions[:lim.MaxRegionsPerProvider]
		}

		status, reason := provAcc.rollup("component")
		outProviders = append(outProviders, ProviderOverview{
			Provider:         p,
			Status:           status,
			StatusReason:     reason,
			MeasuredRatio:    provAcc.ratio(),
			OpenIssues:       ledger.at(providerKey(p)),
			RegionCount:      regionCount,
			ComponentCount:   provComponents,
			Regions:          outRegions,
			RegionsTruncated: regionsTruncated,
			LastMeasured:     provAcc.lastMeasuredString(),
		})
	}

	return NetworkOverview{
		Providers:             outProviders,
		Seams:                 seams,
		SeamsTruncated:        seamsTruncated,
		OpenIssuesLocalized:   localized,
		OpenIssuesUnlocalized: unlocalized,
		GeneratedAt:           now.UTC().Format(time.RFC3339),
	}
}
