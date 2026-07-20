package main

// segment_classifier.go — Go mirror of the address-space segment/device classifier
// (path-causality RCA P0; Python source of truth: src/correlation/segment_classifier.py).
//
// Purpose: stamp a hop's SEGMENT TYPE + device ROLE at INGEST/enrichment time, so the
// signal is present on the event before it reaches the correlation service. Same
// vocabulary, same default-closed multi-signal fusion as the Python classifier — kept in
// lockstep so a hop classifies identically whichever side stamps it.
//
// House rules (CLAUDE.md): STDLIB ONLY — no new module. Longest-prefix match is done with
// net/netip over the BUNDLED snapshot (segmentdata/provider_ip_ranges.json, go:embed'd);
// the classifier never fetches at runtime. All inputs are untrusted: a malformed feed
// entry is skipped (never fatal), an unparseable IP yields unknown + reason. Explicit
// types, no ignored errors.
//
// Scope vs Python: this mirror implements the deterministic + declared signals that matter
// at ingest — provider-CIDR (longest-prefix), RFC1918/RFC4193/RFC6598, the curated ASN
// table, device_role_hint, and (weak) rDNS provider/role hints. TTL/latency timing hints
// stay Python-only (they belong to path-assembly, not ingest) — see the report.

import (
	"embed"
	"encoding/json"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
)

//go:embed segmentdata/provider_ip_ranges.json
var segmentSnapshotFS embed.FS

// ── vocabulary (identical values to segment_classifier.py) ──────────────────

// Segment types.
const (
	SegCloud    = "cloud"
	SegLAN      = "lan"
	SegDC       = "dc"
	SegWAN      = "wan"
	SegWANSeam  = "wan_seam"
	SegInternet = "internet"
	SegUnknown  = "unknown"
)

// Device roles.
const (
	RoleLoadBalancer = "load_balancer"
	RoleWAF          = "waf"
	RoleFirewall     = "firewall"
	RoleDNSResolver  = "dns_resolver"
	RoleRouter       = "router"
	RoleSwitch       = "switch"
	RoleTunnelGW     = "tunnel_gw"
	RoleHost         = "host"
	RoleUnknown      = "unknown"
)

// Confidence tiers.
const (
	ConfStrong = "strong"
	ConfMedium = "medium"
	ConfWeak   = "weak"
	ConfNone   = "none"
)

// segmentToBoundary projects the rich segment_type onto path_graph.BOUNDARY_OF_KIND.
var segmentToBoundary = map[string]string{
	SegCloud: "CLOUD", SegLAN: "LAN", SegDC: "LAN", SegWAN: "CARRIER",
	SegWANSeam: "SD-WAN", SegInternet: "CARRIER", SegUnknown: "UNKNOWN",
}

// compatGroups: segment types that REFINE rather than CONTRADICT one another.
var compatGroups = [][]string{
	{SegLAN, SegDC},
	{SegWAN, SegInternet},
}

func segCompatible(a, b string) bool {
	if a == b {
		return true
	}
	for _, g := range compatGroups {
		ina, inb := false, false
		for _, t := range g {
			if t == a {
				ina = true
			}
			if t == b {
				inb = true
			}
		}
		if ina && inb {
			return true
		}
	}
	return false
}

// ── constants: RFC1918 / RFC4193 / RFC6598 ──────────────────────────────────

var (
	rfc1918 = []netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/8"),
		netip.MustParsePrefix("172.16.0.0/12"),
		netip.MustParsePrefix("192.168.0.0/16"),
	}
	rfc4193 = netip.MustParsePrefix("fc00::/7")      // IPv6 unique-local
	rfc6598 = netip.MustParsePrefix("100.64.0.0/10") // CGNAT / shared address space
)

// asnRow classifies a curated ASN.
type asnRow struct {
	class    string // "cloud" | "transit" | "eyeball"
	provider string
}

// asnTable mirrors _ASN_TABLE in the Python classifier.
var asnTable = map[int]asnRow{
	16509: {"cloud", "aws"}, 14618: {"cloud", "aws"},
	8075: {"cloud", "azure"}, 12076: {"cloud", "azure"},
	15169: {"cloud", "gcp"}, 396982: {"cloud", "gcp"},
	13335: {"cloud", "cloudflare"},
	174:   {"transit", "cogent"}, 3356: {"transit", "lumen"}, 3257: {"transit", "gtt"},
	1299: {"transit", "arelion"}, 2914: {"transit", "ntt"}, 6939: {"transit", "he"},
	6461: {"transit", "zayo"},
}

// ── rDNS + device-role patterns (mirror the Python regex tables) ────────────

type rdnsProv struct {
	re       *regexp.Regexp
	provider string
}

var rdnsProviders = []rdnsProv{
	{regexp.MustCompile(`(?i)(^|\.)compute\.amazonaws\.com$`), "aws"},
	{regexp.MustCompile(`(?i)(^|\.)amazonaws\.com$`), "aws"},
	{regexp.MustCompile(`(?i)(^|\.)1e100\.net$`), "gcp"},
	{regexp.MustCompile(`(?i)(^|\.)googleusercontent\.com$`), "gcp"},
	{regexp.MustCompile(`(?i)(^|\.)cloudapp\.azure\.com$`), "azure"},
	{regexp.MustCompile(`(?i)(^|\.)cloudapp\.net$`), "azure"},
}

type rdnsRole struct {
	re   *regexp.Regexp
	role string
}

var rdnsRoles = []rdnsRole{
	{regexp.MustCompile(`(?i)(^|[-.])(lb|elb|alb|nlb|lbaas|slb)([-.]|\d|$)`), RoleLoadBalancer},
	{regexp.MustCompile(`(?i)(^|[-.])(waf|appgw|appgateway)([-.]|\d|$)`), RoleWAF},
	{regexp.MustCompile(`(?i)(^|[-.])(fw|firewall|asa|palo|fgt|fortigate|ngfw)([-.]|\d|$)`), RoleFirewall},
	{regexp.MustCompile(`(?i)(^|[-.])(dns|resolver|ns\d|unbound|bind)([-.]|\d|$)`), RoleDNSResolver},
	{regexp.MustCompile(`(?i)(^|[-.])(rtr|router|gw|gateway|edge|core)([-.]|\d|$)`), RoleRouter},
	{regexp.MustCompile(`(?i)(^|[-.])(sw|switch|leaf|spine|tor)([-.]|\d|$)`), RoleSwitch},
	{regexp.MustCompile(`(?i)(^|[-.])(vpn|ipsec|tunnel|nva|dx|expressroute)([-.]|\d|$)`), RoleTunnelGW},
}

// roleHint maps a declared device-role hint → (role, optional segment vote, optional seam kind).
type roleHint struct {
	re       *regexp.Regexp
	role     string
	segVote  string
	seamKind string
}

var roleHints = []roleHint{
	{regexp.MustCompile(`(?i)load[_\- ]?balanc|(^|\W)(lb|elb|alb|nlb|slb)(\W|$)`), RoleLoadBalancer, "", ""},
	{regexp.MustCompile(`(?i)waf|app[_\- ]?gateway|web[_\- ]?application[_\- ]?firewall`), RoleWAF, "", ""},
	{regexp.MustCompile(`(?i)firewall|ngfw|(^|\W)(fw|asa|palo|fortigate|fgt)(\W|$)`), RoleFirewall, "", ""},
	{regexp.MustCompile(`(?i)dns|resolver|name[_\- ]?server`), RoleDNSResolver, "", ""},
	{regexp.MustCompile(`(?i)spine|leaf|(^|\W)tor(\W|$)|fabric|datacenter|data[_\- ]?center`), RoleSwitch, SegDC, ""},
	{regexp.MustCompile(`(?i)switch|(^|\W)sw\d`), RoleSwitch, SegLAN, ""},
	{regexp.MustCompile(`(?i)express[_\- ]?route`), RoleTunnelGW, SegWANSeam, "DX"},
	{regexp.MustCompile(`(?i)direct[_\- ]?connect|(^|\W)dx(\W|$)`), RoleTunnelGW, SegWANSeam, "DX"},
	{regexp.MustCompile(`(?i)ipsec|(^|\W)vpn(\W|$)`), RoleTunnelGW, SegWANSeam, "VPN"},
	{regexp.MustCompile(`(?i)sd[_\- ]?wan|velocloud|versa`), RoleTunnelGW, SegWANSeam, "SDWAN"},
	{regexp.MustCompile(`(?i)(^|\W)nva(\W|$)|network[_\- ]?virtual[_\- ]?appliance|tunnel`), RoleTunnelGW, SegWANSeam, ""},
	{regexp.MustCompile(`(?i)router|(^|\W)(rtr|gw)(\W|$)|gateway|edge`), RoleRouter, "", ""},
	{regexp.MustCompile(`(?i)host|server|instance|(^|\W)vm(\W|$)|endpoint`), RoleHost, "", ""},
}

// ── provider trie (longest-prefix match, stdlib) ────────────────────────────

type prefixValue struct {
	Provider string
	Region   string
	Service  string
	Prefix   string
}

// providerTrie does longest-prefix match by probing masked prefixes from longest length to
// shortest — a clean, stdlib-only LPM (no third-party radix tree). Separate length-sets per
// family keep lookups sparse.
type providerTrie struct {
	byPrefix  map[netip.Prefix]prefixValue
	v4Lengths []int // present prefix lengths, longest first
	v6Lengths []int
	Count     int
	SyncedAt  string
}

type snapshotFile struct {
	SyncedAt string            `json:"synced_at"`
	Prefixes []json.RawMessage `json:"prefixes"` // decoded per-entry so one bad row can't abort the load
}

type snapshotPrefix struct {
	Prefix   string `json:"prefix"`
	Provider string `json:"provider"`
	Region   string `json:"region"`
	Service  string `json:"service"`
}

func newProviderTrie() *providerTrie {
	return &providerTrie{byPrefix: make(map[netip.Prefix]prefixValue)}
}

// loadProviderTrie builds the trie from raw snapshot JSON. Malformed entries are skipped
// (untrusted feed data). A decode error yields an empty (CIDR-blind) trie, never a panic.
func loadProviderTrie(raw []byte) *providerTrie {
	t := newProviderTrie()
	var sf snapshotFile
	if err := json.Unmarshal(raw, &sf); err != nil {
		return t // CIDR-blind; RFC/ASN/role signals still work
	}
	t.SyncedAt = sf.SyncedAt
	v4set := map[int]struct{}{}
	v6set := map[int]struct{}{}
	for _, rawEntry := range sf.Prefixes {
		var e snapshotPrefix
		if err := json.Unmarshal(rawEntry, &e); err != nil {
			continue // skip non-object / malformed entry (untrusted feed data)
		}
		p, err := netip.ParsePrefix(strings.TrimSpace(e.Prefix))
		if err != nil {
			continue // skip malformed prefix
		}
		p = p.Masked()
		t.byPrefix[p] = prefixValue{
			Provider: strings.ToLower(strings.TrimSpace(e.Provider)),
			Region:   strings.TrimSpace(e.Region),
			Service:  strings.TrimSpace(e.Service),
			Prefix:   p.String(),
		}
		if p.Addr().Is4() {
			v4set[p.Bits()] = struct{}{}
		} else {
			v6set[p.Bits()] = struct{}{}
		}
		t.Count++
	}
	t.v4Lengths = sortedDesc(v4set)
	t.v6Lengths = sortedDesc(v6set)
	return t
}

func sortedDesc(m map[int]struct{}) []int {
	out := make([]int, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	// insertion sort desc (small n = number of distinct prefix lengths, ≤128)
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j] > out[j-1]; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}

func (t *providerTrie) lookup(ip netip.Addr) (prefixValue, bool) {
	lengths := t.v4Lengths
	if ip.Is6() && !ip.Is4In6() {
		lengths = t.v6Lengths
	}
	for _, l := range lengths {
		pfx, err := ip.Prefix(l)
		if err != nil {
			continue
		}
		if v, ok := t.byPrefix[pfx]; ok {
			return v, true
		}
	}
	return prefixValue{}, false
}

// ── signals + classification result ─────────────────────────────────────────

const (
	tierWeak          = 1
	tierStrong        = 2
	tierAuthoritative = 3
)

// SegmentSignal is one piece of evidence.
type SegmentSignal struct {
	Name        string `json:"signal"`
	Family      string `json:"family"`
	Tier        string `json:"tier"`
	SegmentVote string `json:"segment_vote,omitempty"`
	RoleVote    string `json:"role_vote,omitempty"`
	Provider    string `json:"provider,omitempty"`
	Region      string `json:"region,omitempty"`
	Service     string `json:"service,omitempty"`
	SeamKind    string `json:"seam_kind,omitempty"`
	Detail      string `json:"detail,omitempty"`

	tierRank int // internal
}

// SegmentClass is the classifier output (mirrors Classification.to_dict()).
type SegmentClass struct {
	SegmentType string          `json:"segment_type"`
	DeviceRole  string          `json:"device_role"`
	Confidence  string          `json:"confidence"`
	Boundary    string          `json:"boundary"`
	Provider    string          `json:"provider,omitempty"`
	Region      string          `json:"region,omitempty"`
	Service     string          `json:"service,omitempty"`
	SeamKind    string          `json:"seam_kind,omitempty"`
	Reason      string          `json:"reason"`
	Signals     []SegmentSignal `json:"signals"`
}

// Hop is the classifier input. Only IP is required.
type Hop struct {
	IP             string
	RDNS           string
	DeviceRoleHint string
	ASN            int // 0 = unknown
}

// ── the classifier ──────────────────────────────────────────────────────────

// SegmentClassifier is stateless after construction (read-only trie). Safe for concurrent use.
type SegmentClassifier struct {
	trie *providerTrie
}

var defaultSegmentClassifier *SegmentClassifier

// newSegmentClassifier builds the classifier from the embedded bundled snapshot.
func newSegmentClassifier() *SegmentClassifier {
	raw, err := segmentSnapshotFS.ReadFile("segmentdata/provider_ip_ranges.json")
	if err != nil {
		return &SegmentClassifier{trie: newProviderTrie()} // CIDR-blind fallback
	}
	return &SegmentClassifier{trie: loadProviderTrie(raw)}
}

// getSegmentClassifier returns the process-wide default (built once).
func getSegmentClassifier() *SegmentClassifier {
	if defaultSegmentClassifier == nil {
		defaultSegmentClassifier = newSegmentClassifier()
	}
	return defaultSegmentClassifier
}

// Classify classifies one hop. Default-closed: never guesses a type; a lone weak signal
// never yields a confident classification; no signal → unknown + reason.
func (c *SegmentClassifier) Classify(h Hop) SegmentClass {
	raw := strings.TrimSpace(h.IP)
	if raw == "" {
		return unknownClass("no IP supplied")
	}
	ip, err := netip.ParseAddr(raw)
	if err != nil {
		return unknownClass("unparseable IP " + raw)
	}
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsMulticast() || ip.IsUnspecified() {
		return unknownClass(raw + " is a non-topological address (loopback/link-local/multicast) — not a path segment")
	}

	var signals []SegmentSignal
	signals = append(signals, c.scoreAddressSpace(ip)...)
	signals = append(signals, scoreASN(h.ASN)...)
	signals = append(signals, scoreDeviceRole(h.DeviceRoleHint)...)
	signals = append(signals, scoreRDNS(h.RDNS)...)
	return fuseSegments(signals)
}

func (c *SegmentClassifier) scoreAddressSpace(ip netip.Addr) []SegmentSignal {
	if v, ok := c.trie.lookup(ip); ok {
		return []SegmentSignal{{
			Name: "provider_cidr", Family: "address_space", Tier: "authoritative", tierRank: tierAuthoritative,
			SegmentVote: SegCloud, Provider: v.Provider, Region: v.Region, Service: v.Service,
			Detail: "IP within published " + orDefault(v.Provider, "cloud") + " prefix " + v.Prefix,
		}}
	}
	if ip.Is4() && rfc6598.Contains(ip) {
		return []SegmentSignal{{
			Name: "rfc6598_cgnat", Family: "address_space", Tier: "authoritative", tierRank: tierAuthoritative,
			SegmentVote: SegWAN, Detail: "RFC6598 shared address space (100.64/10) — carrier-grade NAT / SP edge",
		}}
	}
	priv := (ip.Is4() && containsAny(rfc1918, ip)) || (ip.Is6() && !ip.Is4In6() && rfc4193.Contains(ip))
	if priv {
		return []SegmentSignal{{
			Name: "rfc1918_private", Family: "address_space", Tier: "strong", tierRank: tierStrong,
			SegmentVote: SegLAN,
			Detail:      "private address space (RFC1918/RFC4193) — LAN/DC fabric or intra-cloud (ambiguous alone)",
		}}
	}
	if isGlobalUnicast(ip) {
		return []SegmentSignal{{
			Name: "public_unassigned", Family: "address_space", Tier: "weak", tierRank: tierWeak,
			SegmentVote: SegInternet,
			Detail:      "globally routable public address, no provider-CIDR match — internet/transit hint",
		}}
	}
	return nil
}

func scoreASN(asn int) []SegmentSignal {
	if asn <= 0 {
		return nil
	}
	row, ok := asnTable[asn]
	if !ok {
		return []SegmentSignal{{
			Name: "asn_unknown", Family: "asn", Tier: "weak", tierRank: tierWeak,
			SegmentVote: SegInternet, Detail: "ASN not in curated cloud/transit table — public/internet hint",
		}}
	}
	vote := SegInternet
	switch row.class {
	case "cloud":
		vote = SegCloud
	case "transit":
		vote = SegWAN
	}
	return []SegmentSignal{{
		Name: "asn_" + row.class, Family: "asn", Tier: "strong", tierRank: tierStrong,
		SegmentVote: vote, Provider: row.provider,
		Detail: "curated " + row.class + " network (" + row.provider + ")",
	}}
}

func scoreDeviceRole(hint string) []SegmentSignal {
	text := strings.TrimSpace(hint)
	if text == "" {
		return nil
	}
	for _, h := range roleHints {
		if h.re.MatchString(text) {
			return []SegmentSignal{{
				Name: "device_role_hint", Family: "device_role", Tier: "authoritative", tierRank: tierAuthoritative,
				RoleVote: h.role, SegmentVote: h.segVote, SeamKind: h.seamKind,
				Detail: "declared device role from telemetry/LLDP/SNMP: " + text + " → " + h.role,
			}}
		}
	}
	return []SegmentSignal{{
		Name: "device_role_hint", Family: "device_role", Tier: "weak", tierRank: tierWeak,
		Detail: "device role hint " + text + " did not match a known role pattern",
	}}
}

func scoreRDNS(rdns string) []SegmentSignal {
	name := strings.TrimRight(strings.TrimSpace(rdns), ".")
	if name == "" {
		return nil
	}
	var out []SegmentSignal
	for _, p := range rdnsProviders {
		if p.re.MatchString(name) {
			out = append(out, SegmentSignal{
				Name: "rdns_provider", Family: "rdns", Tier: "weak", tierRank: tierWeak,
				SegmentVote: SegCloud, Provider: p.provider,
				Detail: "rDNS " + name + " matches " + p.provider + " naming (hint only)",
			})
			break
		}
	}
	for _, r := range rdnsRoles {
		if r.re.MatchString(name) {
			out = append(out, SegmentSignal{
				Name: "rdns_role", Family: "rdns", Tier: "weak", tierRank: tierWeak,
				RoleVote: r.role, Detail: "rDNS " + name + " suggests role " + r.role + " (hint only)",
			})
			break
		}
	}
	return out
}

// ── fusion (default-closed; mirrors _fuse in Python) ────────────────────────

type segVoteAgg struct {
	families map[string]struct{}
	bestTier int
	provider string
	region   string
	service  string
	seamKind string
}

func fuseSegments(signals []SegmentSignal) SegmentClass {
	role := fuseRole(signals)

	votes := map[string]*segVoteAgg{}
	for _, s := range signals {
		if s.SegmentVote == "" {
			continue
		}
		v := votes[s.SegmentVote]
		if v == nil {
			v = &segVoteAgg{families: map[string]struct{}{}}
			votes[s.SegmentVote] = v
		}
		v.families[s.Family] = struct{}{}
		if s.tierRank > v.bestTier {
			v.bestTier = s.tierRank
		}
		if v.provider == "" {
			v.provider = s.Provider
		}
		if v.region == "" {
			v.region = s.Region
		}
		if v.service == "" {
			v.service = s.Service
		}
		if v.seamKind == "" {
			v.seamKind = s.SeamKind
		}
	}

	if len(votes) == 0 {
		out := unknownClass("no address-space, ASN, device-role or naming signal established a segment type")
		out.DeviceRole = role
		out.Signals = signals
		return out
	}

	// Aggregate over compatible votes (refinements corroborate): union the independent
	// families and take the strongest tier across the compatible group.
	agg := func(t string) (bestTier, fams, ownTier int) {
		fset := map[string]struct{}{}
		for vt, v := range votes {
			if segCompatible(t, vt) {
				for f := range v.families {
					fset[f] = struct{}{}
				}
				if v.bestTier > bestTier {
					bestTier = v.bestTier
				}
			}
		}
		return bestTier, len(fset), votes[t].bestTier
	}

	winner := ""
	var wBest, wFams, wOwn int
	for t := range votes {
		bt, fams, own := agg(t)
		better := winner == "" || bt > wBest ||
			(bt == wBest && fams > wFams) ||
			(bt == wBest && fams == wFams && own > wOwn)
		if better {
			winner, wBest, wFams, wOwn = t, bt, fams, own
		}
	}

	contradicted := false
	for t, v := range votes {
		if !segCompatible(winner, t) && v.bestTier >= tierStrong {
			contradicted = true
			break
		}
	}

	var confidence string
	switch wBest {
	case tierAuthoritative:
		if contradicted {
			confidence = ConfMedium
		} else {
			confidence = ConfStrong
		}
	case tierStrong:
		if wFams >= 2 && !contradicted {
			confidence = ConfStrong
		} else {
			confidence = ConfMedium
		}
	default:
		confidence = ConfWeak
	}

	wv := votes[winner]
	return SegmentClass{
		SegmentType: winner, DeviceRole: role, Confidence: confidence, Boundary: boundaryOf(winner),
		Provider: wv.provider, Region: wv.region, Service: wv.service, SeamKind: wv.seamKind,
		Reason:  reasonFor(winner, wFams, signals, contradicted, confidence),
		Signals: signals,
	}
}

func fuseRole(signals []SegmentSignal) string {
	for _, s := range signals {
		if s.RoleVote != "" && s.tierRank == tierAuthoritative {
			return s.RoleVote
		}
	}
	for _, s := range signals {
		if s.RoleVote != "" {
			return s.RoleVote
		}
	}
	return RoleUnknown
}

func reasonFor(seg string, fams int, signals []SegmentSignal, contradicted bool, confidence string) string {
	drivers := map[string]struct{}{}
	for _, s := range signals {
		if s.SegmentVote == seg {
			drivers[s.Name] = struct{}{}
		}
	}
	names := make([]string, 0, len(drivers))
	for n := range drivers {
		names = append(names, n)
	}
	parts := []string{"classified " + seg + " at " + confidence + " confidence from " +
		strconv.Itoa(fams) + " independent signal family(ies) [" + strings.Join(names, ", ") + "]"}
	if confidence == ConfWeak {
		parts = append(parts, "only weak/hint evidence (rDNS/hostname) — never anchors a verdict")
	}
	if contradicted {
		parts = append(parts, "an independent signal disagreed — confidence capped")
	}
	return strings.Join(parts, "; ")
}

// ── helpers ─────────────────────────────────────────────────────────────────

func unknownClass(reason string) SegmentClass {
	return SegmentClass{
		SegmentType: SegUnknown, DeviceRole: RoleUnknown, Confidence: ConfNone,
		Boundary: "UNKNOWN", Reason: reason, Signals: []SegmentSignal{},
	}
}

func boundaryOf(seg string) string {
	if b, ok := segmentToBoundary[seg]; ok {
		return b
	}
	return "UNKNOWN"
}

func containsAny(nets []netip.Prefix, ip netip.Addr) bool {
	for _, n := range nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// isGlobalUnicast reports whether ip is a globally routable public unicast address (not
// private/CGNAT/loopback/link-local/multicast/unspecified). Callers have already excluded
// the non-topological classes.
func isGlobalUnicast(ip netip.Addr) bool {
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsMulticast() || ip.IsUnspecified() {
		return false
	}
	if ip.Is4() && containsAny(rfc1918, ip) {
		return false
	}
	if ip.Is4() && rfc6598.Contains(ip) {
		return false
	}
	if ip.Is6() && !ip.Is4In6() && rfc4193.Contains(ip) {
		return false
	}
	// Documentation/reserved v4 ranges are not "public routable" for classification.
	for _, doc := range v4NonGlobal {
		if ip.Is4() && doc.Contains(ip) {
			return false
		}
	}
	return true
}

// v4NonGlobal: reserved/documentation ranges that are not classified as public internet.
var v4NonGlobal = []netip.Prefix{
	netip.MustParsePrefix("192.0.2.0/24"),    // TEST-NET-1
	netip.MustParsePrefix("198.51.100.0/24"), // TEST-NET-2
	netip.MustParsePrefix("203.0.113.0/24"),  // TEST-NET-3
	netip.MustParsePrefix("240.0.0.0/4"),     // reserved
}
