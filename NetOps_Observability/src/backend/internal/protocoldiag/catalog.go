package protocoldiag

import (
	"sort"
	"strings"

	"netops/backend/internal/netconcepts"
)

// CommandSpec is one vendor-neutral command CONCEPT plus its per-vendor dialect
// templates. A template may contain the placeholders {if} {peer} {prefix}
// {vrf-scope} which Render substitutes from a Target; an empty argument collapses
// to the command's unscoped form. Templates are authored data (no code), so a
// spec carries no compiled state and a Catalog is immutable once built.
type CommandSpec struct {
	// ID is the stable concept id (e.g. "ospf-neighbor"). Signatures reference a
	// captured command by this id, so it never changes for a given concept.
	ID string
	// Purpose is the operator-facing "why we run this" note. It is rendered into
	// the capture so a TAC reader sees intent alongside output.
	Purpose string
	// templates holds the per-vendor command text. The primary (Cisco IOS-XE)
	// template is always present; Juniper/Nokia fall back to it when unbound.
	templates map[Vendor]string
	// vrfScoped marks a command whose route lookup can be scoped to a VRF /
	// routing-instance; Render then substitutes {vrf-scope} with the dialect's
	// VRF qualifier (reusing netconcepts for the operator-facing label).
	vrfScoped bool
}

// Render returns the dialect command text for vendor v with the Target's
// arguments substituted. An unbound vendor falls back to the primary dialect.
// Whitespace left by empty placeholders is collapsed so the result is always a
// clean, valid command line.
func (s CommandSpec) Render(v Vendor, tgt Target) string {
	rv := renderVendor(v)
	tmpl, ok := s.templates[rv]
	if !ok {
		tmpl = s.templates[VendorCiscoIOSXE]
	}
	scope := ""
	if s.vrfScoped {
		scope = vrfScopeToken(rv, tgt.VRF)
	}
	out := strings.NewReplacer(
		"{if}", tgt.Interface,
		"{peer}", tgt.Peer,
		"{prefix}", tgt.Prefix,
		"{vrf-scope}", scope,
	).Replace(tmpl)
	// strings.Fields collapses the runs of whitespace an empty placeholder
	// leaves behind, yielding the clean unscoped form.
	return strings.Join(strings.Fields(out), " ")
}

// vrfScopeToken renders the dialect CLI qualifier that scopes a route lookup to a
// VRF / routing-instance, or "" when no VRF is set. The concept is resolved
// through internal/netconcepts (VRFDisplayTerm proves the same concept spans
// dialects); the CLI keyword itself is dialect-specific.
func vrfScopeToken(v Vendor, vrf string) string {
	vrf = strings.TrimSpace(vrf)
	if vrf == "" {
		return ""
	}
	// netconcepts confirms the operator's term IS the VRF concept in some dialect;
	// a nonsense token is still passed through verbatim (it is the operator's
	// instance name, case-preserved), we only use netconcepts to stay honest about
	// the concept name in code review, not to gate the operator's own identifier.
	_ = netconcepts.VRFDisplayTerm(string(v))
	switch v {
	case VendorJuniper:
		return "instance " + vrf
	case VendorNokia:
		// The Nokia route templates already carry the `router` keyword
		// (`show router {vrf-scope} route-table`); the scope is the bare
		// service/instance name.
		return vrf
	default: // cisco-iosxe and fallback
		return "vrf " + vrf
	}
}

// spec builds a CommandSpec. juniper/nokia may be "" to fall back to the Cisco
// dialect (declarative binding: an unbound vendor renders the primary form).
func spec(id, purpose, cisco, juniper, nokia string) CommandSpec {
	t := map[Vendor]string{VendorCiscoIOSXE: cisco}
	if juniper != "" {
		t[VendorJuniper] = juniper
	}
	if nokia != "" {
		t[VendorNokia] = nokia
	}
	return CommandSpec{ID: id, Purpose: purpose, templates: t}
}

// specVRF is spec for a VRF-scopable route lookup.
func specVRF(id, purpose, cisco, juniper, nokia string) CommandSpec {
	s := spec(id, purpose, cisco, juniper, nokia)
	s.vrfScoped = true
	return s
}

// Issue is one hand-authored diagnostic scenario: a vendor-neutral description of
// a common protocol fault plus the curated read-only command bundle that captures
// the evidence for it. The bundle is the protocol-specific probes followed by the
// common L1/L2/routing supporting set (most protocol faults are really a layer
// below). Signatures (analyze.go) are authored against a bundle's command ids.
type Issue struct {
	// ID is the stable issue id (e.g. "ospf-neighbor-stuck"). It joins an Issue
	// to its signatures and never changes.
	ID string
	// Protocol is the tab the issue belongs to.
	Protocol Protocol
	// Title is the short operator-facing name.
	Title string
	// Description is the independently-worded explanation of the fault and the
	// classic tell (no vendor doc text — original wording).
	Description string
	// probes are the protocol-specific commands; common is appended at build
	// time. Kept unexported so the catalog is immutable.
	probes []CommandSpec
}

// Bundle returns the full command bundle for the issue: the protocol-specific
// probes followed by the common supporting set, in a stable authored order.
func (i Issue) Bundle() []CommandSpec {
	out := make([]CommandSpec, 0, len(i.probes)+len(commonSupportingSet))
	out = append(out, i.probes...)
	out = append(out, commonSupportingSet...)
	return out
}

// Catalog is the immutable set of issues across all three protocols. It is built
// fresh by DefaultCatalog (no package-level mutable state, §5).
type Catalog struct {
	issues []Issue
	byID   map[string]Issue
}

// NewCatalog builds a catalog from an issue set, copying its input so the result
// is immutable from the caller's side.
func NewCatalog(issues []Issue) *Catalog {
	cp := make([]Issue, len(issues))
	copy(cp, issues)
	byID := make(map[string]Issue, len(cp))
	for _, is := range cp {
		byID[is.ID] = is
	}
	return &Catalog{issues: cp, byID: byID}
}

// Issues returns every issue in authored order.
func (c *Catalog) Issues() []Issue {
	out := make([]Issue, len(c.issues))
	copy(out, c.issues)
	return out
}

// IssuesFor returns the issues for one protocol in authored order.
func (c *Catalog) IssuesFor(p Protocol) []Issue {
	var out []Issue
	for _, is := range c.issues {
		if is.Protocol == p {
			out = append(out, is)
		}
	}
	return out
}

// Issue returns the issue with id and whether it exists.
func (c *Catalog) Issue(id string) (Issue, bool) {
	is, ok := c.byID[id]
	return is, ok
}

// Len reports the total number of issues.
func (c *Catalog) Len() int { return len(c.issues) }

// commonSupportingSet is the L1/L2/routing evidence appended to EVERY bundle:
// interface health (errors/CRC/flaps/MTU), the L3 interface summary, the
// adjacency-layer table, and the routing table. Rendered per dialect; the route
// lookup is VRF-scopable.
var commonSupportingSet = []CommandSpec{
	spec("iface",
		"interface health: errors, CRC, flaps, up/down, MTU (protocol faults are often L1/L2)",
		"show interface {if}",
		"show interfaces {if} extensive",
		"show port {if} detail"),
	spec("ip-int-brief",
		"L3 interface summary: addressing and up/down state",
		"show ip interface brief",
		"show interfaces terse",
		"show router interface"),
	spec("l2-adjacency",
		"link-layer reachability to the neighbor: ARP / MAC table",
		"show arp",
		"show arp",
		"show router arp"),
	specVRF("ip-route",
		"routing table / reachability for the subject prefix or next-hop",
		"show ip route {vrf-scope} {prefix}",
		"show route {vrf-scope} {prefix}",
		"show router {vrf-scope} route-table {prefix}"),
}

// DefaultCatalog builds the full 15-issue matrix (5 BGP, 5 OSPF, 5 IS-IS) from
// the owner spec. Cisco IOS-XE is fully bound; Juniper and Nokia are bound
// declaratively for the command rendering.
func DefaultCatalog() *Catalog {
	var issues []Issue

	// ─── OSPF ────────────────────────────────────────────────────────────────
	issues = append(issues,
		Issue{
			ID: "ospf-neighbor-stuck", Protocol: ProtocolOSPF,
			Title: "Neighbor stuck (EXSTART/EXCHANGE/INIT, not FULL)",
			Description: "The OSPF adjacency negotiates but never reaches FULL. A neighbor " +
				"parked in EXSTART/EXCHANGE is the classic tell for an IP MTU mismatch across " +
				"the link; INIT means hellos are only heard one way.",
			probes: []CommandSpec{
				spec("ospf-neighbor", "adjacency state per neighbor (EXSTART/EXCHANGE/INIT/FULL)",
					"show ip ospf neighbor",
					"show ospf neighbor",
					"show router ospf neighbor"),
				spec("ospf-interface", "interface OSPF params: MTU, area, network-type",
					"show ip ospf interface {if}",
					"show ospf interface {if} detail",
					"show router ospf interface {if} detail"),
			},
		},
		Issue{
			ID: "ospf-adjacency-nonform", Protocol: ProtocolOSPF,
			Title: "Adjacency won't form",
			Description: "No adjacency forms at all. Usually a parameter that must match across " +
				"the link disagrees: hello/dead timers, area id, authentication, network-type, " +
				"or subnet mask.",
			probes: []CommandSpec{
				spec("ospf-interface", "hello/dead timers, area-id, auth, network-type, mask",
					"show ip ospf interface {if}",
					"show ospf interface {if} detail",
					"show router ospf interface {if} detail"),
				spec("ospf-logging", "OSPF parameter-mismatch / error events",
					"show logging | include OSPF",
					"show log messages | match rpd",
					"show log | match OSPF"),
			},
		},
		Issue{
			ID: "ospf-routes-missing", Protocol: ProtocolOSPF,
			Title: "Routes missing / not installed",
			Description: "Expected OSPF routes are absent from the table. Suspect area type " +
				"(stub/NSSA filters externals), administrative distance losing to another source, " +
				"or a router advertising a max-metric (stub-router) LSA.",
			probes: []CommandSpec{
				spec("ospf-database", "link-state database: are the expected LSAs present?",
					"show ip ospf database",
					"show ospf database",
					"show router ospf database"),
				spec("ospf-summary", "process/area view: area type (stub/NSSA), distance, max-metric",
					"show ip ospf",
					"show ospf overview",
					"show router ospf status"),
				spec("ospf-routes", "routes learned via OSPF",
					"show ip route ospf",
					"show route protocol ospf",
					"show router route-table protocol ospf"),
			},
		},
		Issue{
			ID: "ospf-flapping", Protocol: ProtocolOSPF,
			Title: "Flapping neighbor",
			Description: "The adjacency repeatedly drops and re-forms. The state-change count and " +
				"repeated ADJCHG log events point at an unstable link underneath (CRC/errors/flaps) " +
				"or timer instability.",
			probes: []CommandSpec{
				spec("ospf-neighbor", "adjacency state and state-change count",
					"show ip ospf neighbor",
					"show ospf neighbor extensive",
					"show router ospf neighbor detail"),
				spec("ospf-logging", "repeated OSPF adjacency-change events",
					"show logging | include OSPF",
					"show log messages | match OSPF",
					"show log | match OSPF"),
			},
		},
		Issue{
			ID: "ospf-suboptimal", Protocol: ProtocolOSPF,
			Title: "Suboptimal path / wrong metric",
			Description: "Traffic takes a worse path than expected. Most often the auto-cost " +
				"reference-bandwidth is left at its default (100 Mbps), so every link at or above " +
				"100 Mbps shares cost 1 and the SPF can't distinguish 1G from 100G.",
			probes: []CommandSpec{
				spec("ospf-interface", "per-interface cost",
					"show ip ospf interface {if}",
					"show ospf interface {if} detail",
					"show router ospf interface {if} detail"),
				spec("ospf-summary", "reference-bandwidth / SPF parameters",
					"show ip ospf",
					"show ospf overview",
					"show router ospf status"),
				spec("ospf-database", "LSA metrics along the path",
					"show ip ospf database",
					"show ospf database",
					"show router ospf database"),
			},
		},
	)

	// ─── BGP ─────────────────────────────────────────────────────────────────
	issues = append(issues,
		Issue{
			ID: "bgp-session-down", Protocol: ProtocolBGP,
			Title: "Session down (Idle/Active/Connect, not Established)",
			Description: "The BGP session never reaches Established. Idle with no route to the peer " +
				"means the peering address is unreachable (underlay/ACL); Active/Connect with a " +
				"route present means TCP/179 is being blocked to a reachable peer.",
			probes: []CommandSpec{
				spec("bgp-summary", "session state per neighbor",
					"show ip bgp summary",
					"show bgp summary",
					"show router bgp summary"),
				spec("bgp-neighbor", "neighbor detail: last reset reason, transport",
					"show ip bgp neighbors {peer}",
					"show bgp neighbor {peer}",
					"show router bgp neighbor {peer} detail"),
				specVRF("bgp-peer-route", "is the peering address reachable?",
					"show ip route {vrf-scope} {peer}",
					"show route {vrf-scope} {peer}",
					"show router {vrf-scope} route-table {peer}"),
			},
		},
		Issue{
			ID: "bgp-prefix-not-exchanged", Protocol: ProtocolBGP,
			Title: "Prefix not advertised / not received",
			Description: "A prefix the operator expects to send or receive is missing. Check what is " +
				"actually advertised to and received from the peer, and the outbound/inbound policy " +
				"(route-map, prefix-list) or a missing network statement.",
			probes: []CommandSpec{
				spec("bgp-advertised", "prefixes actually advertised to the peer",
					"show ip bgp neighbors {peer} advertised-routes",
					"show route advertising-protocol bgp {peer}",
					"show router bgp neighbor {peer} advertised-routes"),
				spec("bgp-received", "prefixes actually received from the peer",
					"show ip bgp neighbors {peer} received-routes",
					"show route receive-protocol bgp {peer}",
					"show router bgp neighbor {peer} received-routes"),
				spec("bgp-prefix", "table entry for the subject prefix",
					"show ip bgp {prefix}",
					"show route {prefix} detail",
					"show router bgp routes {prefix}"),
			},
		},
		Issue{
			ID: "bgp-route-not-best", Protocol: ProtocolBGP,
			Title: "Route not installed / best-path",
			Description: "The prefix is in the BGP table but not selected/installed. The usual cause " +
				"is an unresolved (inaccessible) next-hop; otherwise best-path is decided on " +
				"local-pref, AS-path, MED or weight.",
			probes: []CommandSpec{
				spec("bgp-prefix", "best-path detail incl. next-hop reachability",
					"show ip bgp {prefix}",
					"show route {prefix} detail",
					"show router bgp routes {prefix} detail"),
				specVRF("bgp-nexthop-route", "is the BGP next-hop resolvable?",
					"show ip route {vrf-scope} {prefix}",
					"show route {vrf-scope} {prefix}",
					"show router {vrf-scope} route-table {prefix}"),
			},
		},
		Issue{
			ID: "bgp-flapping", Protocol: ProtocolBGP,
			Title: "Flapping session / dampening",
			Description: "The session or a set of prefixes flap. The neighbor's flap count and last " +
				"reset reason, plus dampening flap-statistics, show whether route dampening is now " +
				"suppressing the prefix.",
			probes: []CommandSpec{
				spec("bgp-neighbor", "flap count and last reset reason",
					"show ip bgp neighbors {peer}",
					"show bgp neighbor {peer}",
					"show router bgp neighbor {peer} detail"),
				spec("bgp-dampening", "dampened / suppressed prefixes",
					"show ip bgp dampening flap-statistics",
					"show route damping suppressed",
					"show router bgp damping suppressed"),
				spec("bgp-logging", "repeated BGP session events",
					"show logging | include BGP",
					"show log messages | match BGP",
					"show log | match BGP"),
			},
		},
		Issue{
			ID: "bgp-wrong-path", Protocol: ProtocolBGP,
			Title: "Wrong path / policy",
			Description: "The prefix resolves but takes an unexpected path, or does not propagate. " +
				"A well-known community (no-export / no-advertise) or an AS-path/community policy is " +
				"steering or withholding it.",
			probes: []CommandSpec{
				spec("bgp-prefix", "path attributes: communities, AS-path, local-pref, MED",
					"show ip bgp {prefix}",
					"show route {prefix} detail",
					"show router bgp routes {prefix} detail"),
				spec("bgp-neighbor", "applied inbound/outbound policy",
					"show ip bgp neighbors {peer}",
					"show bgp neighbor {peer}",
					"show router bgp neighbor {peer} detail"),
			},
		},
	)

	// ─── IS-IS ───────────────────────────────────────────────────────────────
	issues = append(issues,
		Issue{
			ID: "isis-adjacency-down", Protocol: ProtocolISIS,
			Title: "Adjacency down",
			Description: "No IS-IS adjacency on a link that should have one. Check the level " +
				"(L1/L2), the area (NET), MTU, and authentication — a mismatch on any of these " +
				"prevents the adjacency.",
			probes: []CommandSpec{
				spec("isis-neighbors", "adjacency state per neighbor",
					"show isis neighbors",
					"show isis adjacency",
					"show router isis adjacency"),
				spec("isis-interface", "level, MTU, area, auth per interface",
					"show isis interface {if}",
					"show isis interface {if} extensive",
					"show router isis interface {if} detail"),
				spec("clns-interface", "CLNS/IS-IS interface state",
					"show clns interface {if}",
					"show isis interface {if} extensive",
					"show router isis interface {if} detail"),
			},
		},
		Issue{
			ID: "isis-adjacency-init", Protocol: ProtocolISIS,
			Title: "Adjacency stuck (INIT)",
			Description: "The adjacency reaches INIT but not Up — the analogue of OSPF EXSTART. " +
				"Suspect an MTU / hello-padding problem or a point-to-point-vs-broadcast network-type " +
				"mismatch across the link.",
			probes: []CommandSpec{
				spec("clns-neighbors-detail", "detailed adjacency state (INIT vs Up)",
					"show clns neighbors detail",
					"show isis adjacency detail",
					"show router isis adjacency detail"),
				spec("isis-interface", "network-type (p2p/broadcast), MTU, hello-padding",
					"show isis interface {if}",
					"show isis interface {if} extensive",
					"show router isis interface {if} detail"),
			},
		},
		Issue{
			ID: "isis-routes-missing", Protocol: ProtocolISIS,
			Title: "Routes missing",
			Description: "Expected IS-IS routes are absent. Suspect the overload bit (this IS asks " +
				"not to be used for transit), or L1↔L2 route leaking not being configured.",
			probes: []CommandSpec{
				spec("isis-database", "LSP database incl. overload bit",
					"show isis database",
					"show isis database",
					"show router isis database"),
				spec("isis-routes", "routes learned via IS-IS",
					"show ip route isis",
					"show route protocol isis",
					"show router route-table protocol isis"),
			},
		},
		Issue{
			ID: "isis-flapping", Protocol: ProtocolISIS,
			Title: "Flapping",
			Description: "The adjacency repeatedly drops and re-forms. Repeated adjacency-change " +
				"log events plus interface errors point at an unstable link or timer instability.",
			probes: []CommandSpec{
				spec("isis-neighbors", "adjacency state / uptime",
					"show isis neighbors",
					"show isis adjacency",
					"show router isis adjacency"),
				spec("isis-logging", "repeated IS-IS adjacency-change events",
					"show logging | include ISIS",
					"show log messages | match isis",
					"show log | match ISIS"),
			},
		},
		Issue{
			ID: "isis-overload-suboptimal", Protocol: ProtocolISIS,
			Title: "Overload / suboptimal",
			Description: "Paths are suboptimal or the router is avoided for transit. The overload " +
				"bit forces max metric; a narrow metric-style caps link metric at 63 and blocks " +
				"wide-metric features, distorting SPF.",
			probes: []CommandSpec{
				spec("isis-database-detail", "overload bit and metric-style in the LSPs",
					"show isis database detail",
					"show isis database extensive",
					"show router isis database detail"),
				spec("isis-summary", "process view: metric-style (narrow/wide)",
					"show isis protocol",
					"show isis overview",
					"show router isis status"),
			},
		},
	)

	return NewCatalog(issues)
}

// SortedIssueIDs returns every issue id in the catalog, sorted — a deterministic
// enumeration for tests and UI listing.
func (c *Catalog) SortedIssueIDs() []string {
	out := make([]string, 0, len(c.issues))
	for _, is := range c.issues {
		out = append(out, is.ID)
	}
	sort.Strings(out)
	return out
}
