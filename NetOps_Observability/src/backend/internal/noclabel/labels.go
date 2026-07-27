// Package noclabel holds the server-side NOC humanizers for AI/RCA text.
// These MIRROR the frontend RCA label library
// (src/frontend/src/components/rca/labels.ts) so an operator sees identical
// language whether the text is rendered client-side or composed in an AI
// answer. Kept tiny and dependency-free; when a mapping is added on one side,
// add it on the other.
package noclabel

import (
	"regexp"
	"strings"
)

var (
	entityPrefix = regexp.MustCompile(`(?i)^(?:path|device|host|node|segment|site|service|prefix):`)
	ipv4         = regexp.MustCompile(`^\d{1,3}(?:\.\d{1,3}){3}$`)
	internalHint = regexp.MustCompile(`(?i)(?:^|[-_.])(?:demo|scratch|sidecar|dummy|sandbox|fixture|selftest|test)(?:[-_.]|$)`)
	// a signature token embedded in free text (e.g. a missing-evidence line).
	sigToken = regexp.MustCompile(`sig\.[A-Za-z0-9_.-]+`)
)

// HumanizeMissing rewrites engine signature tokens inside missing-evidence
// lines to NOC language ("sig.ent.middle-mile.dia-egress-latency: single
// modality…" → "ISP / DIA egress latency: single modality…"), so the operator
// never sees a raw signature id in an AI answer.
func HumanizeMissing(lines []string) []string {
	if len(lines) == 0 {
		return lines
	}
	out := make([]string, len(lines))
	for i, l := range lines {
		out[i] = sigToken.ReplaceAllStringFunc(l, SignatureTitle)
	}
	return out
}

// Entity humanizes ONE raw entity token for NOC-facing AI text — a server
// mirror of the UI mapToken: strip the entity-type prefix, take the base before
// any ":" suffix (so "192.0.2.120:established(6)" and a peer-pair "a:b" both
// reduce cleanly), and map a bare IP to "Monitored endpoint" / an internal/test
// target to "Internal / test target". Real device/interface names pass through.
func Entity(raw string) string {
	s := strings.TrimSpace(entityPrefix.ReplaceAllString(strings.TrimSpace(raw), ""))
	if s == "" {
		return raw
	}
	base := strings.TrimSpace(strings.SplitN(s, ":", 2)[0])
	switch {
	case internalHint.MatchString(strings.ToLower(base)):
		return "Internal / test target"
	case ipv4.MatchString(base):
		return "Monitored endpoint"
	default:
		return base
	}
}

// Entities humanizes + de-duplicates a list of entity tokens (order-stable),
// so "a:b, a:established(6), leaf1" → "Monitored endpoint, leaf1" instead of a
// noisy, repetitive raw list.
func Entities(raw []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, r := range raw {
		l := Entity(r)
		if l == "" || seen[l] {
			continue
		}
		seen[l] = true
		out = append(out, l)
	}
	return out
}

// ProblemDisplayID turns a correlation UUID into the friendly NOC handle
// (P-5564D1). Byte-identical to the TS friendlyProblemId: "P-" + first 6 hex of
// the UUID (dashes stripped), uppercased. Display-only — the real UUID stays the
// key for routes/API/citation ids. A non-UUID / already-friendly input is
// returned unchanged so it is safe to call twice.
func ProblemDisplayID(corrID string) string {
	if corrID == "" || strings.HasPrefix(corrID, "P-") {
		return corrID
	}
	hex := strings.ReplaceAll(corrID, "-", "")
	if len(hex) < 6 {
		return corrID
	}
	return "P-" + strings.ToUpper(hex[:6])
}

// ProblemTitle picks the operator-facing title for a correlation: humanize a
// signature id (sig.*) to NOC language; pass through an already-human hypothesis
// unchanged; fall back to a friendly "Correlation P-XXXXXX" when neither exists.
func ProblemTitle(rawHypothesis, corrID string) string {
	h := strings.TrimSpace(rawHypothesis)
	switch {
	case h == "", strings.EqualFold(h, "undetermined"), strings.EqualFold(h, "none"):
		// No signature matched yet — a neutral title (the friendly id is already
		// shown alongside, so don't repeat it here; avoids "P-x: … P-x" and the
		// confusing "undetermined: undetermined").
		_ = corrID
		return "Low-evidence correlation"
	case strings.HasPrefix(h, "sig."):
		return SignatureTitle(h)
	default:
		return h
	}
}

// sigTitle maps a signature id to a plain-English NOC headline. Mirrors the
// frontend SIG_NOC_TITLE map + signatureNocTitle fallback cascade. The verdict /
// confidence badges carry certainty — titles describe the OBSERVED condition
// factually (no speculative "Possible …" hedging).
var sigTitle = map[string]string{
	"sig.ent.wan-edge.bgp-peer-flap":         "BGP peer flapping — WAN edge",
	"sig.ent.wan-edge.bgp-peer-down":         "BGP peer down — WAN edge",
	"sig.ent.middle-mile.dia-egress-latency": "ISP / DIA egress latency",
	"sig.ent.middle-mile.dia-egress-loss":    "ISP / DIA egress packet loss",
	"sig.ent.cloud.region-impairment":        "Cloud region impairment",
	"sig.ent.lan.link-flap":                  "Link flapping — LAN",
	"sig.ent.lan.stp-topology-change":        "Spanning-tree topology change",
	"sig.ent.dc.fabric-link-down":            "Fabric link down — data center",
	"sig.ent.sdwan.tunnel-flap":              "SD-WAN tunnel flapping",
	"sig.ent.sdwan.brownout":                 "SD-WAN path brownout",
	// Application / SaaS experience lane — each cause names ITS suspect; none of
	// these may ever read as a generic "network change" (owner directive 2026-07-12).
	"sig.ent.app.saas-experience-degraded":  "SaaS / application experience degraded",
	"sig.ent.app.lb-target-health-failure":  "Load-balancer target health failure",
	"sig.ent.app.tls-cert-expired":          "TLS certificate expired",
	"sig.ent.app.dns-failover-wrong-target": "DNS failover to a wrong target",
	// Cloud private-path lane
	"sig.ent.cloud.ipsec-tunnel-down":         "IPsec tunnel down — cloud private path",
	"sig.ent.cloud.app-dependency-down":       "Cloud application dependency down",
	"sig.ent.cloud.private-connectivity-down": "Cloud private connectivity down",
	"sig.ent.cloud.route-table-blackhole":     "Cloud route-table blackhole",
	"sig.ent.cloud.sg-nacl-block":             "Cloud security-group / NACL block",
	// Middle-mile IPsec family (truthfulness epic D1a: these fell into the
	// substring cascade, where the bare "ipsec" token routed them to the
	// SD-WAN group — a live report titled an underlay-root case "SD-WAN").
	"sig.ent.middle-mile.ipsec-underlay-down": "Underlay path to VPN peer down",
}

// SignatureTitle humanizes a signature id (server mirror of the UI). Returns
// the raw id only as a last resort (so nothing renders blank), but first tries
// the explicit map, then a domain cascade — order matters: cloud and overlay are
// tested before the generic WAN catch so a cloud/overlay fault is never
// mislabelled "WAN / provider path change".
func SignatureTitle(id string) string {
	if t, ok := sigTitle[id]; ok {
		return t
	}
	if id == "" {
		return ""
	}
	low := strings.ToLower(id)
	contains := func(subs ...string) bool {
		for _, s := range subs {
			if strings.Contains(low, s) {
				return true
			}
		}
		return false
	}
	switch {
	// app/SaaS BEFORE every network rung: an application-domain signature must
	// never be mislabelled as a network change (owner directive 2026-07-12).
	case contains(".app.", "saas", "experience"):
		return "Application / service experience change"
	case contains("k8s", "kubernetes", "mesh"):
		return "Cloud workload networking change"
	case contains("cert", "tls"):
		return "TLS / certificate issue"
	case contains("cloud"):
		return "Cloud service-path change"
	// middle-mile BEFORE the tunnel group: an underlay/provider-path signature
	// that happens to mention ipsec is a transport fault, not an SD-WAN one.
	case contains("middle-mile", "underlay", "dia"):
		return "WAN / provider path change"
	case contains("sdwan", "overlay", "tunnel", "ipsec"):
		return "SD-WAN / tunnel change"
	case contains("dns"):
		return "DNS resolution impairment"
	case contains("mpls", "lsp", "l3vpn", "vrf"):
		return "MPLS / VPN path change"
	case contains("internet", "provider", "congestion", "wan"):
		return "WAN / provider path change"
	case contains("bgp", "ospf", "isis", "routing", "peer"):
		return "Routing adjacency change"
	case contains("link", "access", "uplink"):
		return "Link state change"
	case contains("nat", "fw", "firewall", "policy", "security", "waf", "proxy"):
		return "Security / policy change"
	case contains("device", "resource", "cpu", "mem", "hardware", "fabric"):
		return "Device health change"
	default:
		// honest last resort: an unmapped signature is an anomaly with an
		// undetermined cause — never assert "network change" without evidence.
		return "Anomaly observed — cause undetermined"
	}
}
