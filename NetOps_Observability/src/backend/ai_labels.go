package main

import (
	"regexp"
	"strings"
)

var (
	aiEntityPrefix = regexp.MustCompile(`(?i)^(?:path|device|host|node|segment|site|service|prefix):`)
	aiIPv4         = regexp.MustCompile(`^\d{1,3}(?:\.\d{1,3}){3}$`)
	aiInternalHint = regexp.MustCompile(`(?i)(?:^|[-_.])(?:demo|scratch|sidecar|dummy|sandbox|fixture|selftest|test)(?:[-_.]|$)`)
)

// aiEntityLabel humanizes ONE raw entity token for NOC-facing AI text — a server
// mirror of the UI mapToken: strip the entity-type prefix, take the base before
// any ":" suffix (so "10.70.245.120:established(6)" and a peer-pair "a:b" both
// reduce cleanly), and map a bare IP to "Monitored endpoint" / an internal/test
// target to "Internal / test target". Real device/interface names pass through.
func aiEntityLabel(raw string) string {
	s := strings.TrimSpace(aiEntityPrefix.ReplaceAllString(strings.TrimSpace(raw), ""))
	if s == "" {
		return raw
	}
	base := strings.TrimSpace(strings.SplitN(s, ":", 2)[0])
	switch {
	case aiInternalHint.MatchString(strings.ToLower(base)):
		return "Internal / test target"
	case aiIPv4.MatchString(base):
		return "Monitored endpoint"
	default:
		return base
	}
}

// aiEntityLabels humanizes + de-duplicates a list of entity tokens (order-stable),
// so "a:b, a:established(6), leaf1" → "Monitored endpoint, leaf1" instead of a
// noisy, repetitive raw list.
func aiEntityLabels(raw []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, r := range raw {
		l := aiEntityLabel(r)
		if l == "" || seen[l] {
			continue
		}
		seen[l] = true
		out = append(out, l)
	}
	return out
}

// ai_labels.go — server-side NOC humanizers for AI/RCA text. These MIRROR the
// frontend RCA label library (src/frontend/src/components/rca/labels.ts) so an
// operator sees identical language whether the text is rendered client-side or
// composed in an AI answer. Kept tiny and dependency-free; when a mapping is
// added on one side, add it on the other.

// problemDisplayID turns a correlation UUID into the friendly NOC handle
// (P-5564D1). Byte-identical to the TS friendlyProblemId: "P-" + first 6 hex of
// the UUID (dashes stripped), uppercased. Display-only — the real UUID stays the
// key for routes/API/citation ids. A non-UUID / already-friendly input is
// returned unchanged so it is safe to call twice.
func problemDisplayID(corrID string) string {
	if corrID == "" || strings.HasPrefix(corrID, "P-") {
		return corrID
	}
	hex := strings.ReplaceAll(corrID, "-", "")
	if len(hex) < 6 {
		return corrID
	}
	return "P-" + strings.ToUpper(hex[:6])
}

// aiProblemTitle picks the operator-facing title for a correlation: humanize a
// signature id (sig.*) to NOC language; pass through an already-human hypothesis
// unchanged; fall back to a friendly "Correlation P-XXXXXX" when neither exists.
func aiProblemTitle(rawHypothesis, corrID string) string {
	h := strings.TrimSpace(rawHypothesis)
	if h == "" {
		return "Correlation " + problemDisplayID(corrID)
	}
	if strings.HasPrefix(h, "sig.") {
		return signatureNocTitle(h)
	}
	return h
}

// sigNocTitle maps a signature id to a plain-English NOC headline. Mirrors the
// frontend SIG_NOC_TITLE map + signatureNocTitle fallback cascade. The verdict /
// confidence badges carry certainty — titles describe the OBSERVED condition
// factually (no speculative "Possible …" hedging).
var sigNocTitle = map[string]string{
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
}

// signatureNocTitle humanizes a signature id (server mirror of the UI). Returns
// the raw id only as a last resort (so nothing renders blank), but first tries
// the explicit map, then a domain cascade — order matters: cloud and overlay are
// tested before the generic WAN catch so a cloud/overlay fault is never
// mislabelled "WAN / provider path change".
func signatureNocTitle(id string) string {
	if t, ok := sigNocTitle[id]; ok {
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
	case contains("cloud"):
		return "Cloud service-path change"
	case contains("sdwan", "overlay", "tunnel", "ipsec"):
		return "SD-WAN / tunnel change"
	case contains("dns"):
		return "DNS resolution impairment"
	case contains("mpls", "lsp", "l3vpn", "vrf"):
		return "MPLS / VPN path change"
	case contains("dia", "middle-mile", "internet", "provider", "congestion", "wan"):
		return "WAN / provider path change"
	case contains("bgp", "ospf", "isis", "routing", "peer"):
		return "Routing adjacency change"
	case contains("link", "access", "uplink"):
		return "Link state change"
	case contains("fw", "firewall", "policy", "security"):
		return "Security policy change"
	case contains("device", "resource", "cpu", "mem", "hardware", "fabric"):
		return "Device health change"
	default:
		return "Network change observed"
	}
}
