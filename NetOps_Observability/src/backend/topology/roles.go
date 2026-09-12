// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package topology

// roles.go — discovery-driven DEVICE ROLE classification (path-segmentation
// directive, owner P1 2026-07-19). Assigns each managed device a role on the
// canonical enterprise-connectivity taxonomy so the RCA path view can place it
// into its segment:
//
//   access_switch | distribution_switch | core_router | firewall |
//   load_balancer | wan_edge | carrier_hop | dc_wan_edge | dc_leaf | dc_spine |
//   cloud_edge | unknown
//
// HOUSE RULES (CLAUDE.md §3/§5): pure, stdlib-only, no I/O — the caller gathers
// the facts tenant-scoped and injects them via DeviceFact. Default-closed:
// every assignment carries the EVIDENCE that fired and a word-tier confidence
// (strong/medium/weak — never percentages); when the facts don't establish a
// role the result is unknown, never a guess.
//
// Signals actually consumed (all from facts discovery already collects):
//   · operator role declaration (labels["role"]) — authoritative when it names
//     a known role
//   · identity strings: vendor + model + OS/sysDescr + name (SD-WAN vendor
//     strings ⇒ wan_edge; firewall/LB model strings; cloud-gateway strings;
//     leaf/spine/tor naming + fabric OS hints)
//   · the inferred NOC device type (SNMP sysDescr classification)
//   · LLDP/CDP/BGP-LS adjacency shape: switch fan-out, router fan-out, and
//     IGP participation (BGP-LS presence)
//   · tunnel facts: tunnel count and whether a tunnel terminates in published
//     cloud address space
// Signals the platform does NOT collect yet (MAC/FDB endpoint density, VTEP
// tables, per-device eBGP ASNs) are deliberately absent — see
// docs/design/path-segmentation.md for the honest gap list.

import (
	"fmt"
	"strings"
)

// ── vocabulary ───────────────────────────────────────────────────────────────

// Device roles (canonical path-segmentation taxonomy).
const (
	DevRoleAccessSwitch       = "access_switch"
	DevRoleDistributionSwitch = "distribution_switch"
	DevRoleCoreRouter         = "core_router"
	DevRoleFirewall           = "firewall"
	DevRoleLoadBalancer       = "load_balancer"
	DevRoleWANEdge            = "wan_edge"
	DevRoleCarrierHop         = "carrier_hop"
	DevRoleDCWANEdge          = "dc_wan_edge"
	DevRoleDCLeaf             = "dc_leaf"
	DevRoleDCSpine            = "dc_spine"
	DevRoleCloudEdge          = "cloud_edge"
	DevRoleUnknown            = "unknown"
)

// Confidence tiers — words, never percentages (product language rule).
const (
	RoleConfStrong = "strong"
	RoleConfMedium = "medium"
	RoleConfWeak   = "weak"
)

// RoleEvidence is one fact that fired, in operator-readable words.
type RoleEvidence struct {
	Signal string `json:"signal"` // which classifier signal fired
	Detail string `json:"detail"` // what it saw
}

// RoleResult is the classification outcome. Role == DevRoleUnknown carries no
// confidence and whatever (non-firing) evidence was considered.
type RoleResult struct {
	Role       string         `json:"role"`
	Confidence string         `json:"confidence,omitempty"`
	Evidence   []RoleEvidence `json:"evidence,omitempty"`
}

// EvidenceStrings renders the evidence as "signal: detail" lines (the payload
// keeps them as plain strings so the UI shows them verbatim).
func (r RoleResult) EvidenceStrings() []string {
	out := make([]string, 0, len(r.Evidence))
	for _, e := range r.Evidence {
		out = append(out, e.Signal+": "+e.Detail)
	}
	return out
}

// ── the classifier ───────────────────────────────────────────────────────────

// knownRoles gates the operator declaration: only an exact canonical role name
// is authoritative (free-text site notes never are).
var knownRoles = map[string]bool{
	DevRoleAccessSwitch: true, DevRoleDistributionSwitch: true,
	DevRoleCoreRouter: true, DevRoleFirewall: true, DevRoleLoadBalancer: true,
	DevRoleWANEdge: true, DevRoleCarrierHop: true, DevRoleDCWANEdge: true,
	DevRoleDCLeaf: true, DevRoleDCSpine: true, DevRoleCloudEdge: true,
}

// sdwanStrings — SD-WAN vendor/product strings in sysDescr/model ⇒ WAN edge.
// (Viptela/vEdge/cEdge, VeloCloud, Versa, Silver Peak, Meraki MX, and the
// generic "sd-wan"/"sdwan" product tag any vendor stamps.)
var sdwanStrings = []string{
	"viptela", "vedge", "cedge", "velocloud", "versa", "silver peak",
	"silverpeak", "meraki mx", "sd-wan", "sdwan",
}

// dcFabricStrings — fabric OS / EVPN hints that corroborate a leaf/spine role.
var dcFabricStrings = []string{"vxlan", "evpn", "aci", "nx-os", "nexus", "cumulus", "sonic"}

// ClassifyDeviceRole classifies one device from its injected discovery facts.
// Pure; safe for concurrent use. Order matters: declared role, then strong
// identity strings, then tunnel/adjacency shape — specific before generic so a
// firewall is never mislabelled a router.
func ClassifyDeviceRole(d DeviceFact) RoleResult {
	// 1) Operator declaration — authoritative when it names a canonical role.
	if hint := strings.ToLower(strings.TrimSpace(d.Role)); knownRoles[hint] {
		return RoleResult{
			Role: hint, Confidence: RoleConfStrong,
			Evidence: []RoleEvidence{{Signal: "operator_declared", Detail: "device role declared in inventory labels: " + hint}},
		}
	}

	identity := strings.ToLower(strings.Join([]string{d.Vendor, d.Model, d.SysDescr, d.Name}, " "))
	var ev []RoleEvidence

	// 2) SD-WAN vendor strings ⇒ WAN edge (site side; the DC flavor needs an
	//    operator/site declaration the platform does not collect yet).
	for _, s := range sdwanStrings {
		if strings.Contains(identity, s) {
			ev = append(ev, RoleEvidence{Signal: "sdwan_identity", Detail: "SD-WAN product string " + quoted(s) + " in vendor/model/sysDescr"})
			return RoleResult{Role: DevRoleWANEdge, Confidence: RoleConfStrong, Evidence: ev}
		}
	}

	// 3) NOC device type from the sysDescr classifier — deterministic model
	//    strings, so firewall/LB/cloud-gw carry strong confidence.
	switch d.Type {
	case "firewall":
		return RoleResult{Role: DevRoleFirewall, Confidence: RoleConfStrong,
			Evidence: append(ev, RoleEvidence{Signal: "model_identity", Detail: "firewall product string in vendor/model/sysDescr"})}
	case "load-balancer":
		return RoleResult{Role: DevRoleLoadBalancer, Confidence: RoleConfStrong,
			Evidence: append(ev, RoleEvidence{Signal: "model_identity", Detail: "load-balancer product string in vendor/model/sysDescr"})}
	case "cloud-gw":
		return RoleResult{Role: DevRoleCloudEdge, Confidence: RoleConfStrong,
			Evidence: append(ev, RoleEvidence{Signal: "model_identity", Detail: "cloud-gateway product string (VGW/TGW/VPN gateway/cloud router) in vendor/model/sysDescr"})}
	}

	// 4) Tunnel facts: a tunnel terminating in published cloud space makes the
	//    device the cloud attachment point; site-to-site tunnels sit on the WAN
	//    edge (corroborated inference ⇒ medium).
	if d.HasCloudTunnel {
		return RoleResult{Role: DevRoleCloudEdge, Confidence: RoleConfStrong,
			Evidence: append(ev, RoleEvidence{Signal: "cloud_tunnel", Detail: fmt.Sprintf("%d tunnel interface(s), at least one terminating in published cloud provider address space", d.TunnelCount)})}
	}
	if d.TunnelCount > 0 && (d.Type == "router" || d.Type == "generic") {
		return RoleResult{Role: DevRoleWANEdge, Confidence: RoleConfMedium,
			Evidence: append(ev, RoleEvidence{Signal: "tunnel_endpoint", Detail: fmt.Sprintf("%d site-to-site tunnel interface(s) terminate here", d.TunnelCount)})}
	}

	// 5) Leaf/spine: naming convention + fabric OS corroboration. Convention
	//    alone is medium (it is convention, not measurement); with a fabric OS
	//    hint it stays medium but carries both facts.
	name := strings.ToLower(d.Name)
	if d.Type == "switch" || d.Type == "generic" {
		fabric := ""
		for _, s := range dcFabricStrings {
			if strings.Contains(identity, s) {
				fabric = s
				break
			}
		}
		if hasWordToken(name, "spine") {
			ev = append(ev, RoleEvidence{Signal: "naming_convention", Detail: "hostname carries the 'spine' token"})
			if fabric != "" {
				ev = append(ev, RoleEvidence{Signal: "fabric_identity", Detail: "fabric OS/EVPN string " + quoted(fabric) + " in sysDescr/model"})
			}
			return RoleResult{Role: DevRoleDCSpine, Confidence: RoleConfMedium, Evidence: ev}
		}
		if hasWordToken(name, "leaf") || hasWordToken(name, "tor") {
			ev = append(ev, RoleEvidence{Signal: "naming_convention", Detail: "hostname carries a 'leaf'/'tor' token"})
			if fabric != "" {
				ev = append(ev, RoleEvidence{Signal: "fabric_identity", Detail: "fabric OS/EVPN string " + quoted(fabric) + " in sysDescr/model"})
			}
			return RoleResult{Role: DevRoleDCLeaf, Confidence: RoleConfMedium, Evidence: ev}
		}
	}

	// 6) Adjacency shape (LLDP/CDP/BGP-LS summaries).
	switch d.Type {
	case "switch":
		// IGP participation or wide switch fan-out ⇒ distribution tier.
		if d.HasIGPAdjacency && d.SwitchNeighborCount >= 1 {
			return RoleResult{Role: DevRoleDistributionSwitch, Confidence: RoleConfMedium,
				Evidence: append(ev,
					RoleEvidence{Signal: "igp_participation", Detail: "appears in the BGP-LS/IGP topology"},
					RoleEvidence{Signal: "adjacency_shape", Detail: fmt.Sprintf("LLDP/CDP fan-out to %d switch(es)", d.SwitchNeighborCount)})}
		}
		if d.SwitchNeighborCount >= 3 {
			return RoleResult{Role: DevRoleDistributionSwitch, Confidence: RoleConfWeak,
				Evidence: append(ev, RoleEvidence{Signal: "adjacency_shape", Detail: fmt.Sprintf("LLDP/CDP fan-out to %d switches (no IGP corroboration)", d.SwitchNeighborCount)})}
		}
		// A switch hanging off ≤2 upstream network devices, outside the IGP, is
		// the access tier. WEAK on purpose: the strong access signal (MAC/
		// endpoint density) is not collected yet.
		if d.NeighborCount > 0 && d.SwitchNeighborCount+d.RouterNeighborCount <= 2 && !d.HasIGPAdjacency {
			return RoleResult{Role: DevRoleAccessSwitch, Confidence: RoleConfWeak,
				Evidence: append(ev, RoleEvidence{Signal: "adjacency_shape", Detail: fmt.Sprintf("%d neighbor(s), ≤2 upstream network devices, no IGP participation", d.NeighborCount)})}
		}
	case "router":
		if d.HasIGPAdjacency {
			conf := RoleConfMedium
			evs := append(ev, RoleEvidence{Signal: "igp_participation", Detail: "appears in the BGP-LS/IGP topology"})
			if d.RouterNeighborCount+d.SwitchNeighborCount >= 2 {
				conf = RoleConfStrong
				evs = append(evs, RoleEvidence{Signal: "adjacency_shape", Detail: fmt.Sprintf("adjacencies to %d router(s) and %d switch(es)", d.RouterNeighborCount, d.SwitchNeighborCount)})
			}
			return RoleResult{Role: DevRoleCoreRouter, Confidence: conf, Evidence: evs}
		}
	}

	// 7) Unknown stays unknown — never force a role.
	return RoleResult{Role: DevRoleUnknown, Evidence: ev}
}

// hasWordToken reports whether name carries tok as a word-ish token (delimited
// by start/end, digits, or -_. separators): "dc1-leaf03" → leaf; "leafield" → no.
func hasWordToken(name, tok string) bool {
	for i := 0; ; {
		j := strings.Index(name[i:], tok)
		if j < 0 {
			return false
		}
		j += i
		before := j == 0 || isSep(name[j-1])
		k := j + len(tok)
		after := k >= len(name) || isSep(name[k]) || (name[k] >= '0' && name[k] <= '9')
		if before && after {
			return true
		}
		i = j + 1
	}
}

func isSep(b byte) bool {
	return b == '-' || b == '_' || b == '.' || b == ' ' || b == '/' || (b >= '0' && b <= '9')
}

// quoted quotes a matched identity string for evidence text (avoids importing
// strconv for one Quote call — keeps evidence one-line and readable).
func quoted(s string) string { return "\"" + s + "\"" }
