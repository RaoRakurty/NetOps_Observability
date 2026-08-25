// Package netconcepts canonicalizes vendor-dialect networking terms into one
// platform vocabulary (product wave item 4, 2026-08-25).
//
// The problem it kills: Cisco says "VRF", Juniper says "routing-instance",
// Nokia says "VPRN" (service), Huawei says "VPN instance" — the SAME L3
// isolation concept. Correlix must READ all dialects as one concept (entity
// tokens, correlation identity) while DISPLAYING each device's own dialect
// back to the operator (a Juniper operator should see "routing-instance").
//
// OpenConfig already agrees: gNMI's /network-instances tree is the neutral
// model every vendor maps into — this package is the same normalization for
// the surfaces gNMI does not cover (syslog text, SNMP contexts, UI labels).
package netconcepts

import "strings"

// Concept is a canonical platform vocabulary id.
type Concept string

// ConceptVRF is the canonical id for an L3 forwarding/isolation instance
// (OpenConfig: network-instance of type L3VRF). One id, every dialect.
const ConceptVRF Concept = "vrf"

// vrfSynonyms maps normalized vendor spellings to ConceptVRF. Keys are
// lower-cased with separators collapsed (see canon).
var vrfSynonyms = map[string]struct{}{
	"vrf":             {}, // cisco, arista, frr, generic
	"vrflite":         {}, // cisco "VRF-Lite"
	"routinginstance": {}, // juniper
	"vprn":            {}, // nokia SR OS service
	"vpninstance":     {}, // huawei
	"vpnvrf":          {},
	"l3vpn":           {},
	"networkinstance": {}, // openconfig
	"ipvpn":           {},
}

func canon(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	repl := strings.NewReplacer("-", "", "_", "", " ", "", ".", "")
	return repl.Replace(s)
}

// IsVRFTerm reports whether a vendor token names the VRF concept in any
// supported dialect. Parser-side use: "routing-instance CORP-WAN" and
// "vrf CORP-WAN" both classify as ConceptVRF.
func IsVRFTerm(term string) bool {
	_, ok := vrfSynonyms[canon(term)]
	return ok
}

// VRFDisplayTerm returns the dialect the DEVICE's operator expects to read,
// keyed by vendor. Unknown vendors get the industry-majority "VRF".
func VRFDisplayTerm(vendor string) string {
	switch canon(vendor) {
	case "juniper", "junos", "jnpr":
		return "routing-instance"
	case "nokia", "sros", "alcatel", "alcatellucent", "srlinux":
		return "VPRN"
	case "huawei", "vrp":
		return "VPN instance"
	default: // cisco, iosxe, iosxr, nxos, arista, eos, frr, generic
		return "VRF"
	}
}

// VRFEntityToken builds the canonical correlation identity for one VRF on one
// device — dialect-free on purpose, so a syslog line saying
// "routing-instance CORP-WAN" and a gNMI update for
// network-instance[name=CORP-WAN] land on the SAME entity. Instance names are
// case-preserved (they are operator-chosen identifiers), devices lower-cased
// like the rest of the identity space.
func VRFEntityToken(device, instance string) string {
	return "vrf:" + strings.ToLower(strings.TrimSpace(device)) + ":" + strings.TrimSpace(instance)
}
