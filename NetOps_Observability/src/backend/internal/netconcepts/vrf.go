// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

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

import (
	"strings"

	"netops/backend/internal/vendorprofile"
)

// Concept is a canonical platform vocabulary id.
type Concept string

// ConceptVRF is the canonical id for an L3 forwarding/isolation instance
// (OpenConfig: network-instance of type L3VRF). One id, every dialect.
const ConceptVRF Concept = "vrf"

// T9 (Vendor Profile registry): the synonym table and the display-term switch
// that used to live in this file are now DECLARATIVE DATA — the `dialect` block
// of each vendor profile in internal/vendorprofile. This package keeps the
// CONCEPT vocabulary and the correlation-identity rules; the per-vendor words
// are read through the registry, so adding a dialect is "author one profile".
// Outputs are byte-identical (internal/netconcepts/testdata/vendorprofile_parity.json).

// IsVRFTerm reports whether a vendor token names the VRF concept in any
// supported dialect. Parser-side use: "routing-instance CORP-WAN" and
// "vrf CORP-WAN" both classify as ConceptVRF.
func IsVRFTerm(term string) bool {
	return vendorprofile.Default().IsVRFTerm(term)
}

// VRFDisplayTerm returns the dialect the DEVICE's operator expects to read,
// keyed by vendor. A vendor NO profile claims falls back to the
// industry-majority "VRF" — a deliberate DISPLAY default (rendering a label),
// not an assessment: nothing about the device is claimed by it, and the
// registry itself reports the vendor as unknown so an assessing caller can stay
// honest.
func VRFDisplayTerm(vendor string) string {
	if term, ok := vendorprofile.Default().VRFDisplayTerm(vendor); ok {
		return term
	}
	return "VRF"
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
