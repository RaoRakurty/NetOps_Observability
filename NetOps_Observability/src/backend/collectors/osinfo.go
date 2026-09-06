// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package collectors

import (
	"strings"

	"netops/backend/internal/vendorprofile"
)

// osinfo.go — OS product + version extraction from SNMP sysDescr, the input
// side of Vulnerability Management (build-order #13). sysDescr is the only
// version source an agentless (SNMP-poll-only) deployment is guaranteed to
// have, and every vendor packs its OS name + version into it in a stable,
// documented shape. Parsing is vendor-gated (the vendor comes from
// DetectVendor's sysObjectID lookup, which is authoritative) so one vendor's
// pattern can never misfire on another's text.
//
// T9 (Vendor Profile registry): the per-vendor version patterns and the Cisco
// product-family disambiguation used to live here as package-level regexps and
// a hand-written switch. They are now DECLARATIVE DATA in
// internal/vendorprofile — one profile per (vendor, platform) — and this
// function is the thin adapter that reads through the registry. The outputs are
// byte-identical (collectors/testdata/vendorprofile_parity.json pins them);
// onboarding a vendor is now "author one profile", not "edit this file".
//
// Product names align with the vulnerability feed's CPE product strings
// (cpe:2.3:o:<vendor>:<product>:<version>); the matcher normalizes both sides
// (lowercase, alphanumerics only) so punctuation variants (ios-xe / ios_xe)
// can't cause a miss.

// OSInfo is the OS identity parsed out of a sysDescr. Either field may be ""
// when the text doesn't carry it — callers must treat that as "cannot assess",
// never as "not vulnerable".
type OSInfo struct {
	Product string // CPE-style product (ios, ios_xe, junos, eos, fortios, …)
	Version string // version exactly as the device reports it
}

// ParseOS extracts the OS product + version for a device whose vendor is
// already known (from DetectVendor). Unknown vendors and versionless sysDescrs
// return zero-value fields — the caller reports the device UNASSESSED, never
// "not vulnerable", and NO fallback profile is applied on its behalf.
//
// The vendor id must be the lower-cased, normalized token DetectVendor emits;
// the registry match is exact, exactly as the previous switch statement was.
func ParseOS(vendor, sysDescr string) OSInfo {
	if strings.TrimSpace(sysDescr) == "" {
		return OSInfo{}
	}
	id, ok := vendorprofile.Default().ResolveOS(vendor, sysDescr)
	if !ok {
		return OSInfo{}
	}
	return OSInfo{Product: id.Product, Version: id.Version}
}

// ResolveDeviceOS is the ONE place a device row's software identity is derived,
// and the reason it exists is tracker 231.
//
// ParseOS reads a sysDescr. A device that answers SNMP has one; a device whose
// row was authored by hand or by an importer usually does not — the reference
// lab's SR Linux spines carry `os: "SR Linux"` and nothing else, because the
// platform's ACL refuses the collector host and the real description leaf is
// only reachable over gNMI. "SR Linux" resolves the PRODUCT (srlinux) and
// carries no version, so every advisory read reported those devices UNASSESSED
// forever — correctly, but permanently.
//
// The device row therefore carries a second, explicitly-sourced field
// (models.Device.OSVersion) that any source may write, and this function is the
// resolution order over the two:
//
//  1. OS alone. A live sysDescr answers both halves and ALWAYS wins — a
//     hand-written or stale OSVersion can never override what the device said.
//  2. OS + OSVersion joined. This is the case the lab spines are in: the OS
//     label names the product and the version text carries the version
//     ("SR Linux" + "SRLinux-v26.3.2-…"), and only the pair resolves both.
//  3. OSVersion alone, for a source that wrote the WHOLE description leaf into
//     it and left OS as a display label the vendor pattern does not match.
//
// It NEVER invents: a resolution that yields no version returns a zero Version,
// and the caller must report the device unassessed rather than "not vulnerable"
// (§5g). A product resolved without a version is still returned, because
// "which product, no version" is a more useful unassessed reason than silence.
func ResolveDeviceOS(vendor, osText, osVersion string) OSInfo {
	if osi := ParseOS(vendor, osText); osi.Version != "" {
		return osi
	}
	if strings.TrimSpace(osVersion) == "" {
		return ParseOS(vendor, osText)
	}
	// The join is ordered OS-then-version so a vendor pattern anchored on the
	// product name still matches, and so the version text cannot displace a
	// product the OS label already names.
	if osi := ParseOS(vendor, strings.TrimSpace(osText)+" "+strings.TrimSpace(osVersion)); osi.Version != "" {
		return osi
	}
	if osi := ParseOS(vendor, osVersion); osi.Version != "" {
		return osi
	}
	// Nothing resolved a version. Return whatever product the OS label alone
	// named, so the caller can say WHICH product it could not assess.
	return ParseOS(vendor, osText)
}
