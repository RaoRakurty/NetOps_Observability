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
