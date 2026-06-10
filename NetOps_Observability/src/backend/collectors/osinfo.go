package collectors

import (
	"regexp"
	"strings"
)

// osinfo.go — OS product + version extraction from SNMP sysDescr, the input
// side of Vulnerability Management (build-order #13). sysDescr is the only
// version source an agentless (SNMP-poll-only) deployment is guaranteed to
// have, and every vendor packs its OS name + version into it in a stable,
// documented shape. Parsing is vendor-gated (the vendor comes from
// DetectVendor's sysObjectID lookup, which is authoritative) so one vendor's
// pattern can never misfire on another's text.
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

// Version patterns, one per vendor family. Each is anchored to the vendor's
// own version keyword so free-floating numbers (model names, build hosts)
// can't be mistaken for a version.
var (
	// Cisco: "…, Version 15.2(4)E10, RELEASE…" / "Version 17.09.04a" /
	// NX-OS "…, Version 9.3(10)" / ASA "…Appliance Version 9.16(4)".
	reCiscoVer = regexp.MustCompile(`(?i)\bVersion[ :]+([0-9][0-9A-Za-z.()-]*)`)
	// Juniper: "… kernel JUNOS 21.4R3-S4.9, …" (also "JUNOS 12.3R11.2").
	reJunosVer = regexp.MustCompile(`(?i)\bJUNOS[ :]+([0-9][0-9A-Za-z.-]*)`)
	// Arista: "Arista Networks EOS version 4.33.1F running on …".
	reEOSVer = regexp.MustCompile(`(?i)\bversion[ :]+([0-9][0-9A-Za-z.-]*)`)
	// Fortinet: "FortiGate-60F v7.2.8,build1639,…" — FortiOS versions are
	// always three dotted numerics after a literal 'v'.
	reFortiVer = regexp.MustCompile(`(?i)\bv([0-9]+\.[0-9]+\.[0-9]+)`)
	// Palo Alto: "… PAN-OS 10.2.4-h2 …" (sysDescr often omits the version
	// entirely — the device then reports as unassessed, which is honest).
	rePanVer = regexp.MustCompile(`(?i)\bPAN-?OS[ :]+v?([0-9][0-9A-Za-z.-]*)`)
	// Nokia SR OS: "TiMOS-B-21.10.R6 both/x86_64 Nokia 7750 SR …".
	reTimosVer = regexp.MustCompile(`(?i)\bTiMOS-[A-Z]+-([0-9][0-9A-Za-z.]*)`)
	// Huawei VRP: "… VRP (R) software, Version 8.180 (CE12800 …)".
	reVRPVer = regexp.MustCompile(`(?i)\bVersion[ :]+([0-9][0-9A-Za-z.]*)`)
	// MikroTik: "RouterOS 7.14.2" / "RouterOS v6.49".
	reRouterOSVer = regexp.MustCompile(`(?i)\bRouterOS[ :]+v?([0-9][0-9A-Za-z.]*)`)
	// Linux/net-snmp: "Linux <host> 5.15.0-179-generic #…" — kernel release.
	reLinuxVer = regexp.MustCompile(`(?i)\bLinux\s+\S+\s+([0-9][0-9A-Za-z.+-]*)`)
)

// ParseOS extracts the OS product + version for a device whose vendor is
// already known (from DetectVendor). Unknown vendors and versionless sysDescrs
// return zero-value fields.
func ParseOS(vendor, sysDescr string) OSInfo {
	d := strings.TrimSpace(sysDescr)
	if d == "" {
		return OSInfo{}
	}
	l := strings.ToLower(d)
	switch vendor {
	case "cisco":
		return OSInfo{Product: ciscoProduct(l), Version: trimVer(firstMatch(reCiscoVer, d))}
	case "juniper":
		return OSInfo{Product: "junos", Version: trimVer(firstMatch(reJunosVer, d))}
	case "arista":
		return OSInfo{Product: "eos", Version: trimVer(firstMatch(reEOSVer, d))}
	case "fortinet":
		return OSInfo{Product: "fortios", Version: trimVer(firstMatch(reFortiVer, d))}
	case "paloalto":
		return OSInfo{Product: "pan-os", Version: trimVer(firstMatch(rePanVer, d))}
	case "nokia":
		return OSInfo{Product: "sros", Version: trimVer(firstMatch(reTimosVer, d))}
	case "huawei":
		return OSInfo{Product: "vrp", Version: trimVer(firstMatch(reVRPVer, d))}
	case "mikrotik":
		return OSInfo{Product: "routeros", Version: trimVer(firstMatch(reRouterOSVer, d))}
	case "linux", "net-snmp":
		return OSInfo{Product: "linux_kernel", Version: trimVer(firstMatch(reLinuxVer, d))}
	}
	return OSInfo{}
}

// ciscoProduct disambiguates Cisco's OS families — they share the "Version x"
// phrasing but are entirely separate products with separate CVE streams.
// Order matters: "IOS XE"/"IOS XR" sysDescrs also contain the bare "ios".
func ciscoProduct(lower string) string {
	switch {
	case strings.Contains(lower, "ios xr") || strings.Contains(lower, "ios-xr"):
		return "ios_xr"
	case strings.Contains(lower, "ios xe") || strings.Contains(lower, "ios-xe"):
		return "ios_xe"
	case strings.Contains(lower, "nx-os"):
		return "nx-os"
	case strings.Contains(lower, "adaptive security appliance"):
		return "asa"
	case strings.Contains(lower, "ios"):
		return "ios"
	}
	return ""
}

func firstMatch(re *regexp.Regexp, s string) string {
	if m := re.FindStringSubmatch(s); m != nil {
		return m[1]
	}
	return ""
}

// trimVer strips trailing punctuation a capture can drag along ("15.2(4)E10,"
// from comma-separated sysDescrs).
func trimVer(v string) string {
	return strings.TrimRight(v, ".,;:-")
}
