package configstore

import (
	"regexp"
	"strings"
)

// dialect.go — the per-vendor CLOSED command table and the per-vendor
// NORMALIZATION rule list.
//
// Two properties matter here and both are structural:
//
//  1. The capture command is never composed, never taken from a request and
//     never guessed. It comes from captureCommands below, which is the same
//     closed-allowlist shape internal/verify's command tables use, and an
//     unrecognized platform is REFUSED (ErrNoVendor) rather than probed with a
//     command that might not be read-only on that OS.
//  2. Normalization is what makes content-addressing meaningful. A running
//     config re-read a minute later differs in its timestamp header and its
//     free-running counters; hashing that raw text would mint a new "version"
//     on every capture, defeating both the storage-flat promise and the drift
//     signal. So a documented per-vendor list of VOLATILE lines is stripped
//     before hashing — and the list is deliberately narrow: only lines whose
//     content is a clock or a counter, never a line that could carry
//     configuration intent.

// Vendor is the canonical device-family id the tables key on. The empty value
// is an unrecognized platform: no command, no capture, an honest refusal.
type Vendor string

// The bound vendor dialects.
const (
	VendorCisco   Vendor = "cisco"   // IOS / IOS-XE / IOS-XR / NX-OS
	VendorArista  Vendor = "arista"  // EOS
	VendorJuniper Vendor = "juniper" // Junos
	VendorHuawei  Vendor = "huawei"  // VRP
	VendorNokia   Vendor = "nokia"   // SR OS
	VendorUnknown Vendor = ""
)

// VendorFromPlatform normalizes a free-form platform string (vendor + OS +
// model) into a canonical Vendor. Conservative by construction: anything it does
// not recognize is VendorUnknown, which refuses the capture rather than running
// a foreign command at a device prompt.
func VendorFromPlatform(platform string) Vendor {
	p := strings.ToLower(strings.TrimSpace(platform))
	switch {
	case p == "":
		return VendorUnknown
	// Arista is checked BEFORE Cisco: EOS platform strings frequently name
	// "Cisco-compatible" CLIs, and EOS wants its own volatile-line rules.
	case strings.Contains(p, "arista"), strings.Contains(p, "eos"):
		return VendorArista
	case strings.Contains(p, "cisco"), strings.Contains(p, "ios-xe"),
		strings.Contains(p, "iosxe"), strings.Contains(p, "ios xe"),
		strings.Contains(p, "ios-xr"), strings.Contains(p, "iosxr"),
		strings.Contains(p, "nx-os"), strings.Contains(p, "nxos"):
		return VendorCisco
	case strings.Contains(p, "junos"), strings.Contains(p, "juniper"):
		return VendorJuniper
	case strings.Contains(p, "huawei"), strings.Contains(p, "vrp"):
		return VendorHuawei
	case strings.Contains(p, "nokia"), strings.Contains(p, "sr os"),
		strings.Contains(p, "sros"), strings.Contains(p, "timos"),
		strings.Contains(p, "alcatel"):
		return VendorNokia
	default:
		return VendorUnknown
	}
}

// captureCommands is the CLOSED read-only command allowlist for running-config
// capture — vendor → the EXACT command line. Amending this map is the ONLY way
// a new command can ever run on a device from this module. Every entry is a
// display/show verb: none of them mutates device state, and none of them opens
// a shell.
var captureCommands = map[Vendor]string{
	VendorCisco:   "show running-config",
	VendorArista:  "show running-config",
	VendorJuniper: "show configuration | display set | no-more",
	VendorHuawei:  "display current-configuration",
	VendorNokia:   "admin display-config",
}

// CaptureCommand returns the read-only capture command for a vendor. ok=false is
// the honest "this platform is not bound" answer (→ ErrNoVendor).
func CaptureCommand(v Vendor) (string, bool) {
	cmd, ok := captureCommands[v]
	return cmd, ok
}

// volatileRule is one documented normalization rule: a NAME (so a test and an
// operator can talk about it) and the pattern whose matching lines are dropped
// before hashing.
type volatileRule struct {
	Name string
	Re   *regexp.Regexp
}

// volatileCommon are the vendor-independent volatile lines. Kept separate from
// the per-vendor lists so a new vendor inherits the obvious ones.
//
//	pager-noise    — the paging banner some CLIs emit into a captured session
//	bare-timestamp — a naked "Time: …" / "!Time: …" header line (Arista, and
//	                 several vendors' `| no-more` wrappers)
var volatileCommon = []volatileRule{
	{"bare-timestamp", regexp.MustCompile(`(?i)^\s*!?\s*time\s*:\s`)},
	{"pager-noise", regexp.MustCompile(`(?i)^\s*---\s*more\s*---\s*$`)},
}

// volatileRules is the per-vendor volatile-line rule list. EVERY rule is
// documented by name here; the test suite asserts the list is exercised and that
// normalization is deterministic (same input → same sha, twice).
//
// Cisco (IOS / IOS-XE / IOS-XR / NX-OS)
//
//	building-config   "Building configuration..." progress banner
//	current-config    "Current configuration : 12345 bytes" — a SIZE, which moves
//	                  with any edit and is not itself configuration
//	last-change       "! Last configuration change at …"
//	nvram-updated     "! NVRAM config last updated at …"
//	ntp-clock-period  "ntp clock-period 17179869" — a free-running drift counter
//	                  the device rewrites itself
//	time-stamp        "! Time: …" / "!Time: …"
//
// Arista (EOS)
//
//	eos-time          "! Time: …" — EOS stamps every `show running-config`
//	eos-boot-time     "! boot system flash:…" is CONFIG and is kept; only the
//	                  "! device: …" identification banner is volatile
//
// Juniper (Junos, `| display set`)
//
//	junos-last-commit "## Last commit: 2026-08-25 …" / "## Last changed: …"
//	junos-version-cmt "# version banner emitted by | display set"
//
// Huawei (VRP)
//
//	vrp-last-updated  "!Last configuration was updated at …"
//	vrp-saved-by      "!Last configuration was saved at …" / "#saved by …"
//	vrp-software      "!Software Version …" — moves on upgrade, not on config
//
// Nokia (SR OS)
//
//	sros-generated    "# Generated THU AUG 25 …"
//	sros-finished     "# Finished THU AUG 25 …"
//	sros-tim-version  "# TiMOS-B-…" build banner
var volatileRules = map[Vendor][]volatileRule{
	VendorCisco: {
		{"building-config", regexp.MustCompile(`(?i)^\s*building configuration`)},
		{"current-config", regexp.MustCompile(`(?i)^\s*current configuration\s*:`)},
		{"last-change", regexp.MustCompile(`(?i)^\s*!\s*last configuration change`)},
		{"nvram-updated", regexp.MustCompile(`(?i)^\s*!\s*nvram config last updated`)},
		{"ntp-clock-period", regexp.MustCompile(`(?i)^\s*ntp clock-period\s+\d+`)},
		{"time-stamp", regexp.MustCompile(`(?i)^\s*!\s*time\s*:`)},
	},
	VendorArista: {
		{"eos-time", regexp.MustCompile(`(?i)^\s*!\s*time\s*:`)},
		{"eos-device-banner", regexp.MustCompile(`(?i)^\s*!\s*device\s*:`)},
		{"eos-command", regexp.MustCompile(`(?i)^\s*!\s*command:\s`)},
	},
	VendorJuniper: {
		{"junos-last-commit", regexp.MustCompile(`(?i)^\s*##\s*last (commit|changed)\s*:`)},
		{"junos-version-cmt", regexp.MustCompile(`(?i)^\s*##\s*version\s`)},
	},
	VendorHuawei: {
		{"vrp-last-updated", regexp.MustCompile(`(?i)^\s*!\s*last configuration was (updated|saved)`)},
		{"vrp-saved-by", regexp.MustCompile(`(?i)^\s*#\s*saved by\s`)},
		{"vrp-software", regexp.MustCompile(`(?i)^\s*!\s*software version`)},
	},
	VendorNokia: {
		{"sros-generated", regexp.MustCompile(`(?i)^\s*#\s*generated\s`)},
		{"sros-finished", regexp.MustCompile(`(?i)^\s*#\s*finished\s`)},
		{"sros-tim-version", regexp.MustCompile(`(?i)^\s*#\s*timos-`)},
	},
}

// VolatileRuleNames returns the documented rule names applied for a vendor
// (common rules first). Exported so the test suite can assert the list is the
// one this file documents rather than whatever the code happens to do.
func VolatileRuleNames(v Vendor) []string {
	out := make([]string, 0, len(volatileCommon)+4)
	for _, r := range volatileCommon {
		out = append(out, r.Name)
	}
	for _, r := range volatileRules[v] {
		out = append(out, r.Name)
	}
	return out
}

// isVolatile reports whether a line is dropped by normalization for a vendor.
func isVolatile(v Vendor, line string) bool {
	for _, r := range volatileCommon {
		if r.Re.MatchString(line) {
			return true
		}
	}
	for _, r := range volatileRules[v] {
		if r.Re.MatchString(line) {
			return true
		}
	}
	return false
}
