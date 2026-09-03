package configstore

import (
	"regexp"

	"netops/backend/internal/vendorprofile"
)

// dialect.go — this module's VIEW of the vendor vocabulary.
//
// WHERE THE VENDOR KNOWLEDGE LIVES. In the Vendor Profile registry
// (internal/vendorprofile), under each vendor document's `config_capture`
// block: the platform-text table that names the family, the exact read-only
// capture command, and the named volatile-line rules. This file no longer
// carries any of those tables — it carries the module's TYPE (Vendor), the
// vendor-INDEPENDENT normalization rules, and the resolution seam. Onboarding a
// vendor for config backup is "author a profile", not "edit this file", and the
// ONE VENDOR VOCABULARY guard (vendorprofile.TestNoVendorVocabularyOutsideTheRegistry)
// is what keeps it that way.
//
// Two properties matter here and both are structural:
//
//  1. The capture command is never composed, never taken from a request and
//     never guessed. It is the EXACT string the vendor's profile declares —
//     validated at load to be a read-only show/display verb with no chaining
//     metacharacter — and an unrecognized platform is REFUSED (ErrNoVendor)
//     rather than probed with a command that might not be read-only on that OS.
//  2. Normalization is what makes content-addressing meaningful. A running
//     config re-read a minute later differs in its timestamp header and its
//     free-running counters; hashing that raw text would mint a new "version"
//     on every capture, defeating both the storage-flat promise and the drift
//     signal. So a documented per-vendor list of VOLATILE lines is stripped
//     before hashing — and the list is deliberately narrow: only lines whose
//     content is a clock or a counter, never a line that could carry
//     configuration intent.
//
// WHY Default() AND NOT AN INJECTED REGISTRY. The shipped registry is EMBEDDED,
// immutable reference data built once at start-up — the same thing the hard-
// coded tables that used to live here were, minus the drift. The functions below
// are pure package-level lookups used from the manager, the differ and the HTTP
// layer alike; threading a registry through all of them would buy no testability
// (the profiles ARE the data under test) and would give a caller the power to
// substitute the command a device is sent.

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
	// VendorSRLinux is Nokia SR Linux. It is a SIBLING CAPTURE FAMILY of
	// VendorNokia, not a second vendor: the boxes are Nokia's, but SR Linux
	// answers `info from running flat` in a model-driven CLI that shares neither
	// SR OS' command nor its `# Generated …` header lines, so one family id
	// could not serve both without guessing at one of them. The registry
	// declares it as nokia.json's config_capture.platform_dialect and resolves
	// it ahead of the nokia family (an SR Linux platform label contains
	// "nokia"); everything here — command, volatile rules, secret rules — keys
	// on THIS id.
	VendorSRLinux Vendor = "srlinux"
	VendorUnknown Vendor = ""
)

// VendorFromPlatform normalizes a free-form platform string (vendor + OS +
// model) into a canonical Vendor, through the registry's ranked config_capture
// platform table. Conservative by construction: anything no vendor claims is
// VendorUnknown, which refuses the capture rather than running a foreign command
// at a device prompt.
//
// The registry's rank order carries the one subtlety this resolution has always
// had: Arista is tested BEFORE Cisco, because EOS platform strings frequently
// name a "Cisco-compatible" CLI and EOS wants its own volatile-line rules.
func VendorFromPlatform(platform string) Vendor {
	id, ok := vendorprofile.Default().ConfigCaptureVendorForPlatform(platform)
	if !ok {
		return VendorUnknown
	}
	return Vendor(id)
}

// CaptureCommand returns the read-only capture command for a vendor family. The
// string is the one its profile declares, verbatim; ok=false is the honest
// "this platform is not bound" answer (→ ErrNoVendor). Amending a profile is the
// ONLY way a new command can ever run on a device from this module, and the
// registry validates at LOAD that every one of them is a read-only show/display
// verb carrying no chaining metacharacter.
func CaptureCommand(v Vendor) (string, bool) {
	if v == VendorUnknown {
		return "", false
	}
	return vendorprofile.Default().ConfigCaptureCommand(string(v))
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

// The PER-VENDOR volatile-line rules — Cisco's "Building configuration…" and
// "ntp clock-period", Arista's "! Time:", Junos' "## Last commit:", VRP's
// "!Last configuration was updated", SR OS' "# Generated" — live in the vendor
// profiles (config_capture.volatile_rules), each with the same documented NAME
// the test suite pins. They are compiled once, at registry load.

// VolatileRuleNames returns the documented rule names applied for a vendor
// (the vendor-independent common rules first, then the vendor's own). Exported
// so the test suite can assert the list is the one the profiles document rather
// than whatever the code happens to do.
func VolatileRuleNames(v Vendor) []string {
	vendorRules := vendorprofile.Default().ConfigVolatileRuleNames(string(v))
	out := make([]string, 0, len(volatileCommon)+len(vendorRules))
	for _, r := range volatileCommon {
		out = append(out, r.Name)
	}
	return append(out, vendorRules...)
}

// isVolatile reports whether a line is dropped by normalization for a vendor.
func isVolatile(v Vendor, line string) bool {
	for _, r := range volatileCommon {
		if r.Re.MatchString(line) {
			return true
		}
	}
	return vendorprofile.Default().IsConfigVolatileLine(string(v), line)
}
