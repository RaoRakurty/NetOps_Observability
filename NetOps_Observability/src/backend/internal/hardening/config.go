// Package hardening is Correlix's network-device hardening rule engine (§5e of
// SECURITY_OBSERVABILITY_HLD_2026-08-25): the security-track differentiator.
//
// It is a SELF-CONTAINED PRODUCER of secfindings.Finding objects. Per the
// removable-module constraint, it hard-depends on nothing security-specific in
// the core — only on internal/secfindings (the shared, owned finding model) and
// the standard library. The correlation engine consumes what this package emits
// with zero security-specific code; deleting this package removes the feature
// and touches nothing else.
//
// What it does:
//   - A hand-authored rule/concept CATALOG (§5e starter set) of insecure
//     management services, credential/crypto hygiene, and plane-hardening rules,
//     independently worded (no CIS PDF text — that content is non-commercially
//     licensed) and version-pinned (RulesetVersion).
//   - A per-vendor DETECTION binding over a device's running-config TEXT.
//     Cisco IOS-XE is the primary, fully-bound vendor; Juniper and Nokia are
//     bound declaratively for a subset so adding a vendor is "add a binding",
//     not "change the engine" (this leaves room for the future Vendor Profile,
//     T9, without building it).
//   - The SEAM-AWARE EXPOSURE evaluator (the wedge): a management service that
//     is enabled AND reachable via an interface on an untrusted seam AND has no
//     restricting ACL is EXPOSED (critical); the same service behind an ACL or
//     only on a mgmt seam is informational. This is the check no config scanner
//     can copy without a topology/seam model.
//
// Every emitted finding carries a dialect-rendered REMEDIATION (the "what to
// configure"). The engine FAILS CLOSED: if the running-config or the seam model
// is unavailable it emits StatusUnknown (never a false green), never a silent
// Pass.
package hardening

import (
	"regexp"
	"strings"

	"netops/backend/internal/vendorprofile"
)

// Vendor is the canonical device-family id the per-vendor detection bindings key
// on. It mirrors the netconcepts vendor-dialect pattern (item 4): the engine
// reasons about a vendor-neutral CONCEPT and renders detection + remediation in
// the device's dialect. The empty value is an unrecognized vendor — its rules
// evaluate to NotApplicable (honest non-verdict), never a false Pass.
type Vendor string

const (
	// VendorCiscoIOSXE is the primary, fully-bound dialect.
	VendorCiscoIOSXE Vendor = "cisco-iosxe"
	// VendorJuniper is bound for a declarative subset (Junos set-format).
	VendorJuniper Vendor = "juniper"
	// VendorNokia is bound for a declarative subset (Nokia SR OS — the classic
	// TiMOS configuration grammar). SR Linux is NOT this dialect; see
	// VendorSRLinux.
	VendorNokia Vendor = "nokia"
	// VendorArista is Arista EOS. It is its own dialect and not cisco-iosxe: EOS
	// borrows IOS' SHOW grammar (which is why its CLI binding is cisco-iosxe)
	// but not IOS' CONFIGURATION grammar, so the IOS rules would have scored a
	// dozen controls against lines EOS never writes. See dialect_fabric.go.
	VendorArista Vendor = "arista"
	// VendorSRLinux is Nokia SR Linux — a flat `set / <path> <value>` rendering
	// of a YANG tree that shares no configuration statement with SR OS.
	VendorSRLinux Vendor = "srlinux"
	// VendorUnknown is an unrecognized vendor: rules are NotApplicable.
	VendorUnknown Vendor = ""
)

// VendorFromPlatform normalizes a free-form platform string (as carried on
// secfindings.Resource.Platform, e.g. "Cisco IOS-XE 17.9") into a canonical
// Vendor. It is deliberately conservative: an unrecognized platform maps to
// VendorUnknown so its rules are reported NotApplicable rather than misdetected
// against the wrong dialect.
//
// T9 (Vendor Profile registry): the substring table it used to hold as a switch
// is now DECLARATIVE DATA — the `detection.platform_contains` /
// `detection.platform_rank` and `hardening.binding` fields of the vendor
// profiles in internal/vendorprofile. The rank is carried in the data because
// first-match-wins order is load-bearing. Outputs are byte-identical
// (internal/hardening/testdata/vendorprofile_parity.json). Adding a dialect is
// "author one profile + add the bindings", not "edit this switch".
func VendorFromPlatform(platform string) Vendor {
	binding, ok := vendorprofile.Default().HardeningBindingForPlatform(platform)
	if !ok {
		return VendorUnknown
	}
	return Vendor(binding)
}

// DisplayVendor renders a Vendor as an operator-facing label (dialect-aware, in
// the spirit of netconcepts.VRFDisplayTerm). A binding no profile declares —
// including VendorUnknown — renders as "unknown vendor", never as some other
// vendor's name.
func DisplayVendor(v Vendor) string {
	if label, ok := vendorprofile.Default().HardeningDisplay(string(v)); ok {
		return label
	}
	return "unknown vendor"
}

// Config is a parsed device running-configuration. It is vendor-neutral at the
// container level; the per-vendor detection closures know how to read it. It is
// immutable after New and holds no external references, so it is safe to share.
type Config struct {
	vendor Vendor
	lines  []string
}

// NewConfig parses raw running-config text for a vendor. Lines are split on
// newlines and right-trimmed; blank lines and bare comment markers ("!") are
// retained as-is (detection helpers ignore them) so line-oriented evidence stays
// faithful to the source.
func NewConfig(vendor Vendor, raw string) *Config {
	raw = strings.ReplaceAll(raw, "\r\n", "\n")
	split := strings.Split(raw, "\n")
	lines := make([]string, 0, len(split))
	for _, ln := range split {
		lines = append(lines, strings.TrimRight(ln, " \t"))
	}
	return &Config{vendor: vendor, lines: lines}
}

// Vendor returns the dialect this config was parsed under.
func (c *Config) Vendor() Vendor { return c.vendor }

// Lines returns a copy of the config lines (callers cannot mutate the config).
func (c *Config) Lines() []string {
	out := make([]string, len(c.lines))
	copy(out, c.lines)
	return out
}

// FirstMatch returns the first line matching re (trimmed) and whether one
// existed.
func (c *Config) FirstMatch(re *regexp.Regexp) (string, bool) {
	for _, ln := range c.lines {
		if re.MatchString(ln) {
			return strings.TrimSpace(ln), true
		}
	}
	return "", false
}

// Has reports whether any line matches re.
func (c *Config) Has(re *regexp.Regexp) bool {
	_, ok := c.FirstMatch(re)
	return ok
}

// Stanza is a top-level IOS-style configuration block: a header line at column 0
// plus the indented child lines beneath it, up to the next column-0 line.
type Stanza struct {
	Header   string
	Children []string
}

// IOSStanzas returns the IOS-style blocks whose header line matches headerRe. A
// header is a line with no leading whitespace; its children are the subsequent
// leading-whitespace lines until the next column-0 line. Used for VTY/line and
// control-plane block reasoning where a rule depends on a sub-line's presence.
func (c *Config) IOSStanzas(headerRe *regexp.Regexp) []Stanza {
	var out []Stanza
	for i := 0; i < len(c.lines); i++ {
		ln := c.lines[i]
		if ln == "" || ln == "!" {
			continue
		}
		if isIndented(ln) {
			continue
		}
		if !headerRe.MatchString(strings.TrimSpace(ln)) {
			continue
		}
		st := Stanza{Header: strings.TrimSpace(ln)}
		for j := i + 1; j < len(c.lines); j++ {
			child := c.lines[j]
			if child == "" || child == "!" {
				continue
			}
			if !isIndented(child) {
				break
			}
			st.Children = append(st.Children, strings.TrimSpace(child))
		}
		out = append(out, st)
	}
	return out
}

// ChildHas reports whether any child line of the Stanza matches re.
func (s Stanza) ChildHas(re *regexp.Regexp) bool {
	for _, ch := range s.Children {
		if re.MatchString(ch) {
			return true
		}
	}
	return false
}

func isIndented(ln string) bool {
	return len(ln) > 0 && (ln[0] == ' ' || ln[0] == '\t')
}
