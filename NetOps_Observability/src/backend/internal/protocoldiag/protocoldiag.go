// Package protocoldiag is Correlix's operator-initiated ROUTING-PROTOCOL
// DIAGNOSTICS backend (Troubleshooting page, item 7, owner spec
// TROUBLESHOOTING_PROTOCOL_DIAGNOSTICS_2026-08-27).
//
// It is the collect→analyze half of a point-in-time, shareable capture: an
// operator picks a protocol (BGP / OSPF / IS-IS) and one of that protocol's five
// most common issues; Collect runs a curated bundle of READ-ONLY `show` commands
// against the operator's own device; Analyze runs rules-as-code failure
// signatures over the captured text and returns a plain verdict + likely cause +
// remediation (or, honestly, "no known signature matched — raw output for TAC");
// and a redaction pass produces a shareable TAC export. It complements — does not
// replace — the passive correlation engine (this is "capture the evidence myself,
// right now"); it does NOT touch internal/correlation.
//
// SHAPE (mirrors internal/hardening and internal/threatlane): a rules-as-code
// CATALOG (the issue→command-bundle matrix, version-pinned), a command SOURCE
// behind a NARROW injected interface (CommandRunner) with an in-memory stub, and
// an Analyze engine of hand-authored signatures. The real command source is
// SSHCommandRunner over SSHGateway (sshrunner.go / sshgw.go) — the same vendored
// ssh client and the same pinned host-key custody the operator terminal uses —
// wired by the integrator behind FEATURE_PROTOCOL_DIAG_COLLECT (env.go) and
// DORMANT by default. It is a pure,
// deterministic LIBRARY: no goroutines, no shared mutable state (safe under -race
// by construction), no HTTP handler, no store — so it ships no org_isolation_test
// (there is no data-returning surface to leak; see the commit note). §3a is still
// honored: every Collection's TenantID is stamped from the SUBJECT DEVICE (which
// is itself principal-scoped at the call site upstream), NEVER from a request
// body.
//
// VENDOR-DIALECT AWARE (reuses internal/netconcepts, product item 4): an issue is
// a vendor-neutral CONCEPT; each command renders in the device's dialect
// ("OSPF neighbor" → Cisco `show ip ospf neighbor`, Juniper `show ospf neighbor`,
// Nokia `show router ospf neighbor`). Cisco IOS-XE is the primary, fully-bound
// dialect; Juniper and Nokia are bound declaratively for the command rendering,
// so adding a vendor is "add a binding", not "change the engine".
//
// SAFETY (§8): the collector ENFORCES read-only — a command that is not a
// show/display/get/info read is REFUSED before it is ever run (a config command
// can never leave this package), and command output can carry secrets/PII so the
// TAC export runs an explicit REDACTION pass first.
package protocoldiag

import "strings"

// RulesetVersion is the pinned version stamp for the hand-authored catalog +
// signatures in this package (§5c version-pinning). It is stamped onto every
// Collection and AnalyzeResult so a verdict is replayable against the exact
// ruleset it was scored under. Bump it whenever a command bundle, a signature's
// match, or its remediation changes.
const RulesetVersion = "correlix-protocoldiag-2026-08-27"

// Protocol is the routing protocol a diagnostics tab covers. It is the top-level
// grouping of the issue catalog.
type Protocol string

const (
	// ProtocolBGP is the Border Gateway Protocol tab.
	ProtocolBGP Protocol = "bgp"
	// ProtocolOSPF is the OSPF (v2) tab.
	ProtocolOSPF Protocol = "ospf"
	// ProtocolISIS is the IS-IS tab.
	ProtocolISIS Protocol = "isis"
)

// Vendor is the canonical device-family id the per-vendor command bindings key
// on. It mirrors the internal/hardening + internal/netconcepts vendor-dialect
// pattern: the catalog reasons about a vendor-neutral concept and renders each
// command in the device's dialect. The empty value is an unrecognized vendor —
// its bundle falls back to the primary (Cisco IOS-XE) dialect and the fallback is
// recorded honestly on the Collection so the operator is never misled about which
// dialect was rendered.
type Vendor string

const (
	// VendorCiscoIOSXE is the primary, fully-bound dialect.
	VendorCiscoIOSXE Vendor = "cisco-iosxe"
	// VendorJuniper is bound declaratively (Junos show-command dialect).
	VendorJuniper Vendor = "juniper"
	// VendorNokia is bound declaratively (Nokia SR OS `show router …` dialect).
	VendorNokia Vendor = "nokia"
	// VendorUnknown is an unrecognized vendor.
	VendorUnknown Vendor = ""
)

// VendorFromPlatform normalizes a free-form platform string (e.g.
// "Cisco IOS-XE 17.9", "Juniper Junos 22.4") into a canonical Vendor. It is
// deliberately conservative: an unrecognized platform maps to VendorUnknown so
// the caller can decide, rather than mis-rendering against the wrong dialect.
func VendorFromPlatform(platform string) Vendor {
	p := strings.ToLower(strings.TrimSpace(platform))
	switch {
	case p == "":
		return VendorUnknown
	case strings.Contains(p, "ios-xe"), strings.Contains(p, "iosxe"),
		strings.Contains(p, "ios xe"), strings.Contains(p, "ios-xr"),
		strings.Contains(p, "iosxr"), strings.Contains(p, "nx-os"),
		strings.Contains(p, "nxos"), strings.Contains(p, "cisco"),
		strings.Contains(p, "arista"), strings.Contains(p, "eos"):
		return VendorCiscoIOSXE
	case strings.Contains(p, "junos"), strings.Contains(p, "juniper"):
		return VendorJuniper
	case strings.Contains(p, "nokia"), strings.Contains(p, "sr os"),
		strings.Contains(p, "sros"), strings.Contains(p, "sr linux"),
		strings.Contains(p, "srlinux"), strings.Contains(p, "timos"):
		return VendorNokia
	default:
		return VendorUnknown
	}
}

// DisplayVendor renders a Vendor as an operator-facing label.
func DisplayVendor(v Vendor) string {
	switch v {
	case VendorCiscoIOSXE:
		return "Cisco IOS-XE"
	case VendorJuniper:
		return "Juniper Junos"
	case VendorNokia:
		return "Nokia SR OS"
	default:
		return "unknown vendor"
	}
}

// renderVendor is the dialect actually rendered for v: a recognized vendor
// renders in its own dialect, an unknown vendor falls back to the primary
// (Cisco IOS-XE) so a bundle is always produced. The chosen dialect is recorded
// on the Collection (RenderedVendor) so the fallback is never silent.
func renderVendor(v Vendor) Vendor {
	switch v {
	case VendorJuniper, VendorNokia, VendorCiscoIOSXE:
		return v
	default:
		return VendorCiscoIOSXE
	}
}

// Confidence is how strongly a fired signature stands behind its verdict. It is
// honest, not decorative: a single-condition tell (a state string alone) is
// Medium; a multi-condition match (state + corroborating evidence) is High; a
// weak/heuristic tell is Low.
type Confidence string

const (
	// ConfidenceHigh is a multi-condition or unambiguous match.
	ConfidenceHigh Confidence = "high"
	// ConfidenceMedium is a single clear tell.
	ConfidenceMedium Confidence = "medium"
	// ConfidenceLow is a weak/heuristic tell — a triage hint, not a verdict.
	ConfidenceLow Confidence = "low"
)

// confidenceRank orders confidence for deterministic sorting (higher first).
func confidenceRank(c Confidence) int {
	switch c {
	case ConfidenceHigh:
		return 3
	case ConfidenceMedium:
		return 2
	case ConfidenceLow:
		return 1
	default:
		return 0
	}
}

// Device is the subject of a capture — the minimal identity the collector needs.
// It is populated at the call site from the principal-scoped device inventory
// (device_ssh.go authorizes the operator against their OWN device first); this
// package trusts the caller to have done that authorization and simply STAMPS the
// device's tenant onto the Collection (§3a: owner from the resolved device, never
// from a request body).
type Device struct {
	// ID is the stable inventory device id.
	ID string
	// Hostname is the operator-facing device name.
	Hostname string
	// Platform is the free-form platform string used to derive the dialect.
	Platform string
	// Address is the management address the LIVE command source dials. It is
	// empty for the in-memory/stub runners (which never reach a network) and is
	// populated at the call site from the same principal-scoped inventory row the
	// device SSH gateway uses. Never taken from a request body.
	Address string
	// Port is the device SSH port; 0 means "use the gateway's default".
	Port int
	// TenantID is the owning tenant, resolved upstream from the authenticated
	// principal's device lookup. It is stamped onto the Collection.
	TenantID string
}

// Vendor derives the canonical vendor from the device platform string.
func (d Device) Vendor() Vendor { return VendorFromPlatform(d.Platform) }

// Target carries the optional command arguments an issue's bundle substitutes
// into its commands: the interface under investigation, the BGP peer address, the
// prefix in question, and the VRF / routing-instance to scope route lookups to.
// Every field is optional — an empty field renders the command in its
// unscoped/"all" form (e.g. an empty Interface yields `show ip ospf interface`,
// which lists every interface). All fields are UNTRUSTED input; the collector
// re-validates the fully-rendered command as read-only before running it.
type Target struct {
	Interface string
	Peer      string
	Prefix    string
	VRF       string
	// Address is the L3 or L2 address an ARP / MAC lookup is scoped to. It is
	// used ONLY by the state battery (statebattery.go); the 15-issue catalog's
	// templates carry no {addr} placeholder, so adding it changes nothing about
	// what the catalog renders.
	Address string
}
