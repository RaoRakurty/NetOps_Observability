// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// Package vendorprofile is Correlix's VENDOR PROFILE REGISTRY (T9,
// SECURITY_BUILD_PLAN_2026-08-25; design VENDOR_EXTENSIBILITY_DESIGN_2026-08-25).
//
// The problem it kills: vendor knowledge was scattered across four unrelated
// packages — SNMP detection (collectors), dialect terms (netconcepts), hardening
// detect/remediate bindings (hardening), advisory provider selection (advisory)
// — so onboarding one vendor meant editing 4-7 touch-points. This package is the
// ONE extension point: engines READ profiles, they never hard-code a vendor.
// Adding a vendor is "author one profile", not "change an engine".
//
// SHAPE. A Profile is DECLARATIVE DATA, checked in as JSON under profiles/ (one
// document per vendor) and EMBEDDED at build time, so the binary is
// self-contained and the offline/air-gap build keeps working. The loader is
// STRICT: unknown keys are rejected, required fields are enforced, and the
// cross-profile invariants (unique ids, unique ranks, one os-parse default per
// vendor) are checked at load — a malformed profile fails loudly at start-up
// rather than silently degrading a lookup.
//
// WHY JSON AND NOT YAML. The catalog under telemetry-catalog/ is YAML because
// Python reads it. This registry is read by the GO backend, whose dependency
// rule (CLAUDE.md §6) allows no YAML module — hand-rolling a YAML parser for a
// nested schema is exactly the error-prone wire code the rule exists to avoid.
// JSON is stdlib, and encoding/json's DisallowUnknownFields gives the strict
// schema validation the design asks for for free. The ONE VOCABULARY
// requirement is met not by sharing a file but by a DRIFT TEST
// (catalog_consistency_test.go) that binds these ids to the vendor/platform
// identifiers telemetry-catalog/collection.yaml and events.yaml already use.
//
// HONESTY. There is NO default profile. An unknown vendor resolves to "not
// found" at every lookup and the caller reports unassessed — a silently applied
// fallback profile would be a false claim about a device we do not know.
//
// This package depends on the standard library ONLY (no core packages, no
// consumer packages), so every consumer can read through it with no import
// cycle and no hidden coupling.
package vendorprofile

import "strings"

// SchemaVersion is the profile-document schema this loader understands. A
// document declaring anything else is rejected (no silent forward/backward
// compatibility guessing).
const SchemaVersion = 1

// Fidelity ladder — the SAME vocabulary telemetry-catalog/collection.yaml uses
// for its fidelity_status column, plus the explicit "unassessed" rung for a
// dimension a profile has not claimed at all. Only lab_validated /
// live_validated may be advertised as "supported".
const (
	FidelityUnassessed    = "unassessed"
	FidelityDocClaimed    = "doc_claimed"
	FidelityLabValidated  = "lab_validated"
	FidelityLiveValidated = "live_validated"
	FidelityDegraded      = "degraded"
	FidelityFailed        = "failed"
)

// OSParse is a profile's contribution to sysDescr OS identification: the CPE
// product this platform reports as, and the sysDescr markers that select it
// within its vendor. An EMPTY SysDescrContainsAny means "the vendor's
// unconditional default product" — at most one profile per vendor may declare
// that, and it must sort last (highest Rank).
type OSParse struct {
	// Product is the CPE-style product string (ios_xe, junos, eos, sros, …). It
	// is the same token the vulnerability feed matches on
	// (cpe:2.3:o:<vendor>:<product>:<version>).
	Product string `json:"product"`
	// SysDescrContainsAny are lower-cased substrings; ANY match selects this
	// product. Empty = unconditional (the vendor default).
	SysDescrContainsAny []string `json:"sysdescr_contains_any"`
	// Rank orders product resolution within a vendor, ascending, first match
	// wins. Ranks must be unique within a vendor.
	Rank int `json:"rank"`
}

// Detection is everything that identifies a device as this profile. The
// vendor-level fields (SysObjectIDPrefixes, SysDescrContains, SysDescrRank,
// OSVersionPattern) are authored once per vendor document and COPIED onto every
// profile of that vendor by the loader, so a Profile is self-describing.
type Detection struct {
	// SysObjectIDPrefixes are IANA-enterprise sysObjectID prefixes, each of the
	// exact shape "1.3.6.1.4.1.<enterprise>". A device whose sysObjectID sits
	// under one of them is this vendor (the authoritative SNMP identity).
	SysObjectIDPrefixes []string `json:"sysobjectid_prefixes,omitempty"`
	// SysDescrContains are lower-cased sysDescr substrings used as the TEXT
	// BACKSTOP when the enterprise number is unknown. ANY match wins.
	SysDescrContains []string `json:"sysdescr_contains,omitempty"`
	// SysDescrRank orders the text backstop across vendors, ascending, first
	// match wins. It is load-bearing: "BIG-IP … : Linux 3.10" must resolve to
	// f5, not linux. 0 = the vendor does not participate in text detection.
	SysDescrRank int `json:"sysdescr_rank,omitempty"`
	// OSVersionPattern is the vendor's version-capture regexp (capture group 1).
	// Anchored to the vendor's own version keyword so a model number can never
	// be read as a version. Shared by every profile of the vendor.
	OSVersionPattern string `json:"os_version_pattern,omitempty"`
	// OSParse is this platform's product resolution within the vendor. nil = the
	// platform is not identified from sysDescr (e.g. a gNMI-native platform).
	OSParse *OSParse `json:"os_parse,omitempty"`
	// PlatformContains are lower-cased substrings of a free-form platform label
	// ("Cisco IOS-XE 17.9") that select this profile. Empty = never selected by
	// platform text.
	PlatformContains []string `json:"platform_contains,omitempty"`
	// PlatformRank orders platform-text resolution across ALL profiles,
	// ascending, first match wins. Must be unique among participating profiles.
	PlatformRank int `json:"platform_rank,omitempty"`
	// SyslogAppNames are RFC5424 APP-NAME hints for this platform's device logs.
	SyslogAppNames []string `json:"syslog_appnames,omitempty"`
	// SyslogFacilities are the vendor's own log facility/mnemonic-prefix hints.
	SyslogFacilities []string `json:"syslog_facilities,omitempty"`
}

// Dialect is the vendor's networking vocabulary — the netconcepts pattern
// (Cisco "VRF" ≡ Juniper "routing-instance" ≡ Nokia "VPRN") lifted out of code
// into data. Authored per vendor, copied onto every profile of that vendor.
type Dialect struct {
	// VRFTerm is the word THIS vendor's operator expects to read for the L3
	// isolation concept.
	VRFTerm string `json:"vrf_term,omitempty"`
	// VRFTermKeys are the free-form vendor tokens that select VRFTerm. They are
	// canonicalized (lower-cased, separators removed) at load.
	VRFTermKeys []string `json:"vrf_term_keys,omitempty"`
	// VRFSynonyms are this vendor's spellings of the VRF concept, used to
	// classify a parser token as ConceptVRF. Canonicalized at load.
	VRFSynonyms []string `json:"vrf_synonyms,omitempty"`
	// VRFScopeKeyword is the CLI token this vendor's operator types AHEAD of a
	// VRF / routing-instance NAME to scope a lookup to it: the command renders
	// as `<keyword> <name>`. An EMPTY keyword means this vendor scopes with the
	// bare name (its command templates already carry whatever keyword the CLI
	// needs, e.g. SR Linux `show network-instance <name> …`), so nothing is
	// emitted ahead of it.
	//
	// It is the DATA behind the `{vrf-scope}` placeholder in the TAC command
	// plans (internal/tac): the concept is one, the keyword is per-dialect, and
	// authoring a new dialect must not mean editing a switch in Go. Authored
	// per vendor from that vendor's own command reference:
	//
	//	cisco     "vrf"           — `show ip route vrf <name>` (IOS/IOS-XE/IOS-XR/NX-OS
	//	                            command references; the ASA plan scopes nothing)
	//	arista    "vrf"           — `show ip ospf vrf <name>` (EOS command reference)
	//	juniper   "instance"      — `show ospf neighbor instance <name>` (Junos CLI reference)
	//	huawei    "vpn-instance"  — `display ip routing-table vpn-instance <name>` (VRP command reference)
	//	nokia     ""              — SR Linux `show network-instance <name> …` and SR OS
	//	                            `show router <name> …` carry the keyword in the
	//	                            template; the scope is the bare instance name
	//	paloalto  ""              — PAN-OS scopes with `logical-router <name>` /
	//	                            `virtual-router <name>`, both already in the
	//	                            templates; there is no separate PAN-OS keyword
	//	fortinet  ""              — no authored FortiOS command is VRF-scoped, so no
	//	                            keyword is established for it
	//
	// A vendor with no TAC dialect leaves it unset; nothing renders for it.
	VRFScopeKeyword string `json:"vrf_scope_keyword,omitempty"`
}

// Capture is the read-only command set a config-capture run issues over the SSH
// gateway. It is DECLARED HERE and consumed by the config backup / drift
// modules; an empty field means "not established for this platform" — capture
// reports unassessed rather than guessing a command at a live device.
type Capture struct {
	RunningConfigCmd string   `json:"running_config_cmd,omitempty"`
	ShowVersionCmd   string   `json:"show_version_cmd,omitempty"`
	PagerOffCmds     []string `json:"pager_off_cmds,omitempty"`
	PromptRegex      string   `json:"prompt_regex,omitempty"`

	// ── packet capture (consumed by internal/pcap) ───────────────────────────
	//
	// PcapStartCmd / PcapStopCmd / PcapFetchCmd / PcapCleanupCmd are the BOUNDED
	// packet-capture command templates for this platform. They are TEMPLATES
	// with typed holes, never free-form strings, and CapturePcapPlaceholders is
	// the closed set of holes a template may contain:
	//
	//	{iface}  — an interface name validated by pcap.ValidateInterface
	//	{file}   — the on-device file base name, derived from a server-minted
	//	           32-hex capture id (never a caller string)
	//	{count}  — the packet bound, already clamped
	//	{secs}   — the duration bound, already clamped
	//	{filter} — a pcap-style filter validated and re-rendered by
	//	           pcap.ValidateFilter
	//	{name}   — the capture-point name platforms that configure one need
	//	           (IOS-XE), also derived from the minted capture id
	//	{mb}     — the byte ceiling expressed in whole megabytes, for the one
	//	           platform whose buffer knob is denominated that way (IOS-XE)
	//
	// A template may also carry OPTIONAL GROUPS in square brackets: the text
	// inside `[` … `]` is emitted only when every placeholder inside it has a
	// value. That is what lets ONE template express "…and, if the operator asked
	// for a filter, this clause" without a second template or a template
	// language — `{filter}` MUST sit inside such a group, so an unfiltered
	// capture can never render a dangling clause. Groups do not nest.
	//
	// An empty field means "not established for this platform" — capture is
	// REFUSED rather than guessing a command at a live device.
	PcapStartCmd []string `json:"pcap_start_cmd,omitempty"`
	PcapStopCmd  []string `json:"pcap_stop_cmd,omitempty"`
	// PcapFetchCmd is RESERVED for a platform whose file retrieval is a CLI
	// command rather than the SSH gateway's transfer channel. No shipped profile
	// declares one, and internal/pcap's registry-backed table REFUSES to build a
	// platform that does — ignoring a declared command would make the profile a
	// lie about what runs at the device (§10, no silent failure).
	PcapFetchCmd []string `json:"pcap_fetch_cmd,omitempty"`
	// PcapCleanupCmd tears the capture point AND the on-device file down. It runs
	// on every exit path, success or failure: a capture point left configured on
	// a production interface is the packet-capture design's top operational risk,
	// so a platform that declares a start with no cleanup is rejected at load.
	PcapCleanupCmd []string `json:"pcap_cleanup_cmd,omitempty"`
	// PcapRemotePath is the on-device file the start template writes. Required
	// whenever PcapStartCmd is set — a start with no path is unusable.
	PcapRemotePath string `json:"pcap_remote_path,omitempty"`
	// PcapSupportsFilter reports whether this platform's capture command can
	// express a pcap-style filter. FALSE means a filtered request is REFUSED,
	// never silently widened (Cisco IOS-XE Embedded Packet Capture has no
	// pcap-filter syntax). A platform declaring false may not carry {filter} in
	// any template, and one carrying {filter} must declare true — enforced at
	// load, so the claim and the commands cannot drift apart.
	PcapSupportsFilter bool `json:"pcap_supports_filter,omitempty"`

	// PcapFamily is the flat CAPTURE-FAMILY key internal/pcap, its API, its
	// store rows and its metrics already use for this platform ("cisco_iosxe",
	// "cisco_nxos", "juniper_junos", "arista_eos"). It is declared HERE so the
	// family and the commands it names are one document: a family key is not a
	// second id space maintained beside the registry, it is a field OF the
	// profile that owns the commands. Empty = this platform is not a capture
	// family (packet capture is refused for it).
	PcapFamily string `json:"pcap_family,omitempty"`
	// PcapPlatformRules resolve a device's FREE-FORM platform text onto this
	// profile's PcapFamily.
	//
	// They are deliberately NOT Detection.PlatformContains. That table answers
	// "which profile is this platform?" with ranked SUBSTRINGS; capture-family
	// resolution answers "which capture grammar does this device speak?" with
	// whole TOKENS, because a substring rule for "eos" also matches the vendor
	// string "acme-networks SomeOS" and rendering Arista commands at an unknown
	// device is the exact failure the capture design refuses. The two questions
	// have different answers (a Catalyst or an ISR is the IOS-XE capture family
	// though its platform text says neither "ios-xe" nor "iosxe"), so they are
	// two tables, each authored for its own question.
	PcapPlatformRules []PcapPlatformRule `json:"pcap_platform_rules,omitempty"`
}

// PcapPlatformRule is ONE ranked rule that maps free-form platform text onto a
// capture family. A rule matches when the text carries any of its Tokens as a
// whole token, or when the CONCATENATION of the text's tokens contains any of
// its Joined substrings — the joined form is what identifies the two-part names
// ("ios-xe", "nx-os") a token test alone would miss.
//
// Ranks are GLOBAL and unique across every profile: capture-family resolution is
// first-match-wins over one ordered list, and the order is load-bearing (a
// Nexus platform string also carries "cisco", so the NX-OS rule must be tested
// before the bare-vendor fallback).
type PcapPlatformRule struct {
	// Rank orders this rule against every other pcap platform rule, ascending,
	// first match wins. Must be > 0 and unique registry-wide.
	Rank int `json:"rank"`
	// Tokens are lower-case WHOLE tokens of the platform text.
	Tokens []string `json:"tokens,omitempty"`
	// Joined are lower-case substrings of the platform text's tokens
	// CONCATENATED, for the names a separator splits ("nx-os" → "nxos").
	Joined []string `json:"joined,omitempty"`
}

// CapturePcapPlaceholders is the CLOSED set of holes a pcap command template may
// contain. It is exported because it is a CONTRACT between this registry and
// internal/pcap: the registry validates that a template uses nothing else, and
// the renderer supplies exactly these names. Adding one is a deliberate act in
// both packages.
var CapturePcapPlaceholders = []string{"iface", "file", "count", "secs", "filter", "name", "mb"}

// HasPcapCommands reports whether this platform declares a packet-capture
// command set at all. False is the honest "not established here" — the caller
// refuses the capture rather than guessing.
func (c Capture) HasPcapCommands() bool { return len(c.PcapStartCmd) > 0 }

// ─── OS-version source ladder ────────────────────────────────────────────────

// OSVersionProbeVersionToken is the ONE placeholder a version_render template
// may contain. It is exported because it is a CONTRACT between this registry
// and internal/osprobe: the registry validates that a template uses nothing
// else, and the ladder supplies exactly this name.
const OSVersionProbeVersionToken = "{version}"

// OSVersionProbe is a platform's contribution to the OS-VERSION SOURCE LADDER
// (internal/osprobe): WHERE a running device's software version can be read
// from over a transport that is not SNMP, and HOW to turn what that transport
// answers into the canonical string this vendor's own os_version_pattern parses.
//
// WHY IT IS DATA. The version a device reports over gNMI or over its CLI is not
// the sysDescr text: SR Linux answers `show version` with `Software Version :
// v26.3.2` and its gNMI software-version leaf with `v26.3.2-426-g2b38957bbca`,
// while the vendor's os_version_pattern is anchored on `SRLinux-v`. A per-vendor
// regexp written next to the collector would be exactly the second vocabulary
// this package exists to abolish (see vocabulary_guard_test.go), so the pattern
// and the canonical rendering are authored HERE, per platform.
//
// WHY THE RENDER STEP EXISTS, and why it is required rather than optional. The
// row's os_version leaf is read back by collectors.ResolveDeviceOS through the
// VENDOR os_version_pattern — the same parser a sysDescr goes through — so a
// probe that wrote a bare "26.3.2" would store a string its own platform cannot
// parse, and the device would stay UNASSESSED with a version sitting right
// there in the row. VersionRender is the platform's statement of the canonical
// form, and the loader PROVES the round trip: rendering a probe token must
// produce a string the vendor pattern captures that same token back out of. A
// platform therefore cannot declare a probe that writes an unreadable value.
//
// An EMPTY block is the honest "no non-SNMP version source is established for
// this platform": the ladder skips the gNMI and CLI rungs for it rather than
// guessing a path or a command at a live device.
type OSVersionProbe struct {
	// GNMIPaths are the gNMI paths, in preference order, whose leaf carries this
	// platform's software version (SR Linux
	// `/platform/control[slot=A]/software-version`, OpenConfig
	// `/system/state/software-version`). The ladder tries them in order and
	// stops at the first that answers.
	GNMIPaths []string `json:"gnmi_paths,omitempty"`
	// GNMIVersionPattern extracts the version out of the leaf VALUE, capture
	// group 1. Required when GNMIPaths is set.
	GNMIVersionPattern string `json:"gnmi_version_pattern,omitempty"`
	// CLIVersionPattern extracts the version out of the output of the profile's
	// OWN capture.show_version_cmd, capture group 1. Declaring it requires that
	// command: the ladder never invents a command at a device.
	CLIVersionPattern string `json:"cli_version_pattern,omitempty"`
	// VersionRender is the canonical form the extracted version is written to
	// the device row in — one OSVersionProbeVersionToken placeholder inside the
	// vendor's own version phrasing ("SRLinux-v{version}", "Version {version}").
	// Required whenever any pattern above is declared.
	VersionRender string `json:"version_render,omitempty"`
	// Notes records the evidence behind the paths, the patterns and the
	// rendering — the same fidelity discipline the rest of a profile carries.
	Notes string `json:"notes,omitempty"`
}

// HasGNMI reports whether this platform declares a gNMI version source.
func (o OSVersionProbe) HasGNMI() bool { return len(o.GNMIPaths) > 0 && o.GNMIVersionPattern != "" }

// HasCLI reports whether this platform declares a CLI version source.
func (o OSVersionProbe) HasCLI() bool { return o.CLIVersionPattern != "" }

// Declared reports whether the block says anything at all.
func (o OSVersionProbe) Declared() bool { return o.HasGNMI() || o.HasCLI() }

// Render turns an extracted version into the canonical string the vendor's
// os_version_pattern parses. An empty version renders to "" — a probe that read
// nothing must never produce a value that LOOKS like a reading.
func (o OSVersionProbe) Render(version string) string {
	if version == "" || o.VersionRender == "" {
		return ""
	}
	return strings.ReplaceAll(o.VersionRender, OSVersionProbeVersionToken, version)
}

// AdvisoryBinding selects the VendorAdvisoryProvider for this platform and names
// the product ids an advisory query carries.
type AdvisoryBinding struct {
	// Provider is a provider identity (an internal/advisory Source* value).
	Provider string `json:"provider,omitempty"`
	// ProductIDs are the CPE product strings advisories are matched under.
	ProductIDs []string `json:"product_ids,omitempty"`
}

// HardeningBinding names the rule-binding dialect the hardening catalog keys on
// for this platform, plus its operator-facing label.
type HardeningBinding struct {
	// Binding is the hardening dialect id ("cisco-iosxe", "juniper", "nokia").
	// Empty = no hardening bindings exist for this platform: its rules report
	// NotApplicable (an honest non-verdict), never a false Pass.
	Binding string `json:"binding,omitempty"`
	// Display is the operator-facing label for Binding. Every profile sharing a
	// Binding must declare the SAME Display (enforced at load).
	Display string `json:"display,omitempty"`
}

// CLIBinding names the SHOW-COMMAND DIALECT this platform speaks: the family
// whose read-only `show` / `display` grammar a diagnostic renders in.
//
// It is a SEPARATE axis from HardeningBinding even where the two ids coincide.
// Arista EOS speaks the Cisco IOS-XE show grammar but the hardening catalog
// ships NO Arista rule bindings; conflating the two would either invent an
// Arista hardening verdict or refuse to render an EOS show command. One field
// per question is what keeps both answers honest.
type CLIBinding struct {
	// Dialect is the CLI dialect id ("cisco-iosxe", "juniper", "nokia").
	// Empty = this platform's show grammar is NOT established here: the caller
	// reports an unknown dialect (and records any fallback it renders), never a
	// silently guessed command.
	Dialect string `json:"dialect,omitempty"`
	// Display is the operator-facing label for Dialect. Every profile sharing a
	// Dialect must declare the SAME Display (enforced at load).
	Display string `json:"display,omitempty"`
}

// ConfigCapture is the VENDOR-LEVEL running-config capture binding: how a
// free-form platform label resolves to this vendor family, the read-only
// command a config-backup run issues, and the volatile lines normalization
// strips before the capture is content-addressed.
//
// WHY VENDOR LEVEL, beside the per-platform Capture block. The config-backup
// module (internal/configstore) resolves a device to a VENDOR FAMILY and never
// to a platform: one Junos command serves every Junos box, and the volatile
// header a device stamps on `show running-config` is a property of the OS
// family, not of the chassis. A per-profile answer would force the module to
// pick one platform of a vendor to speak for the rest, which is a guess. The
// per-profile Capture.RunningConfigCmd stays what it is — the PLATFORM's
// command — and the two may legitimately differ (Junos capture appends
// `| no-more` to defeat the pager over the gateway).
type ConfigCapture struct {
	// PlatformContains are lower-cased substrings of a free-form platform label
	// that select this VENDOR for config capture. Empty = the vendor does not
	// participate (its devices are refused, never probed with a guess).
	PlatformContains []string `json:"platform_contains,omitempty"`
	// PlatformRank orders vendor resolution across ALL vendors, ascending, first
	// match wins. It is load-bearing: an EOS platform string frequently names a
	// "Cisco-compatible" CLI, so arista must be tested before cisco. Must be
	// unique among participating vendors.
	PlatformRank int `json:"platform_rank,omitempty"`
	// RunningConfigCmd is the EXACT read-only command a capture issues at the
	// device prompt. Empty = not established for this vendor: the capture is
	// REFUSED rather than run with a command that might not be read-only there.
	RunningConfigCmd string `json:"running_config_cmd,omitempty"`
	// VolatileRules are the documented lines normalization drops before hashing.
	// The list is deliberately narrow: only lines whose content is a clock, a
	// counter or a build banner — never a line that could carry configuration
	// intent, which would silently hide a change.
	VolatileRules []VolatileRule `json:"volatile_rules,omitempty"`
	// PlatformDialects are the SIBLING capture families a vendor ships beside
	// its own. See ConfigCaptureDialect for why they exist and why they are not
	// a second vendor document.
	PlatformDialects []ConfigCaptureDialect `json:"platform_dialects,omitempty"`
}

// ConfigCaptureDialect is a capture family a vendor ships that is NOT the
// vendor's own family — a second operating system under one vendor name whose
// capture command and volatile lines are genuinely different.
//
// WHY THIS EXISTS. The vendor-level ConfigCapture answers "one command per
// vendor family", which is right for every vendor that ships one CLI. Nokia
// ships two: SR OS answers `admin display-config` in the classic TiMOS CLI, and
// SR Linux answers `info from running flat` in a completely different one. They
// are the same VENDOR, so they cannot be two vendor documents (the document name
// IS the vendor id), and they are not the same FAMILY, so one command cannot
// serve both — issuing SR OS' command at an SR Linux prompt is exactly the
// "probe it and see" behaviour internal/configstore refuses to do.
//
// A dialect is resolved in the SAME ranked, first-match-wins pass as the vendor
// families (its PlatformRank shares the one global rank space, and load
// enforces uniqueness), so a dialect that must win over its own vendor simply
// ranks lower. Everything downstream — the capture command, the volatile-rule
// list, the redaction rule set — keys on the resolved ID, which for a dialect is
// its own id, never the vendor's.
type ConfigCaptureDialect struct {
	// ID is the capture family id the resolver returns and every consumer keys
	// on. It must be unique across ALL vendor ids and ALL dialect ids.
	ID string `json:"id"`
	// PlatformContains / PlatformRank are exactly the vendor-level fields, in
	// the same global rank space.
	PlatformContains []string `json:"platform_contains,omitempty"`
	PlatformRank     int      `json:"platform_rank,omitempty"`
	// RunningConfigCmd is the EXACT read-only command this family answers.
	RunningConfigCmd string `json:"running_config_cmd,omitempty"`
	// VolatileRules are this family's documented normalization rules. A dialect
	// does NOT inherit its vendor's: the two CLIs stamp different headers.
	VolatileRules []VolatileRule `json:"volatile_rules,omitempty"`
	// Notes records how the command was established (live device, or docs).
	Notes string `json:"notes,omitempty"`
}

// VolatileRule is one named normalization rule. The NAME is part of the
// contract (a test and an operator talk about it by name, and a silent deletion
// is what the rule-name pin catches); the PATTERN is a Go regexp matched against
// a whole captured line.
type VolatileRule struct {
	Name    string `json:"name"`
	Pattern string `json:"pattern"`
}

// SNMPConfigGen is the vendor's SNMP ONBOARDING CLI block: the ready-to-paste
// configuration an operator applies to grant Correlix read-only SNMP access.
//
// It is a TEMPLATE, never a format string: the generator MINTS the credential
// (crypto/rand) and the template says where it goes. SNMPConfigGenPlaceholders
// is the closed set of holes, and a template that names anything else fails at
// LOAD — the alternative, a positional %s table, is exactly how a minted secret
// ends up in the wrong field of somebody's device configuration.
//
// A vendor declares BOTH templates or NEITHER: half a binding would silently
// hand a v2c operator the generic fallback while claiming a first-class one.
type SNMPConfigGen struct {
	// V2CTemplate renders the SNMPv2c read-only community block.
	V2CTemplate string `json:"v2c_template,omitempty"`
	// V3Template renders the SNMPv3 authPriv user block.
	V3Template string `json:"v3_template,omitempty"`
}

// SNMPConfigGenPlaceholders is the CLOSED set of holes an onboarding template
// may carry, written `<<name>>`. The `<< >>` delimiters (rather than the
// `{name}` the packet-capture templates use) are forced by the payload: several
// vendors' onboarding syntax contains literal braces (`add { user { … } }` on
// F5), and a template language whose delimiter appears in the text it renders
// cannot say which is which.
//
//	community    — the minted v2c community string
//	sec_name     — the v3 security (user) name
//	auth_key     — the minted v3 authentication key
//	priv_key     — the minted v3 privacy key
//	mgmt_subnet  — the operator's management subnet, defaulted by the caller
//	mask         — that subnet's mask, defaulted by the caller
var SNMPConfigGenPlaceholders = []string{"community", "sec_name", "auth_key", "priv_key", "mgmt_subnet", "mask"}

// DeviceTypeHints is the vendor's contribution to FUNCTIONAL device-type
// inference: the free-form model/OS/hostname text its gear reads as, and the
// vendor spellings that are themselves a role.
//
// WHY IT IS NOT DeviceClass. Profile.DeviceClass narrows which hardening rule
// families apply to a KNOWN platform; this answers a different question about a
// device the registry may not identify at all — "what does an operator call this
// box?" — from the same text an operator reads (vendor + model + OS + name).
// A Catalyst 9800 is device_class switch/wireless and device TYPE "wlc"; the
// two vocabularies are not interchangeable and are kept apart on purpose.
type DeviceTypeHints struct {
	// VendorTokens are EXACT lower-cased spellings of the vendor field that are
	// themselves a role claim ("fortigate", "palo alto"). They are matched whole,
	// not as substrings: a vendor token is an identity, not a hint.
	VendorTokens []string `json:"vendor_tokens,omitempty"`
	// VendorKind is the device type VendorTokens imply. Required when
	// VendorTokens is set, and drawn from DeviceTypeOrder.
	VendorKind string `json:"vendor_kind,omitempty"`
	// TextHints maps a device type to the lower-cased substrings of the
	// vendor+model+OS+name text that select it. A LEADING OR TRAILING SPACE IS
	// SIGNIFICANT (" mx" must not match "mx-series-lookalike"), so these are the
	// one string list the loader does not require to be trimmed.
	TextHints map[string][]string `json:"text_hints,omitempty"`
}

// DeviceTypeOrder is the CLOSED device-type vocabulary AND the order inference
// evaluates it in. The order is the engine's policy, not a vendor's fact:
// specific roles are tested before the generic switch-vs-router split so a
// firewall is never mislabelled a router. A type absent here cannot be
// authored in a profile.
var DeviceTypeOrder = []string{"firewall", "load-balancer", "wlc", "ap", "cloud-gw", "switch", "router"}

// VerifyBinding is the ACTIVE-VERIFICATION command allowlist for a VENDOR
// FAMILY: check id -> the EXACT read-only command line the verification engine
// (internal/verify) may execute on a device of this vendor.
//
// It is authored at the VENDOR level, not per platform, because the engine keys
// on the discovery vendor token a device's sysObjectID/sysDescr resolved to —
// it never knows the platform of a device it is about to interrogate.
//
// The engine composes NOTHING at runtime: a check id selects a row, and the SSH
// runner re-validates the exact string against this table before executing it.
// The registry therefore enforces the read-only shape AT LOAD (see
// validateVerifyCommand): a document whose command is not a bare show/display
// read, or that carries a shell/CLI metacharacter or a state-changing verb,
// fails the build rather than a live router.
type VerifyBinding struct {
	// Commands maps a verification check id ("ssh_interfaces", "ssh_bgp_edge")
	// to the exact command line. An id this vendor does not declare is simply
	// absent: the check is reported SKIPPED, never guessed against another
	// vendor's grammar.
	Commands map[string]string `json:"commands,omitempty"`
}

// ThreatBinding declares which device-log detections the threat lane has
// ASSESSED for this platform. An empty list means unassessed — the lane's rules
// still run (they are text matches), but the platform makes no coverage claim.
type ThreatBinding struct {
	// LogRuleIDs are internal/threatlane LogRule ids assessed against this
	// platform's log grammar. A drift test asserts every id exists.
	LogRuleIDs []string `json:"log_rule_ids,omitempty"`
	// MnemonicPrefixes are the vendor log mnemonic prefixes those rules key on.
	MnemonicPrefixes []string `json:"mnemonic_prefixes,omitempty"`
}

// Profile is ONE (vendor, platform) descriptor: everything the platform needs to
// know about that software family, in one declarative place. It is REFERENCE
// DATA — global, read-only, not tenant data (§3a) — and immutable once loaded.
type Profile struct {
	// ID is the canonical key, "<vendor>/<platform>" (e.g. "cisco/ios_xe"). The
	// platform segment is the CPE product string, the same identifier the
	// telemetry catalog and the vulnerability feed use.
	ID string `json:"-"`
	// Vendor is the canonical vendor id, lower-case, matching the vendor tokens
	// telemetry-catalog/events.yaml uses ("cisco", "arista", "nokia", …).
	Vendor string `json:"-"`
	// Platform is the CPE product string ("ios_xe", "junos", "srlinux", …).
	Platform string `json:"platform"`
	// PlatformAliases are other identifiers the catalog uses for this platform
	// (e.g. "ceos" for arista/eos). Resolved by Lookup.
	PlatformAliases []string `json:"platform_aliases,omitempty"`
	// DisplayName is the operator-facing platform label ("Cisco IOS-XE").
	DisplayName string `json:"display_name"`
	// DeviceClass narrows which hardening rule families apply
	// (router|switch|firewall|wireless|host).
	DeviceClass []string `json:"device_class"`
	// Fidelity is this profile's claim strength, on the catalog's ladder.
	Fidelity  string           `json:"fidelity"`
	Detection Detection        `json:"detection"`
	Dialect   Dialect          `json:"-"`
	Capture   Capture          `json:"capture"`
	Advisory  AdvisoryBinding  `json:"advisory"`
	Hardening HardeningBinding `json:"hardening"`
	// CLI is the show-command dialect this platform speaks. Optional: a profile
	// that declares none is a platform whose CLI grammar we have not
	// established.
	CLI    CLIBinding    `json:"cli,omitempty"`
	Threat ThreatBinding `json:"threat"`
	// OSVersionProbe is where this platform's software version can be READ from
	// over a transport SNMP could not reach, and how the reading is rendered
	// into the canonical string the vendor's os_version_pattern parses. Empty =
	// no non-SNMP version source is established here (see the type doc).
	OSVersionProbe OSVersionProbe `json:"os_version_probe,omitempty"`
}

// VendorRecord is the vendor-level view: identity, detection, dialect and the
// ids of the platform profiles authored under it. A vendor with NO profiles is
// DETECTION-ONLY — honest partial coverage (we can name the device, we claim
// nothing else about it), never a silently completed profile.
type VendorRecord struct {
	ID          string
	DisplayName string
	Detection   Detection
	Dialect     Dialect
	// Verify is the vendor's active-verification command allowlist (vendor
	// level: the engine keys on the discovery vendor token, not on a platform).
	Verify VerifyBinding
	// ConfigCapture is the vendor's running-config capture binding (command +
	// volatile-line rules); the config-backup module resolves to a vendor.
	ConfigCapture ConfigCapture
	// SNMPConfigGen is the vendor's SNMP onboarding CLI templates.
	SNMPConfigGen SNMPConfigGen
	// DeviceType is the vendor's contribution to functional device-type
	// inference.
	DeviceType DeviceTypeHints
	ProfileIDs []string
}

// OSIdentity is the OS product + version parsed out of a sysDescr. Either field
// may be "" when the text does not carry it — a caller must treat that as
// "cannot assess", never as "not vulnerable".
type OSIdentity struct {
	Product string
	Version string
}
