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
	Threat    ThreatBinding    `json:"threat"`
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
	ProfileIDs  []string
}

// OSIdentity is the OS product + version parsed out of a sysDescr. Either field
// may be "" when the text does not carry it — a caller must treat that as
// "cannot assess", never as "not vulnerable".
type OSIdentity struct {
	Product string
	Version string
}
