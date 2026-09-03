package hardening

// RulesetVersion is the pinned version stamp for the hand-authored catalog in
// this package. It is stamped onto every emitted finding's EvidenceRef so a
// verdict is replayable against the exact ruleset it was scored under (§5c
// version-pinning). Bump it whenever a rule's detection or remediation changes.
const RulesetVersion = "correlix-hardening-2026-08-27"

// Rule category names — the plane of hardening a rule governs. Used for the
// Finding.Category grouping and for operator-facing sectioning.
const (
	CategoryMgmtService = "mgmt-service"   // insecure management services
	CategoryAccessCtrl  = "access-control" // source restriction / exposure
	CategoryCredential  = "credential"     // credential & auth hygiene
	CategoryCrypto      = "crypto"         // transport crypto hygiene
	CategoryPlane       = "plane"          // logging / NTP / control-plane
	// CategoryCoverage is NOT a plane of hardening: it groups the findings that
	// describe our ABILITY to assess a device at all (today: a platform label
	// that resolves to no dialect). It is deliberately its own category so a
	// coverage gap can never be counted, faceted or scored as a hardening
	// verdict on the device.
	CategoryCoverage = "coverage"
)

// DetectResult is the outcome of running one rule's detection against a config.
// Tripped=true means the INSECURE condition is present (the rule fails). Evidence
// is the offending config excerpt (for a present-condition rule) or a short note
// naming what was missing (for an absent-condition rule) — it becomes the
// finding's Observed field.
type DetectResult struct {
	Tripped  bool
	Evidence string
	// NotApplicable marks a verdict of "this control cannot exist on this
	// platform" — the CONCEPT has no realization in the operating system, so
	// there is nothing to observe and nothing to fix.
	//
	// It is distinct from both other answers and neither of them is honest in
	// its place. A Pass would claim we looked at the device and found it
	// hardened; leaving the vendor UNBOUND would report the generic "control not
	// assessed for this platform", which is what we say when we have not done
	// the work — and an operator cannot tell that from a gap in our coverage.
	// SR Linux has no telnet server anywhere in its model and neither EOS nor SR
	// Linux implements SSHv1, so "telnet disabled" and "SSH pinned to v2" are
	// structurally satisfied on those platforms, and saying exactly that is the
	// §5g-honest answer. Evidence carries the REASON, which the engine renders
	// as the finding's Detail.
	//
	// A binding may only set this when the platform genuinely cannot express the
	// insecure state. "We have not written the detection yet" is an unbound
	// vendor, not a NotApplicable.
	NotApplicable bool
}

// VendorBinding is a rule's per-vendor realization: the dialect-specific
// detection over a running-config plus the dialect-rendered remediation snippet.
// A rule that has no binding for a device's vendor is reported NotApplicable
// (honest non-verdict), never a false Pass.
type VendorBinding struct {
	// Detect decides whether the insecure condition holds in cfg. It never
	// panics on a well-formed *Config and treats a missing line as a real,
	// assessed observation (the fail-closed "config missing entirely" case is
	// handled one level up, in the engine, not here).
	Detect func(cfg *Config) DetectResult
	// Remediation is the dialect-rendered "what to configure" the finding
	// carries. Every binding MUST set it — a hardening finding without a fix is
	// invalid (§5e).
	Remediation string
}

// Rule is one hand-authored hardening check: a vendor-neutral CONCEPT with a
// canonical control mapping and a set of per-vendor detection/remediation
// bindings. The engine iterates rules and, for the device's vendor, emits a
// posture finding (Pass / Fail / NotApplicable) with the binding's remediation.
type Rule struct {
	// ID is the stable canonical rule id (also the Finding.RawRuleID). It never
	// changes for a given concept so historical findings stay joinable.
	ID string
	// Title is the human-facing control title.
	Title string
	// Concept is the vendor-neutral hardening concept the rule reasons about.
	Concept string
	// Severity is one of the secfindings.Severity* constants — the weight of a
	// FAIL. Info-level rules describe defense-in-depth posture.
	Severity string
	// Controls are the mapped control tags (800-53 / CIS / PCI, §5d). The FIRST
	// entry is the canonical 800-53 control id used for Finding.ControlID; the
	// whole slice populates Finding.Standards.
	Controls []string
	// Category is one of the Category* constants.
	Category string
	// Intended is the vendor-neutral secure end-state (the finding's Intended).
	Intended string
	// bindings holds the per-vendor detection + remediation. Unexported so a
	// catalog is immutable once built (no global mutable rule state, §5).
	bindings map[Vendor]VendorBinding
}

// Binding returns the rule's binding for a vendor and whether one exists.
func (r Rule) Binding(v Vendor) (VendorBinding, bool) {
	b, ok := r.bindings[v]
	return b, ok
}

// canonicalControl returns the rule's canonical (first) control id, or "".
func (r Rule) canonicalControl() string {
	if len(r.Controls) == 0 {
		return ""
	}
	return r.Controls[0]
}

// ExposureBinding is a seam-aware probe's per-vendor realization: how to tell
// whether the management service is ENABLED, whether a source ACL RESTRICTS it,
// and the dialect-rendered remediation for the exposed case.
type ExposureBinding struct {
	// Enabled reports whether the service is turned on / listening, and returns
	// the config evidence for it.
	Enabled func(cfg *Config) (on bool, evidence string)
	// Restricted reports whether a source ACL / access-class restricts who can
	// reach the service. A restricted service on an untrusted seam is
	// informational rather than critical.
	Restricted func(cfg *Config) bool
	// Remediation is the dialect-rendered fix for the EXPOSED verdict.
	Remediation string
}

// ExposureProbe is a seam-aware management-service exposure check (the §5e
// differentiator). Unlike a posture Rule, its verdict depends on the SEAM MODEL,
// not the config alone: the same enabled service is EXPOSED (critical) on an
// untrusted seam with no ACL, and informational behind an ACL or on a mgmt-only
// seam.
type ExposureProbe struct {
	// ID is the stable canonical probe id (Finding.RawRuleID).
	ID string
	// Service is the management service the probe governs ("telnet","ssh",
	// "snmp","http") — used in narrative and as the exposure grouping.
	Service string
	// Title is the human-facing title.
	Title string
	// Controls are the mapped control tags; first entry is canonical.
	Controls []string
	// Intended is the vendor-neutral secure end-state.
	Intended string
	// bindings holds the per-vendor enabled/restricted logic.
	bindings map[Vendor]ExposureBinding
}

// Binding returns the probe's binding for a vendor and whether one exists.
func (p ExposureProbe) Binding(v Vendor) (ExposureBinding, bool) {
	b, ok := p.bindings[v]
	return b, ok
}

func (p ExposureProbe) canonicalControl() string {
	if len(p.Controls) == 0 {
		return ""
	}
	return p.Controls[0]
}

// Catalog is the immutable set of hardening rules + seam-aware exposure probes.
// It is built fresh by DefaultCatalog (no package-level mutable state, §5); a
// caller needing a custom set composes its own via NewCatalog.
type Catalog struct {
	rules  []Rule
	probes []ExposureProbe
}

// NewCatalog builds a catalog from a rule set and a probe set, copying its inputs
// so the returned catalog is immutable from the caller's side.
func NewCatalog(rules []Rule, probes []ExposureProbe) *Catalog {
	r := make([]Rule, len(rules))
	copy(r, rules)
	p := make([]ExposureProbe, len(probes))
	copy(p, probes)
	return &Catalog{rules: r, probes: p}
}

// Rules returns the catalog's posture rules (in authored order).
func (c *Catalog) Rules() []Rule {
	out := make([]Rule, len(c.rules))
	copy(out, c.rules)
	return out
}

// Probes returns the catalog's seam-aware exposure probes (in authored order).
func (c *Catalog) Probes() []ExposureProbe {
	out := make([]ExposureProbe, len(c.probes))
	copy(out, c.probes)
	return out
}

// Len reports the total number of checks (rules + probes) in the catalog.
func (c *Catalog) Len() int { return len(c.rules) + len(c.probes) }
