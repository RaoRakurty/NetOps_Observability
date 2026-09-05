package hardening

import (
	"context"
	"sort"
	"strconv"
	"strings"
	"time"

	"netops/backend/internal/secfindings"
)

// Device is the subject of an evaluation: the identity + dialect + owning tenant.
// TenantID is stamped onto every emitted finding from THIS record (the
// device-inventory row, which is itself principal-scoped), NEVER from a config
// or any request body (§3a: stamp the owner from the token/record, not the
// payload).
type Device struct {
	ID       string
	Hostname string
	Platform string // free-form, e.g. "Cisco IOS-XE 17.9"; normalized via VendorFromPlatform
	TenantID string
}

// Engine runs a hardening catalog against a device, pulling the running-config
// from a ConfigSource and seam attribution from a SeamResolver. Both externals
// are injected as interfaces (§5: interfaces for all external dependencies) so
// the engine is a pure, testable producer with no hidden coupling.
type Engine struct {
	catalog *Catalog
	cfgSrc  ConfigSource
	seams   SeamResolver
	now     func() time.Time
	// LICENCE-BEGIN
	// dialectAllowed gates which vendor dialects this deployment may evaluate.
	// nil = every dialect (the default, and what every test and every
	// unlicensed build gets), so this package's behaviour is unchanged unless
	// an integrator deliberately injects a gate.
	dialectAllowed func(Vendor) bool
	// LICENCE-END
}

// Option configures an Engine.
type Option func(*Engine)

// WithClock injects the time source (default time.Now). Tests use it for
// deterministic timestamps.
func WithClock(now func() time.Time) Option {
	return func(e *Engine) {
		if now != nil {
			e.now = now
		}
	}
}

// NewEngine builds an Engine. catalog, cfgSrc and seams must be non-nil; passing
// nil is a programming error the caller must avoid (the engine does not paper
// over a missing dependency with a silent no-op).
// LICENCE-BEGIN
// WithDialectGate injects the commercial dialect gate: allow(v) reports whether
// this deployment may evaluate vendor dialect v.
//
// It is an INJECTED seam and not a package-level switch, because this package
// must keep knowing nothing about licensing (the entitlement service lives in
// internal/entitlement and the wiring binds the two — see the LICENCE block in
// main.go). Passing nil, or not passing the option at all, allows every dialect,
// which is what every unit test and every build without the wiring gets.
//
// The degradation is HONEST: a device whose dialect is not licensed is not
// silently skipped and is never scored against some other platform's grammar —
// it gets exactly one finding saying the dialect is not included, in the same
// shape as the existing "platform unresolved" coverage finding.
func WithDialectGate(allow func(Vendor) bool) Option {
	return func(e *Engine) { e.dialectAllowed = allow }
}

// LICENCE-END

func NewEngine(catalog *Catalog, cfgSrc ConfigSource, seams SeamResolver, opts ...Option) *Engine {
	e := &Engine{catalog: catalog, cfgSrc: cfgSrc, seams: seams, now: time.Now}
	for _, o := range opts {
		o(e)
	}
	return e
}

// Evaluate runs the device's OWN control set — the catalog rules and seam-aware
// exposure probes that carry a binding for the device's resolved dialect — and
// returns the findings in a deterministic order.
//
// THE BINDING IS THE GATE, AND IT IS RESOLVED FIRST (the 2026-09-03 lab defect).
// Evaluate used to iterate the WHOLE catalog for every device and decide the
// verdict afterwards, with the missing-config test ahead of the binding test.
// Two consequences, both wrong and both observed on the lab fabric:
//
//   - With no config on file, an SR Linux spine was reported against all 27
//     posture rules + 4 exposure probes — cdp-run-global, pad-service,
//     no-aaa-new-model, vty-no-access-class and the rest of the Cisco IOS
//     catalogue — as 32 Unknowns. Those controls do not exist on the platform:
//     the device was never in scope for them, so "not assessed" is not the
//     honest word for them, it is noise that buries the 14 controls that ARE
//     the device's control set.
//   - With a config on file it was no better, only quieter: the same 18
//     unbound checks each emitted a NotApplicable whose Detail said "no
//     detection binding for Nokia SR Linux" — our coverage gap rendered as a
//     per-device verdict, once per device, forever.
//
// So: a rule or probe with NO binding for the resolved dialect is NOT this
// device's control and is not emitted at all. What IS emitted is honest about
// every remaining case:
//
//   - platform unresolved (no vendor profile matches the label) → NOTHING is
//     evaluated and exactly ONE finding says so (RulePlatformUnresolved,
//     StatusUnknown). Never a fallback dialect, never the IOS catalogue.
//   - running-config unavailable, rule bound → StatusUnknown (never Pass).
//   - bound, but the control has no realization on the platform
//     (DetectResult.NotApplicable) → StatusNotApplicable WITH the reason.
//   - seam model unavailable for an exposure probe → StatusUnknown.
//
// Every emitted finding carries the ruleset version stamp and, where the
// evaluation touched a real config, a by-reference EvidenceRef.
func (e *Engine) Evaluate(ctx context.Context, dev Device) ([]secfindings.Finding, error) {
	vendor := VendorFromPlatform(dev.Platform)
	// LICENCE-BEGIN — a dialect this deployment is not licensed for is reported,
	// not skipped. Placed AFTER resolution so the finding can name the dialect,
	// and BEFORE any config is fetched so an unlicensed dialect costs nothing.
	if vendor != VendorUnknown && e.dialectAllowed != nil && !e.dialectAllowed(vendor) {
		return []secfindings.Finding{e.dialectNotLicensed(dev, vendor)}, nil
	}
	// LICENCE-END
	if vendor == VendorUnknown {
		// No dialect ⇒ no control set. Emitting the catalogue here would score
		// the device against SOME OTHER platform's grammar; emitting nothing
		// would read as "clear". One honest finding is the only correct answer.
		return []secfindings.Finding{e.platformUnresolved(dev)}, nil
	}

	raw, haveCfg, err := e.cfgSrc.RunningConfig(ctx, dev.ID)
	if err != nil {
		return nil, err
	}
	var cfg *Config
	if haveCfg {
		cfg = NewConfig(vendor, raw)
	}

	var out []secfindings.Finding

	// ── posture rules ────────────────────────────────────────────────────────
	for _, rule := range e.catalog.Rules() {
		binding, bound := rule.Binding(vendor)
		if !bound {
			// Not one of this platform's controls — see the header. A gap in
			// OUR coverage is a catalog property, not a per-device verdict.
			continue
		}
		f := e.base(dev, secfindings.EvidencePosture)
		f.RawRuleID = rule.ID
		// ID is the PER-FINDING discriminator secbus.nativeIDOf folds into the
		// deterministic signal identity. It must be the RULE id, not the control
		// id: several rules/probes legitimately map onto the SAME canonical
		// control (exposure-snmp and exposure-http are both AC-4), and without
		// this segment their verdicts for one device in one scan collapse onto
		// ONE native_id — the second would dedup away downstream as a
		// redelivery, which is silent evidence loss.
		f.ID = rule.ID
		f.ControlID = rule.canonicalControl()
		f.ControlTitle = rule.Title
		f.Standards = rule.Controls
		f.Category = rule.Category
		f.Intended = rule.Intended

		if !haveCfg {
			f.Severity = rule.Severity
			f.Detail = "running-config unavailable — control not assessed (fail-closed)"
			f.SetStatus(secfindings.StatusUnknown)
			out = append(out, f)
			continue
		}
		res := binding.Detect(cfg)
		switch {
		case res.NotApplicable:
			// The control has no realization on this platform (see
			// DetectResult.NotApplicable). Say WHY it cannot apply — an
			// operator must be able to tell a structural non-verdict from a
			// gap in our coverage.
			f.Detail = res.Evidence
			f.SetStatus(secfindings.StatusNotApplicable)
		default:
			f.Remediation = binding.Remediation
			f.EvidenceRef = e.evidenceRef(dev, rule.ID)
			if res.Tripped {
				f.Severity = rule.Severity
				f.Observed = res.Evidence
				f.SetStatus(secfindings.StatusFail)
			} else {
				f.Severity = secfindings.SeverityInfo
				f.Observed = res.Evidence
				f.SetStatus(secfindings.StatusPass)
			}
		}
		out = append(out, f)
	}

	// ── seam-aware exposure probes (the differentiator) ──────────────────────
	for _, probe := range e.catalog.Probes() {
		if _, bound := probe.Binding(vendor); !bound {
			continue // not this platform's probe — same rule as the rules above
		}
		out = append(out, e.evaluateExposure(ctx, dev, vendor, cfg, haveCfg, probe))
	}

	sortFindings(out)
	return out, nil
}

// RulePlatformUnresolved is the RawRuleID/ControlID of the single finding a
// device with an unresolvable platform label produces. It is deliberately NOT a
// catalog rule: it is a statement about our ability to assess the device at all,
// which is why it carries no standards tag and no severity above info.
const RulePlatformUnresolved = "platform-unresolved"

// platformLabelMax bounds the operator-supplied platform label echoed into the
// finding narrative (§9 bounded, §8 no unbounded external string on the bus).
const platformLabelMax = 120

// platformUnresolved is the ONE honest finding for a device whose platform label
// matches no vendor profile: nothing was evaluated, and the finding says exactly
// that and why, so the UI can render an unassessed device instead of a clear one.
func (e *Engine) platformUnresolved(dev Device) secfindings.Finding {
	f := e.base(dev, secfindings.EvidencePosture)
	f.ID = RulePlatformUnresolved
	f.RawRuleID = RulePlatformUnresolved
	f.ControlID = RulePlatformUnresolved
	f.ControlTitle = "Device platform unresolved — no hardening control assessed"
	f.Category = CategoryCoverage
	f.Severity = secfindings.SeverityInfo
	f.Intended = "Every device resolves to a vendor dialect whose hardening controls can be evaluated."
	f.Observed = truncateLabel(dev.Platform)
	f.Detail = "unassessed: platform unresolved — " + describePlatform(dev.Platform) +
		", so NO hardening control was evaluated for this device"
	f.Remediation = "Complete device discovery (vendor + OS, or SNMP sysDescr) or add a vendor profile " +
		"whose detection.platform_contains recognizes this platform label."
	f.SetStatus(secfindings.StatusUnknown)
	return f
}

// LICENCE-BEGIN

// RuleDialectNotLicensed is the coverage finding emitted for a device whose
// vendor dialect this deployment is not licensed to evaluate.
const RuleDialectNotLicensed = "dialect-not-licensed"

// dialectNotLicensed is the honest answer for an unlicensed dialect.
//
// It deliberately mirrors platformUnresolved rather than returning an empty
// slice: an empty result reads as "this device is clean", which would be a lie
// about a device nothing looked at. StatusUnknown plus a stated reason is the
// same honesty rule the rest of this engine follows — "unassessed" is a
// verdict, and "no findings" is not.
func (e *Engine) dialectNotLicensed(dev Device, vendor Vendor) secfindings.Finding {
	f := e.base(dev, secfindings.EvidencePosture)
	f.ID = RuleDialectNotLicensed
	f.RawRuleID = RuleDialectNotLicensed
	f.ControlID = RuleDialectNotLicensed
	f.ControlTitle = "Device dialect not included in this licence — no hardening control assessed"
	f.Category = CategoryCoverage
	f.Severity = secfindings.SeverityInfo
	f.Intended = "Every device resolves to a vendor dialect whose hardening controls can be evaluated."
	f.Observed = truncateLabel(dev.Platform)
	f.Detail = "unassessed: the " + string(vendor) + " hardening dialect is not included in this licence, " +
		"so NO hardening control was evaluated for this device. Nothing has been hidden or deleted — " +
		"the device is still discovered, still monitored, and still appears everywhere else."
	f.Remediation = "Add the multi-vendor hardening dialects to this deployment's licence, " +
		"or exclude this device from the hardening scope."
	f.SetStatus(secfindings.StatusUnknown)
	return f
}

// LICENCE-END

// describePlatform renders the platform clause of the narrative, naming an
// ABSENT label explicitly rather than quoting an empty string at the operator.
func describePlatform(platform string) string {
	if label := truncateLabel(platform); label != "" {
		return "the platform label " + strconv.Quote(label) + " matches no vendor profile"
	}
	return "this device carries no platform label at all (no vendor/OS on its inventory row)"
}

func truncateLabel(platform string) string {
	label := strings.TrimSpace(platform)
	if len(label) > platformLabelMax {
		return label[:platformLabelMax] + "…"
	}
	return label
}

// evaluateExposure runs one seam-aware probe. This is the wedge: the verdict
// depends on the SEAM MODEL, not the config alone.
//
//	service enabled AND reachable via an untrusted seam AND no ACL → EXPOSED (critical)
//	same service behind an ACL, or only on a mgmt seam               → informational
func (e *Engine) evaluateExposure(ctx context.Context, dev Device, vendor Vendor, cfg *Config, haveCfg bool, probe ExposureProbe) secfindings.Finding {
	f := e.base(dev, secfindings.EvidenceExposure)
	f.RawRuleID = probe.ID
	f.ID = probe.ID // see the note on the posture loop: control ids are shared
	f.ControlID = probe.canonicalControl()
	f.ControlTitle = probe.Title
	f.Standards = probe.Controls
	f.Category = CategoryAccessCtrl
	f.Intended = probe.Intended

	binding, bound := probe.Binding(vendor)

	// Fail closed on a missing config or a missing binding.
	if !haveCfg {
		f.Severity = secfindings.SeverityHigh
		f.Detail = "running-config unavailable — exposure not assessed (fail-closed)"
		f.SetStatus(secfindings.StatusUnknown)
		return f
	}
	if !bound {
		f.Detail = "no exposure binding for " + DisplayVendor(vendor) + " — not assessed for this platform"
		f.SetStatus(secfindings.StatusNotApplicable)
		return f
	}

	f.Remediation = binding.Remediation
	f.EvidenceRef = e.evidenceRef(dev, probe.ID)

	on, evidence := binding.Enabled(cfg)
	if !on {
		// Service is off — not exposed. A real, assessed Pass.
		f.Severity = secfindings.SeverityInfo
		f.Observed = evidence
		f.Detail = probe.Service + " is not enabled"
		f.SetStatus(secfindings.StatusPass)
		return f
	}

	// Service is on — now the seam model decides. Fail closed if it has no data.
	seams, haveSeams, err := e.seams.DeviceSeams(ctx, dev.ID)
	if err != nil || !haveSeams {
		f.Severity = secfindings.SeverityHigh
		f.Observed = evidence
		f.Detail = "seam model unavailable for device — exposure of enabled " + probe.Service + " not assessed (fail-closed)"
		f.SetStatus(secfindings.StatusUnknown)
		return f
	}

	restricted := binding.Restricted(cfg)
	untrusted, hasUntrusted := pickUntrusted(seams)

	if hasUntrusted && !restricted {
		// EXPOSED: enabled service, reachable via an untrusted seam, no ACL.
		f.Severity = secfindings.SeverityCritical
		f.Observed = evidence
		f.Detail = probe.Service + " enabled and reachable from the " + untrusted.SeamType +
			" seam (" + untrusted.Interface + ") with no restricting ACL"
		f.SeamContext = &secfindings.SeamContext{
			SeamID:         untrusted.SeamID,
			SeamType:       untrusted.SeamType,
			InternetFacing: true,
		}
		f.SetStatus(secfindings.StatusFail)
		return f
	}

	// Informational: the service is enabled but not exposed — either restricted
	// by an ACL, or only present on a trusted/mgmt seam.
	f.Severity = secfindings.SeverityInfo
	f.Observed = evidence
	// Assemble the parenthetical from only the clauses that apply — when no
	// trusted seam exists (e.g. only untrusted seams, service ACL-restricted)
	// the old string concatenation rendered a malformed "(; restricted by ACL)".
	var clauses []string
	if trusted, ok := pickTrusted(seams); ok {
		f.SeamContext = &secfindings.SeamContext{SeamID: trusted.SeamID, SeamType: trusted.SeamType}
		clauses = append(clauses, "attributed to the "+trusted.SeamType+" seam")
	}
	if restricted {
		clauses = append(clauses, "restricted by ACL")
	} else {
		clauses = append(clauses, "no untrusted seam reaches it")
	}
	f.Detail = probe.Service + " enabled but not exposed (" + strings.Join(clauses, "; ") + ")"
	f.SetStatus(secfindings.StatusPass)
	return f
}

// base builds the common finding skeleton for a device + evidence class.
func (e *Engine) base(dev Device, evidenceClass string) secfindings.Finding {
	return secfindings.Finding{
		Source:        secfindings.SourceNetRule,
		Time:          e.now().UTC(),
		TenantID:      dev.TenantID, // §3a: stamped from the device record, never a body
		EvidenceClass: evidenceClass,
		// ResolvePlatform stamps the registry-resolved profile id alongside the
		// free-form label, so a consumer keys on one canonical identity instead
		// of re-parsing the label with its own vendor table (T9).
		Resource: secfindings.Resource{
			DeviceID:   dev.ID,
			DeviceName: dev.Hostname,
			Hostname:   dev.Hostname,
			Kind:       secfindings.KindNetworkDevice,
			Platform:   dev.Platform,
		}.ResolvePlatform(),
	}
}

// evidenceRef builds the by-reference, version-pinned pointer to the config the
// verdict was derived from (§5c: the finding names WHERE the evidence lives and
// under WHICH ruleset version, without copying the raw config).
func (e *Engine) evidenceRef(dev Device, ruleID string) *secfindings.EvidenceRef {
	return &secfindings.EvidenceRef{
		Locator:        "running-config:" + dev.ID + "#" + ruleID,
		Kind:           "config-line",
		RulesetVersion: RulesetVersion,
	}
}

// sortFindings imposes a deterministic total order: evidence class, then rule id,
// then device id, then seam id. Stable output is a §11 requirement (a diff of two
// runs must reflect real change, not map iteration).
func sortFindings(fs []secfindings.Finding) {
	sort.SliceStable(fs, func(i, j int) bool {
		a, b := fs[i], fs[j]
		if a.EvidenceClass != b.EvidenceClass {
			return a.EvidenceClass < b.EvidenceClass
		}
		if a.RawRuleID != b.RawRuleID {
			return a.RawRuleID < b.RawRuleID
		}
		if a.Resource.DeviceID != b.Resource.DeviceID {
			return a.Resource.DeviceID < b.Resource.DeviceID
		}
		return seamKey(a) < seamKey(b)
	})
}

func seamKey(f secfindings.Finding) string {
	if f.SeamContext == nil {
		return ""
	}
	return f.SeamContext.SeamID
}
