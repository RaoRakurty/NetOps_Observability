package hardening

import (
	"context"
	"sort"
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
func NewEngine(catalog *Catalog, cfgSrc ConfigSource, seams SeamResolver, opts ...Option) *Engine {
	e := &Engine{catalog: catalog, cfgSrc: cfgSrc, seams: seams, now: time.Now}
	for _, o := range opts {
		o(e)
	}
	return e
}

// Evaluate runs the full catalog (posture rules + seam-aware exposure probes)
// against one device and returns the findings in a deterministic order.
//
// Fail-closed guarantees:
//   - running-config unavailable → every check emits StatusUnknown (never Pass).
//   - a rule/probe with no binding for the device's vendor → StatusNotApplicable
//     (honest non-verdict, never a false Pass).
//   - seam model unavailable for an exposure probe → StatusUnknown.
//
// Every emitted finding carries the ruleset version stamp and, where the
// evaluation touched a real config, a by-reference EvidenceRef.
func (e *Engine) Evaluate(ctx context.Context, dev Device) ([]secfindings.Finding, error) {
	vendor := VendorFromPlatform(dev.Platform)

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
		f := e.base(dev, secfindings.EvidencePosture)
		f.RawRuleID = rule.ID
		f.ControlID = rule.canonicalControl()
		f.ControlTitle = rule.Title
		f.Standards = rule.Controls
		f.Category = rule.Category
		f.Intended = rule.Intended

		binding, bound := rule.Binding(vendor)
		switch {
		case !haveCfg:
			f.Severity = rule.Severity
			f.Detail = "running-config unavailable — control not assessed (fail-closed)"
			f.SetStatus(secfindings.StatusUnknown)
		case !bound:
			f.Detail = "no detection binding for " + DisplayVendor(vendor) + " — control not assessed for this platform"
			f.SetStatus(secfindings.StatusNotApplicable)
		default:
			res := binding.Detect(cfg)
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
		out = append(out, e.evaluateExposure(ctx, dev, vendor, cfg, haveCfg, probe))
	}

	sortFindings(out)
	return out, nil
}

// evaluateExposure runs one seam-aware probe. This is the wedge: the verdict
// depends on the SEAM MODEL, not the config alone.
//
//	service enabled AND reachable via an untrusted seam AND no ACL → EXPOSED (critical)
//	same service behind an ACL, or only on a mgmt seam               → informational
func (e *Engine) evaluateExposure(ctx context.Context, dev Device, vendor Vendor, cfg *Config, haveCfg bool, probe ExposureProbe) secfindings.Finding {
	f := e.base(dev, secfindings.EvidenceExposure)
	f.RawRuleID = probe.ID
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
	if trusted, ok := pickTrusted(seams); ok {
		f.SeamContext = &secfindings.SeamContext{SeamID: trusted.SeamID, SeamType: trusted.SeamType}
		f.Detail = probe.Service + " enabled but not exposed (attributed to the " + trusted.SeamType + " seam"
	} else {
		f.Detail = probe.Service + " enabled but not exposed ("
	}
	if restricted {
		f.Detail += "; restricted by ACL)"
	} else {
		f.Detail += "; no untrusted seam reaches it)"
	}
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
		Resource: secfindings.Resource{
			DeviceID:   dev.ID,
			DeviceName: dev.Hostname,
			Hostname:   dev.Hostname,
			Kind:       secfindings.KindNetworkDevice,
			Platform:   dev.Platform,
		},
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
