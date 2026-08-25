// Package advisory owns the VENDOR-ADVISORY provider seam (§5g/§5h,
// SECURITY_OBSERVABILITY_HLD_2026-08-25). It answers one question — "which
// advisories affect (vendor, platform, version)?" — behind a vendor-AGNOSTIC
// interface so multiple sources plug in interchangeably: the offline CSV feed
// (internal/vuln, the air-gap canonical path), an in-memory mock for tests, and
// (design-only for now) the Cisco openVuln CSAF/OAuth2 connector.
//
// Correlix OWNS the normalized shapes here (Advisory, VersionConstraint, Query);
// no external tool's format leaks into them, and no Cisco specifics leak into
// the interface. The package converts matched advisories into the owned
// secfindings.Finding model (EvidenceClass "exposure") via emit.go — it wires to
// no HTTP handler, no correlation engine and no bus (those are later tasks). It
// deliberately depends only on internal/vuln (the version matcher + feed it
// wraps), internal/secfindings (the finding model it emits) and the stdlib.
package advisory

import (
	"context"
	"errors"
	"strings"

	"netops/backend/internal/secfindings"
	"netops/backend/internal/vuln"
)

// Provider-source identities. These are the Advisory.Source / provider Name()
// values this package defines. They are NOT secfindings.Source* constants (that
// package is owned elsewhere and not modified here); the emit path maps them
// onto the finding Source category — see findingSource in emit.go.
const (
	SourceOfflineFeed   = "offline-feed"   // the internal/vuln CSV feed (air-gap canonical)
	SourceCiscoOpenVuln = "cisco-openvuln" // Cisco openVuln (design-only stub)
)

// Errors a provider returns instead of an empty slice, so a caller surfaces
// "unassessed" and NEVER a false "all clear" (§5g honesty). A genuine
// assessment that found nothing returns (nil, nil).
var (
	// ErrNotProvisioned — the provider has no data yet (e.g. the offline feed
	// file is not present). The device is UNASSESSED, not clear.
	ErrNotProvisioned = errors.New("advisory: provider not provisioned")
	// ErrNotConfigured — the provider needs credentials/config it does not have
	// (e.g. the Cisco openVuln OAuth2 client credentials). Unassessed.
	ErrNotConfigured = errors.New("advisory: provider not configured (credentials required)")
)

// Query identifies the device software an advisory lookup is about. It is the
// vendor-agnostic input every VendorAdvisoryProvider takes; Platform is the
// product / OS family (e.g. "IOS-XE", "asa", "junos"), Version the exact build.
type Query struct {
	Vendor   string
	Platform string
	Version  string
}

// VersionConstraint is the normalized affected-version bound an advisory carries
// (Correlix-owned; mirrors NVD cpeMatch semantics — either Exact or any subset
// of the four range bounds). It is the provider-agnostic version model, so the
// interface never leaks internal/vuln.Entry.
type VersionConstraint struct {
	Exact     string `json:"exact,omitempty"`
	StartIncl string `json:"start_incl,omitempty"`
	StartExcl string `json:"start_excl,omitempty"`
	EndIncl   string `json:"end_incl,omitempty"`
	EndExcl   string `json:"end_excl,omitempty"`
}

// Matches reports whether device version v falls inside this constraint. It
// reuses the exported vuln.CompareVersions primitive (the same network-OS
// version ordering the offline feed uses) so the owned matcher and the feed's
// matcher order releases identically. The offline provider delegates to the
// feed's own richer matcher (build-suffix tolerant); this method is the owned
// path used by providers that carry constraints directly (mock, future vendor).
func (c VersionConstraint) Matches(v string) bool {
	if v == "" {
		return false
	}
	if c.Exact != "" {
		return vuln.CompareVersions(v, c.Exact) == 0
	}
	if c.StartIncl == "" && c.StartExcl == "" && c.EndIncl == "" && c.EndExcl == "" {
		return false // an unconstrained row matches nothing, not everything
	}
	if c.StartIncl != "" && vuln.CompareVersions(v, c.StartIncl) < 0 {
		return false
	}
	if c.StartExcl != "" && vuln.CompareVersions(v, c.StartExcl) <= 0 {
		return false
	}
	if c.EndIncl != "" && vuln.CompareVersions(v, c.EndIncl) > 0 {
		return false
	}
	if c.EndExcl != "" && vuln.CompareVersions(v, c.EndExcl) >= 0 {
		return false
	}
	return true
}

// Advisory is Correlix's NORMALIZED advisory record — the shape every provider
// fills in. Severity/CVSS/KEV are the core triage facts; EPSS and EoLRelevant
// are OPTIONAL enrichment (pointers so "absent" is distinct from "0"/"false") —
// the offline CSV carries neither today, so the offline provider leaves them
// nil; a vendor provider that supplies them threads them through unchanged.
type Advisory struct {
	CVE             string            `json:"cve"`
	Severity        string            `json:"severity"` // a secfindings.Severity* value
	CVSS            float64           `json:"cvss"`
	KEV             bool              `json:"kev"`            // CISA Known Exploited Vulnerabilities
	EPSS            *float64          `json:"epss,omitempty"` // optional exploitation probability [0,1]
	EoLRelevant     *bool             `json:"eol,omitempty"`  // optional: device version is end-of-life (no fixes)
	Summary         string            `json:"summary,omitempty"`
	Source          string            `json:"source,omitempty"` // producing provider (a Source* value)
	Published       string            `json:"published,omitempty"`
	AffectedVersion VersionConstraint `json:"affected_version"`
}

// VendorAdvisoryProvider is the §5h plugin seam: "which advisories affect
// (vendor, platform, version)?". Impls are interchangeable (offline CSV feed,
// in-memory mock, Cisco openVuln/CSAF, …) and vendor-AGNOSTIC — no vendor
// specifics appear in this contract.
type VendorAdvisoryProvider interface {
	// Name is the provider's stable identity; it is also stamped as
	// Advisory.Source by well-behaved impls.
	Name() string
	// AdvisoriesFor returns the advisories whose affected-version constraint the
	// query's version satisfies (a version-SCOPED query — the provider does the
	// matching). It returns an error when it cannot assess the query
	// (ErrNotProvisioned / ErrNotConfigured, or ctx.Err()); an empty slice with
	// a nil error means "assessed, none apply" — never conflate the two.
	AdvisoriesFor(ctx context.Context, q Query) ([]Advisory, error)
}

// normalizeSeverity folds a feed/advisory severity token onto a
// secfindings.Severity* value. "none"/unrecognized collapse to info so a finding
// always carries a known severity (never a raw external token).
func normalizeSeverity(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "critical":
		return secfindings.SeverityCritical
	case "high":
		return secfindings.SeverityHigh
	case "medium", "moderate":
		return secfindings.SeverityMedium
	case "low":
		return secfindings.SeverityLow
	default: // "none", "", or anything unknown
		return secfindings.SeverityInfo
	}
}
