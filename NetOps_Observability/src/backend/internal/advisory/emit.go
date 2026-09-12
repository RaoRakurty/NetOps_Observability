// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package advisory

import (
	"context"
	"fmt"
	"time"

	"netops/backend/internal/secfindings"
)

// Device is the subject of an advisory assessment: the software coordinates used
// to query (Vendor/Product/Version) plus the identity to stamp on the emitted
// finding (Resource). It keeps the query inputs and the finding-subject in one
// place so a caller passes a device once.
type Device struct {
	Vendor   string
	Product  string
	Version  string
	Resource secfindings.Resource
}

func (d Device) query() Query {
	return Query{Vendor: d.Vendor, Platform: d.Product, Version: d.Version}
}

// EmitOptions carries what an Advisory does not itself know: the tenant to stamp
// (from the authenticated principal, §3a — NEVER from a finding body), the
// assessment run id, and the verdict time.
type EmitOptions struct {
	// TenantID is stamped onto Finding.TenantID (json:"-", never serialized).
	// §3a: it comes from the caller's authenticated principal, not the advisory.
	TenantID string
	ScanID   string
	// Now is the verdict time; a zero value defaults to time.Now().UTC().
	Now time.Time
}

// FindingsFor runs the provider for dev and converts each matched advisory into
// a secfindings.Finding of EvidenceClass "exposure" (a matched advisory means
// the device IS exposed → StatusFail). It PRESERVES honesty: a provider error
// (ErrNotProvisioned / ErrNotConfigured / ctx) propagates so the caller surfaces
// "unassessed", never a false clear; a genuine empty result yields (nil, nil).
//
// This is the ADDITIVE new emit path (owner direction) — it neither touches nor
// replaces internal/vuln's existing /api/vulns matching; it layers the owned
// finding model on top via the provider seam.
func FindingsFor(ctx context.Context, p VendorAdvisoryProvider, dev Device, opts EmitOptions) ([]secfindings.Finding, error) {
	advs, err := p.AdvisoriesFor(ctx, dev.query())
	if err != nil {
		return nil, fmt.Errorf("advisory: assess %s/%s %s via %s: %w", dev.Vendor, dev.Product, dev.Version, p.Name(), err)
	}
	if len(advs) == 0 {
		return nil, nil
	}
	out := make([]secfindings.Finding, 0, len(advs))
	for _, a := range advs {
		out = append(out, findingFromAdvisory(a, dev, opts))
	}
	return out, nil
}

// findingSource maps an Advisory.Source onto the finding Source category the
// design names (task T3): the offline CSV feed keeps "offline-feed"; every other
// (live vendor) provider is the vendor-api category. secfindings is NOT modified
// to add an offline-feed constant — the field is a free string and the offline
// value is owned by this package.
func findingSource(advSource string) string {
	if advSource == SourceOfflineFeed {
		return SourceOfflineFeed
	}
	return secfindings.SourceVendorAPI
}

// findingFromAdvisory converts one Advisory into the owned normalized finding.
// The CVE is the rule identity (ControlID + RawRuleID); Standards carries the
// CVE plus the KEV/EPSS/EoL triage TAGS (secfindings.Finding has no dedicated
// EPSS/EoL field and is not modified, so the optional enrichment is threaded
// through Standards + Detail where the advisory provides it); evidence is held
// by reference to the CVE under the producing feed/provider version.
func findingFromAdvisory(a Advisory, dev Device, opts EmitOptions) secfindings.Finding {
	now := opts.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}

	res := dev.Resource
	if res.Kind == "" {
		res.Kind = secfindings.KindNetworkDevice
	}

	// Standards / triage tags — CVE first, then the enrichment that is present.
	standards := []string{a.CVE}
	if a.KEV {
		standards = append(standards, "CISA-KEV")
	}
	if a.EPSS != nil {
		standards = append(standards, fmt.Sprintf("EPSS=%.4f", *a.EPSS))
	}
	if a.EoLRelevant != nil && *a.EoLRelevant {
		standards = append(standards, "EoL")
	}

	// Detail — the summary, with the same optional enrichment threaded through in
	// human-readable form for operators/correlation.
	detail := a.Summary
	if a.KEV {
		detail = appendClause(detail, "CISA KEV: actively exploited")
	}
	if a.EPSS != nil {
		detail = appendClause(detail, fmt.Sprintf("EPSS %.1f%%", *a.EPSS*100))
	}
	if a.EoLRelevant != nil && *a.EoLRelevant {
		detail = appendClause(detail, "device version is end-of-life — no fixes available")
	}

	f := secfindings.Finding{
		Source:        findingSource(a.Source),
		ScanID:        opts.ScanID,
		Time:          now,
		EvidenceClass: secfindings.EvidenceExposure,
		Standards:     standards,
		ControlID:     a.CVE,
		ControlTitle:  a.CVE,
		Category:      "vulnerability",
		Severity:      a.Severity,
		Resource:      res,
		Detail:        detail,
		RawRuleID:     a.CVE,
		EvidenceRef: &secfindings.EvidenceRef{
			Locator:        a.CVE,
			Kind:           "vendor-advisory",
			RulesetVersion: a.Source,
		},
	}
	// A matched advisory is an exposure verdict, not a non-verdict.
	f.SetStatus(secfindings.StatusFail)
	// §3a: tenant stamped from the caller's principal, never serialized.
	f.TenantID = opts.TenantID
	return f
}

// appendClause joins an optional bracketed clause onto detail without producing
// a leading separator when detail is empty.
func appendClause(detail, clause string) string {
	if detail == "" {
		return "[" + clause + "]"
	}
	return detail + " [" + clause + "]"
}
