package compliancemodel

import (
	"time"

	"netops/backend/internal/compliance"
	"netops/backend/internal/secfindings"
)

// EmitOptions carries what a legacy compliance.Finding does not itself know: the
// tenant to stamp (from the authenticated principal, §3a — NEVER from a finding
// body), the assessment run id, and the verdict time. Mirrors advisory.EmitOptions
// so the two owned-finding emit paths read the same.
type EmitOptions struct {
	// TenantID is stamped onto Finding.TenantID (json:"-", never serialized).
	// §3a: it comes from the caller's authenticated principal, not the finding.
	TenantID string
	ScanID   string
	// Now is the verdict time; a zero value defaults to time.Now().UTC().
	Now time.Time
}

// Convert evolves one legacy compliance.Finding onto the owned secfindings.Finding
// model (EvidenceClass "posture"). It builds on the T1 converter
// (secfindings.FromComplianceFinding — used unchanged) and then stamps the
// producer-assigned fields the converter deliberately leaves blank:
//
//   - TenantID / ScanID / Time — provenance from the caller (§3a tenant from the
//     authenticated principal, never from the finding body).
//   - ControlID              — the CANONICAL owned control id (§5d), assigned here
//     from the check→control mapping (the mapping layer's job); the PRIMARY
//     (first) mapped control is used as the finding's control id.
//   - EvidenceRef            — a by-reference, version-pinned pointer to the check
//     that produced the verdict, stamped with the seed CatalogVersion so the
//     verdict is replayable against the exact mapping it was scored under (§5c).
//
// It does NOT modify internal/compliance or internal/secfindings — additive only.
func (c *Catalog) Convert(cf compliance.Finding, opts EmitOptions) secfindings.Finding {
	f := secfindings.FromComplianceFinding(cf)

	now := opts.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}
	f.Time = now
	f.ScanID = opts.ScanID
	// §3a: tenant stamped from the caller's principal, never serialized to a client.
	f.TenantID = opts.TenantID

	// Assign the canonical owned control id from the mapping (primary control).
	if refs := c.ControlsForCheck(cf.Check); len(refs) > 0 {
		f.ControlID = refs[0].ControlID
	}

	// Evidence held BY REFERENCE: the pointer is the check id under the pinned
	// catalog version, never a copy of the underlying config/telemetry (§5c).
	f.EvidenceRef = &secfindings.EvidenceRef{
		Locator:        cf.Check,
		Kind:           "compliance-check",
		RulesetVersion: CatalogVersion,
	}
	return f
}

// ConvertAll converts a batch of legacy findings, preserving order. It is the
// evolution entrypoint a compliance run uses to produce owned findings without
// re-running any check (compliance.Evaluate stays the source of the verdicts).
func (c *Catalog) ConvertAll(cfs []compliance.Finding, opts EmitOptions) []secfindings.Finding {
	if len(cfs) == 0 {
		return nil
	}
	out := make([]secfindings.Finding, 0, len(cfs))
	for _, cf := range cfs {
		out = append(out, c.Convert(cf, opts))
	}
	return out
}
