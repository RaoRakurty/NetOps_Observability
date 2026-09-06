// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package advisory

import (
	"context"
	"fmt"
)

// CiscoOpenVulnProvider is a DESIGN-ONLY, interface-conformant stub for Cisco's
// openVuln advisory API (owner direction 2026-08-25: design now, implement
// later). It compiles, satisfies VendorAdvisoryProvider, and returns
// ErrNotConfigured until the live connector is wired. It adds NO http/oauth
// import, NO network call and NO credential-handling logic — only the shape and
// the binding contract below.
//
// IMPLEMENTATION CONTRACT (do not violate when this is built for real):
//
//	Auth — Cisco openVuln requires a REGISTERED APPLICATION using OAuth 2.0
//	client-credentials (client_id + client_secret exchanged for a bearer
//	token). Those are SECRETS: they MUST be read from Correlix's sealing/vault
//	mechanism at call time — the vault.Decrypt(tenant, fieldID, sealed) pattern
//	used by ai/copilot_config.go (FieldCopilotKey) and cloudconn/broker.go —
//	NEVER from source, env vars or a config file (§8, CLAUDE.md §8). Store the
//	client_id/secret sealed exactly like the copilot key; decrypt into memory
//	only for the token exchange, keep them write-only and out of logs. The
//	secret reader must be INJECTED (an interface, §5), not reached for globally,
//	so this provider stays testable and the core carries no secret plumbing.
//
//	Data model — CSAF (Common Security Advisory Framework). Cisco recommends
//	CSAF over the older CVRF, so the live provider parses the OS-version
//	endpoint (e.g. OSType/iosxe?version=17.9.4a) CSAF documents into []Advisory.
//	CSAF carries the CVE id, product_status version branches (→ VersionConstraint),
//	CVSS and severity; KEV/EPSS/EoL enrichment is joined in the background SYNC
//	layer (CISA KEV, FIRST EPSS, Cisco EoX), not fetched per call.
//
//	Network shape — a background SYNC pulls advisories into the LOCAL,
//	version-pinned store (§5c/§5g); AdvisoriesFor then re-matches LOCALLY, so
//	the runtime path is offline and rate-limit-free. This stub performs neither
//	the sync nor the match.
type CiscoOpenVulnProvider struct {
	// configured is false for the stub. When the live connector lands this
	// becomes true only once an injected secret reader has yielded valid OAuth2
	// client credentials — the stub never sets it.
	configured bool
}

// NewCiscoOpenVulnProvider returns the unconfigured stub. It never carries
// credentials; wiring the real secret reader is a later task.
func NewCiscoOpenVulnProvider() *CiscoOpenVulnProvider {
	return &CiscoOpenVulnProvider{configured: false}
}

// Name identifies the Cisco openVuln provider.
func (p *CiscoOpenVulnProvider) Name() string { return SourceCiscoOpenVuln }

// AdvisoriesFor conforms to the seam but is not implemented: without provisioned
// OAuth2 client credentials it returns ErrNotConfigured, so a caller surfaces
// the device as UNASSESSED (never a false clear, §5g) rather than crashing.
func (p *CiscoOpenVulnProvider) AdvisoriesFor(ctx context.Context, q Query) ([]Advisory, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !p.configured {
		return nil, fmt.Errorf("%w: Cisco openVuln OAuth2 client credentials must be provisioned via the sealing/vault mechanism", ErrNotConfigured)
	}
	// Unreachable in the stub; the live connector queries the LOCAL synced store.
	return nil, fmt.Errorf("%w: live Cisco openVuln connector not implemented", ErrNotConfigured)
}
