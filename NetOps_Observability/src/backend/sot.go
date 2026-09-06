// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// sot.go — the Source-of-Truth provider seam.
//
// SoT is a ROLE filled by a PROVIDER, not a product. The platform's own internal
// inventory (Infrastructure → Devices + the sites store) is the DEFAULT provider
// and needs nothing external. An external CMDB (NetBox today; ServiceNow/Infoblox
// later) is an OPTIONAL connector that becomes the authority only when configured.
//
// One join point — geomapResolve — reads intent through SoTProvider, so neither
// the /api/geomap response nor the executive_geo projection knows or cares which
// provider answered. See docs/design/sot-provider-model.md.

import "context"

// SoTSite is a declared site with operator intent (placement) the wire can't give.
type SoTSite struct {
	Slug      string
	Name      string
	Status    string
	Lat       float64
	Lng       float64
	HasCoords bool
	// Owner is operator-declared ownership intent (team / on-call / business unit
	// responsible for the site). The wire can't supply it; the SoT can. This is the
	// ownership seam (Phase 3) — providers populate it when they carry it (internal
	// sites store today; ServiceNow/NetBox tenancy later), and consumers route
	// ownership through here rather than re-deriving it per surface. Empty = unset.
	Owner string
	// Source labels the evidence the projection attaches: "internal" | "netbox".
	Source string
}

// SoTProvider supplies operator INTENT. Sites/DeviceSites are TENANT-SCOPED: a
// non-cross principal must only ever receive its own tenant's intent. Every method
// MUST be safe on an empty provider (zero values, never panic).
type SoTProvider interface {
	Name() string
	// Sites returns the declared sites VISIBLE to the (tenant, cross) principal.
	Sites(ctx context.Context, tenant string, cross bool) ([]SoTSite, error)
	// DeviceSites maps a device identity token → site slug. May be nil when
	// placement is carried on the device itself (the internal provider reads
	// Device.Labels["site"], so it returns nil here).
	DeviceSites(ctx context.Context, tenant string, cross bool) (map[string]string, error)
	// Configured reports whether this provider is the active authority.
	Configured() bool
	// DeviceRecordSource is the Device.Source value under which this provider's
	// DECLARED device records appear in the inventory, used by drift detection to
	// pair declared intent against the observed inventory. Returns "" when the
	// provider carries NO separate declared records — the internal provider IS the
	// inventory, so there is nothing to drift device fields against; an external
	// provider that isn't read back into the inventory (e.g. NetBox in write-only
	// mode) likewise returns "". Drift checks stay inactive (honest "cannot assess")
	// rather than flooding false "unregistered" findings when no declared records
	// exist. See compliance.go.
	DeviceRecordSource() string
}

// activeSoT resolves the Source-of-Truth authority for the OBSERVABILITY plane
// (inventory placement, sites, geo, drift). This is ALWAYS the internal provider:
// the platform's own SNMP-discovered inventory + internal sites store ARE the
// source of truth (owner decision 2026-06-20). NetBox, when connected, is an
// AUTOMATION connector (Devices↔NetBox push/pull, see netbox_sync.go) — it never
// supersedes the platform's inventory, never drifts it, and never locks the
// placement UI read-only. The SoTProvider seam remains so a future external
// authority could be wired here explicitly, but none is selected by default.
func (s *server) activeSoT() SoTProvider {
	return &internalProvider{sites: s.sites, deviceSites: s.deviceSites}
}

// ── internal provider: the platform itself (DEFAULT) ─────────────────────────────

type internalProvider struct {
	sites       *sitesStore
	deviceSites *deviceSiteStore
}

func (p *internalProvider) Name() string     { return "internal" }
func (p *internalProvider) Configured() bool { return true } // always available

// The internal inventory is itself the authority — there is no separate declared
// device record to pair against, so device-field drift is not applicable.
func (p *internalProvider) DeviceRecordSource() string { return "" }

// DeviceSites returns operator device→site bindings (tenant-scoped). Placement
// can also come from a discovery-stamped Device.Labels["site"]; an explicit
// operator binding wins (buildGeomap checks `assign` before the label).
func (p *internalProvider) DeviceSites(_ context.Context, tenant string, cross bool) (map[string]string, error) {
	if p.deviceSites == nil {
		return nil, nil
	}
	return p.deviceSites.Assignments(tenant, cross), nil
}

func (p *internalProvider) Sites(_ context.Context, tenant string, cross bool) ([]SoTSite, error) {
	if p.sites == nil {
		return nil, nil
	}
	rows := p.sites.All(tenant, cross) // tenant-scoped: no cross-tenant leakage
	out := make([]SoTSite, 0, len(rows))
	for _, st := range rows {
		out = append(out, st.toSoT())
	}
	return out, nil
}

// NOTE: NetBox is intentionally NOT an SoT authority provider. It is an automation
// connector only (netbox_sync.go). The placement/sites/geo/drift authority is the
// internal provider above; see activeSoT.
