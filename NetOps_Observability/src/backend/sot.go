package main

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
	// Source labels the evidence the projection attaches: "internal" | "netbox".
	Source string
}

// SoTProvider supplies operator INTENT. Every method is tenant-scoped by the
// caller and MUST be safe on an empty provider (zero values, never panic).
type SoTProvider interface {
	Name() string
	// Sites returns declared sites (with coordinates when set).
	Sites(ctx context.Context) ([]SoTSite, error)
	// DeviceSites maps a device identity token → site slug. May be nil when
	// placement is carried on the device itself (the internal provider reads
	// Device.Labels["site"], so it returns nil here).
	DeviceSites(ctx context.Context) (map[string]string, error)
	// Configured reports whether this provider is the active authority.
	Configured() bool
}

// activeSoT resolves the authority: an enabled+configured external provider wins,
// otherwise the always-available internal provider. The internal provider is never
// "off" — at worst it is empty, which the UI handles with its onboarding state.
func (s *server) activeSoT() SoTProvider {
	if nb := (&netboxProvider{s: s}); nb.Configured() {
		return nb
	}
	return &internalProvider{sites: s.sites}
}

// ── internal provider: the platform itself (DEFAULT) ─────────────────────────────

type internalProvider struct {
	sites *sitesStore
}

func (p *internalProvider) Name() string     { return "internal" }
func (p *internalProvider) Configured() bool { return true } // always available
func (p *internalProvider) DeviceSites(context.Context) (map[string]string, error) {
	// Placement lives on the device (Labels["site"]); buildGeomap reads it directly.
	return nil, nil
}

func (p *internalProvider) Sites(context.Context) ([]SoTSite, error) {
	if p.sites == nil {
		return nil, nil
	}
	rows := p.sites.All()
	out := make([]SoTSite, 0, len(rows))
	for _, st := range rows {
		out = append(out, st.toSoT())
	}
	return out, nil
}

// ── netbox provider: wraps the existing fetch + cache (OPTIONAL, external) ───────

type netboxProvider struct {
	s *server
}

func (p *netboxProvider) Name() string { return "netbox" }

func (p *netboxProvider) Configured() bool {
	if p.s == nil || p.s.netboxCfg == nil {
		return false
	}
	cfg := p.s.netboxCfg.effective()
	return cfg.Enabled && cfg.URL != "" && cfg.Token != ""
}

func (p *netboxProvider) Sites(ctx context.Context) ([]SoTSite, error) {
	sites, _, err := p.fetch(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]SoTSite, 0, len(sites))
	for _, nb := range sites {
		if nb.Slug == "" {
			continue
		}
		s := SoTSite{Slug: nb.Slug, Name: nb.Name, Source: "netbox"}
		if nb.Status != nil {
			s.Status = nb.Status.Value
		}
		if nb.Latitude != nil && nb.Longitude != nil {
			s.Lat, s.Lng, s.HasCoords = *nb.Latitude, *nb.Longitude, true
		}
		out = append(out, s)
	}
	return out, nil
}

func (p *netboxProvider) DeviceSites(ctx context.Context) (map[string]string, error) {
	_, assign, err := p.fetch(ctx)
	return assign, err
}
