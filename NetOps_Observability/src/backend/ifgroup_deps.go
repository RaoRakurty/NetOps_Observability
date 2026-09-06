// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// ifgroup_deps.go — the wiring for internal/ifgroup (per-device interfaces
// grouped by routing instance, frontend-wave item 4).
//
// internal/ifgroup holds NO ambient authority: it cannot reach the inventory,
// VictoriaMetrics, the vendor-profile registry or the logger except through the
// Deps assembled here. Every collaborator below is the SAME primitive the rest
// of the platform uses for that job — deliberately reused rather than
// re-derived, because a second implementation of tenant scoping is a second
// thing that can silently be wrong:
//
//	Authz        → s.requirePerm(infrastructure:read) + principalTenant
//	LookupDevice → s.discovery.Get + deviceTenant
//	CanSee       → the central Authorize() device-view policy (canSeeDevice)
//	ScopeFilters → metricsScopeFilters / restrictedTelemetry (the
//	               /api/metrics/query rule, verbatim — operator visibility included)
//	VMQuery      → s.vmInstantScoped              (extra_filters[] on the wire)
//	VRFTerm      → internal/netconcepts over the vendor-profile registry
//
// The module is READ-ONLY and collects nothing; see internal/ifgroup/doc.go for
// what is and is not actually collected on this platform, and why an interface
// with no vrf label is reported as UNGROUPED rather than as a member of a
// default instance.

import (
	"context"
	"errors"
	"net/http"

	"netops/backend/internal/ifgroup"
	"netops/backend/internal/netconcepts"
	"netops/backend/internal/vendorprofile"
)

// buildIfGroup assembles the module. It returns an error rather than a
// half-wired API: ifgroup.New refuses an incomplete Deps, and a nil *API answers
// 404 on its route, so a failure here is dormant, never unscoped.
func (s *server) buildIfGroup() (*ifgroup.API, error) {
	return ifgroup.New(ifgroup.Deps{
		Authz:        s.ifgroupAuthz,
		LookupDevice: s.ifgroupLookupDevice,
		CanSee:       ifgroupCanSee,
		ScopeFilters: s.ifgroupScopeFilters,
		VMQuery:      s.ifgroupVMQuery,
		VRFTerm:      ifgroupVRFTerm,
		WriteJSON:    writeJSON,
		WriteError:   writeError,
		LogWarn:      func(m string, f map[string]any) { logWarn("ifgroup", m, f) },
	})
}

// ifgroupAuthz maps the module's single gate onto the RBAC model. Interface
// state and utilisation are per-tenant DATA read from the metric store, so it is
// requirePerm + a tenant filter — NOT a platform gate (§3a rule 3). The module
// has no write surface.
func (s *server) ifgroupAuthz(w http.ResponseWriter, r *http.Request, gate ifgroup.Gate) (ifgroup.Principal, bool) {
	if gate != ifgroup.GateRead {
		// The module declares exactly one gate. An unknown gate is a wiring bug,
		// and the safe answer to a gate we cannot map is refusal.
		writeError(w, http.StatusForbidden, errors.New("unsupported gate"))
		return ifgroup.Principal{}, false
	}
	claims, ok := s.requirePerm(w, r, "infrastructure", LevelRead)
	if !ok {
		return ifgroup.Principal{}, false
	}
	tenant, cross := principalTenant(claims)
	return ifgroup.Principal{Tenant: tenant, Cross: cross, Subject: claims.Sub}, true
}

// ifgroupLookupDevice resolves one device id from the shared inventory. The
// OWNER is stamped from the inventory row (deviceTenant), never from the
// request — the module then asks CanSee about it.
func (s *server) ifgroupLookupDevice(id string) (ifgroup.Device, bool) {
	if s.discovery == nil {
		return ifgroup.Device{}, false
	}
	d, ok := s.discovery.Get(id)
	if !ok {
		return ifgroup.Device{}, false
	}
	return ifgroup.Device{ID: d.ID, Name: d.Name, Vendor: d.Vendor, TenantID: deviceTenant(d)}, true
}

// ifgroupCanSee is the §3a rule-1 boundary, routed through the SAME central
// policy canSeeDevice uses: a TENANTED principal sees only its own tenant's
// devices, and never another tenant's. The module renders a false verdict as a
// 404 identical to an absent device, so existence is never revealed.
//
// Same honest caveat as igpmonCanSee: rbac.SameTenantStrict("", "") is true, so
// a token carrying NO tenant matches an untagged, platform-owned device and can
// read it. Verified live 2026-09-03. Not a cross-tenant leak — no tenant's
// device reaches another tenant — but it is not what the sentence this replaced
// claimed, and the fix belongs in rbac.Authorize, not here.
func ifgroupCanSee(d ifgroup.Device, p ifgroup.Principal) bool {
	return Authorize(
		Principal{Tenant: p.Tenant, Cross: p.Cross},
		ActionView,
		Resource{Type: ResDevice, Tenant: d.TenantID},
	).Allow
}

// ifgroupScopeFilters returns the caller's VictoriaMetrics `extra_filters[]`
// device boundary. It is the /api/metrics/query rule verbatim (proxyMetrics),
// including the operator-visibility restriction:
//
//   - an operator scoped INTO a restricted tenant matches nothing;
//   - a scoped tenant gets its own devices only (and the match-nothing sentinel
//     when it has none — never an unfiltered read);
//   - the platform owner in Global view is unrestricted except that restricted
//     tenants' devices are excluded;
//   - only an unrestricted cross-tenant principal gets nil, which ifgroup reads
//     as "nothing to restrict".
func (s *server) ifgroupScopeFilters(r *http.Request, _ ifgroup.Principal) []string {
	claims, _ := userFrom(r.Context())
	ids, names, cross := s.visibleDeviceMetricLabels(claims)
	rt := s.restrictedTelemetry(claims)
	switch {
	case rt.deny:
		return []string{`{device="__netops_no_visible_device__"}`}
	case !cross:
		return metricsScopeFilters(ids, names, cross)
	case len(rt.ids) > 0 || len(rt.names) > 0:
		if f := metricsExcludeFilter(rt.ids, rt.names); f != "" {
			return []string{f}
		}
	}
	return nil
}

// errIfGroupUnscopableMetrics is the fail-closed condition when the configured
// metric backend cannot enforce label scoping. extra_filters[] is a
// VictoriaMetrics extension; a Prometheus upstream would evaluate the query
// UNSCOPED, so the read is refused rather than served fleet-wide. Same rule as
// proxyMetrics' 501.
var errIfGroupUnscopableMetrics = errors.New("ifgroup: metrics scoping requires a VictoriaMetrics backend")

// ifgroupVMQuery runs one instant query with the caller's device boundary on the
// wire. The filters are passed to VictoriaMetrics as extra_filters[], which it
// AND-injects into every series selector server-side.
func (s *server) ifgroupVMQuery(ctx context.Context, query string, filters []string) ([]ifgroup.Sample, error) {
	if len(filters) > 0 && !metricsUpstreamIsVictoria(envOr("VICTORIA_URL", envOr("METRICS_URL", "http://victoria:8428"))) {
		return nil, errIfGroupUnscopableMetrics
	}
	samples, err := s.vmInstantScoped(ctx, query, filters)
	if err != nil {
		return nil, err
	}
	out := make([]ifgroup.Sample, 0, len(samples))
	for _, sm := range samples {
		out = append(out, ifgroup.Sample{Labels: sm.Labels, Value: sm.Value})
	}
	return out, nil
}

// ifgroupVRFTerm resolves the device vendor's own word for the VRF concept, and
// reports whether a vendor profile actually CLAIMS that vendor. The word for an
// unclaimed vendor is the industry-majority display default from
// internal/netconcepts — rendering a label, not identifying the device — so the
// response can stay honest about which of the two it is showing.
func ifgroupVRFTerm(vendor string) (string, bool) {
	if term, ok := vendorprofile.Default().VRFDisplayTerm(vendor); ok {
		return term, true
	}
	return netconcepts.VRFDisplayTerm(vendor), false
}
