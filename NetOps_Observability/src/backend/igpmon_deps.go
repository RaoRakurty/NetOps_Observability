package backend

// igpmon_deps.go — the wiring for internal/igpmon (OSPF + IS-IS advanced
// monitoring, Project 4 D item 11).
//
// internal/igpmon holds NO ambient authority: it cannot reach ClickHouse,
// VictoriaMetrics, the inventory or the logger except through the Deps
// assembled here. Every collaborator below is the SAME primitive the rest of
// the platform uses for that job — deliberately reused rather than re-derived,
// because a second implementation of tenant scoping is a second thing that can
// silently be wrong:
//
//	Authz        → s.requirePerm(infrastructure:read) + principalTenant
//	Scope        → chTenantScope(r)               (ClickHouse row policies)
//	CHQuery      → s.chRowsScope                  (the one scoped read path)
//	ScopeFilters → metricsScopeFilters / restrictedTelemetry (the /api/metrics
//	               query rule, verbatim — including operator visibility)
//	VMQuery      → s.vmInstantScoped              (extra_filters[] on the wire)
//	LookupDevice → s.discovery.Get + deviceTenant
//	CanSee       → the central Authorize() device-view policy (canSeeDevice)
//
// The module is READ-ONLY and collects nothing; see internal/igpmon/doc.go for
// what is and is not actually collected on this platform, and why an absent
// source is reported as null rather than zero.

import (
	"context"
	"errors"
	"net/http"
	"time"

	"netops/backend/internal/igpmon"
)

// igpmonCHTag stamps system.query_log.log_comment so this module's ClickHouse
// reads are attributable to a per-endpoint budget (#100).
const igpmonCHTag = "api:igpmon"

// buildIGPMon assembles the module. It returns an error rather than a
// half-wired API: igpmon.New refuses an incomplete Deps, and a nil *API answers
// 404 on every route, so a failure here is dormant, never unscoped.
func (s *server) buildIGPMon() (*igpmon.API, error) {
	return igpmon.New(igpmon.Deps{
		Now:          time.Now,
		Authz:        s.igpmonAuthz,
		LookupDevice: s.igpmonLookupDevice,
		CanSee:       igpmonCanSee,
		Scope:        chTenantScope,
		CHQuery:      s.igpmonCHQuery,
		ScopeFilters: s.igpmonScopeFilters,
		VMQuery:      s.igpmonVMQuery,
		Metrics:      igpmon.NewMetrics(),
		WriteJSON:    writeJSON,
		WriteError:   writeError,
		LogWarn:      func(m string, f map[string]any) { logWarn("igpmon", m, f) },
	})
}

// igpmonAuthz maps the module's single gate onto the RBAC model. OSPF/IS-IS
// adjacency state is per-tenant DATA read from the correlation spine and the
// metric store, so it is requirePerm + a tenant filter — NOT a platform gate
// (§3a rule 3). Every route in the module is a READ; there is no write surface.
func (s *server) igpmonAuthz(w http.ResponseWriter, r *http.Request, gate igpmon.Gate) (igpmon.Principal, bool) {
	if gate != igpmon.GateRead {
		// The module declares exactly one gate. An unknown gate is a wiring bug,
		// and the safe answer to a gate we cannot map is refusal.
		writeError(w, http.StatusForbidden, errors.New("unsupported gate"))
		return igpmon.Principal{}, false
	}
	claims, ok := s.requirePerm(w, r, "infrastructure", LevelRead)
	if !ok {
		return igpmon.Principal{}, false
	}
	tenant, cross := principalTenant(claims)
	return igpmon.Principal{Tenant: tenant, Cross: cross, Subject: claims.Sub}, true
}

// igpmonLookupDevice resolves one device id from the shared inventory. The
// OWNER is stamped from the inventory row (deviceTenant), never from the
// request — the module then asks CanSee about it.
func (s *server) igpmonLookupDevice(id string) (igpmon.Device, bool) {
	if s.discovery == nil {
		return igpmon.Device{}, false
	}
	d, ok := s.discovery.Get(id)
	if !ok {
		return igpmon.Device{}, false
	}
	return igpmon.Device{ID: d.ID, Name: d.Name, TenantID: deviceTenant(d)}, true
}

// igpmonCanSee is the §3a rule-1 boundary, routed through the SAME central
// policy canSeeDevice uses: a TENANTED principal sees only its own tenant's
// devices, and never another tenant's. The module renders a false verdict here
// as a 404 identical to an absent device, so existence is never revealed.
//
// One honest caveat about untagged devices, verified on the live stack
// (2026-09-03) rather than assumed: rbac.SameTenantStrict("", "") is true, so
// a principal whose token carries NO tenant matches an untagged, platform-owned
// device and can read it — including through this route. That is the central
// policy's behaviour (internal/rbac/authz.go), not this module's, and it is not
// a cross-tenant leak (no tenant's device is ever exposed to another tenant).
// It is recorded here because the sentence this comment replaced claimed the
// opposite, and a comment claiming an isolation property the code does not have
// is worse than no comment. Tightening it belongs in rbac.Authorize, whose
// blast radius is every tenant-scoped resource.
func igpmonCanSee(d igpmon.Device, p igpmon.Principal) bool {
	return Authorize(
		Principal{Tenant: p.Tenant, Cross: p.Cross},
		ActionView,
		Resource{Type: ResDevice, Tenant: d.TenantID},
	).Allow
}

// igpmonCHQuery runs the module's one ClickHouse read at the caller's
// tenant_scope. The tenant_iso FORCE row policies on corr_signals /
// corr_signals_archive enforce on that scope server-side, so the module's own
// WHERE clause narrows but the policy isolates.
func (s *server) igpmonCHQuery(ctx context.Context, scope, sql string) ([]map[string]any, error) {
	return s.chRowsScope(ctx, scope, sql, igpmonCHTag)
}

// igpmonScopeFilters returns the caller's VictoriaMetrics `extra_filters[]`
// device boundary. It is the /api/metrics/query rule verbatim (proxyMetrics),
// including the operator-visibility restriction:
//
//   - an operator scoped INTO a restricted tenant matches nothing;
//   - a scoped tenant gets its own devices only (and the match-nothing sentinel
//     when it has none — never an unfiltered read);
//   - the platform owner in Global view is unrestricted except that restricted
//     tenants' devices are excluded;
//   - only an unrestricted cross-tenant principal gets nil, which igpmon reads
//     as "nothing to restrict".
func (s *server) igpmonScopeFilters(r *http.Request, _ igpmon.Principal) []string {
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

// errIGPMonUnscopableMetrics is the fail-closed condition when the configured
// metric backend cannot enforce label scoping. extra_filters[] is a
// VictoriaMetrics extension; a Prometheus upstream would evaluate the query
// UNSCOPED, so the read is refused (and igpmon reports live_series:false with a
// note) rather than served fleet-wide. Same rule as proxyMetrics' 501.
var errIGPMonUnscopableMetrics = errors.New("igpmon: metrics scoping requires a VictoriaMetrics backend")

// igpmonVMQuery runs one instant query with the caller's device boundary on the
// wire. The filters are passed to VictoriaMetrics as extra_filters[], which it
// AND-injects into every series selector server-side.
func (s *server) igpmonVMQuery(ctx context.Context, query string, filters []string) ([]igpmon.Sample, error) {
	if len(filters) > 0 && !metricsUpstreamIsVictoria(envOr("VICTORIA_URL", envOr("METRICS_URL", "http://victoria:8428"))) {
		return nil, errIGPMonUnscopableMetrics
	}
	samples, err := s.vmInstantScoped(ctx, query, filters)
	if err != nil {
		return nil, err
	}
	out := make([]igpmon.Sample, 0, len(samples))
	for _, sm := range samples {
		out = append(out, igpmon.Sample{Labels: sm.Labels, Value: sm.Value})
	}
	return out, nil
}
