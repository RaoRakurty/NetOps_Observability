// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// cloud_handlers.go — Cloud App Observability API (#81 P3A). Read surfaces over the
// cloud inventory, tenant-scoped via principalTenant. These back the App Observability
// UI (Applications / Cloud Resources / Attribution / Unknowns).
//
//   GET /api/cloud/resources             — the cloud inventory (resource→app)
//   GET /api/cloud/identity-map          — the (match_key→app) mappings flows join on
//   GET /api/cloud/apps                  — apps derived from attributed resources
//   GET /api/cloud/attribution/coverage  — confirmed/strong/suspected/unknown + top-unknown

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"netops/backend/cloud"
	"netops/backend/internal/chschema"
)

// ── the operator-visibility restriction on this plane ───────────────────────
//
// The cloud plane is the customer's provider estate: its resources and their
// names, the accounts they sit in, the flow pairs between them, the provider's
// own change and security events, and the daily figures the provider BILLED that
// tenant. A cost line is commercially sensitive on its own — it is what the
// customer spends, by account and by service.
//
// A tenant that has switched the restriction on is invisible to the platform
// owner in logs, flows, metrics, tunnels, igpmon and the BMP feed. It must be
// invisible here too, and it has to be invisible through TWO storage models at
// once: the inventory STORE, which is asked for a (tenant, cross) pair, and
// ClickHouse, whose row policies enforce on a tenant_scope SETTING. Neither can
// express the rule alone. The store has no notion of a tenant the operator may
// not read, and the ClickHouse policies unlock everything under '__all__' by
// design — that is what the platform owner reads the Global view with. So the
// rule is resolved ONCE per request, from the same operatorTelemetryRestriction
// resolver the logs path uses, and each half is handed to the storage model in
// the form that model understands.
//
// It lives in this file rather than its own because the §2 root-package ceiling
// counts FILES: a new file here is a new domain in the wrong place, and this is
// not a new domain — it is the cloud read plane's own rule.

const (
	// cloudRestrictedScope is the tenant a DENIED store read is answered under.
	// It is not a tenant: no row anywhere carries it, so every tenant-keyed store
	// returns nothing for it and the caller gets a correctly shaped, empty view.
	// A resource by id answers 404, which is the same answer an id that does not
	// exist gets — never a 403, which would confirm the tenant has an estate.
	// This is the same sentinel-scope trick the DEM lane uses.
	cloudRestrictedScope = "__netops_operator_restricted__"

	// cloudDeniedCHScope is the ClickHouse tenant_scope a DENIED read runs at.
	// The cloud tables all carry the STRICT row policy
	// (tenant_id = getSetting('tenant_scope') OR getSetting('tenant_scope') = '__all__'),
	// so a scope no row carries matches nothing — including untagged rows, which
	// the strict policy does not share. It is the same sentinel chTenantScope
	// already fails closed to for a request with no claims.
	cloudDeniedCHScope = "__none__"
)

// cloudVisibility is the restriction resolved for one request. The two fields are
// the two halves of the rule: deny is the operator scoped INTO a restricted
// tenant (read nothing), exclude is the set of restricted tenants to drop from
// the operator's cross-tenant Global view.
type cloudVisibility struct {
	deny    bool
	exclude []string
	// scope is the caller's ClickHouse tenant_scope, derived at the ONE
	// chokepoint (s.chTenantScope) and carried here so no cloud read has to
	// re-derive it. The chokepoint already folds the deny half in, so this is
	// the read-nothing scope for a denied caller before chScope even looks.
	scope string
}

// cloudVisibilityFor resolves the rule for the request's principal. It is a
// no-op for every tenant's own users and for a platform with nothing restricted,
// which is the default, so ordinary deployments are unaffected.
func (s *server) cloudVisibilityFor(r *http.Request) cloudVisibility {
	claims, _ := userFrom(r.Context())
	tenant, cross := principalTenant(claims)
	exclude, deny := s.operatorTelemetryRestriction(claims, tenant, cross)
	return cloudVisibility{
		deny:    deny,
		exclude: exclude,
		scope:   cloud.SafeScopeLiteral(s.chTenantScope(r)),
	}
}

// storeScope narrows the (tenant, cross) pair a STORE read is issued with. A
// denied caller is scoped to a tenant that owns nothing; everyone else is
// unchanged.
func (v cloudVisibility) storeScope(tenant string, cross bool) (string, bool) {
	if v.deny {
		return cloudRestrictedScope, false
	}
	return tenant, cross
}

// chScope is the ClickHouse tenant_scope literal for this read.
//
// The scope was derived at the chokepoint, which already folds the deny half in
// for every ClickHouse read in the process. The explicit deny branch stays
// because this lane must not depend on that fold to stay closed: it is the same
// sentinel either way, and two independent reasons for it is what defence in
// depth means here.
func (v cloudVisibility) chScope() string {
	if v.deny {
		return cloudDeniedCHScope
	}
	return v.scope
}

// pred is the SQL exclusion predicate for the operator's Global view, as a
// leading-AND fragment ready to append to a WHERE clause. Empty for everyone
// else. The row policies cannot express this — '__all__' unlocks every tenant by
// design — so the exclusion has to be a predicate on the row's own tenant_id, the
// same column the logs path names in its must_not clause.
func (v cloudVisibility) pred() string {
	if len(v.exclude) == 0 {
		return ""
	}
	return " AND tenant_id NOT IN (" + sqlInList(v.exclude) + ")"
}

// hides reports whether a row owned by tenantID is invisible to this caller.
// Case-insensitive and blank-tolerant: the two sides are minted by different
// stores (the tenant store and the cloud inventory rows).
func (v cloudVisibility) hides(tenantID string) bool {
	if len(v.exclude) == 0 {
		return false
	}
	id := strings.TrimSpace(tenantID)
	if id == "" {
		return false
	}
	for _, x := range v.exclude {
		if strings.EqualFold(strings.TrimSpace(x), id) {
			return true
		}
	}
	return false
}

// resources drops a restricted tenant's resources from an inventory listing.
// It is a function rather than an inline loop because the app registry, the
// coverage report, the console links, the service-map endpoint names and the
// topology join are all DERIVED from the same slice: filtering once, at the
// read, is what stops a hidden resource coming back as an app, a tag-compliance
// row or a node on a map.
func (v cloudVisibility) resources(in []cloud.CloudResource) []cloud.CloudResource {
	if len(v.exclude) == 0 {
		return in
	}
	out := make([]cloud.CloudResource, 0, len(in))
	for _, c := range in {
		if v.hides(c.TenantID) {
			continue
		}
		out = append(out, c)
	}
	return out
}

// mappings drops a restricted tenant's identity mappings — the (match_key → app)
// rows flow attribution joins on. They name the tenant's apps and its ENIs.
func (v cloudVisibility) mappings(in []cloud.CloudIdentityMapping) []cloud.CloudIdentityMapping {
	if len(v.exclude) == 0 {
		return in
	}
	out := make([]cloud.CloudIdentityMapping, 0, len(in))
	for _, m := range in {
		if v.hides(m.TenantID) {
			continue
		}
		out = append(out, m)
	}
	return out
}

// connectors drops a restricted tenant's inventory-source provenance rows, which
// name the account the inventory was collected from.
func (v cloudVisibility) connectors(in []cloud.ConnectorInfo) []cloud.ConnectorInfo {
	if len(v.exclude) == 0 {
		return in
	}
	out := make([]cloud.ConnectorInfo, 0, len(in))
	for _, c := range in {
		if v.hides(c.TenantID) {
			continue
		}
		out = append(out, c)
	}
	return out
}

// isCloudAppToken bounds an app id used in a SQL literal: real app names carry
// letters/digits/.-_:/ and a space — never a quote/backslash/control char. Rejects
// injection without over-restricting (we cannot use isAlphaToken — apps have dots).
func isCloudAppToken(s string) bool { return cloud.IsCloudAppToken(s) }

func (s *server) cloudResources(r *http.Request) ([]cloud.CloudResource, string, bool, error) {
	claims, _ := userFrom(r.Context())
	tenant, cross := principalTenant(claims)
	// The operator-visibility restriction, applied at the ONE shared inventory
	// read. Everything derived from this slice — the app registry, the coverage
	// report, the console links, the service-map endpoint names, the topology
	// join — is derived from what survives here, so a hidden resource cannot come
	// back through any of them.
	vis := s.cloudVisibilityFor(r)
	tenant, cross = vis.storeScope(tenant, cross)
	res, err := s.cloud.ListResources(r.Context(), tenant, cross)
	if err != nil {
		return res, tenant, cross, err
	}
	res = vis.resources(res)
	// Manual overrides win over inference EVERYWHERE this inventory is read
	// (2026-07 review): the overlay used to apply only on the /resources
	// handler, so a confirmed operator assignment lifted the Resources table
	// but Apps / Coverage / Untagged still counted the resource as unknown —
	// the operator's fix looked like it didn't take. One shared read = one truth.
	if err := s.overlayManualMappings(r, tenant, cross, res); err != nil {
		return res, tenant, cross, err
	}
	return res, tenant, cross, nil
}

func (s *server) handleCloudResources(w http.ResponseWriter, r *http.Request) {
	claims, ok := s.requirePerm(w, r, "infrastructure", LevelRead)
	if !ok {
		return
	}
	// Server-side filters + keyset pagination (rev #2): the store filters and pages
	// in SQL, so a scale-out tenant's inventory is never loaded whole into memory.
	filter, err := parseCloudResourceFilter(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	tenant, cross := principalTenant(claims)
	// The restriction narrows the scope this page is read at; a restricted
	// tenant's rows are then dropped from the page itself, because the operator's
	// Global page spans tenants and the store has no notion of a tenant the
	// caller may not read.
	vis := s.cloudVisibilityFor(r)
	tenant, cross = vis.storeScope(tenant, cross)
	page, err := s.cloud.QueryResources(r.Context(), tenant, cross, filter)
	if err != nil {
		if errors.Is(err, cloud.ErrBadCursor) {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	res := vis.resources(page.Resources)
	// Manual operator overrides win over inference EVERYWHERE this inventory is read
	// (2026-07 review): one shared read = one truth, so the page agrees with
	// Apps / Coverage / Untagged. Applied to the returned page here.
	if err := s.overlayManualMappings(r, tenant, cross, res); err != nil {
		// Rendering the page without the overlay would show every CONFIRMED
		// assignment as the inferred guess, indistinguishable from an operator
		// who never assigned anything. Refuse the read instead.
		writeError(w, http.StatusBadGateway, err)
		return
	}
	// Inventory-source provenance (live poller vs hand fixture) — drives the
	// UI's honest data-mode badge. Tenant-scoped like the resources themselves.
	connectors, err := s.cloud.ListConnectors(r.Context(), tenant, cross)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	// Provenance names the ACCOUNT the inventory was collected from — a restricted
	// tenant's account id is as much its own as the resources in it.
	connectors = vis.connectors(connectors)
	// Live state per resource (provider status checks, provider traffic, our
	// active checks). Absent feeds stay "unknown" — never a fabricated healthy.
	live := s.cloudLiveStates(r.Context(), vis.chScope(), vis.pred(), res)
	out := make([]map[string]any, 0, len(res))
	for _, rs := range res {
		row := map[string]any{"resource": rs}
		if st, ok := live[rs.ResourceID]; ok {
			row["health"] = st.Health
			row["health_basis"] = st.HealthBasis
			if st.TrafficBytes != nil {
				row["traffic_bytes"] = *st.TrafficBytes
			}
			if st.CPUPct != nil {
				row["cpu_pct"] = *st.CPUPct
			}
		}
		out = append(out, row)
	}
	// Console deep-links, resource id → provider console URL (see cloud_console.go).
	// Only resolvable resources appear — an absent entry means "no honest link".
	consoleURLs := make(map[string]string, len(res))
	for _, rs := range res {
		if u := resourceConsoleURL(rs); u != "" {
			consoleURLs[rs.ResourceID] = u
		}
	}
	// The tenant's required-tag list (Wave 4 #11) rides along so the UI computes
	// "missing tags" against the SAME governance list the compliance report uses.
	requiredTags, _ := s.governance.RequiredTags(tenant)
	writeJSON(w, http.StatusOK, map[string]any{"resources": res, "live": out, "console_urls": consoleURLs, "connectors": connectors, "count": len(res), "next_cursor": page.NextCursor, "required_tags": requiredTags})
}

// parseCloudResourceFilter reads the /api/cloud/resources filter + pagination query
// params, validating every one at the boundary (§3 zero-trust) so a bad value is a
// clean 400 rather than a silently-empty result. Values are bounded and control-char
// free; provider/attribution are enum-checked; limit is clamped to cloud.PageMax.
func parseCloudResourceFilter(r *http.Request) (cloud.ResourceFilter, error) {
	q := r.URL.Query()
	f := cloud.ResourceFilter{Cursor: strings.TrimSpace(q.Get("cursor"))}
	if len(f.Cursor) > 2048 {
		return f, cloud.ErrBadCursor
	}
	get := func(key string) (string, error) {
		v := strings.TrimSpace(q.Get(key))
		if !boundedFilterVal(v) {
			return "", fmt.Errorf("invalid %s filter", key)
		}
		return v, nil
	}
	var err error
	if f.Provider, err = get("provider"); err != nil {
		return f, err
	}
	// provider is a multi-value OR set ("aws,azure" — Wave 2 #5 scope bar);
	// every part must be a known cloud, so a typo is a clean 400.
	for _, p := range cloud.FilterValues(f.Provider) {
		if !cloud.ValidProvider(cloud.Provider(strings.ToLower(p))) {
			return f, errors.New("invalid provider (want aws|azure|gcp)")
		}
	}
	if f.Account, err = get("account"); err != nil {
		return f, err
	}
	if f.Region, err = get("region"); err != nil {
		return f, err
	}
	if f.Type, err = get("type"); err != nil {
		return f, err
	}
	if f.Family, err = get("family"); err != nil {
		return f, err
	}
	// family is a CLASS filter over the kinds.go vocabulary; a typo is a clean
	// 400, never a silently-empty result.
	if f.Family != "" {
		f.Family = strings.ToLower(f.Family)
		if !cloud.ValidComponentFamily(f.Family) {
			return f, errors.New("invalid family (want instance|lb|waf|firewall|dns|gateway|seam|k8s|serverless|db|other)")
		}
	}
	if f.Tag, err = get("tag"); err != nil {
		return f, err
	}
	if f.Attribution, err = get("attribution"); err != nil {
		return f, err
	}
	if f.Attribution != "" && !validAttribution(f.Attribution) {
		return f, errors.New("invalid attribution")
	}
	if lim := strings.TrimSpace(q.Get("limit")); lim != "" {
		n, e := strconv.Atoi(lim)
		if e != nil || n <= 0 {
			return f, errors.New("invalid limit")
		}
		if n > cloud.PageMax {
			n = cloud.PageMax
		}
		f.Limit = n
	}
	return f, nil
}

// boundedFilterVal rejects an over-long or control-char-bearing filter value — the
// values are used as parameterized query args (never interpolated), this is
// belt-and-braces input hygiene at the boundary.
func boundedFilterVal(s string) bool {
	if len(s) > 256 {
		return false
	}
	for _, c := range s {
		if c < 0x20 || c == 0x7f {
			return false
		}
	}
	return true
}

// validAttribution bounds the attribution filter to the confidence ladder plus the
// two roll-up buckets.
func validAttribution(s string) bool {
	switch s {
	case "confirmed", "strong", "suspected", "weak", "unknown", "attributed", "unattributed":
		return true
	default:
		return false
	}
}

// overlayManualMappings applies confirmed operator overrides (resource_mappings)
// onto the attributed inventory in place: a manual mapping sets AppName/AppID to
// the assigned service, marks it operator-authoritative (SrcOperatorCatalog,
// Confirmed), so the human decision beats both a tag and an inference. No-op when
// the store is off (file backend).
//
// THREE states, never two (the cloud_monitor_eval.go shape): the mapping store
// did not answer (error — returned, because silently skipping the overlay
// REVERTS every operator-CONFIRMED assignment to the inferred guess and the page
// looks normal) / it answered with no mappings (nothing to overlay) / overlaid.
func (s *server) overlayManualMappings(r *http.Request, tenant string, cross bool, res []cloud.CloudResource) error {
	if s.bizServices == nil {
		return nil // file backend: manual mappings are not a feature here
	}
	byID, err := s.bizServices.MappingsByResource(r.Context(), tenant, cross)
	if err != nil {
		return fmt.Errorf("read operator service mappings: %w", err)
	}
	if len(byID) == 0 {
		return nil // answered: this tenant has confirmed no assignments
	}
	for i := range res {
		m, ok := byID[res[i].ResourceID]
		if !ok || strings.TrimSpace(m.ServiceName) == "" {
			continue
		}
		res[i].AppName = m.ServiceName
		res[i].AppID = cloud.AppIDFromName(m.ServiceName)
		res[i].Source = cloud.SrcOperatorCatalog
		res[i].Confidence = cloud.Confirmed
	}
	return nil
}

func (s *server) handleCloudIdentityMap(w http.ResponseWriter, r *http.Request) {
	claims, ok := s.requirePerm(w, r, "infrastructure", LevelRead)
	if !ok {
		return
	}
	tenant, cross := principalTenant(claims)
	// The mappings name the tenant's apps and the ENIs/IPs they live on, so they
	// obey the restriction like the inventory they were derived from.
	vis := s.cloudVisibilityFor(r)
	tenant, cross = vis.storeScope(tenant, cross)
	maps, err := s.cloud.ListMappings(r.Context(), tenant, cross)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	maps = vis.mappings(maps)
	writeJSON(w, http.StatusOK, map[string]any{"mappings": maps, "count": len(maps)})
}

func (s *server) handleCloudApps(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requirePerm(w, r, "infrastructure", LevelRead); !ok {
		return
	}
	res, _, _, err := s.cloudResources(r)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	apps := cloud.DeriveApps(res)
	vis := s.cloudVisibilityFor(r)
	// Roll the resources' live state up to the app: worst health wins (an app is
	// only as healthy as its unhealthiest resource), traffic sums.
	live := s.cloudLiveStates(r.Context(), vis.chScope(), vis.pred(), res)
	// Worst-wins rank with unknown ABOVE healthy (audit D-P2-10): an app holding
	// an unmeasured resource must not read plain "healthy" — silence is not
	// health. Faults still outrank blindness. "" seeds the fold so the first
	// real state (including healthy) always lands with its basis.
	rank := map[string]int{"": 0, "healthy": 1, "unknown": 2, "degraded": 3, "down": 4}
	type appLive struct {
		Health  string   `json:"health"`
		Basis   string   `json:"health_basis"`
		Traffic *float64 `json:"traffic_bytes,omitempty"`
	}
	byApp := map[string]*appLive{}
	for _, rs := range res {
		st, ok := live[rs.ResourceID]
		if !ok {
			continue
		}
		key := rs.AppID
		if key == "" {
			key = rs.AppName
		}
		if key == "" {
			key = rs.ResourceName
		}
		cur := byApp[key]
		if cur == nil {
			cur = &appLive{}
			byApp[key] = cur
		}
		if rank[st.Health] > rank[cur.Health] {
			cur.Health, cur.Basis = st.Health, st.HealthBasis
		}
		if st.TrafficBytes != nil {
			t := *st.TrafficBytes
			if cur.Traffic != nil {
				t += *cur.Traffic
			}
			cur.Traffic = &t
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"apps": apps, "live": byApp, "count": len(apps)})
}

func (s *server) handleCloudCoverage(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requirePerm(w, r, "infrastructure", LevelRead); !ok {
		return
	}
	res, tenant, _, err := s.cloudResources(r)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	// The TENANT's required-tag list drives the compliance report (Wave 4 #11:
	// the governance editor is what coverage/missing-tags actually read).
	requiredTags, _ := s.governance.RequiredTags(tenant)
	writeJSON(w, http.StatusOK, map[string]any{
		"coverage":       cloud.Coverage(res),
		"top_unknown":    cloud.TopUnknown(res, 25),
		"required_tags":  requiredTags,
		"tag_compliance": cloud.TagCompliance(res, requiredTags),
	})
}

// handleCloudAppRca serves GET /api/cloud/app-rca?app=<app> — the REAL engine-formed
// cloud RCA object(s) for an application (#81 P3G integration). Bridges the App
// Observability detail to the correlation engine: instead of a heuristic verdict, the
// app's panel links to the actual corr_object the engine grounded from cloud signals.
// Tenant-scoped via proxyClickHouse (the corr_objects row policy). Empty list when the
// app has no active RCA — "unknown" stays first-class, we never invent one.
func (s *server) handleCloudAppRca(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requirePerm(w, r, "infrastructure", LevelRead); !ok {
		return
	}
	app := strings.TrimSpace(r.URL.Query().Get("app"))
	if !isCloudAppToken(app) {
		writeError(w, http.StatusBadRequest, errors.New("invalid or missing app"))
		return
	}
	// has(affected.apps, app): only objects whose blast radius actually names this app.
	// cross_plane = the object carries an attached non-cloud observer (independent
	// corroboration) — derived from the distinct signal sources on the object.
	// Per-object signals live in corr_signals_archive (archived_for UUID), NOT
	// corr_signals. Join the object's archived window to derive the independent-
	// observer (cross_plane) fact + observed source planes. Joined on archived_for
	// only — the latest object version can outrun the archived version (close events
	// bump version without re-archiving), so a version-precise join would miss rows;
	// "any non-cloud observer ever grounded" is the honest cross-plane signal.
	// Bounded read (2026-07-09 incident): the archive is prefiltered to the picked
	// objects' ids — joining the raw table put ALL archive rows on the join's
	// build side (27.8M rows hashed per call). The archived_for skip index makes
	// the IN-prefilter a granule-pruned lookup.
	// #100 hardening: pick from the corr_current HOT projection with NAMED
	// narrow columns (never SELECT * — column pruning through a view is an
	// optimizer behavior, not a contract; one added reference re-widens it).
	// Corroboration facts (audit D-P2-12): observers = DISTINCT observer_ids
	// (who actually saw it), not source planes; the "corroborated" bit is the
	// engine's own plane_count ≥ 2 (the platform-wide ≥2-independent-streams
	// standard) — a countIf(source != 'cloud') fired on every flow-touched
	// object and carried no information.
	// Alias-shadowing guard (tracker 200, the 1c402b5c/dda24f37 class): both
	// datetime projections alias the ISO conversion back onto the column name
	// (window_start / created_at) because those ARE the served wire fields.
	// ClickHouse resolves a SELECT alias INSIDE the ORDER BY of the same query,
	// so the sort names the raw aggregate `any(o.created_at)` — the DateTime64
	// domain — and never the ISO String the alias renders. Latent before this
	// (RFC 3339 text sorts like the instant); a format change or an added range
	// predicate turns it into a silent mis-sort or code 386.
	// The operator-visibility restriction applies to the object pick: an app name
	// can be shared across tenants, so a restricted tenant's investigation could
	// otherwise be served for another tenant's app.
	vis := s.cloudVisibilityFor(r)
	sql := `
WITH picked AS (
     SELECT correlation_id, version, state, verdict_tier, top_confidence,
            top_hypothesis, signal_count, window_start, created_at, affected,
            plane_count
       FROM netops.corr_current FINAL
      WHERE has(JSONExtract(affected,'apps','Array(String)'), '` + app + `')` + vis.pred() + `
      ORDER BY created_at DESC
      LIMIT 10
)
SELECT toString(o.correlation_id)                   AS correlation_id,
       any(o.verdict_tier)                          AS verdict_tier,
       any(o.top_confidence)                        AS confidence,
       any(o.top_hypothesis)                        AS top_hypothesis,
       any(o.signal_count)                          AS signal_count,
       any(o.state)                                 AS state,
       ` + chschema.ISO("any(o.window_start)") + `         AS window_start,
       ` + chschema.ISO("any(o.created_at)") + `           AS created_at,
       any(o.affected)                              AS affected,
       arraySort(groupUniqArray(a.source))          AS sources,
       uniqExact(a.observer_id)                     AS observer_count,
       arraySort(groupUniqArray(8)(a.observer_id))  AS observers,
       any(o.plane_count)                           AS plane_count,
       any(o.plane_count) >= 2                      AS cross_plane
  FROM picked AS o
  INNER JOIN (
       SELECT archived_for, source, observer_id FROM netops.corr_signals_archive
        WHERE archived_for IN (SELECT correlation_id FROM picked)
  ) AS a
       ON a.archived_for = o.correlation_id
 GROUP BY o.correlation_id
 ORDER BY any(o.created_at) DESC
 FORMAT JSON`
	proxyClickHouseScope(w, r, vis.chScope(), sql)
}

// startCloudInventory loads the cloud inventory from the fixture provider into the
// store and keeps it FRESH (opt-in: CLOUD_FIXTURES_DIR). The cloud-ingest poller
// rewrites the fixture files from the live provider APIs every discovery cycle;
// loading only at boot served a stale lifecycle state (a started instance still
// read "stopped") until the next api restart — the exact 33h-staleness class the
// audit flagged on Azure (P0-2), on the consumer side. Real per-tenant SDK
// connectors replace this loader later; the store + API are unchanged. Stamps
// CLOUD_FIXTURE_TENANT (default "" = platform/global) — never a tenant from a fixture.
func (s *server) startCloudInventory(ctx context.Context) {
	// Layered inventory dirs (hygiene split): CLOUD_FIXTURES_DIR holds the
	// tracked static fixtures, CLOUD_RUNTIME_DIR the live poller's snapshots
	// (a gitignored data/ mount). A runtime file shadows the same-named
	// fixture, so a live deployment reads live data and a fresh install still
	// gets the demo fixtures.
	dir := os.Getenv("CLOUD_FIXTURES_DIR")
	runtime := os.Getenv("CLOUD_RUNTIME_DIR")
	if (dir == "" && runtime == "") || s.cloud == nil {
		return
	}
	tenant := os.Getenv("CLOUD_FIXTURE_TENANT") // "" = global
	prov := cloud.NewLayeredFixtureProvider(dir, runtime)
	lastCount := -1
	load := func() {
		res, err := prov.ListResources(ctx, tenant, "")
		if err != nil {
			logError("cloud", "fixture inventory load failed", map[string]any{"err": err.Error()})
			return
		}
		maps, _ := prov.ListIdentityMappings(ctx, tenant, "") // best-effort: identity mappings are optional enrichment; error → none
		if e := s.cloud.ReplaceInventory(ctx, tenant, res, maps); e != nil {
			logError("cloud", "inventory store failed", map[string]any{"err": e.Error()})
			return
		}
		// Provenance of each inventory file (live-poller stamp vs hand fixture) —
		// the UI's data-mode badge is derived from this, never assumed.
		if conns, e := prov.Connectors(ctx); e == nil {
			if e := s.cloud.ReplaceConnectors(ctx, tenant, conns); e != nil {
				logError("cloud", "connector provenance store failed", map[string]any{"err": e.Error()})
			}
		}
		if len(res) != lastCount {
			logInfo("cloud", "loaded fixture inventory", map[string]any{"resources": len(res), "mappings": len(maps)})
			lastCount = len(res)
		}
	}
	load()
	go func() {
		t := time.NewTicker(2 * time.Minute)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				load()
			}
		}
	}()
}
