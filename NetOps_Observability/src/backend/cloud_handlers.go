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

// isCloudAppToken bounds an app id used in a SQL literal: real app names carry
// letters/digits/.-_:/ and a space — never a quote/backslash/control char. Rejects
// injection without over-restricting (we cannot use isAlphaToken — apps have dots).
func isCloudAppToken(s string) bool { return cloud.IsCloudAppToken(s) }

func (s *server) cloudResources(r *http.Request) ([]cloud.CloudResource, string, bool, error) {
	claims, _ := userFrom(r.Context())
	tenant, cross := principalTenant(claims)
	res, err := s.cloud.ListResources(r.Context(), tenant, cross)
	if err != nil {
		return res, tenant, cross, err
	}
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
	page, err := s.cloud.QueryResources(r.Context(), tenant, cross, filter)
	if err != nil {
		if errors.Is(err, cloud.ErrBadCursor) {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	res := page.Resources
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
	// Live state per resource (provider status checks, provider traffic, our
	// active checks). Absent feeds stay "unknown" — never a fabricated healthy.
	live := s.cloudLiveStates(r.Context(), chTenantScope(r), res)
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
	maps, err := s.cloud.ListMappings(r.Context(), tenant, cross)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
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
	// Roll the resources' live state up to the app: worst health wins (an app is
	// only as healthy as its unhealthiest resource), traffic sums.
	live := s.cloudLiveStates(r.Context(), chTenantScope(r), res)
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
	sql := `
WITH picked AS (
     SELECT correlation_id, version, state, verdict_tier, top_confidence,
            top_hypothesis, signal_count, window_start, created_at, affected,
            plane_count
       FROM netops.corr_current FINAL
      WHERE has(JSONExtract(affected,'apps','Array(String)'), '` + app + `')
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
 ORDER BY created_at DESC
 FORMAT JSON`
	proxyClickHouse(w, r, sql)
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
		maps, _ := prov.ListIdentityMappings(ctx, tenant, "")
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
