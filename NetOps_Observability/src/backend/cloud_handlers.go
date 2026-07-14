package main

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
	"net/http"
	"os"
	"strings"
	"time"

	"netops/backend/cloud"
)

// isCloudAppToken bounds an app id used in a SQL literal: real app names carry
// letters/digits/.-_:/ and a space — never a quote/backslash/control char. Rejects
// injection without over-restricting (we cannot use isAlphaToken — apps have dots).
func isCloudAppToken(s string) bool {
	if s == "" || len(s) > 128 {
		return false
	}
	for _, c := range s {
		ok := c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' ||
			c == '.' || c == '-' || c == '_' || c == ':' || c == '/' || c == ' '
		if !ok {
			return false
		}
	}
	return true
}

func (s *server) cloudResources(r *http.Request) ([]cloud.CloudResource, string, bool, error) {
	claims, _ := userFrom(r.Context())
	tenant, cross := principalTenant(claims)
	res, err := s.cloud.ListResources(r.Context(), tenant, cross)
	return res, tenant, cross, err
}

func (s *server) handleCloudResources(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requirePerm(w, r, "infrastructure", LevelRead); !ok {
		return
	}
	res, _, _, err := s.cloudResources(r)
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
	writeJSON(w, http.StatusOK, map[string]any{"resources": res, "live": out, "count": len(res)})
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
	rank := map[string]int{"unknown": 0, "healthy": 1, "degraded": 2, "down": 3}
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
			cur = &appLive{Health: "unknown"}
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
	res, _, _, err := s.cloudResources(r)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"coverage":    cloud.Coverage(res),
		"top_unknown": cloud.TopUnknown(res, 25),
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
	sql := `
WITH picked AS (
     SELECT correlation_id, version, state, verdict_tier, top_confidence,
            top_hypothesis, signal_count, window_start, created_at, affected
       FROM netops.corr_current FINAL
      WHERE has(JSONExtract(affected,'apps','Array(String)'), '` + app + `')
      ORDER BY created_at DESC
      LIMIT 10
)
SELECT toString(o.correlation_id)            AS correlation_id,
       any(o.verdict_tier)                   AS verdict_tier,
       any(o.top_confidence)                 AS confidence,
       any(o.top_hypothesis)                 AS top_hypothesis,
       any(o.signal_count)                   AS signal_count,
       any(o.state)                          AS state,
       toString(any(o.window_start))         AS window_start,
       toString(any(o.created_at))           AS created_at,
       any(o.affected)                       AS affected,
       arraySort(groupUniqArray(a.source))   AS sources,
       countIf(a.source != 'cloud') > 0      AS cross_plane
  FROM picked AS o
  INNER JOIN (
       SELECT archived_for, source FROM netops.corr_signals_archive
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
	dir := os.Getenv("CLOUD_FIXTURES_DIR")
	if dir == "" || s.cloud == nil {
		return
	}
	tenant := os.Getenv("CLOUD_FIXTURE_TENANT") // "" = global
	prov := cloud.NewFixtureProvider(dir)
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
