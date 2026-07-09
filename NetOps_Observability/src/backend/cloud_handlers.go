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
	writeJSON(w, http.StatusOK, map[string]any{"resources": res, "count": len(res)})
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
	writeJSON(w, http.StatusOK, map[string]any{"apps": apps, "count": len(apps)})
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
	sql := `
WITH picked AS (
     SELECT * FROM netops.corr_objects_latest
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
// store at boot (opt-in: CLOUD_FIXTURES_DIR). Real per-tenant SDK connectors replace
// this loader later; the store + API are unchanged. Stamps CLOUD_FIXTURE_TENANT
// (default "" = platform/global, visible to the owner) — never a tenant from a fixture.
func (s *server) startCloudInventory(ctx context.Context) {
	dir := os.Getenv("CLOUD_FIXTURES_DIR")
	if dir == "" || s.cloud == nil {
		return
	}
	tenant := os.Getenv("CLOUD_FIXTURE_TENANT") // "" = global
	prov := cloud.NewFixtureProvider(dir)
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
	logInfo("cloud", "loaded fixture inventory", map[string]any{"resources": len(res), "mappings": len(maps)})
}
