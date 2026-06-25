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
	"net/http"
	"os"

	"netops/backend/cloud"
)

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
