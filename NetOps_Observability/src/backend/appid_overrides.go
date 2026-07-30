package backend

// appid_overrides.go — main-side wiring for the operator app catalog
// (appid/catalog_store.go, extracted P2 RA.15): handlers + the three-state
// overridesFor composition.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"netops/backend/appid"
)

type (
	AppCatalogEntry = appid.AppCatalogEntry
	appCatalogStore = appid.CatalogStore
	tenantOverrides = appid.TenantOverrides
)

func newAppCatalogStore() appCatalogStore { return appid.NewCatalogStore() }

func validateAppCatalogInput(kind, value, app string) error {
	return appid.ValidateCatalogInput(kind, value, app)
}

// ── handlers ────────────────────────────────────────────────────────────────

func (s *server) handleAppIDCatalog(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		claims, ok := s.requirePerm(w, r, "infrastructure", LevelRead)
		if !ok {
			return
		}
		tenant, cross := principalTenant(claims)
		out, err := s.appOverrides.List(r.Context(), tenant, cross)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"entries": out, "count": len(out)})
	case http.MethodPost:
		claims, ok := s.requirePerm(w, r, "infrastructure", LevelWrite)
		if !ok {
			return
		}
		var in AppCatalogEntry
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 32<<10)).Decode(&in); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		if err := validateAppCatalogInput(in.MatchKind, in.MatchValue, in.AppLabel); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		tenant, cross := principalTenant(claims)
		if !cross {
			in.TenantID = tenant // scoped principal owns what it creates; body tenant ignored
		}
		out, err := s.appOverrides.Create(r.Context(), tenant, cross, in)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		writeJSON(w, http.StatusCreated, out)
	default:
		writeError(w, http.StatusMethodNotAllowed, errors.New("GET or POST"))
	}
}

func (s *server) handleAppIDCatalogByID(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/appid/catalog/")
	if !isUUIDToken(id) {
		writeError(w, http.StatusBadRequest, errors.New("invalid catalog id"))
		return
	}
	if r.Method != http.MethodDelete {
		writeError(w, http.StatusMethodNotAllowed, errors.New("DELETE only"))
		return
	}
	claims, ok := s.requirePerm(w, r, "infrastructure", LevelWrite)
	if !ok {
		return
	}
	tenant, cross := principalTenant(claims)
	ok2, err := s.appOverrides.Delete(r.Context(), tenant, cross, id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	if !ok2 {
		writeError(w, http.StatusNotFound, errNotFound)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"deleted": id})
}

// overridesFor loads the caller's tenant override entries and builds the per-tenant
// prefix + domain override structures (SrcOperator). Cheap: app_catalog is
// operator-curated.
//
// THREE states, never two (the cloud_monitor_eval.go shape). Operator overrides
// are the HIGHEST-precedence attribution source, so "the store did not answer"
// and "this tenant declared no overrides" must not share a branch: they used to,
// and a Postgres blip silently dropped the authoritative layer while the answer
// still carried a provenance/confidence as if the ladder had been complete.
// Callers that publish an attribution ANSWER must refuse on error; callers that
// merely enrich a list may continue, but must say so.
func (s *server) overridesFor(ctx context.Context, tenant string, cross bool) (tenantOverrides, error) {
	if s.appOverrides == nil {
		return tenantOverrides{}, nil // no override backend configured at all
	}
	entries, err := s.appOverrides.List(ctx, tenant, cross)
	if err != nil {
		return tenantOverrides{}, fmt.Errorf("read operator app overrides: %w", err)
	}
	if len(entries) == 0 {
		return tenantOverrides{}, nil // answered: this tenant declared none
	}
	return appid.BuildOverrides(entries), nil
}
