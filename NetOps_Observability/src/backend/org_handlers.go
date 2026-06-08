package main

// org_handlers.go — REST surface for the Organization layer (orgs.go).
//
//	GET    /api/orgs           list orgs (cross-tenant sees all; a tenant admin
//	                           sees only its own org)
//	POST   /api/orgs           create org              (platform owner only)
//	PATCH  /api/orgs/{id}      update note/region/SSO  (platform owner only)
//	DELETE /api/orgs/{id}      delete (refused if it still owns tenants; Global
//	                           is permanent)            (platform owner only)
//	GET    /api/regions        the known data-residency regions (for selectors)
//
// Orgs sit above tenants and are a platform-governance entity; mutations are
// restricted to the platform owner. Region routing/isolation is unchanged here.

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
)

type createOrgRequest struct {
	Name          string `json:"name"`
	Note          string `json:"note"`
	HomeRegion    string `json:"home_region"`
	SSOConnection string `json:"sso_connection"`
}

func (s *server) handleOrgs(w http.ResponseWriter, r *http.Request) {
	claims, ok := s.requireAdmin(w, r)
	if !ok {
		return
	}
	_, cross := principalTenant(claims)
	switch r.Method {
	case http.MethodGet:
		all := s.orgs.List()
		if cross {
			writeJSON(w, http.StatusOK, all)
			return
		}
		// A tenant admin sees only the org its own tenant belongs to.
		ownOrg := s.principalOrg(claims)
		out := make([]Org, 0, 1)
		for _, o := range all {
			if strings.EqualFold(o.ID, ownOrg) {
				out = append(out, o)
			}
		}
		writeJSON(w, http.StatusOK, out)
	case http.MethodPost:
		if _, ok := s.requirePlatformAdmin(w, r); !ok {
			return
		}
		var req createOrgRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		o, err := s.orgs.Create(req.Name, req.Note, req.HomeRegion, req.SSOConnection)
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		logInfo("orgs", "organization created", map[string]any{"org_id": o.ID, "home_region": o.HomeRegion})
		writeJSON(w, http.StatusCreated, o)
	default:
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *server) handleOrgByID(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requirePlatformAdmin(w, r); !ok {
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/api/orgs/")
	if id == "" || strings.Contains(id, "/") {
		writeError(w, http.StatusBadRequest, errors.New("invalid organization id"))
		return
	}
	switch r.Method {
	case http.MethodPatch:
		var u orgUpdate
		if err := json.NewDecoder(r.Body).Decode(&u); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		if u.Note == nil && u.HomeRegion == nil && u.SSOConnection == nil {
			writeError(w, http.StatusBadRequest, errors.New("no updatable field provided"))
			return
		}
		o, err := s.orgs.Update(id, u)
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		logInfo("orgs", "organization updated", map[string]any{"org_id": o.ID, "home_region": o.HomeRegion})
		writeJSON(w, http.StatusOK, o)
	case http.MethodDelete:
		if _, found := s.orgs.Get(id); !found {
			writeError(w, http.StatusNotFound, errors.New("organization not found"))
			return
		}
		// Refuse to delete an org that still owns tenants — it would orphan them.
		// Move/remove the tenants first (mirrors the tenant delete-guard).
		if n := s.tenants.CountByOrg(id); n > 0 {
			writeError(w, http.StatusConflict, fmt.Errorf("organization still owns %d tenant(s) — reassign or remove them first", n))
			return
		}
		if err := s.orgs.Delete(id); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		logWarn("orgs", "organization deleted", map[string]any{"org_id": id})
		w.WriteHeader(http.StatusNoContent)
	default:
		w.Header().Set("Allow", "PATCH, DELETE")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleRegions exposes the known data-residency regions so the UI can populate
// org/tenant region selectors without hard-coding the list. Any admin may read.
func (s *server) handleRegions(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireAdmin(w, r); !ok {
		return
	}
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, http.StatusOK, RegionList())
}
