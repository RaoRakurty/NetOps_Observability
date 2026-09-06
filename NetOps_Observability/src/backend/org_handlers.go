// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

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

	// LICENCE-BEGIN
	"netops/backend/internal/entitlement"
	// LICENCE-END
)

type createOrgRequest struct {
	Name string `json:"name"`
	// Slug is the optional human URL handle. Blank → derived from Name. Validated
	// + globally unique + immutable either way. The org's security key is the
	// opaque id minted server-side, never this slug.
	Slug          string `json:"slug"`
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
		// LICENCE-BEGIN — an ORG is the MSP/fleet construct: orgs exist to group
		// many tenants under one operator, so creating one beyond the seeded
		// Global org IS multi-tenant fleet management (owner spec, 2026-09-04).
		//
		// The seeded Global org always exists and is never gated — a
		// single-tenant deployment needs no entitlement to work normally, and
		// isolation between whatever orgs already exist is a safety property that
		// no licence state can touch.
		if err := entitlement.Require(s.entitlements, entitlement.FeatureMSPManagement); err != nil {
			entitlement.WriteRefusal(w, err)
			return
		}
		// LICENCE-END
		o, err := s.orgs.Create(req.Name, req.Slug, req.Note, req.HomeRegion, req.SSOConnection)
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		logInfo("orgs", "organization created", map[string]any{"org_id": o.ID, "org_slug": o.Slug, "home_region": o.HomeRegion})
		s.recordIdentityAudit(r, claims, "ORG_CREATED", auditOrgDetail(o))
		writeJSON(w, http.StatusCreated, o)
	default:
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *server) handleOrgByID(w http.ResponseWriter, r *http.Request) {
	claims, ok := s.requirePlatformAdmin(w, r)
	if !ok {
		return
	}
	ref := strings.TrimPrefix(r.URL.Path, "/api/orgs/")
	if ref == "" || strings.Contains(ref, "/") {
		writeError(w, http.StatusBadRequest, errors.New("invalid organization id"))
		return
	}
	// The path segment is UNTRUSTED (id or slug). Resolve it to the canonical
	// opaque id before any mutation; fail closed if it doesn't resolve.
	org, found := s.orgs.Resolve(ref)
	if !found {
		writeError(w, http.StatusNotFound, errors.New("organization not found"))
		return
	}
	id := org.ID
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
		s.recordIdentityAudit(r, claims, "ORG_UPDATED", auditOrgDetail(o))
		writeJSON(w, http.StatusOK, o)
	case http.MethodDelete:
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
		s.recordIdentityAudit(r, claims, "ORG_DELETED", auditOrgDetail(org))
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
