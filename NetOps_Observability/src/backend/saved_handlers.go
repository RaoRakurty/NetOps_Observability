// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
)

// REST surface for saved objects:
//   GET    /api/saved          list (optional ?type=saved_search|dashboard|report)
//   POST   /api/saved          create  {type,name,body}
//   GET    /api/saved/{id}     fetch one
//   PUT    /api/saved/{id}     update  {name?,body?}
//   DELETE /api/saved/{id}     remove

type savedRequest struct {
	Type     string          `json:"type"`
	Name     string          `json:"name"`
	TenantID string          `json:"tenant_id"`
	Body     json.RawMessage `json:"body"`
}

func (s *server) handleSaved(w http.ResponseWriter, r *http.Request) {
	claims, _ := userFrom(r.Context())
	switch r.Method {
	case http.MethodGet:
		// Tenant isolation: List is RLS/scope-filtered per request (pg backend) or
		// in-memory filtered (file backend); visibleSavedFor is the app-layer pass
		// on top, and it carries the operator-visibility restriction — the store's
		// own scope answers everything to a cross-tenant caller (tracker 306).
		writeJSON(w, http.StatusOK, s.visibleSavedFor(claims, r.URL.Query().Get("type")))
	case http.MethodPost:
		var req savedRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		// A scoped principal can only create objects inside its own tenant; a
		// cross-tenant principal may target any tenant (defaults to global).
		// §3a.2: the owner comes from the token whenever the caller is scoped.
		v := s.savedVisibilityFor(claims)
		objTenant := req.TenantID
		if !v.cross {
			objTenant = v.tenant
		}
		// ...but never INTO a tenant the operator-visibility restriction hides
		// from this caller. A saved `report` is a standing delivery instruction
		// the platform executes on a timer against that tenant's data, so
		// planting one is a write-path route to the read the restriction forbids.
		// 403, not 404: the tenant id came from this caller's own request, so
		// refusing plainly discloses nothing it did not already supply.
		if !v.creatable(objTenant) {
			writeError(w, http.StatusForbidden, errors.New("tenant not available to this principal"))
			return
		}
		obj, err := s.saved.Create(req.Type, strings.TrimSpace(req.Name), claims.Sub, objTenant, req.Body)
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		logInfo("saved", "created", map[string]any{"id": obj.ID, "type": obj.Type, "owner": obj.Owner, "tenant": obj.TenantID})
		writeJSON(w, http.StatusCreated, obj)
	default:
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *server) handleSavedByID(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/saved/")
	if id == "" || strings.Contains(id, "/") {
		writeError(w, http.StatusBadRequest, errors.New("invalid id"))
		return
	}
	claims, _ := userFrom(r.Context())
	// The RESOLVED rule, not a bare (tenant, cross) pair: the saved store's Get
	// is UNSCOPED — every gate below is the only thing standing between the
	// caller and another tenant's object, and the tenancy half of those gates
	// answers true for everything cross-tenant (tracker 306).
	v := s.savedVisibilityFor(claims)
	switch r.Method {
	case http.MethodGet:
		obj, ok := s.saved.Get(id)
		// 404 (not 403) for objects outside the caller's reach — its own tenant's,
		// and a restricted tenant's: don't reveal the id exists.
		if !ok || !v.visible(obj) {
			writeError(w, http.StatusNotFound, errors.New("not found"))
			return
		}
		writeJSON(w, http.StatusOK, obj)
	case http.MethodPut:
		// A scoped principal may only mutate an object owned by its own tenant,
		// and nobody may mutate one the restriction hides. Checked BEFORE the
		// write, so the refusal is not a rollback.
		if obj, ok := s.saved.Get(id); !ok || !v.mutable(obj) {
			writeError(w, http.StatusNotFound, errors.New("not found"))
			return
		}
		var req savedRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		obj, err := s.saved.Update(id, strings.TrimSpace(req.Name), req.Body)
		if err != nil {
			writeError(w, http.StatusNotFound, err)
			return
		}
		writeJSON(w, http.StatusOK, obj)
	case http.MethodDelete:
		if obj, ok := s.saved.Get(id); !ok || !v.mutable(obj) {
			writeError(w, http.StatusNotFound, errors.New("not found"))
			return
		}
		if err := s.saved.Delete(id); err != nil {
			writeError(w, http.StatusNotFound, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		w.Header().Set("Allow", "GET, PUT, DELETE")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}
