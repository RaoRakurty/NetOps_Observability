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
		// in-memory filtered (file backend); visibleSaved stays as a defense-in-
		// depth app-layer pass.
		tenant, cross := principalTenant(claims)
		writeJSON(w, http.StatusOK, visibleSaved(s.saved.List(r.URL.Query().Get("type"), tenant, cross), claims))
	case http.MethodPost:
		var req savedRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		// A scoped principal can only create objects inside its own tenant; a
		// cross-tenant principal may target any tenant (defaults to global).
		tenant, cross := principalTenant(claims)
		objTenant := req.TenantID
		if !cross {
			objTenant = tenant
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
	tenant, cross := principalTenant(claims)
	switch r.Method {
	case http.MethodGet:
		obj, ok := s.saved.Get(id)
		// 404 (not 403) for out-of-tenant objects: don't reveal the id exists.
		if !ok || !canSeeSaved(obj, tenant, cross) {
			writeError(w, http.StatusNotFound, errors.New("not found"))
			return
		}
		writeJSON(w, http.StatusOK, obj)
	case http.MethodPut:
		// A scoped principal may only mutate an object owned by its own tenant.
		if obj, ok := s.saved.Get(id); !ok || !canMutateSaved(obj, tenant, cross) {
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
		if obj, ok := s.saved.Get(id); !ok || !canMutateSaved(obj, tenant, cross) {
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
