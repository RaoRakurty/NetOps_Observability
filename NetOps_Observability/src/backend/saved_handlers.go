// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"netops/backend/internal/rbac"
	"netops/backend/internal/saved"
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

// savedModule is the RBAC module a saved object's type belongs to: a saved
// report is a Reports object, everything else (searches, dashboards, views)
// an Explore one.
func savedModule(objType string) string {
	if objType == "report" {
		return "reports"
	}
	return "explore"
}

// savedCanRead: the caller may read the module the object belongs to. This is
// what keeps a zero-permission credential out — above all an `ingest:*` API
// key, which is published inside customers' web pages (the RUM snippet) and so
// must not list, read or touch a single saved object (2026-11-22: the routes
// carried no permission check at all).
func (s *server) savedCanRead(claims jwtClaims, objType string) bool {
	return s.roles.Allows(claims.Role, savedModule(objType), rbac.LevelRead)
}

// savedCanWrite: the caller holds write permission on SOME module. Read-only,
// auditor, api-client and ingest principals hold none, so they cannot create,
// change or delete saved objects; operators (alerts/infrastructure write) keep
// saving searches, dashboards and reports as before.
func (s *server) savedCanWrite(claims jwtClaims, objType string) bool {
	if !s.savedCanRead(claims, objType) {
		return false
	}
	for _, m := range rbac.Modules {
		if s.roles.Allows(claims.Role, m, rbac.LevelWrite) {
			return true
		}
	}
	return false
}

func (s *server) handleSaved(w http.ResponseWriter, r *http.Request) {
	claims, _ := userFrom(r.Context())
	switch r.Method {
	case http.MethodGet:
		typ := r.URL.Query().Get("type")
		if typ != "" && !s.savedCanRead(claims, typ) {
			writeError(w, http.StatusForbidden, errors.New(savedModule(typ)+" read permission required"))
			return
		}
		if !s.savedCanRead(claims, "") && !s.savedCanRead(claims, "report") {
			writeError(w, http.StatusForbidden, errors.New("read permission required"))
			return
		}
		// Tenant isolation: List is RLS/scope-filtered per request (pg backend) or
		// in-memory filtered (file backend); visibleSavedFor is the app-layer pass
		// on top, and it carries the operator-visibility restriction — the store's
		// own scope answers everything to a cross-tenant caller (tracker 306).
		out := s.visibleSavedFor(claims, typ)
		kept := make([]saved.Object, 0, len(out))
		for _, o := range out {
			if s.savedCanRead(claims, o.Type) {
				kept = append(kept, o)
			}
		}
		writeJSON(w, http.StatusOK, kept)
	case http.MethodPost:
		var req savedRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		if !s.savedCanWrite(claims, req.Type) {
			writeError(w, http.StatusForbidden, errors.New("write permission required to save"))
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
		// and a restricted tenant's: don't reveal the id exists. A caller without
		// read on the object's module gets the same answer.
		if !ok || !v.visible(obj) || !s.savedCanRead(claims, obj.Type) {
			writeError(w, http.StatusNotFound, errors.New("not found"))
			return
		}
		writeJSON(w, http.StatusOK, obj)
	case http.MethodPut:
		// A scoped principal may only mutate an object owned by its own tenant,
		// and nobody may mutate one the restriction hides. Checked BEFORE the
		// write, so the refusal is not a rollback.
		if obj, ok := s.saved.Get(id); !ok || !v.mutable(obj) || !s.savedCanRead(claims, obj.Type) {
			writeError(w, http.StatusNotFound, errors.New("not found"))
			return
		} else if !s.savedCanWrite(claims, obj.Type) {
			writeError(w, http.StatusForbidden, errors.New("write permission required to change it"))
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
		if obj, ok := s.saved.Get(id); !ok || !v.mutable(obj) || !s.savedCanRead(claims, obj.Type) {
			writeError(w, http.StatusNotFound, errors.New("not found"))
			return
		} else if !s.savedCanWrite(claims, obj.Type) {
			writeError(w, http.StatusForbidden, errors.New("write permission required to delete it"))
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
