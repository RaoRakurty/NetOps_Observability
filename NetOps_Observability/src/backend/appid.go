package main

// appid.go — Application Identification registry HTTP surface (#81 P0).
//   GET/POST    /api/applications
//   GET/DELETE  /api/applications/{id}     (DELETE = archive, never hard-delete)
// The catalog feeds + LPM-trie resolver + flow→app enrichment land in P1; this is
// the registry half of the P0 contract. All tenant-scoped via principalTenant; the
// store enforces isolation (CLAUDE.md §3a) and the cross-org test is appid_isolation_test.go.

import (
	"encoding/json"
	"errors"
	"net/http"
	"netops/backend/appid"
	"strings"
)

func (s *server) handleApplications(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		claims, ok := s.requirePerm(w, r, "infrastructure", LevelRead)
		if !ok {
			return
		}
		tenant, cross := principalTenant(claims)
		includeArchived := r.URL.Query().Get("archived") == "true"
		out, err := s.applications.List(r.Context(), tenant, cross, includeArchived)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		writeJSON(w, http.StatusOK, out)
	case http.MethodPost:
		claims, ok := s.requirePerm(w, r, "infrastructure", LevelWrite)
		if !ok {
			return
		}
		var in appid.Application
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&in); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		if err := appid.ValidateApplicationInput(in.Name, in.Criticality); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		tenant, cross := principalTenant(claims)
		if !cross {
			in.TenantID = tenant // scoped principal owns what it creates; tenant in the body is ignored
		}
		out, err := s.applications.Create(r.Context(), tenant, cross, in)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		writeJSON(w, http.StatusCreated, out)
	default:
		writeError(w, http.StatusMethodNotAllowed, errors.New("GET or POST"))
	}
}

func (s *server) handleApplicationByID(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/applications/")
	if i := strings.IndexByte(id, '/'); i >= 0 {
		id = id[:i]
	}
	if !isUUIDToken(id) {
		writeError(w, http.StatusBadRequest, errors.New("invalid application id"))
		return
	}
	switch r.Method {
	case http.MethodGet:
		claims, ok := s.requirePerm(w, r, "infrastructure", LevelRead)
		if !ok {
			return
		}
		tenant, cross := principalTenant(claims)
		app, found, err := s.applications.Get(r.Context(), tenant, cross, id)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		if !found {
			writeError(w, http.StatusNotFound, errNotFound)
			return
		}
		writeJSON(w, http.StatusOK, app)
	case http.MethodDelete:
		claims, ok := s.requirePerm(w, r, "infrastructure", LevelWrite)
		if !ok {
			return
		}
		tenant, cross := principalTenant(claims)
		ok2, err := s.applications.Archive(r.Context(), tenant, cross, id)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		if !ok2 {
			writeError(w, http.StatusNotFound, errNotFound)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"archived": id})
	default:
		writeError(w, http.StatusMethodNotAllowed, errors.New("GET or DELETE"))
	}
}
