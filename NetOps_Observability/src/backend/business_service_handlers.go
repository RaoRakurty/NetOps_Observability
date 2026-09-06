// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// business_service_handlers.go — API for the Business Service mapping (Azure
// optional-tags epic). Per-tenant data surfaces: every handler is requirePerm +
// principalTenant + tenant-filtered (CLAUDE.md §3a.3). The owner is stamped from
// the token, never the request body (§3a.2).
//
//   GET    /api/cloud/business-services            — list named services
//   POST   /api/cloud/business-services            — create a named service
//   PUT    /api/cloud/business-services/{id}        — rename/edit a service
//   DELETE /api/cloud/business-services/{id}        — delete (mappings revert to inference)
//   GET    /api/cloud/resource-mappings            — list resource→service overrides
//   PUT    /api/cloud/resource-mappings            — bulk-assign resources to a service
//   DELETE /api/cloud/resource-mappings/{resid...}  — clear a resource's override

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"netops/backend/cloud"
	"netops/backend/internal/servicecat"
	"strings"
)

var errBizSvcStoreOff = errors.New("business service store requires the Postgres backend")

// bizSvcName bounds a service name: printable, single line, ≤128 chars. Rejects
// control chars without over-restricting (services carry spaces, dots, dashes).
func bizSvcName(s string) bool {
	s = strings.TrimSpace(s)
	if s == "" || len(s) > 128 {
		return false
	}
	for _, c := range s {
		if c < 0x20 || c == 0x7f {
			return false
		}
	}
	return true
}

// bizSvcOwner bounds the optional owner label (a team or person). Empty means
// unset; non-empty follows the same printable single-line ≤128 rule as names.
func bizSvcOwner(s string) bool {
	return strings.TrimSpace(s) == "" || bizSvcName(s)
}

// bizSvcRunbookURL bounds the optional per-service runbook link (Wave 4 #12
// resolution actions). Empty means unset; non-empty must be an absolute
// https:// URL with a host, ≤512 chars, no control chars — the UI renders it
// as a click-through action, so only a scheme a browser can safely open is
// accepted (no javascript:, data:, http:, or relative URLs).
func bizSvcRunbookURL(s string) bool {
	s = strings.TrimSpace(s)
	if s == "" {
		return true
	}
	if len(s) > 512 {
		return false
	}
	for _, c := range s {
		if c < 0x20 || c == 0x7f {
			return false
		}
	}
	u, err := url.Parse(s)
	return err == nil && u.Scheme == "https" && u.Host != ""
}

func (s *server) handleBusinessServices(w http.ResponseWriter, r *http.Request) {
	if s.bizServices == nil {
		writeError(w, http.StatusNotImplemented, errBizSvcStoreOff)
		return
	}
	switch r.Method {
	case http.MethodGet:
		claims, ok := s.requirePerm(w, r, "infrastructure", LevelRead)
		if !ok {
			return
		}
		tenant, cross := principalTenant(claims)
		out, err := s.bizServices.ListServices(r.Context(), tenant, cross)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"business_services": out, "count": len(out)})
	case http.MethodPost:
		claims, ok := s.requirePerm(w, r, "infrastructure", LevelWrite)
		if !ok {
			return
		}
		var in cloud.BusinessService
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 32<<10)).Decode(&in); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		if !bizSvcName(in.Name) {
			writeError(w, http.StatusBadRequest, errors.New("invalid service name"))
			return
		}
		if in.Criticality != "" && !servicecat.ValidCriticality[in.Criticality] {
			writeError(w, http.StatusBadRequest, errors.New("invalid criticality"))
			return
		}
		if !bizSvcOwner(in.Owner) {
			writeError(w, http.StatusBadRequest, errors.New("invalid owner"))
			return
		}
		in.Owner = strings.TrimSpace(in.Owner)
		if !bizSvcRunbookURL(in.RunbookURL) {
			writeError(w, http.StatusBadRequest, errors.New("invalid runbook_url (absolute https:// URL, max 512 chars)"))
			return
		}
		in.RunbookURL = strings.TrimSpace(in.RunbookURL)
		tenant, cross := principalTenant(claims)
		if !cross {
			in.TenantID = tenant // scoped principal owns what it creates
		}
		in.CreatedBy = claims.Sub
		out, err := s.bizServices.CreateService(r.Context(), tenant, cross, in)
		if errors.Is(err, cloud.ErrConflict) {
			writeError(w, http.StatusConflict, errors.New("a service with that name already exists"))
			return
		}
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		writeJSON(w, http.StatusCreated, out)
	default:
		writeError(w, http.StatusMethodNotAllowed, errors.New("GET or POST"))
	}
}

func (s *server) handleBusinessServiceByID(w http.ResponseWriter, r *http.Request) {
	if s.bizServices == nil {
		writeError(w, http.StatusNotImplemented, errBizSvcStoreOff)
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/api/cloud/business-services/")
	if !isUUIDToken(id) {
		writeError(w, http.StatusBadRequest, errors.New("invalid service id"))
		return
	}
	switch r.Method {
	case http.MethodPut:
		claims, ok := s.requirePerm(w, r, "infrastructure", LevelWrite)
		if !ok {
			return
		}
		var in cloud.BusinessService
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 32<<10)).Decode(&in); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		if !bizSvcName(in.Name) {
			writeError(w, http.StatusBadRequest, errors.New("invalid service name"))
			return
		}
		if in.Criticality != "" && !servicecat.ValidCriticality[in.Criticality] {
			writeError(w, http.StatusBadRequest, errors.New("invalid criticality"))
			return
		}
		if !bizSvcOwner(in.Owner) {
			writeError(w, http.StatusBadRequest, errors.New("invalid owner"))
			return
		}
		in.Owner = strings.TrimSpace(in.Owner)
		if !bizSvcRunbookURL(in.RunbookURL) {
			writeError(w, http.StatusBadRequest, errors.New("invalid runbook_url (absolute https:// URL, max 512 chars)"))
			return
		}
		in.RunbookURL = strings.TrimSpace(in.RunbookURL)
		tenant, cross := principalTenant(claims)
		found, err := s.bizServices.UpdateService(r.Context(), tenant, cross, id, in)
		if errors.Is(err, cloud.ErrConflict) {
			writeError(w, http.StatusConflict, errors.New("a service with that name already exists"))
			return
		}
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		if !found {
			writeError(w, http.StatusNotFound, cloud.ErrNotFound)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"updated": id})
	case http.MethodDelete:
		claims, ok := s.requirePerm(w, r, "infrastructure", LevelWrite)
		if !ok {
			return
		}
		tenant, cross := principalTenant(claims)
		found, err := s.bizServices.DeleteService(r.Context(), tenant, cross, id)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		if !found {
			writeError(w, http.StatusNotFound, cloud.ErrNotFound)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"deleted": id})
	default:
		writeError(w, http.StatusMethodNotAllowed, errors.New("PUT or DELETE"))
	}
}

// assignRequest is the bulk-assignment body: bind a set of resources to a named
// service (by id) or to a free-text service name.
type assignRequest struct {
	BusinessServiceID string   `json:"business_service_id"`
	ServiceName       string   `json:"service_name"`
	ResourceIDs       []string `json:"resource_ids"`
}

func (s *server) handleResourceMappings(w http.ResponseWriter, r *http.Request) {
	if s.bizServices == nil {
		writeError(w, http.StatusNotImplemented, errBizSvcStoreOff)
		return
	}
	switch r.Method {
	case http.MethodGet:
		claims, ok := s.requirePerm(w, r, "infrastructure", LevelRead)
		if !ok {
			return
		}
		tenant, cross := principalTenant(claims)
		out, err := s.bizServices.ListMappings(r.Context(), tenant, cross)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"resource_mappings": out, "count": len(out)})
	case http.MethodPut:
		claims, ok := s.requirePerm(w, r, "infrastructure", LevelWrite)
		if !ok {
			return
		}
		var in assignRequest
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 256<<10)).Decode(&in); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		if len(in.ResourceIDs) == 0 || len(in.ResourceIDs) > 5000 {
			writeError(w, http.StatusBadRequest, errors.New("resource_ids must be 1..5000"))
			return
		}
		if in.BusinessServiceID != "" && !isUUIDToken(in.BusinessServiceID) {
			writeError(w, http.StatusBadRequest, errors.New("invalid business_service_id"))
			return
		}
		if in.ServiceName != "" && !bizSvcName(in.ServiceName) {
			writeError(w, http.StatusBadRequest, errors.New("invalid service_name"))
			return
		}
		if in.BusinessServiceID == "" && in.ServiceName == "" {
			writeError(w, http.StatusBadRequest, errors.New("business_service_id or service_name required"))
			return
		}
		tenant, cross := principalTenant(claims)
		n, err := s.bizServices.AssignResources(r.Context(), tenant, cross,
			in.BusinessServiceID, in.ServiceName, claims.Sub, in.ResourceIDs)
		if errors.Is(err, cloud.ErrNotFound) {
			writeError(w, http.StatusNotFound, errors.New("business service not found"))
			return
		}
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"assigned": n})
	default:
		writeError(w, http.StatusMethodNotAllowed, errors.New("GET or PUT"))
	}
}

func (s *server) handleResourceMappingByID(w http.ResponseWriter, r *http.Request) {
	if s.bizServices == nil {
		writeError(w, http.StatusNotImplemented, errBizSvcStoreOff)
		return
	}
	if r.Method != http.MethodDelete {
		writeError(w, http.StatusMethodNotAllowed, errors.New("DELETE"))
		return
	}
	claims, ok := s.requirePerm(w, r, "infrastructure", LevelWrite)
	if !ok {
		return
	}
	// The resource id is an ARM id / ARN / GCP path — slashes and all — so it is
	// the remainder of the path, URL-decoded by net/http already.
	resID := strings.TrimPrefix(r.URL.Path, "/api/cloud/resource-mappings/")
	if strings.TrimSpace(resID) == "" || len(resID) > 512 {
		writeError(w, http.StatusBadRequest, errors.New("invalid resource id"))
		return
	}
	tenant, cross := principalTenant(claims)
	found, err := s.bizServices.ClearMapping(r.Context(), tenant, cross, resID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	if !found {
		writeError(w, http.StatusNotFound, cloud.ErrNotFound)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"cleared": resID})
}
